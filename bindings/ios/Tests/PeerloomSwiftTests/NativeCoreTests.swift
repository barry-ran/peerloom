// MIT — Copyright (c) 2026 Peerloom contributors.
import XCTest
import Foundation
import CPeerloom
@testable import PeerloomSwift

final class EmptyStore: IdentityStore, @unchecked Sendable {
    func perform(_ request: StorageRequest) throws -> StorageReply {
        XCTAssertFalse(Thread.isMainThread)
        return StorageReply(revision: 0)
    }
}
final class MockNative: NativeAPI, @unchecked Sendable {
    private let lock = NSLock()
    private var callback: NativeCallback?
    private var context: UInt64 = 0
    private var sequence: UInt64 = 10
    private var final = false
    private var validValue = true
    var isValid: Bool {
        get { lock.lock(); defer { lock.unlock() }; return validValue }
        set { lock.lock(); validValue = newValue; lock.unlock() }
    }
    var holdReads = false
    let readSubmitted = DispatchSemaphore(value: 0)
    let validityChecked = DispatchSemaphore(value: 0)
    private var heldRead: (@Sendable () -> Void)?
    func completeHeldRead() {
        lock.lock(); let action = heldRead; heldRead = nil; lock.unlock(); action?()
    }
    var released = 0
    func create(_ data: Data, callback: NativeCallback, context: UInt64) -> (UInt32, UInt64) {
        lock.lock(); self.callback = callback; self.context = context; lock.unlock()
        return (0, 1)
    }
    func emit(kind: UInt32, request: UInt64 = 0, connection: UInt64 = 0, channel: UInt64 = 0, status: UInt32 = 0, data: Data = Data()) {
        lock.lock(); let callback = callback, context = context; lock.unlock()
        data.withUnsafeBytes { bytes in
            var event = dp_event(abi_version: 1, kind: kind, request_id: request, connection: connection,
                status: status, struct_size: UInt32(MemoryLayout<dp_event>.size),
                payload: bytes.bindMemory(to: UInt8.self).baseAddress, payload_len: numericCast(data.count), channel: channel)
            withUnsafePointer(to: &event) { callback?(context, $0) }
        }
    }
    func submit(_ sdk: UInt64, operation: UInt32, connection: UInt64, data: Data) -> (UInt32, UInt64) {
        lock.lock(); sequence += 1; let request = sequence; lock.unlock()
        DispatchQueue.global().async { self.emit(kind: 1, request: request, data: data) }
        return (0, request)
    }
    func channelValid(_ sdk: UInt64, connection: UInt64, channel: UInt64) -> UInt32 { let result: UInt32 = isValid ? 0 : 5; validityChecked.signal(); return result }
    func channelSubmit(_ sdk: UInt64, connection: UInt64, channel: UInt64, operation: UInt32, data: Data) -> (UInt32, UInt64) {
        lock.lock(); sequence += 1; let request = sequence; lock.unlock()
        if operation == 2 && holdReads {
            lock.lock()
            heldRead = { [self] in self.emit(kind: 1, request: request, connection: connection, channel: channel, data: Data([7, 8])) }
            lock.unlock()
            readSubmitted.signal()
            return (0, request)
        }
        DispatchQueue.global().async {
            let result = operation == 3 ? Data("{\"written\":2}".utf8) : Data("{\"disposition\":\"dropped\"}".utf8)
            self.emit(kind: 1, request: request, connection: connection, channel: channel, data: result)
        }
        return (0, request)
    }
    func cancel(_ sdk: UInt64, request: UInt64) -> UInt32 { 11 }
    func shutdown(_ sdk: UInt64) -> UInt32 {
        DispatchQueue.global().async {
            self.emit(kind: 9)
            self.lock.lock(); self.final = true; self.lock.unlock()
        }
        return 0
    }
    func state(_ sdk: UInt64) -> UInt32 { lock.lock(); defer { lock.unlock() }; return final ? 2 : 1 }
    func release(_ sdk: UInt64) -> UInt32 {
        lock.lock(); defer { lock.unlock() }
        guard final else { return 11 }
        released += 1; return 0
    }
    func valid(_ sdk: UInt64, connection: UInt64) -> UInt32 { isValid ? 0 : 5 }
    func storage(_ sdk: UInt64, request: UInt64, status: UInt32, data: Data) -> UInt32 { 0 }
}
final class NativeCoreTests: XCTestCase {
    func testOptionalCapacityDefaultsAndLargeValuesEncodeWithoutClamping() throws {
        var config = PeerloomConfiguration(origin: "https://localhost", applicationID: UUID().uuidString)
        XCTAssertEqual(config.maxConnections, 0)
        XCTAssertEqual(config.maxChannelsPerConnection, 0)
        XCTAssertEqual(config.maxChannelCreationsPerConnection, 0)
        for count in [0, 500] {
            config.maxConnections = count
            config.maxChannelsPerConnection = count
            config.maxChannelCreationsPerConnection = count
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(config)) as? [String: Any])
            XCTAssertEqual(json["max_connections"] as? Int, count)
            XCTAssertEqual(json["max_channels_per_connection"] as? Int, count)
            XCTAssertEqual(json["max_channel_creations_per_connection"] as? Int, count)
        }
    }

    func testRetainedEventRechecksAtSynchronousConsumption() async throws {
        let native = MockNative(), core = NativeCore(store: EmptyStore(), api: native)
        try core.create(Data())
        native.emit(kind: 6, connection: 42, data: Data([1, 2]))
        let retained = try await core.nextEvent()
        XCTAssertNotNil(retained)
        let copy = retained
        native.isValid = false
        XCTAssertThrowsError(try retained!.consumePayload()) { error in
            XCTAssertEqual(error as? PeerloomError, .native(5))
        }
        XCTAssertThrowsError(try copy!.consumePayload()) { error in
            XCTAssertEqual(error as? PeerloomError, .invalidEvent)
        }
        try await core.close()
    }
    func testRetainedEventsKeepBoundedCreditsUntilConsumption() async throws {
        let native = MockNative(), core = NativeCore(store: EmptyStore(), api: native)
        try core.create(Data())
        var retained: [PeerloomEvent] = []
        for _ in 0..<32 {
            native.emit(kind: 6, connection: 42, data: Data([1]))
            let event = try await core.nextEvent()
            retained.append(try XCTUnwrap(event))
        }
        native.emit(kind: 6, connection: 42, data: Data([2]))
        do { _ = try await core.nextEvent(); XCTFail("retained payloads lost their credits") }
        catch { XCTAssertEqual(error as? PeerloomError, .eventOverflow) }
        XCTAssertEqual(retained.count, 32)
        retained.removeAll()
        try await core.close()
    }
    @MainActor
    func testReadRechecksAfterCallerActorResumes() async throws {
        let native = MockNative(), core = NativeCore(store: EmptyStore(), api: native)
        native.holdReads = true
        try core.create(Data())
        let stream = try PeerloomChannel(core: core, connection: 42, handle: 52,
            metadata: Data("{\"mode\":\"reliable_stream\",\"label\":\"stream\"}".utf8))
        let reading = Task { @MainActor in try await stream.read(maxBytes: 2) }
        let submitted = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            DispatchQueue.global().async {
                continuation.resume(returning: native.readSubmitted.wait(timeout: .now() + 5) == .success)
            }
        }
        XCTAssertTrue(submitted)
        let invalidated = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            native.completeHeldRead()
            // A broken nonisolated implementation may check on its generic executor here;
            // the correct implementation cannot resume while this MainActor is blocked.
            _ = native.validityChecked.wait(timeout: .now() + 1)
            native.isValid = false
            invalidated.signal()
        }
        XCTAssertEqual(invalidated.wait(timeout: .now() + 5), .success)
        do { _ = try await reading.value; XCTFail("expired read reached caller actor") }
        catch { XCTAssertEqual(error as? PeerloomError, .native(5)) }
        try await core.close()
    }

    func testTypedChildMetadataAndPartialWriteResult() async throws {
        let native = MockNative(), core = NativeCore(store: EmptyStore(), api: native)
        try core.create(Data())
        let message = try PeerloomChannel(core: core, connection: 42, handle: 51,
            metadata: Data("{\"mode\":\"low_latency_message\",\"label\":\"test\"}".utf8))
        let disposition = try await message.send(Data([1, 2, 3]))
        XCTAssertEqual(disposition, .dropped)
        let stream = try PeerloomChannel(core: core, connection: 42, handle: 52,
            metadata: Data("{\"mode\":\"reliable_stream\",\"label\":\"stream\"}".utf8))
        let written = try await stream.write(Data([1, 2, 3]))
        XCTAssertEqual(written, 2)
        native.emit(kind: 12, connection: 42, channel: 51)
        native.emit(kind: 14, connection: 42, channel: 51, data: Data([9]))
        native.isValid = false
        native.emit(kind: 3)
        let event = try await core.nextEvent()
        XCTAssertEqual(event?.kind, 3)
        try await core.close()
    }

    func testEarlyCompletionsAndQuiescentRelease() async throws {
        let native = MockNative(), core = NativeCore(store: EmptyStore(), api: native)
        try core.create(Data())
        try await withThrowingTaskGroup(of: Void.self) { group in
            for value in 0..<16 {
                group.addTask {
                    let input = Data([UInt8(value)])
                    let output = try await core.perform(operation: 4, connection: 1, input: input)
                    XCTAssertEqual(output, input)
                }
            }
            try await group.waitForAll()
        }
        try await core.close()
        XCTAssertEqual(native.released, 1)
        try await core.close()
        XCTAssertEqual(native.released, 1)
    }
    func testExpiredBufferedReadyAndMessageAreNotDelivered() async throws {
        let native = MockNative(), core = NativeCore(store: EmptyStore(), api: native)
        try core.create(Data())
        native.emit(kind: 5, connection: 42)
        native.emit(kind: 6, connection: 42, data: Data("expired".utf8))
        native.isValid = false
        native.emit(kind: 3)
        let event = try await core.nextEvent()
        XCTAssertEqual(event?.kind, 3)
        try await core.close()
        let ended = try await core.nextEvent()
        XCTAssertNil(ended)
    }
    func testHostEventOverflowStopsInsteadOfDroppingAndContinuing() async throws {
        let native = MockNative(), core = NativeCore(store: EmptyStore(), api: native)
        try core.create(Data())
        for _ in 0..<33 { native.emit(kind: 2) }
        do { _ = try await core.nextEvent(); XCTFail("overflow accepted") }
        catch { XCTAssertEqual(error as? PeerloomError, .eventOverflow) }
        try await core.close()
        XCTAssertEqual(native.released, 1)
    }
    func testRealNativeCreateLoadAndShutdown() async throws {
        // This MUST fail while the Apple C-ABI gate remains closed; no test-only success shim.
        let core = NativeCore(store: EmptyStore())
        let config = PeerloomConfiguration(origin: "https://127.0.0.1:1/", applicationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, Error>) in
            DispatchQueue.global().async {
                do { try core.create(encodeJSON(config)); result.resume() }
                catch { result.resume(throwing: error) }
            }
        }
        do { _ = try await core.perform(operation: 1, connection: 0, input: Data("{}".utf8)); XCTFail("empty identity loaded") }
        catch { XCTAssertEqual(error as? PeerloomError, .native(2)) }
        try await core.close()
    }
    func testRealNativeRejectsUntrustedTLS() async throws {
        guard let origin = ProcessInfo.processInfo.environment["PEERLOOM_TLS_ORIGIN"] else {
            XCTFail("native gate must provide loopback TLS fixture"); return
        }
        let config = PeerloomConfiguration(origin: origin, applicationID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        let sdk = try await PeerloomSDK.open(configuration: config, store: EmptyStore())
        do {
            _ = try await sdk.start(registration: PeerloomRegistration(installationPublicKey: "apple-test-only", registrationGrant: "reg_test_only"),
                                    idempotencyKey: "apple-tls-negative-" + UUID().uuidString)
            XCTFail("untrusted certificate accepted")
        } catch { XCTAssertEqual(error as? PeerloomError, .native(10)) }
        try await sdk.close()
    }

}
