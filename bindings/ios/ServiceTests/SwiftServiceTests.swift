// MIT — Copyright (c) 2026 Peerloom contributors.
// Simulator-only real Go/Keychain/WebRTC acceptance; never prints fixture contents.
import XCTest
import Foundation
import Darwin
import PeerloomSwift

private enum ServiceFailure: Error { case fixture, timeout, event, overflow, mismatch }
private struct ServiceDevice: Decodable, Sendable {
    let application_id: String
    let device_id: String
    let device_credential: String
    let expires_at: String
    var stored: StoredIdentity {
        StoredIdentity(deviceID: device_id, deviceCredential: device_credential, expiresAt: expires_at)
    }
}
private struct ServiceFixture: Decodable, Sendable {
    let origin: String
    let source: ServiceDevice
    let target: ServiceDevice
    let third: ServiceDevice
    static func load() throws -> ServiceFixture {
        guard let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
            throw ServiceFailure.fixture
        }
        let path = documents.appendingPathComponent("peerloom-service-fixture.json")
        var metadata = stat()
        guard lstat(path.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_mode & 0o777 == 0o600, metadata.st_uid == geteuid(), metadata.st_nlink == 1,
              metadata.st_size > 0, metadata.st_size <= 65536 else { throw ServiceFailure.fixture }
        let fixture: ServiceFixture
        do { fixture = try JSONDecoder().decode(ServiceFixture.self, from: Data(contentsOf: path)) }
        catch { throw ServiceFailure.fixture }
        guard let url = URL(string: fixture.origin), url.scheme == "http", url.host == "127.0.0.1",
              url.port != nil, url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path == "/" else { throw ServiceFailure.fixture }
        let devices = [fixture.source, fixture.target, fixture.third]
        guard Set(devices.map(\.application_id)).count == 3,
              Set(devices.map(\.device_id)).count == 3,
              devices.allSatisfy({ UUID(uuidString: $0.application_id) != nil && UUID(uuidString: $0.device_id) != nil }) else {
            throw ServiceFailure.fixture
        }
        return fixture
    }
}
private actor ServiceMailbox {
    private var online = false
    private var incoming: [String] = []
    private var connections: [String: UInt64] = [:]
    private var channels: [String: PeerloomChannel] = [:]
    private var messages: [UInt64: [Data]] = [:]
    private var defaultMessages = 0
    private var failed = false
    private let binary = Data([0, 255, 1, 0, 2, 3])
    func accept(_ event: PeerloomEvent, sdk: PeerloomSDK) throws {
        if event.kind == 12 {
            let channel = try sdk.incomingChannel(from: event)
            guard channels.count < 8 || channels[channel.label] != nil else { throw ServiceFailure.overflow }
            channels[channel.label] = channel
            return
        }
        let bytes = try event.consumePayload()
        switch event.kind {
        case 2: online = true
        case 3, 7, 13: break
        case 4:
            struct Incoming: Decodable { let session_id: String }
            let value = try JSONDecoder().decode(Incoming.self, from: bytes)
            guard incoming.count < 2, UUID(uuidString: value.session_id) != nil else { throw ServiceFailure.event }
            incoming.append(value.session_id)
        case 5:
            struct Ready: Decodable { let peer_device_id: String }
            let value = try JSONDecoder().decode(Ready.self, from: bytes)
            guard connections.count < 2 || connections[value.peer_device_id] != nil else { throw ServiceFailure.overflow }
            connections[value.peer_device_id] = event.connection
        case 6:
            guard bytes == binary else { throw ServiceFailure.mismatch }
            defaultMessages += 1
            guard defaultMessages <= 16 else { throw ServiceFailure.overflow }
        case 14:
            guard bytes == binary, messages[event.channel, default: []].count < 16 else { throw ServiceFailure.mismatch }
            messages[event.channel, default: []].append(bytes)
        default: throw ServiceFailure.event
        }
    }
    func fail() { failed = true }
    private func check() throws { if failed { throw ServiceFailure.event } }
    func isOnline() throws -> Bool? { try check(); return online ? true : nil }
    func takeIncoming() throws -> String? { try check(); return incoming.isEmpty ? nil : incoming.removeFirst() }
    func connection(_ peer: String) throws -> UInt64? { try check(); return connections[peer] }
    func channel(_ label: String) throws -> PeerloomChannel? { try check(); return channels[label] }
    func received(_ channel: UInt64) throws -> Bool? { try check(); return messages[channel, default: []].isEmpty ? nil : true }
    func receivedDefault() throws -> Bool? { try check(); return defaultMessages > 0 ? true : nil }
}
private func eventually<T>(_ body: () async throws -> T?) async throws -> T {
    let deadline = DispatchTime.now().uptimeNanoseconds + 45_000_000_000
    repeat {
        try Task.checkCancellation()
        if let value = try await body() { return value }
        try await Task.sleep(nanoseconds: 20_000_000)
    } while DispatchTime.now().uptimeNanoseconds < deadline
    throw ServiceFailure.timeout
}

final class SwiftServiceTests: XCTestCase {
    func testRealGoKeychainThreeDevicesAndThreeChannelModes() async throws {
        // Neither an injected memory store nor MockNative is used in this suite.
        let fixture = try await Task.detached { try ServiceFixture.load() }.value
        print("[Swift service] fixture loaded")
        let devices = [fixture.source, fixture.target, fixture.third]
        var sdks: [PeerloomSDK] = []
        var pumps: [Task<Void, Never>] = []
        var reverseRead: Task<Data, Error>?
        let boxes = [ServiceMailbox(), ServiceMailbox(), ServiceMailbox()]
        do {
            for (index, device) in devices.enumerated() {
                try await Task.detached {
                    let store = try KeychainIdentityStore()
                    let scope = IdentityScope(serverOrigin: fixture.origin, applicationID: device.application_id)
                    let empty = try store.perform(StorageRequest(operation: .load, scope: scope))
                    guard empty.revision == 0, empty.identity == nil else { throw ServiceFailure.fixture }
                    let saved = try store.perform(StorageRequest(operation: .save, scope: scope,
                        expectedRevision: 0, identity: device.stored))
                    guard saved.revision == 1 else { throw ServiceFailure.fixture }
                    let loaded = try store.perform(StorageRequest(operation: .load, scope: scope))
                    guard loaded.identity == device.stored else { throw ServiceFailure.fixture }
                }.value
                var config = PeerloomConfiguration(origin: fixture.origin, applicationID: device.application_id)
                config.developmentLoopback = true
                config.maxConnections = 2
                config.maxChannelsPerConnection = 4
                config.maxChannelCreationsPerConnection = 8
                let sdk = try await PeerloomSDK.open(configuration: config)
                sdks.append(sdk)
                let box = boxes[index]
                pumps.append(Task {
                    do {
                        for try await event in sdk.events { try await box.accept(event, sdk: sdk) }
                    } catch is CancellationError { }
                    catch { await box.fail() }
                })
                let id = try await sdk.start()
                guard id == device.device_id else { throw ServiceFailure.mismatch }
                _ = try await eventually { try await box.isOnline() }
            }
            print("[Swift service] Keychain identities loaded and three SDKs online")
            for index in 1...2 {
                try await sdks[0].connect(to: devices[index].device_id)
                let incoming = try await eventually { try await boxes[index].takeIncoming() }
                try await sdks[index].respond(to: incoming, accept: true)
                _ = try await eventually { try await boxes[0].connection(devices[index].device_id) }
                _ = try await eventually { try await boxes[index].connection(devices[0].device_id) }
            }
            print("[Swift service] two explicitly approved sessions ready")
            let parent = try await eventually { try await boxes[0].connection(devices[1].device_id) }
            let other = try await eventually { try await boxes[0].connection(devices[2].device_id) }
            guard parent != other else { throw ServiceFailure.mismatch }
            let reliable = try await sdks[0].openChannel(on: parent, mode: .reliableMessage, label: "swift-reliable")
            let remoteReliable = try await eventually { try await boxes[1].channel("swift-reliable") }
            let low = try await sdks[0].openChannel(on: parent, mode: .lowLatencyMessage, label: "swift-low")
            let remoteLow = try await eventually { try await boxes[1].channel("swift-low") }
            let stream = try await sdks[0].openChannel(on: parent, mode: .reliableStream, label: "swift-stream")
            let remoteStream = try await eventually { try await boxes[1].channel("swift-stream") }
            print("[Swift service] three typed channels ready")
            let binary = Data([0, 255, 1, 0, 2, 3])
            guard try await reliable.send(binary) == .sent else { throw ServiceFailure.mismatch }
            _ = try await eventually { try await boxes[1].received(remoteReliable.handle) }
            guard try await remoteReliable.send(binary) == .sent else { throw ServiceFailure.mismatch }
            _ = try await eventually { try await boxes[0].received(reliable.handle) }
            // Fixed workload, not retry-to-green: low-latency mode does not promise all packets.
            for _ in 0..<8 { _ = try await low.send(binary) }
            _ = try await eventually { try await boxes[1].received(remoteLow.handle) }
            let reverse = Task { try await stream.read(maxBytes: 64) }
            reverseRead = reverse
            guard try await stream.write(binary) == binary.count,
                  try await remoteStream.read(maxBytes: 64) == binary,
                  try await remoteStream.write(binary) == binary.count,
                  try await reverse.value == binary else { throw ServiceFailure.mismatch }
            let transfer = Data((0..<(256 * 1024)).map { UInt8(truncatingIfNeeded: $0 * 17) })
            var offset = 0
            while offset < transfer.count {
                let chunk = transfer.subdata(in: offset..<min(offset + 65536, transfer.count))
                let written = try await stream.write(chunk)
                guard written > 0, written <= chunk.count else { throw ServiceFailure.mismatch }
                var consumed = 0
                while consumed < written {
                    let bytes = try await remoteStream.read(maxBytes: min(4093, written - consumed))
                    guard !bytes.isEmpty, bytes.count <= written - consumed,
                          bytes == transfer.subdata(in: (offset + consumed)..<(offset + consumed + bytes.count)) else {
                        throw ServiceFailure.mismatch
                    }
                    consumed += bytes.count
                }
                offset += written
            }
            try await stream.finishWrite()
            guard try await remoteStream.read(maxBytes: 64).isEmpty else { throw ServiceFailure.mismatch }
            do { _ = try await stream.write(binary); throw ServiceFailure.mismatch }
            catch PeerloomError.native(5) { }
            guard try await remoteStream.write(binary) == binary.count,
                  try await stream.read(maxBytes: 64) == binary else { throw ServiceFailure.mismatch }
            try await remoteStream.finishWrite()
            guard try await stream.read(maxBytes: 64).isEmpty else { throw ServiceFailure.mismatch }
            try await reliable.close()
            guard !reliable.isValid, stream.isValid else { throw ServiceFailure.mismatch }
            try await sdks[0].closeConnection(parent)
            guard !stream.isValid else { throw ServiceFailure.mismatch }
            try await sdks[0].send(binary, on: other)
            _ = try await eventually { try await boxes[2].receivedDefault() }
            print("[Swift service] real Go/WSS + DP Keychain + 3 devices/2 connections + message/low/256KiB stream/duplex/FIN + parent-child gate passed")
        } catch {
            for pump in pumps { pump.cancel() }
            reverseRead?.cancel()
            for sdk in sdks { try? await sdk.close() }
            if let reverseRead { _ = try? await reverseRead.value }
            for pump in pumps { await pump.value }
            // Do not interpolate fixture, JSON, storage snapshots or arbitrary error descriptions.
            if case PeerloomError.native(let code) = error { print("[Swift service] native_error_code=\(code)") }
            XCTFail("real Swift service acceptance failed; fixture and credentials withheld")
            throw ServiceFailure.event
        }
        for pump in pumps { pump.cancel() }
        reverseRead?.cancel()
        for sdk in sdks { try await sdk.close() }
        if let reverseRead { _ = try? await reverseRead.value }
        for pump in pumps { await pump.value }
    }
}
