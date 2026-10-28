// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation
import CPeerloom

public enum PeerloomError: Error, Equatable, Sendable {
    case native(UInt32), invalidEvent, eventOverflow, concurrentEventReader
}
/// SDK-owned bytes remain private until synchronous consumption on the caller's executor.
fileprivate final class EventPayload: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes: Data?
    private let valid: @Sendable () -> Bool
    private var release: (@Sendable () -> Void)?
    init(_ bytes: Data, valid: @escaping @Sendable () -> Bool, release: @escaping @Sendable () -> Void) {
        self.bytes = bytes; self.valid = valid; self.release = release
    }
    var isValid: Bool { valid() }
    func consume() throws -> Data {
        lock.lock()
        guard let value = bytes else { lock.unlock(); throw PeerloomError.invalidEvent }
        bytes = nil
        let finish = release; release = nil
        let allowed = valid()
        lock.unlock()
        // No await/executor hop between authorization check and caller receiving these bytes.
        finish?()
        guard allowed else { throw PeerloomError.native(5) }
        return value
    }
    deinit { release?() }
}
public struct PeerloomEvent: Sendable {
    public let kind: UInt32
    public let connection: UInt64
    public let status: UInt32
    public let channel: UInt64
    private let owned: EventPayload
    fileprivate init(kind: UInt32, connection: UInt64, status: UInt32, channel: UInt64, owned: EventPayload) {
        self.kind = kind; self.connection = connection; self.status = status; self.channel = channel; self.owned = owned
    }
    /// Single consumption. Retained copies share the same bounded credit and consumed state.
    /// After this synchronous call returns, any further application queuing is caller-owned.
    public func consumePayload() throws -> Data { try owned.consume() }
    fileprivate var isDeliverable: Bool { owned.isValid }
}
struct NativeCompletion: Sendable { let channel: UInt64; let payload: Data }
typealias NativeCallback = @convention(c) (UInt64, UnsafePointer<dp_event>?) -> Void
protocol NativeAPI: Sendable {
    func create(_ data: Data, callback: NativeCallback, context: UInt64) -> (UInt32, UInt64)
    func submit(_ sdk: UInt64, operation: UInt32, connection: UInt64, data: Data) -> (UInt32, UInt64)
    func channelSubmit(_ sdk: UInt64, connection: UInt64, channel: UInt64, operation: UInt32, data: Data) -> (UInt32, UInt64)
    func channelValid(_ sdk: UInt64, connection: UInt64, channel: UInt64) -> UInt32
    func cancel(_ sdk: UInt64, request: UInt64) -> UInt32
    func shutdown(_ sdk: UInt64) -> UInt32
    func state(_ sdk: UInt64) -> UInt32
    func release(_ sdk: UInt64) -> UInt32
    func valid(_ sdk: UInt64, connection: UInt64) -> UInt32
    func storage(_ sdk: UInt64, request: UInt64, status: UInt32, data: Data) -> UInt32
}
extension NativeAPI {
    // Older test adapters remain explicit Unsupported, never an emulated success.
    func channelSubmit(_ sdk: UInt64, connection: UInt64, channel: UInt64, operation: UInt32, data: Data) -> (UInt32, UInt64) { (7, 0) }
    func channelValid(_ sdk: UInt64, connection: UInt64, channel: UInt64) -> UInt32 { 7 }
}
struct CNativeAPI: NativeAPI {
    func create(_ data: Data, callback: NativeCallback, context: UInt64) -> (UInt32, UInt64) {
        var handle: UInt64 = 0
        let status = data.withUnsafeBytes { dp_sdk_create($0.bindMemory(to: UInt8.self).baseAddress, numericCast(data.count), callback, context, &handle) }
        return (status, handle)
    }
    func submit(_ sdk: UInt64, operation: UInt32, connection: UInt64, data: Data) -> (UInt32, UInt64) {
        var request: UInt64 = 0
        let status = data.withUnsafeBytes { dp_sdk_submit(sdk, operation, connection, $0.bindMemory(to: UInt8.self).baseAddress, numericCast(data.count), &request) }
        return (status, request)
    }
    func channelSubmit(_ sdk: UInt64, connection: UInt64, channel: UInt64, operation: UInt32, data: Data) -> (UInt32, UInt64) {
        var request: UInt64 = 0
        let status = data.withUnsafeBytes { dp_channel_submit(sdk, connection, channel, operation, $0.bindMemory(to: UInt8.self).baseAddress, numericCast(data.count), &request) }
        return (status, request)
    }
    func channelValid(_ sdk: UInt64, connection: UInt64, channel: UInt64) -> UInt32 { dp_channel_is_valid(sdk, connection, channel) }
    func cancel(_ sdk: UInt64, request: UInt64) -> UInt32 { dp_sdk_cancel(sdk, request) }
    func shutdown(_ sdk: UInt64) -> UInt32 { var request: UInt64 = 0; return dp_sdk_shutdown(sdk, &request) }
    func state(_ sdk: UInt64) -> UInt32 { dp_sdk_state(sdk) }
    func release(_ sdk: UInt64) -> UInt32 { dp_sdk_release(sdk) }
    func valid(_ sdk: UInt64, connection: UInt64) -> UInt32 { dp_connection_is_valid(sdk, connection) }
    func storage(_ sdk: UInt64, request: UInt64, status: UInt32, data: Data) -> UInt32 {
        data.withUnsafeBytes { dp_storage_complete(sdk, request, status, $0.bindMemory(to: UInt8.self).baseAddress, numericCast(data.count)) }
    }
}

private let callback: NativeCallback = { context, pointer in
    guard context != 0, let address = UnsafeRawPointer(bitPattern: UInt(context)), let pointer else { return }
    let core = Unmanaged<NativeCore>.fromOpaque(address).takeUnretainedValue()
    let event = pointer.pointee
    guard event.abi_version == 1, event.struct_size >= UInt32(MemoryLayout<dp_event>.size),
          let length = Int(exactly: event.payload_len), length >= 0, length <= 65536, length == 0 || event.payload != nil else {
        core.fail(PeerloomError.invalidEvent); return
    }
    // No borrowed C pointer escapes this stack frame.
    let payload = length == 0 ? Data() : Data(bytes: event.payload!, count: length)
    core.receive(kind: event.kind, request: event.request_id, connection: event.connection, status: event.status, payload: payload, channel: event.channel)
}

private final class Ticket: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var request: UInt64 = 0
    func cancel() -> UInt64 { lock.lock(); defer { lock.unlock() }; cancelled = true; return request }
    func install(_ id: UInt64) -> Bool { lock.lock(); defer { lock.unlock() }; request = id; return cancelled }
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
}

final class NativeCore: @unchecked Sendable {
    private let lock = NSLock()
    private let io = DispatchQueue(label: "io.peerloom.apple.native", qos: .utility)
    private let storageIO = DispatchQueue(label: "io.peerloom.apple.keychain", qos: .utility)
    private let api: NativeAPI
    private let store: IdentityStore
    private var handle: UInt64 = 0
    private var context: UInt64 = 0
    private var stopping = false
    private var released = false
    private var nativeFinal = false
    private var timer: DispatchSourceTimer?
    private var pending: [UInt64: CheckedContinuation<NativeCompletion, Error>] = [:]
    private var admitted = 0
    private var storageJobs = 0
    private var closeWaiters: [CheckedContinuation<Void, Error>] = []
    private var events: [PeerloomEvent] = []
    private var dataEvents = 0
    private var controlEvents = 0
    private var eventWaiter: CheckedContinuation<Void, Error>?
    private var eventError: Error?
    private var reading = false

    init(store: IdentityStore, api: NativeAPI = CNativeAPI()) { self.store = store; self.api = api }
    func create(_ config: Data) throws {
        // Called on a worker queue; serialize an unusually early callback against installation.
        lock.lock()
        let retained = Unmanaged.passRetained(self)
        context = UInt64(UInt(bitPattern: retained.toOpaque()))
        let result = api.create(config, callback: callback, context: context)
        if result.0 != 0 {
            context = 0; lock.unlock(); retained.release()
            throw PeerloomError.native(result.0)
        }
        handle = result.1
        lock.unlock()
    }
    func perform(operation: UInt32, connection: UInt64, input: Data) async throws -> Data {
        try await performDetailed(operation: operation, connection: connection, input: input).payload
    }
    func performDetailed(operation: UInt32, connection: UInt64, channel: UInt64? = nil, input: Data, isolation: isolated (any Actor)? = #isolation) async throws -> NativeCompletion {
        lock.lock()
        guard !stopping, !released else { lock.unlock(); throw PeerloomError.native(5) }
        guard admitted < 32 else { lock.unlock(); throw PeerloomError.native(6) }
        admitted += 1
        lock.unlock()
        // Retain the host-delivery credit until this executor actually consumes the reply.
        defer { lock.lock(); admitted -= 1; lock.unlock() }
        let ticket = Ticket()
        let value: NativeCompletion = try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                io.async { [self] in
                    lock.lock()
                    if stopping || ticket.isCancelled {
                        lock.unlock()
                        continuation.resume(throwing: ticket.isCancelled ? CancellationError() : PeerloomError.native(5))
                        return
                    }
                    let result: (UInt32, UInt64)
                    if let channel {
                        result = api.channelSubmit(handle, connection: connection, channel: channel, operation: operation, data: input)
                    } else {
                        result = api.submit(handle, operation: operation, connection: connection, data: input)
                    }
                    if result.0 != 0 {
                        lock.unlock(); continuation.resume(throwing: PeerloomError.native(result.0)); return
                    }
                    pending[result.1] = continuation
                    let cancelled = ticket.install(result.1)
                    let sdk = handle
                    lock.unlock()
                    if cancelled { _ = api.cancel(sdk, request: result.1) }
                }
            }
        }, onCancel: { [self] in
            let request = ticket.cancel()
            if request != 0 { io.async { [self] in _ = api.cancel(currentHandle(), request: request) } }
        })
        if let channel, operation == 2 {
            // A continuation can sit on a paused actor after native callback dispatch.
            guard channelIsValid(connection: connection, channel: channel) else { throw PeerloomError.native(5) }
        }
        return value
    }
    func channelIsValid(connection: UInt64, channel: UInt64) -> Bool {
        lock.lock(); let sdk = handle, stopped = stopping; lock.unlock()
        return !stopped && sdk != 0 && api.channelValid(sdk, connection: connection, channel: channel) == 0
    }
    private func connectionIsValid(_ connection: UInt64) -> Bool {
        lock.lock(); let sdk = handle, stopped = stopping; lock.unlock()
        return !stopped && sdk != 0 && api.valid(sdk, connection: connection) == 0
    }
    private func releaseEventCredit(isData: Bool) {
        // Deinit may run while the queue lock is held. Enqueue only the accounting action.
        io.async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            if isData { self.dataEvents -= 1 } else { self.controlEvents -= 1 }
            self.lock.unlock()
        }
    }
    private func currentHandle() -> UInt64 { lock.lock(); defer { lock.unlock() }; return handle }

    func receive(kind: UInt32, request: UInt64, connection: UInt64, status: UInt32, payload: Data, channel: UInt64 = 0) {
        if kind == 1 {
            lock.lock()
            let completion = pending.removeValue(forKey: request)
            lock.unlock()
            guard let completion else { fail(PeerloomError.invalidEvent); return }
            if status == 0 { completion.resume(returning: NativeCompletion(channel: channel, payload: payload)) }
            else if status == 9 { completion.resume(throwing: CancellationError()) }
            else { completion.resume(throwing: PeerloomError.native(status)) }
            return
        }
        if kind == 10 { storageRequest(request, payload: payload); return }
        if kind == 9 {
            lock.lock(); nativeFinal = true; stopping = true
            let waiter = eventWaiter; eventWaiter = nil
            lock.unlock(); waiter?.resume()
            schedulePoll()
            return
        }
        lock.lock()
        if stopping && [5, 6, 12, 14].contains(kind) { lock.unlock(); return }
        let isData = kind == 6 || kind == 14
        guard (isData ? dataEvents : controlEvents) < 32 else {
            lock.unlock(); fail(PeerloomError.eventOverflow); return
        }
        if isData { dataEvents += 1 } else { controlEvents += 1 }
        let owned = EventPayload(payload, valid: { [weak self] in
            guard let self else { return false }
            if kind == 5 || kind == 6 { return self.connectionIsValid(connection) }
            if kind == 12 || kind == 14 { return self.channelIsValid(connection: connection, channel: channel) }
            return true
        }, release: { [weak self] in self?.releaseEventCredit(isData: isData) })
        events.append(PeerloomEvent(kind: kind, connection: connection, status: status, channel: channel, owned: owned))
        let waiter = eventWaiter; eventWaiter = nil
        lock.unlock(); waiter?.resume()
    }
    private func storageRequest(_ request: UInt64, payload: Data) {
        lock.lock()
        let sdk = handle
        guard storageJobs < 8, !released else {
            lock.unlock(); _ = api.storage(sdk, request: request, status: 255, data: Data()); return
        }
        storageJobs += 1
        lock.unlock()
        storageIO.async { [self] in
            var status: UInt32 = 0
            var response = Data()
            do {
                let request = try JSONDecoder().decode(StorageRequest.self, from: payload)
                response = try encodeJSON(store.perform(request))
                if response.count > 16384 { status = 255; response = Data() }
            } catch StoreError.conflict { status = 11 }
            catch { status = 255 }
            _ = api.storage(sdk, request: request, status: status, data: response)
            lock.lock(); storageJobs -= 1; lock.unlock()
        }
    }
    func fail(_ error: Error) {
        lock.lock(); eventError = error; events.removeAll()
        let waiter = eventWaiter; eventWaiter = nil
        lock.unlock(); waiter?.resume(); requestShutdown()
    }
    func requestShutdown() {
        lock.lock()
        let shouldStart = !stopping && !released
        stopping = true
        let waiter = eventWaiter; eventWaiter = nil
        lock.unlock(); waiter?.resume()
        if shouldStart { io.async { [self] in _ = api.shutdown(currentHandle()); beginPoll() } }
        else { schedulePoll() }
    }
    func close() async throws {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            if released { lock.unlock(); continuation.resume(); return }
            guard closeWaiters.count < 32 else { lock.unlock(); continuation.resume(throwing: PeerloomError.native(6)); return }
            closeWaiters.append(continuation)
            lock.unlock()
            requestShutdown()
        }
        // Cancellation never frees a still-live callback context or pretends to roll back CAS.
    }
    private func schedulePoll() { io.async { [self] in beginPoll() } }
    private func beginPoll() {
        if timer != nil { return }
        lock.lock(); let done = released; lock.unlock()
        if done { return }
        let source = DispatchSource.makeTimerSource(queue: io)
        timer = source
        source.schedule(deadline: .now(), repeating: .milliseconds(10))
        source.setEventHandler { [self] in pollRelease() }
        source.resume()
    }
    private func pollRelease() {
        lock.lock()
        let sdk = handle
        let ready = nativeFinal && storageJobs == 0 && admitted == 0
        lock.unlock()
        guard ready, api.state(sdk) == 2, api.release(sdk) == 0 else { return }
        lock.lock()
        handle = 0; released = true
        let retained = context; context = 0
        let waiters = closeWaiters; closeWaiters.removeAll()
        let eventReader = eventWaiter; eventWaiter = nil
        lock.unlock()
        timer?.cancel(); timer = nil
        waiters.forEach { $0.resume() }; eventReader?.resume()
        if let address = UnsafeRawPointer(bitPattern: UInt(retained)) {
            Unmanaged<NativeCore>.fromOpaque(address).release()
        }
    }

    func nextEvent() async throws -> PeerloomEvent? {
        lock.lock()
        guard !reading else { lock.unlock(); throw PeerloomError.concurrentEventReader }
        reading = true
        lock.unlock()
        defer { lock.lock(); reading = false; lock.unlock() }
        while true {
            try Task.checkCancellation()
            lock.lock()
            if let error = eventError { lock.unlock(); throw error }
            if !events.isEmpty {
                let event = events.removeFirst()
                lock.unlock()
                // Filtering here is only an optimization; consumePayload rechecks synchronously
                // after any further legacy AsyncIterator/caller-actor scheduling.
                if !event.isDeliverable { continue }
                return event
            }
            let ended = stopping || released
            lock.unlock()
            if ended { return nil }
            try await withTaskCancellationHandler(operation: {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    lock.lock()
                    if Task.isCancelled { lock.unlock(); continuation.resume(throwing: CancellationError()); return }
                    if !events.isEmpty || stopping || eventError != nil { lock.unlock(); continuation.resume(); return }
                    eventWaiter = continuation
                    lock.unlock()
                }
            }, onCancel: { [self] in
                lock.lock(); let waiter = eventWaiter; eventWaiter = nil; lock.unlock()
                waiter?.resume(throwing: CancellationError())
            })
        }
    }
}
