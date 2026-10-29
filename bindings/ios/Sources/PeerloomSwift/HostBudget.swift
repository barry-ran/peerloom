// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation

/// Accounts only host-owned storage, separately from native allocations and application memory.
final class HostBudget: @unchecked Sendable {
    private let lock = NSLock()
    let bytes: Int
    private let criticalReserve: Int
    private var connections = 0
    private var streams = 0
    private var dataCount = 0
    private var criticalCount = 0
    private var dataBytes = 0
    private var criticalBytes = 0
    private var lifecycleBytes = 0

    init(bytes: Int = 134217728) throws {
        guard bytes >= 2097152 else { throw PeerloomError.native(1) }
        self.bytes = bytes
        criticalReserve = max(262144, bytes / 8)
    }
    private func add(_ a: Int, _ b: Int) throws -> Int {
        let (value, overflow) = a.addingReportingOverflow(b)
        guard !overflow else { throw PeerloomError.native(6) }
        return value
    }
    private func multiply(_ a: Int, _ b: Int) throws -> Int {
        let (value, overflow) = a.multipliedReportingOverflow(by: b)
        guard !overflow else { throw PeerloomError.native(6) }
        return value
    }
    private func limits(_ c: Int, _ s: Int) throws -> (Int, Int) {
        (try add(64, add(multiply(8, c), multiply(2, s))), try add(64, add(c, s)))
    }
    func population(connections: Int, streams: Int) throws {
        lock.lock(); defer { lock.unlock() }
        guard connections >= 0, streams >= 0 else { throw PeerloomError.native(1) }
        _ = try limits(connections, streams)
        self.connections = connections; self.streams = streams
    }
    func acquire(bytes payloadBytes: Int, critical: Bool) throws -> HostReservation {
        try acquireInternal(bytes: payloadBytes, critical: critical, counted: true)
    }
    func acquireLifecycle(bytes: Int = 256) throws -> HostReservation {
        try acquireInternal(bytes: bytes, critical: true, counted: false, lifecycle: true)
    }
    func acquireUrgentReset(bytes: Int) throws -> HostReservation {
        try acquireInternal(bytes: bytes, critical: true, counted: false)
    }
    private func acquireInternal(bytes payloadBytes: Int, critical: Bool, counted: Bool, lifecycle: Bool = false) throws -> HostReservation {
        lock.lock(); defer { lock.unlock() }
        guard payloadBytes >= 0 else { throw PeerloomError.native(1) }
        let size = try add(payloadBytes, 256)
        let (dataLimit, criticalLimit) = try limits(connections, streams)
        let used = !critical ? dataBytes : (!lifecycle ? criticalBytes : lifecycleBytes)
        let ceiling = !critical ? bytes - criticalReserve : (!lifecycle ? criticalReserve / 2 : criticalReserve - criticalReserve / 2)
        guard size <= ceiling - used,
              (!counted || (critical ? criticalCount < criticalLimit : dataCount < dataLimit)) else {
            throw PeerloomError.native(6)
        }
        let ticket = HostReservation(owner: self, bytes: size, critical: critical, counted: counted, lifecycle: lifecycle)
        if critical { if !lifecycle { if counted { criticalCount += 1 }; criticalBytes += size } else { lifecycleBytes += size } }
        else { if counted { dataCount += 1 }; dataBytes += size }
        return ticket
    }
    fileprivate func release(bytes: Int, critical: Bool, counted: Bool, lifecycle: Bool) {
        lock.lock(); defer { lock.unlock() }
        if critical { if !lifecycle { if counted { criticalCount -= 1 }; criticalBytes -= bytes } else { lifecycleBytes -= bytes } }
        else { if counted { dataCount -= 1 }; dataBytes -= bytes }
        assert(dataCount >= 0 && criticalCount >= 0 && dataBytes >= 0 && criticalBytes >= 0 && lifecycleBytes >= 0)
    }
    var usage: [Int] {
        lock.lock(); defer { lock.unlock() }
        return [dataCount, criticalCount, dataBytes, criticalBytes + lifecycleBytes]
    }
}
final class HostReservation: @unchecked Sendable {
    private let lock = NSLock()
    private var owner: HostBudget?
    private let bytes: Int
    private let critical: Bool
    private let counted: Bool
    private let lifecycle: Bool
    fileprivate init(owner: HostBudget, bytes: Int, critical: Bool, counted: Bool, lifecycle: Bool) {
        self.owner = owner; self.bytes = bytes; self.critical = critical; self.counted = counted; self.lifecycle = lifecycle
    }
    func permits(bytes count: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return owner != nil && count >= 0 && count <= bytes - 256
    }
    func release() {
        lock.lock(); let budget = owner; owner = nil; lock.unlock()
        budget?.release(bytes: bytes, critical: critical, counted: counted, lifecycle: lifecycle)
    }
    deinit { release() }
}
