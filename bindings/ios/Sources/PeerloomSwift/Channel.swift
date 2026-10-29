// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation

public enum PeerloomChannelMode: String, Codable, Sendable {
    case reliableMessage = "reliable_message"
    case lowLatencyMessage = "low_latency_message"
    case reliableStream = "reliable_stream"
}
public struct PeerloomMessageQueue: Encodable, Sendable {
    public var maxMessages = 256
    public var maxBytes = 1048576
    public var ttlMilliseconds = 30000
    public var overflow = "fail"
    public init() {}
    enum CodingKeys: String, CodingKey {
        case maxMessages = "max_messages", maxBytes = "max_bytes", ttlMilliseconds = "ttl_ms", overflow
    }
}
public enum PeerloomSendDisposition: String, Decodable, Sendable { case sent, dropped }
public final class PeerloomChannel: @unchecked Sendable {
    private let core: NativeCore
    public let connection: UInt64
    public let handle: UInt64
    public let mode: PeerloomChannelMode
    public let label: String
    public let targetEpoch: String?
    init(core: NativeCore, connection: UInt64, handle: UInt64, metadata: Data) throws {
        struct Metadata: Decodable { let mode: PeerloomChannelMode; let label: String }
        let value = try JSONDecoder().decode(Metadata.self, from: metadata)
        self.core = core; self.connection = connection; self.handle = handle
        self.mode = value.mode; self.label = value.label
        self.targetEpoch = try decodeTargetEpoch(metadata)
    }
    public var isValid: Bool { core.channelIsValid(connection: connection, channel: handle) }
    /// Local send/drop disposition, never peer business receipt.
    public func send(_ message: Data) async throws -> PeerloomSendDisposition {
        guard mode != .reliableStream else { throw PeerloomError.native(7) }
        struct Result: Decodable { let disposition: PeerloomSendDisposition }
        let result = try await core.performDetailed(operation: 1, connection: connection, channel: handle, input: message)
        return try JSONDecoder().decode(Result.self, from: result.payload).disposition
    }
    /// Empty successful result is EOF; opposite-direction writes can proceed concurrently.
    public func read(maxBytes: Int, isolation: isolated (any Actor)? = #isolation) async throws -> Data {
        guard mode == .reliableStream else { throw PeerloomError.native(7) }
        guard (1...65536).contains(maxBytes) else { throw PeerloomError.native(1) }
        return try await core.performDetailed(operation: 2, connection: connection, channel: handle,
                                              input: encodeJSON(["max_bytes":maxBytes]), isolation: isolation).payload
    }
    /// Advance by the returned count. Never retry an uncertain partial stream write.
    public func write(_ bytes: Data) async throws -> Int {
        guard mode == .reliableStream else { throw PeerloomError.native(7) }
        struct Result: Decodable { let written: Int }
        let result = try await core.performDetailed(operation: 3, connection: connection, channel: handle, input: bytes)
        let written = try JSONDecoder().decode(Result.self, from: result.payload).written
        guard (0...bytes.count).contains(written) else { throw PeerloomError.native(255) }
        return written
    }
    public func finishWrite() async throws {
        guard mode == .reliableStream else { throw PeerloomError.native(7) }
        _ = try await core.performDetailed(operation: 4, connection: connection, channel: handle, input: Data())
    }
    public func close() async throws {
        _ = try await core.performDetailed(operation: 5, connection: connection, channel: handle, input: Data())
    }
}
