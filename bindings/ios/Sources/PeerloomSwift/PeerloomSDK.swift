// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation

public struct PeerloomConfiguration: Encodable, Sendable {
    public let origin: String
    public let applicationID: String
    public var developmentLoopback = false
    public var autoReconnect = true
    private let abiVersion = 1
    private let storage = "external"
    enum CodingKeys: String, CodingKey {
        case origin, applicationID = "application_id", developmentLoopback = "development_loopback"
        case autoReconnect = "auto_reconnect", abiVersion = "abi_version", storage
    }
    public init(origin: String, applicationID: String) { self.origin = origin; self.applicationID = applicationID }
}
public struct PeerloomRegistration: Encodable, Sendable {
    public let installationPublicKey: String
    public let registrationGrant: String
    public var sdkVersion = "peerloom-swift/0.1.0"
    public var metadata: [String: String] = [:]
    #if os(iOS)
    private let platform = "ios"
    #else
    private let platform = "macos"
    #endif
    enum CodingKeys: String, CodingKey {
        case installationPublicKey = "installation_public_key", registrationGrant = "registration_grant"
        case sdkVersion = "sdk_version", metadata, platform
    }
    public init(installationPublicKey: String, registrationGrant: String) {
        self.installationPublicKey = installationPublicKey; self.registrationGrant = registrationGrant
    }
}
public struct PeerloomEvents: AsyncSequence, Sendable {
    public typealias Element = PeerloomEvent
    let core: NativeCore
    public struct AsyncIterator: AsyncIteratorProtocol {
        let core: NativeCore
        public mutating func next() async throws -> PeerloomEvent? { try await core.nextEvent() }
    }
    public func makeAsyncIterator() -> AsyncIterator { AsyncIterator(core: core) }
}

/// Source wrapper for the current capacity-one reliable-message ABI, not a complete five-platform SDK.
public final class PeerloomSDK: @unchecked Sendable {
    private let core: NativeCore
    public var events: PeerloomEvents { PeerloomEvents(core: core) }
    private init(core: NativeCore) { self.core = core }
    public static func open(configuration: PeerloomConfiguration, store: IdentityStore? = nil) async throws -> PeerloomSDK {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                do {
                    let storage = try store ?? KeychainIdentityStore()
                    let core = NativeCore(store: storage)
                    try core.create(encodeJSON(configuration))
                    continuation.resume(returning: PeerloomSDK(core: core))
                } catch { continuation.resume(throwing: error) }
            }
        }
    }
    deinit { core.requestShutdown() }
    /// Caller retains original registration and key for uncertain server replay. No durable mutation journal is implied.
    public func start(registration: PeerloomRegistration? = nil, idempotencyKey: String? = nil) async throws -> String {
        struct Start: Encodable { let registration: PeerloomRegistration?; let idempotency_key: String? }
        struct Result: Decodable { let device_id: String }
        let result = try await core.perform(operation: 1, connection: 0,
                                          input: encodeJSON(Start(registration: registration, idempotency_key: idempotencyKey)))
        return try JSONDecoder().decode(Result.self, from: result).device_id
    }
    public func connect(to deviceID: String) async throws {
        _ = try await core.perform(operation: 2, connection: 0, input: encodeJSON(["target_device_id": deviceID]))
    }
    public func respond(to sessionID: String, accept: Bool) async throws {
        struct Response: Encodable { let session_id: String; let accept: Bool }
        _ = try await core.perform(operation: 3, connection: 0, input: encodeJSON(Response(session_id: sessionID, accept: accept)))
    }
    public func send(_ data: Data, on connection: UInt64) async throws {
        guard data.count <= 65536 else { throw PeerloomError.native(1) }
        _ = try await core.perform(operation: 4, connection: connection, input: data)
    }
    public func refreshCredentials() async throws { _ = try await core.perform(operation: 5, connection: 0, input: Data()) }
    public func closeConnection(_ connection: UInt64) async throws { _ = try await core.perform(operation: 6, connection: connection, input: Data()) }
    /// Waits for native quiescence, external storage work and successful release. Not a forced timeout/kill.
    public func close() async throws { try await core.close() }
}
