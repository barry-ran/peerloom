// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation

public enum StoreError: Error, Equatable, Sendable {
    case conflict, unavailable, invalidRecord, revisionOverflow
}

public struct IdentityScope: Codable, Equatable, Sendable {
    public let serverOrigin: String
    public let applicationID: String
    enum CodingKeys: String, CodingKey { case serverOrigin = "server_origin", applicationID = "application_id" }
    public init(serverOrigin: String, applicationID: String) {
        self.serverOrigin = serverOrigin
        self.applicationID = applicationID
    }
    func validate() throws {
        guard serverOrigin.utf8.count <= 2048,
              let url = URLComponents(string: serverOrigin),
              ["https", "http"].contains(url.scheme), url.host != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path == "/", UUID(uuidString: applicationID)?.uuidString.lowercased() == applicationID
        else { throw StoreError.invalidRecord }
    }
}

public struct StoredIdentity: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let deviceID: String
    public let deviceCredential: String
    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id", deviceCredential = "device_credential"
    }
    public init(deviceID: String, deviceCredential: String) {
        self.deviceID = deviceID; self.deviceCredential = deviceCredential
    }
    // ABI 2 rejects legacy and unknown identity fields rather than silently migrating secrets.
    private struct IdentityKey: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    public init(from decoder: Decoder) throws {
        let keys = try decoder.container(keyedBy: IdentityKey.self)
        guard Set(keys.allKeys.map(\.stringValue)) == Set(["device_id", "device_credential"])
        else { throw StoreError.invalidRecord }
        let values = try decoder.container(keyedBy: CodingKeys.self)
        deviceID = try values.decode(String.self, forKey: .deviceID)
        deviceCredential = try values.decode(String.self, forKey: .deviceCredential)
        try validate()
    }
    public var description: String { "StoredIdentity(<redacted>)" }
    public var debugDescription: String { description }
    func validate() throws {
        guard UUID(uuidString: deviceID) != nil, deviceCredential.hasPrefix("dev_"),
              deviceCredential.utf8.count <= 4096, !deviceCredential.contains("\n") else { throw StoreError.invalidRecord }
    }
}

public struct StorageRequest: Codable, Sendable {
    public enum Operation: String, Codable, Sendable { case load, save, delete }
    public let operation: Operation
    public let scope: IdentityScope
    public let expectedRevision: UInt64?
    public let identity: StoredIdentity?
    enum CodingKeys: String, CodingKey { case operation, scope, expectedRevision = "expected_revision", identity }
    public init(operation: Operation, scope: IdentityScope, expectedRevision: UInt64? = nil, identity: StoredIdentity? = nil) {
        self.operation = operation; self.scope = scope; self.expectedRevision = expectedRevision; self.identity = identity
    }
    func validate() throws {
        try scope.validate()
        switch operation {
        case .load:
            guard expectedRevision == nil, identity == nil else { throw StoreError.invalidRecord }
        case .save:
            guard expectedRevision != nil, identity != nil else { throw StoreError.invalidRecord }
            try identity?.validate()
        case .delete:
            guard expectedRevision != nil, identity == nil else { throw StoreError.invalidRecord }
        }
    }
}

public struct StorageReply: Codable, Equatable, Sendable {
    public let revision: UInt64
    public let identity: StoredIdentity?
    public init(revision: UInt64, identity: StoredIdentity? = nil) { self.revision = revision; self.identity = identity }
}

/// Blocking implementation contract. The SDK calls it only on its private IO queue.
/// Save/delete must atomically compare revision and commit the entire snapshot; delete keeps a tombstone.
public protocol IdentityStore: AnyObject, Sendable {
    func perform(_ request: StorageRequest) throws -> StorageReply
}

func encodeJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return try encoder.encode(value)
}
