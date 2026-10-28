// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation
import Security
import LocalAuthentication
import CryptoKit
import Darwin

/// Device-local, non-synchronizing Keychain storage. No plaintext fallback and no unlock UI.
/// All cooperating processes sharing an access group MUST supply the same app-group lock directory.
public final class KeychainIdentityStore: IdentityStore, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?
    private let directory: URL
    #if os(macOS)
    private var testKeychain: SecKeychain?
    #endif
    private struct Record: Codable {
        let format: Int
        let scope: IdentityScope
        let revision: UInt64
        let identity: StoredIdentity?
    }
    public init(accessGroup: String? = nil, sharedLockDirectory: URL? = nil) throws {
        guard accessGroup == nil || sharedLockDirectory != nil,
              (accessGroup?.utf8.count ?? 0) <= 256 else { throw StoreError.invalidRecord }
        self.service = "io.peerloom.sdk.identity.v1"
        self.accessGroup = accessGroup
        if let directory = sharedLockDirectory {
            guard directory.isFileURL else { throw StoreError.invalidRecord }
            self.directory = directory
        } else {
            guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            else { throw StoreError.unavailable }
            self.directory = support.appendingPathComponent("PeerloomCAS", isDirectory: true)
        }
    }
    #if os(macOS) && DEBUG
    /// Validation only: isolated file-based Keychain, NOT the production data-protection backend.
    @_spi(Validation) public init(validationKeychain: SecKeychain, lockDirectory: URL, service: String) throws {
        guard service.hasPrefix("io.peerloom.validation."), lockDirectory.isFileURL else { throw StoreError.invalidRecord }
        self.service = service; self.accessGroup = nil; self.directory = lockDirectory
        self.testKeychain = validationKeychain
    }
    #endif

    public func perform(_ request: StorageRequest) throws -> StorageReply {
        guard !Thread.isMainThread else { throw StoreError.unavailable }
        try request.validate()
        let account = SHA256.hash(data: try encodeJSON(request.scope)).map { String(format: "%02x", $0) }.joined()
        return try withFileLock(account: account) {
            let current = try read(scope: request.scope, account: account)
            if request.operation == .load { return StorageReply(revision: current?.revision ?? 0, identity: current?.identity) }
            guard let expected = request.expectedRevision else { throw StoreError.invalidRecord }
            guard expected < UInt64.max else { throw StoreError.revisionOverflow }
            guard (current?.revision ?? 0) == expected else { throw StoreError.conflict }
            let record = Record(format: 1, scope: request.scope, revision: expected + 1, identity: request.identity)
            let data = try encodeJSON(record)
            guard data.count <= 16384 else { throw StoreError.invalidRecord }
            let status: OSStatus
            if current == nil {
                var attributes = base(account: account, adding: true)
                attributes[kSecValueData as String] = data
                attributes[kSecAttrGeneric as String] = revisionData(record.revision)
                attributes[kSecAttrSynchronizable as String] = false
                #if os(macOS)
                if testKeychain == nil { attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly }
                #else
                attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                #endif
                status = SecItemAdd(attributes as CFDictionary, nil)
                if status == errSecDuplicateItem { throw StoreError.conflict }
            } else {
                var query = base(account: account)
                // Atomic matching in Security also fences accidental callers using different lock files.
                query[kSecAttrGeneric as String] = revisionData(expected)
                status = SecItemUpdate(query as CFDictionary,
                    [kSecValueData as String: data, kSecAttrGeneric as String: revisionData(record.revision)] as CFDictionary)
                if status == errSecItemNotFound { throw StoreError.conflict }
            }
            guard status == errSecSuccess else { throw StoreError.unavailable }
            return StorageReply(revision: record.revision)
        }
    }

    private func base(account: String, adding: Bool = false) -> [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrAccount as String: account]
        let authentication = LAContext()
        authentication.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = authentication
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        #if os(macOS)
        if let keychain = testKeychain {
            query.removeValue(forKey: kSecUseAuthenticationContext as String)
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
            if adding { query[kSecUseKeychain as String] = keychain }
            else { query[kSecMatchSearchList as String] = [keychain] }
        } else {
            query[kSecUseDataProtectionKeychain as String] = true
        }
        #endif
        return query
    }
    private func read(scope: IdentityScope, account: String) throws -> Record? {
        var query = base(account: account)
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw StoreError.unavailable }
        guard let attributes = result as? [String: Any], let data = attributes[kSecValueData as String] as? Data,
              data.count <= 16384, let revision = attributes[kSecAttrGeneric as String] as? Data
        else { throw StoreError.invalidRecord }
        let record = try JSONDecoder().decode(Record.self, from: data)
        guard record.format == 1, record.scope == scope, record.revision > 0,
              revision == revisionData(record.revision) else { throw StoreError.invalidRecord }
        try record.identity?.validate()
        return record
    }
    private func revisionData(_ value: UInt64) -> Data {
        var value = value.bigEndian
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    private func withFileLock<T>(account: String, body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        var directoryInfo = stat()
        guard lstat(directory.path, &directoryInfo) == 0,
              directoryInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR), directoryInfo.st_uid == geteuid(),
              directoryInfo.st_mode & 0o777 == 0o700 else { throw StoreError.unavailable }
        let path = directory.appendingPathComponent(account + ".lock").path
        let descriptor = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw StoreError.unavailable }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              info.st_uid == geteuid(), info.st_nlink == 1, info.st_mode & 0o777 == 0o600
        else { throw StoreError.unavailable }
        let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            guard [EWOULDBLOCK, EAGAIN, EINTR].contains(errno), DispatchTime.now().uptimeNanoseconds < deadline
            else { throw StoreError.unavailable }
            usleep(5_000)
        }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }
}
