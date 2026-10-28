// MIT — Copyright (c) 2026 Peerloom contributors.
import XCTest
import Foundation
import Security
@_spi(Validation) @testable import PeerloomSwift

func onWorker<T>(_ body: @escaping () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .utility).async {
            do { continuation.resume(returning: try body()) }
            catch { continuation.resume(throwing: error) }
        }
    }
}
final class KeychainTests: XCTestCase {
    private var directory: URL!
    private var store: KeychainIdentityStore!
    private var scope: IdentityScope!
    #if os(macOS)
    private var keychain: SecKeychain!
    private var password: String!
    private var keychainPath: String!
    private var service: String!
    #endif
    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("peerloom-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        scope = IdentityScope(serverOrigin: "https://example.invalid/", applicationID: UUID().uuidString.lowercased())
        #if os(macOS)
        password = UUID().uuidString
        keychainPath = directory.appendingPathComponent("isolated.keychain-db").path
        service = "io.peerloom.validation." + UUID().uuidString
        let result = password.withCString { SecKeychainCreate(keychainPath, UInt32(password.utf8.count), $0, false, nil, &keychain) }
        guard result == errSecSuccess else { throw StoreError.unavailable }
        store = try KeychainIdentityStore(validationKeychain: keychain, lockDirectory: directory.appendingPathComponent("locks"), service: service)
        #else
        // iOS simulator test exercises the actual data-protection implementation, not a mock.
        store = try KeychainIdentityStore(sharedLockDirectory: directory.appendingPathComponent("locks"))
        #endif
    }
    override func tearDownWithError() throws {
        #if os(macOS)
        if let keychain { XCTAssertEqual(SecKeychainDelete(keychain), errSecSuccess) }
        #endif
        if let directory { try FileManager.default.removeItem(at: directory) }
    }
    private func identity(_ suffix: String = "one") -> StoredIdentity {
        StoredIdentity(deviceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", deviceCredential: "dev_private_" + suffix, expiresAt: "2030-01-01T00:00:00Z")
    }
    func testSaveLoadCASAndPersistentDeleteTombstone() async throws {
        let store = store!, scope = scope!, value = identity()
        let initial = try await onWorker { try store.perform(StorageRequest(operation: .load, scope: scope)) }
        XCTAssertEqual(initial, StorageReply(revision: 0))
        let saved = try await onWorker { try store.perform(StorageRequest(operation: .save, scope: scope, expectedRevision: 0, identity: value)) }
        XCTAssertEqual(saved.revision, 1)
        do { _ = try await onWorker { try store.perform(StorageRequest(operation: .save, scope: scope, expectedRevision: 0, identity: value)) }; XCTFail("stale CAS") }
        catch { XCTAssertEqual(error as? StoreError, .conflict) }
        let loaded = try await onWorker { try store.perform(StorageRequest(operation: .load, scope: scope)) }
        XCTAssertEqual(loaded, StorageReply(revision: 1, identity: value))
        let deleted = try await onWorker { try store.perform(StorageRequest(operation: .delete, scope: scope, expectedRevision: 1)) }
        XCTAssertEqual(deleted.revision, 2)
        let tombstone = try await onWorker { try store.perform(StorageRequest(operation: .load, scope: scope)) }
        XCTAssertEqual(tombstone, StorageReply(revision: 2))
        do { _ = try await onWorker { try store.perform(StorageRequest(operation: .save, scope: scope, expectedRevision: 0, identity: value)) }; XCTFail("tombstone reset") }
        catch { XCTAssertEqual(error as? StoreError, .conflict) }
    }
    func testConcurrentCASHasExactlyOneWinner() async throws {
        let store = store!, scope = scope!, value = identity()
        let outcomes = await withTaskGroup(of: Bool.self) { group -> [Bool] in
            for _ in 0..<8 {
                group.addTask {
                    do { _ = try await onWorker { try store.perform(StorageRequest(operation: .save, scope: scope, expectedRevision: 0, identity: value)) }; return true }
                    catch { return false }
                }
            }
            var result: [Bool] = []
            for await item in group { result.append(item) }
            return result
        }
        XCTAssertEqual(outcomes.filter { $0 }.count, 1)
        let loaded = try await onWorker { try store.perform(StorageRequest(operation: .load, scope: scope)) }
        XCTAssertEqual(loaded.revision, 1)
    }
    func testMainThreadAndOverflowFailClosed() async throws {
        let store = store!, scope = scope!, value = identity()
        await MainActor.run {
            XCTAssertThrowsError(try store.perform(StorageRequest(operation: .load, scope: scope)))
        }
        do { _ = try await onWorker { try store.perform(StorageRequest(operation: .save, scope: scope, expectedRevision: UInt64.max, identity: value)) }; XCTFail("overflow accepted") }
        catch { XCTAssertEqual(error as? StoreError, .revisionOverflow) }
        XCTAssertEqual(value.description, "StoredIdentity(<redacted>)")
    }
    #if os(macOS)
    func testLockedKeychainDoesNotBecomeEmptyOrPrompt() async throws {
        let store = store!, scope = scope!, value = identity()
        _ = try await onWorker { try store.perform(StorageRequest(operation: .save, scope: scope, expectedRevision: 0, identity: value)) }
        XCTAssertEqual(SecKeychainLock(keychain), errSecSuccess)
        do { _ = try await onWorker { try store.perform(StorageRequest(operation: .load, scope: scope)) }; XCTFail("locked Keychain accepted") }
        catch { XCTAssertEqual(error as? StoreError, .unavailable) }
        let status = password.withCString { SecKeychainUnlock(keychain, UInt32(password.utf8.count), $0, true) }
        XCTAssertEqual(status, errSecSuccess)
        let unchanged = try await onWorker { try store.perform(StorageRequest(operation: .load, scope: scope)) }
        XCTAssertEqual(unchanged, StorageReply(revision: 1, identity: value))
    }
    func testCrossProcessCASUsingIsolatedKeychain() async throws {
        guard let binary = ProcessInfo.processInfo.environment["PEERLOOM_STORE_PROBE_BIN"] else {
            XCTFail("native gate must provide PEERLOOM_STORE_PROBE_BIN"); return
        }
        let document: [String: Any] = ["keychain": keychainPath!, "password": password!, "locks": directory.appendingPathComponent("locks").path,
            "service": service!, "request": ["operation": "save", "scope": ["server_origin": scope.serverOrigin, "application_id": scope.applicationID],
            "expected_revision": 0, "identity": ["device_id": identity().deviceID, "device_credential": identity().deviceCredential, "expires_at": identity().expiresAt]]]
        let data = try JSONSerialization.data(withJSONObject: document)
        let outcomes: [String] = try await onWorker {
            var children: [(Process, Pipe)] = []
            for _ in 0..<2 {
                let process = Process(), input = Pipe(), output = Pipe()
                process.executableURL = URL(fileURLWithPath: binary)
                process.standardInput = input; process.standardOutput = output; process.standardError = FileHandle.nullDevice
                try process.run()
                input.fileHandleForWriting.write(data); try input.fileHandleForWriting.close()
                children.append((process, output))
            }
            defer { for (child, _) in children where child.isRunning { child.terminate() } }
            let deadline = Date().addingTimeInterval(8)
            while children.contains(where: { $0.0.isRunning }) && Date() < deadline { Thread.sleep(forTimeInterval: 0.01) }
            guard !children.contains(where: { $0.0.isRunning }) else { throw StoreError.unavailable }
            return children.map { String(data: $0.1.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)!.trimmingCharacters(in: .whitespacesAndNewlines) }
        }
        XCTAssertEqual(outcomes.sorted(), ["conflict", "ok"])
    }
    #endif
}
