// MIT — Copyright (c) 2026 Peerloom contributors.
// DEBUG-only native test helper. Secrets arrive through stdin, never argv or output.
import Foundation
#if os(macOS) && DEBUG
import Security
@_spi(Validation) import PeerloomSwift
struct Input: Decodable {
    let keychain: String; let password: String; let locks: String; let service: String
    let request: StorageRequest
}
final class ResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value = "unavailable"
    func set(_ text: String) { lock.lock(); value = text; lock.unlock() }
    func get() -> String { lock.lock(); defer { lock.unlock() }; return value }
}
let inputData = FileHandle.standardInput.readDataToEndOfFile()
var result = "unavailable"
if inputData.count <= 32768 {
    do {
        let input = try JSONDecoder().decode(Input.self, from: inputData)
        var keychain: SecKeychain?
        guard SecKeychainOpen(input.keychain, &keychain) == errSecSuccess, let keychain else { throw StoreError.unavailable }
        let status = input.password.withCString { SecKeychainUnlock(keychain, UInt32(input.password.utf8.count), $0, true) }
        guard status == errSecSuccess else { throw StoreError.unavailable }
        let store = try KeychainIdentityStore(validationKeychain: keychain, lockDirectory: URL(fileURLWithPath: input.locks), service: input.service)
        let completed = DispatchSemaphore(value: 0), box = ResultBox()
        DispatchQueue.global().async {
            do { _ = try store.perform(input.request); box.set("ok") }
            catch StoreError.conflict { box.set("conflict") }
            catch { box.set("unavailable") }
            completed.signal()
        }
        if completed.wait(timeout: .now() + 5) == .success { result = box.get() }
    } catch { result = "unavailable" }
}
print(result)
#else
print("unsupported")
#endif
