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
private struct ServiceRegistration: Decodable, Sendable {
    let application_id: String
    let registration_grant: String
    let installation_public_key: String
    let idempotency_key: String
}
private struct ServiceFixture: Decodable, Sendable {
    let origin: String
    let source: ServiceDevice
    let target: ServiceDevice
    let third: ServiceDevice
    let first_registration: ServiceRegistration
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
        let registration = fixture.first_registration
        guard UUID(uuidString: registration.application_id) != nil,
              !devices.contains(where: { $0.application_id == registration.application_id }),
              !registration.registration_grant.isEmpty, registration.registration_grant.utf8.count <= 4096,
              !registration.installation_public_key.isEmpty, registration.installation_public_key.utf8.count <= 4096,
              !registration.idempotency_key.isEmpty, registration.idempotency_key.utf8.count <= 128 else {
            throw ServiceFailure.fixture
        }
        return fixture
    }
}
private let postClosePayload = Data([3, 2, 0, 1, 255, 0])

private actor ServiceMailbox {
    private var online = false
    private var incoming: [String] = []
    private var connections: [String: UInt64] = [:]
    private var channels: [String: PeerloomChannel] = [:]
    private var messages: [UInt64: [Data]] = [:]
    private var closedChannels: [UInt64: UInt64] = [:]
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
        case 3, 7: break
        case 13:
            guard event.channel != 0, event.connection != 0,
                  closedChannels[event.channel] == nil, closedChannels.count < 8 else {
                throw ServiceFailure.event
            }
            closedChannels[event.channel] = event.connection
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
            guard (bytes == binary || (bytes == postClosePayload && channels["swift-low"]?.handle == event.channel)),
                  messages[event.channel, default: []].count < 16 else { throw ServiceFailure.mismatch }
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
    func postCloseCount(_ channel: UInt64) throws -> Int {
        try check(); return messages[channel, default: []].filter { $0 == postClosePayload }.count
    }
    func receivedDefault() throws -> Bool? { try check(); return defaultMessages > 0 ? true : nil }
    func closed(_ channel: PeerloomChannel) throws -> Bool? {
        try check()
        guard let parent = closedChannels[channel.handle] else { return nil }
        guard parent == channel.connection else { throw ServiceFailure.mismatch }
        return true
    }
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

// 仅 CLOSE 接受原生 OK/CLOSED 竞态；completion 从不替代两端 CHANNEL_CLOSED 排空证据。
private func closeChannelAndWait(_ local: PeerloomChannel, remote: PeerloomChannel,
                                 label: String, sourceBox: ServiceMailbox,
                                 targetBox: ServiceMailbox) async throws {
    guard local.label == label, remote.label == label,
          local.mode == remote.mode else { throw ServiceFailure.mismatch }
    do { try await local.close() }
    catch PeerloomError.native(5) { }
    _ = try await eventually { try await sourceBox.closed(local) }
    _ = try await eventually { try await targetBox.closed(remote) }
    guard !local.isValid, !remote.isValid else { throw ServiceFailure.mismatch }
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
        var registrationSDK: PeerloomSDK?
        let boxes = [ServiceMailbox(), ServiceMailbox(), ServiceMailbox()]
        do {
            let first = fixture.first_registration
            try await Task.detached {
                let store = try KeychainIdentityStore()
                let scope = IdentityScope(serverOrigin: fixture.origin, applicationID: first.application_id)
                let empty = try store.perform(StorageRequest(operation: .load, scope: scope))
                guard empty.revision == 0, empty.identity == nil else { throw ServiceFailure.fixture }
            }.value
            var firstConfig = PeerloomConfiguration(origin: fixture.origin, applicationID: first.application_id)
            firstConfig.developmentLoopback = true
            let firstSDK = try await PeerloomSDK.open(configuration: firstConfig)
            registrationSDK = firstSDK
            let registeredID = try await firstSDK.start(registration: PeerloomRegistration(
                installationPublicKey: first.installation_public_key, registrationGrant: first.registration_grant),
                idempotencyKey: first.idempotency_key)
            guard UUID(uuidString: registeredID) != nil,
                  !devices.contains(where: { $0.device_id == registeredID }) else { throw ServiceFailure.mismatch }
            try await firstSDK.close()
            registrationSDK = nil
            try await Task.detached {
                let store = try KeychainIdentityStore()
                let scope = IdentityScope(serverOrigin: fixture.origin, applicationID: first.application_id)
                let saved = try store.perform(StorageRequest(operation: .load, scope: scope))
                guard saved.revision > 0, saved.identity?.deviceID == registeredID,
                      saved.identity?.deviceCredential.isEmpty == false else { throw ServiceFailure.mismatch }
            }.value
            print("[Swift service] Swift first registration persisted in Keychain")
            let reopenedSDK = try await PeerloomSDK.open(configuration: firstConfig)
            registrationSDK = reopenedSDK
            guard try await reopenedSDK.start() == registeredID else { throw ServiceFailure.mismatch }
            try await reopenedSDK.close()
            registrationSDK = nil
            print("[Swift service] Swift reopen restored the same registered device")
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
            try await closeChannelAndWait(reliable, remote: remoteReliable, label: "swift-reliable",
                                          sourceBox: boxes[0], targetBox: boxes[1])
            guard low.isValid, remoteLow.isValid, stream.isValid, remoteStream.isValid else {
                throw ServiceFailure.mismatch
            }
            // 固定新增工作量，以新接收计数证明兄弟仍能传输，不用旧消息冒充。
            guard try await boxes[1].postCloseCount(remoteLow.handle) == 0 else { throw ServiceFailure.mismatch }
            for _ in 0..<8 { _ = try await low.send(postClosePayload) }
            _ = try await eventually {
                try await boxes[1].postCloseCount(remoteLow.handle) > 0 ? true : nil
            }
            // 关闭一个 child 不应破坏父连接；使用新的实际消息证明仍可双向通信。
            try await sdks[0].send(binary, on: parent)
            _ = try await eventually { try await boxes[1].receivedDefault() }
            try await sdks[1].send(binary, on: remoteReliable.connection)
            _ = try await eventually { try await boxes[0].receivedDefault() }
            try await sdks[0].closeConnection(parent)
            guard !stream.isValid else { throw ServiceFailure.mismatch }
            try await sdks[0].send(binary, on: other)
            _ = try await eventually { try await boxes[2].receivedDefault() }
            print("[Swift service] real Go/WSS + DP Keychain + 3 devices/2 connections + message/low/256KiB stream/duplex/FIN + parent-child gate passed")
        } catch {
            for pump in pumps { pump.cancel() }
            reverseRead?.cancel()
            if let registrationSDK { try? await registrationSDK.close() }
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
