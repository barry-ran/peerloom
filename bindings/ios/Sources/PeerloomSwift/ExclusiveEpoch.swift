// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation

// Descriptive metadata only: native gate validity is still checked at consumption.
func decodeTargetEpoch(_ data: Data) throws -> String? {
    struct Wire: Decodable {
        let exclusive_target: Bool
        let exclusive_protocol_version: Int
        let target_epoch: String
    }
    guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw PeerloomError.invalidEvent
    }
    let fields = ["exclusive_target", "exclusive_protocol_version", "target_epoch"]
    if fields.allSatisfy({ object[$0] == nil }) { return nil }
    guard fields.allSatisfy({ object[$0] != nil && !(object[$0] is NSNull) }),
          try hasIntegerVersionOne(data) else { throw PeerloomError.invalidEvent }
    let wire = try JSONDecoder().decode(Wire.self, from: data)
    guard wire.exclusive_target, wire.exclusive_protocol_version == 1,
          let value = Int64(wire.target_epoch), value > 0, String(value) == wire.target_epoch else {
        throw PeerloomError.invalidEvent
    }
    let epoch = wire.target_epoch
    return epoch
}

// JSONDecoder/NSNumber may normalize 1.0 into an integer. Inspect only the original
// top-level version token after Foundation has validated the complete JSON object.
private func hasIntegerVersionOne(_ data: Data) throws -> Bool {
    let bytes = Array(data)
    var index = 0
    var depth = 0
    var matches = 0
    func whitespace(_ byte: UInt8) -> Bool { byte == 32 || byte == 9 || byte == 10 || byte == 13 }
    while index < bytes.count {
        let byte = bytes[index]
        if byte == 34 {
            let start = index
            index += 1
            while index < bytes.count {
                if bytes[index] == 92 { index += 2; continue }
                if bytes[index] == 34 { break }
                index += 1
            }
            guard index < bytes.count else { return false }
            let end = index
            index += 1
            guard depth == 1 else { continue }
            var cursor = index
            while cursor < bytes.count && whitespace(bytes[cursor]) { cursor += 1 }
            guard cursor < bytes.count && bytes[cursor] == 58 else { continue }
            let key = try JSONDecoder().decode(String.self, from: Data(bytes[start...end]))
            guard key == "exclusive_protocol_version" else { continue }
            cursor += 1
            while cursor < bytes.count && whitespace(bytes[cursor]) { cursor += 1 }
            guard cursor < bytes.count && bytes[cursor] == 49 else { return false }
            cursor += 1
            while cursor < bytes.count && whitespace(bytes[cursor]) { cursor += 1 }
            guard cursor < bytes.count && (bytes[cursor] == 44 || bytes[cursor] == 125) else { return false }
            matches += 1
        } else {
            if byte == 123 || byte == 91 { depth += 1 }
            if byte == 125 || byte == 93 { depth -= 1 }
            index += 1
        }
    }
    return matches == 1
}

public struct PeerloomConnectionInfo: Sendable {
    public let handle: UInt64
    public let sessionID: String
    public let peerDeviceID: String
    public let generation: Int64
    public let targetEpoch: String?
    init(event: PeerloomEvent) throws {
        guard event.kind == 5 else { throw PeerloomError.invalidEvent }
        try self.init(handle: event.connection, payload: event.consumePayload())
    }
    init(handle: UInt64, payload: Data) throws {
        struct Wire: Decodable { let session_id: String; let peer_device_id: String; let generation: Int64 }
        let wire = try JSONDecoder().decode(Wire.self, from: payload)
        guard handle != 0, UUID(uuidString: wire.session_id) != nil, UUID(uuidString: wire.peer_device_id) != nil,
              (1...9007199254740991).contains(wire.generation) else { throw PeerloomError.invalidEvent }
        self.handle = handle; sessionID = wire.session_id; peerDeviceID = wire.peer_device_id
        generation = wire.generation; targetEpoch = try decodeTargetEpoch(payload)
    }
}
