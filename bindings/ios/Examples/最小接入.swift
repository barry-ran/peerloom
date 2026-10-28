// MIT — Copyright (c) 2026 Peerloom contributors.
import Foundation
import PeerloomSwift

/// No business UI or hardware identity. Obtain registration grants from the authorized backend.
/// The caller retains registration + idempotencyKey across uncertain outcomes.
func runPeerloom(origin: String, applicationID: String,
                 registration: PeerloomRegistration?, idempotencyKey: String?,
                 onEvent: @escaping @Sendable (PeerloomEvent) async -> Void) async throws {
    let sdk = try await PeerloomSDK.open(configuration: PeerloomConfiguration(origin: origin, applicationID: applicationID))
    do {
        _ = try await sdk.start(registration: registration, idempotencyKey: idempotencyKey)
        for try await event in sdk.events {
            // The caller decides target acceptance; this example never silently approves an incoming peer.
            await onEvent(event)
        }
    } catch {
        try? await sdk.close()
        throw error
    }
    try await sdk.close()
}
