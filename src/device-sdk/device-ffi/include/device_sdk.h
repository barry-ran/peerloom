#ifndef PEERLOOM_DEVICE_SDK_H
#define PEERLOOM_DEVICE_SDK_H
/* MIT — Copyright (c) 2026 Peerloom contributors.
 * Native ABI v1 with append-only event extension. C11/C++17.
 * No Rust layout, owning pointer, or caller buffer crosses an asynchronous task.
 */
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DP_OK UINT32_C(0)
#define DP_INVALID_ARGUMENT UINT32_C(1)
#define DP_NOT_READY UINT32_C(2)
#define DP_UNAUTHORIZED UINT32_C(3)
#define DP_TIMEOUT UINT32_C(4)
#define DP_CLOSED UINT32_C(5)
#define DP_BUFFER_FULL UINT32_C(6)
#define DP_UNSUPPORTED UINT32_C(7)
#define DP_INVALID_HANDLE UINT32_C(8)
#define DP_CANCELLED UINT32_C(9)
#define DP_OUTCOME_UNKNOWN UINT32_C(10)
#define DP_BUSY UINT32_C(11)
#define DP_INTERNAL UINT32_C(255)
#define DP_OP_START UINT32_C(1)
#define DP_OP_CONNECT UINT32_C(2)
#define DP_OP_RESPOND UINT32_C(3)
#define DP_OP_SEND UINT32_C(4)
#define DP_OP_REFRESH UINT32_C(5)
#define DP_OP_CLOSE_CONNECTION UINT32_C(6)
#define DP_OP_RESET_IDENTITY UINT32_C(7)
#define DP_OP_OPEN_CHANNEL UINT32_C(8)
#define DP_CHANNEL_SEND UINT32_C(1)
#define DP_CHANNEL_READ UINT32_C(2)
#define DP_CHANNEL_WRITE UINT32_C(3)
#define DP_CHANNEL_FINISH_WRITE UINT32_C(4)
#define DP_CHANNEL_CLOSE UINT32_C(5)
#define DP_EVENT_COMPLETE UINT32_C(1)
#define DP_EVENT_ONLINE UINT32_C(2)
#define DP_EVENT_OFFLINE UINT32_C(3)
#define DP_EVENT_INCOMING UINT32_C(4)
#define DP_EVENT_CONNECTION_READY UINT32_C(5)
#define DP_EVENT_MESSAGE UINT32_C(6)
#define DP_EVENT_CONNECTION_CLOSED UINT32_C(7)
#define DP_EVENT_PERSISTENCE_PENDING UINT32_C(8)
#define DP_EVENT_SHUTDOWN UINT32_C(9)
#define DP_EVENT_STORAGE_REQUEST UINT32_C(10)
#define DP_EVENT_STOPPED UINT32_C(11)
#define DP_EVENT_CHANNEL_READY UINT32_C(12)
#define DP_EVENT_CHANNEL_CLOSED UINT32_C(13)
#define DP_EVENT_CHANNEL_MESSAGE UINT32_C(14)
#define DP_CAP_RELIABLE_MESSAGE UINT64_C(1)
#define DP_CAP_ASYNC_CAS_STORE UINT64_C(2)
#define DP_CAP_EXPLICIT_MEMORY_STORE UINT64_C(4)
#define DP_CAP_RESET_IDENTITY UINT64_C(8)
#define DP_CAP_MULTIPLE_CONNECTIONS UINT64_C(16)
#define DP_CAP_TYPED_CHANNELS UINT64_C(32)
#define DP_CAP_RELIABLE_STREAM UINT64_C(64)
#define DP_CAP_LOW_LATENCY_MESSAGE UINT64_C(128)

typedef struct dp_event {
    uint32_t abi_version;
    uint32_t kind;
    uint64_t request_id;
    uint64_t connection;
    uint32_t status;
    uint32_t struct_size;
    const uint8_t *payload;
    size_t payload_len;
    /* Optional appended ABI-v1 field; check struct_size before reading. */
    uint64_t channel;
} dp_event;
/* Payload/event pointers are borrowed ONLY during this callback. Copy if retained.
 * One dedicated serial callback thread per SDK; host dispatches to its own UI.
 * Verify abi_version and struct_size before reading fields; future minor additions append.
 * context is an opaque integer chosen by host, not an owned pointer.
 * Reentrant nonblocking API calls allowed; callback must not throw/longjmp/unwind.
 * Never wait for another callback inside this callback. Slow callbacks cause bounded
 * backpressure; a callback that never returns prevents release indefinitely.
 */
typedef void (*dp_callback)(uint64_t context, const dp_event *event);
#if defined(__ANDROID__)
/* Same Rust image as the SDK. Call on a JVM-attached thread with live JNIEnv* and
 * Application Context jobject before networking; both JNI arguments remain caller-owned. */
uint32_t dp_android_tls_initialize(void *jni_env, void *application_context);
#endif
uint32_t dp_abi_version(void);
uint64_t dp_capabilities(void);
/* JSON UTF-8 <=16KiB, no trailing NUL. Required fields:
 * {"abi_version":1,"origin":"https://...","application_id":"UUID",
 *  "storage":"external"|"memory","development_loopback":false,"auto_reconnect":true}
 * HTTPS/WSS required except explicit dev IP-literal loopback. Memory is not durable.
 * No fixed SDK-instance ceiling. Optional max_connections,
 * max_channels_per_connection (including the default reliable message channel), and
 * max_channel_creations_per_connection default to 0: no application count cap.
 * Positive values impose explicit limits; if both channel limits are positive,
 * the active limit must not exceed the lifetime creation budget (not refunded on close).
 * Protocol stream-ID limits, resource exhaustion, bounded queues and the separate
 * byte budgets still apply. Unlimited does not preallocate capacity.
 * ffi_resource_budget_bytes defaults to 134217728 (minimum 2097152). This bounds
 * charged FFI buffers/metadata, not process RSS or core/host allocations. Critical
 * control owns R=max(262144,budget/8) bytes that data cannot consume.
 * R/2 is reserved for management operations and storage callbacks; the remainder covers
 * lifecycle notifications, including a Closed reservation per published object.
 * Inputs copied before return; non-null pointers must be valid/aligned as appropriate.
 * Immediate error => output0, no asynchronous completion. No callbacks on create failure.
 * On success, callback code must remain loaded until release succeeds.
 */
uint32_t dp_sdk_create(const uint8_t *json, size_t len, dp_callback callback,
                       uint64_t context, uint64_t *out_sdk);
/* Admission grows lazily with connections C and reliable streams S, including
 * retired objects until their Closed callback returns or notification is discarded:
 * ordinary credits=64+8*C+2*S; independent close/reset credits=64+C+S.
 * Byte exhaustion returns FULL without acceptance. Each admitted operation reserves
 * its terminal slot and bytes until callback returns; shrinking object counts cannot
 * revoke existing reservations. Successful admission => unique request ID and exactly one COMPLETE event.
 * Completion may occur before submit returns; correlate by returned request ID.
 * Start: {} loads host store; registration:
 * {"registration":{"platform":"linux","installation_public_key":"...",
 * "registration_grant":"reg_...","sdk_version":"...","metadata":{}},
 * "idempotency_key":"host-retained-key"}. Keep exact request/key for uncertain replay.
 * Direct enrollment omits registration_grant; server must explicitly enable direct.
 * Its idempotency_key is a secret: fresh CSPRNG32 bytes as canonical base64url43 chars.
 * Keep it securely with the exact body; UUID/public installation keys are not sufficient.
 * Connect: {"target_device_id":"UUID"}; respond: {"session_id":"UUID","accept":true}.
 * Send: raw binary <=65536 bytes, connection handle required. Empty messages allowed.
 * Refresh/close: empty input; close requires connection handle. Others connection=0.
 * Successful close admission immediately refuses new sends/message callbacks; already
 * running callback/send cannot be recalled. Existing queued sends may settle first.
 * Connect completion means request submitted, not connected; await CONNECTION_READY.
 * Send completion means locally queued, NOT remote application receipt/exactly-once.
 * Reset: {"expected_device_id":"current UUID","retry":false}, connection=0.
 * Admission immediately fences old delivery and cancels queued cancellable operations.
 * Running work may settle; reset is itself irreversible/non-cancellable (cancel => BUSY).
 * Success writes a CAS tombstone and leaves SDK ready for an explicit new START/register.
 * It does not revoke the old server device or auto-register/reuse a registration key.
 * Failure leaves admission stopped; retry=true recovers only that same confirmed reset.
 * OUTCOME_UNKNOWN must not be treated as success; retain the instance to retry/read back.
 * A new registration must use fresh request/grant/recovery key, never the old identity.
 * Unknown operation returns UNSUPPORTED; typed children use the separate entry below.
 */
uint32_t dp_sdk_submit(uint64_t sdk, uint32_t operation, uint64_t connection,
                       const uint8_t *input, size_t len, uint64_t *out_request);
/* Typed child operations share the SDK dynamic credits/byte budget with sdk_submit.
 * All three handles must belong together; handles never alias another generation.
 * SEND: complete binary message; OK payload {"disposition":"sent"|"dropped"}.
 * "sent" is local acceptance, not peer receipt; dropped is explicit queue policy.
 * READ: JSON {"max_bytes":N}, 1<=N<=65536. OK payload is up to N raw stream bytes;
 * zero-length OK is EOF, never an empty read request. Exactly one outstanding read
 * per stream; unrelated channels and stream writes must continue while it waits.
 * WRITE: raw bytes <=65536; OK JSON {"written":N}, which can be smaller than input.
 * Advance only by N; never automatically replay an uncertain write (stream closes).
 * FINISH_WRITE: empty input, sends one-way FIN; the read direction remains usable.
 * CLOSE: empty input, irreversible local delivery fence at successful admission.
 * FINISH_WRITE also cannot be cancelled after admission; it fences future writes.
 * The other end of a closed connection/generation/reset invalidates every child.
 * READ completions recheck authorization at callback dispatch: expired bytes are
 * removed and reported CLOSED, not delivered or silently losing the completion.
 * Unsupported mode/operation combinations fail immediately, with output0 and no event.
 * Open via sdk_submit OPEN_CHANNEL + connection and JSON mode/label/queue; mode is
 * reliable_message, low_latency_message, or reliable_stream. Queue drop/TTL policies
 * apply ONLY to messages; they never drop a middle byte range in a stream.
 * Message queue: {max_messages:1..256,max_bytes:1..1048576,ttl_ms:1..60000,
 * overflow:"fail"|"drop_oldest"|"drop_newest"}; omitted uses engineering defaults.
 * Stream rejects queue options; WRITE/FIN have a fixed 30s send deadline starting
 * at ABI admission, including queue time. Expiry closes the stream (never skips bytes).
 * Stream receive is bounded with backpressure, not a receive TTL/drop policy.
 * COMPLETE for successful open includes the appended channel handle. Unsolicited
 * CHANNEL_READY announces peer-opened channels with mode/label/session/generation JSON.
 */
uint32_t dp_channel_submit(uint64_t sdk, uint64_t connection, uint64_t channel,
                           uint32_t operation, const uint8_t *input, size_t len,
                           uint64_t *out_request);
/* Recheck at host delivery after dispatching away from the native callback thread. */
uint32_t dp_channel_is_valid(uint64_t sdk, uint64_t connection, uint64_t channel);
/* Only queued work can be cancelled (one CANCELLED completion). Close admission is
 * irreversible locally and cannot be cancelled. Running work/close/reset => BUSY,
 * not aborted: remote registration/rotation cannot safely be rolled back. Cancellation
 * never retracts a completed remote mutation. Process crash recovery journal not provided.
 */
uint32_t dp_sdk_cancel(uint64_t sdk, uint64_t request_id);
/* Nonblocking: stop admission, drain accepted completions, close transport/SDK, then final
 * SHUTDOWN callback. No callbacks after that callback returns. Running operations settle
 * first; storage callbacks remain serviceable during shutdown. Hung host callback => no
 * safe forced release. Poll state/release from host, never synchronously wait in callback.
 */
uint32_t dp_sdk_shutdown(uint64_t sdk, uint64_t *out_request);
/* STORAGE_REQUEST payload JSON includes operation=load/save/delete, scope={server_origin,
 * application_id}, expected_revision (null on load), identity (save only).
 * Host MUST perform atomic CAS, use encrypted platform storage, preserve tombstone revision.
 * Callback may schedule async work then return; finish via storage_complete within10s.
 * Load OK JSON: {"revision":N,"identity":null|{device_id,device_credential,expires_at}}.
 * Save/delete OK: {"revision":expected+1}. BUSY means CAS conflict; INTERNAL unavailable.
 * All replies <=16KiB. Timeouts/cancellation permit old OR fully committed new snapshot,
 * never partial writes. SDK reconciles a cancelled committed save by load+identity match.
 * Late/duplicate/cross-instance request replies rejected; never log payload credentials.
 */
uint32_t dp_storage_complete(uint64_t sdk, uint64_t storage_request_id, uint32_t status,
                             const uint8_t *json, size_t len);
/* state: 0 created/running,1 shutting down,2 quiescent,3 invalid handle. State2 is advisory;
 * release may briefly return BUSY until thread epilogues finish. release never self-joins.
 * After successful release handle is invalid forever; handles are never reused.
 */
uint32_t dp_sdk_state(uint64_t sdk);
/* Host queues must recheck immediately before delivering Ready/Message to application.
 * Read-only: no renewal, no transport exposure. Running callbacks cannot be recalled. */
uint32_t dp_connection_is_valid(uint64_t sdk, uint64_t connection);
uint32_t dp_sdk_release(uint64_t sdk);
#ifdef __cplusplus
}
#endif
#endif
