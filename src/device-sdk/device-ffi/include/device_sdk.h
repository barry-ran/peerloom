#ifndef PEERLOOM_DEVICE_SDK_H
#define PEERLOOM_DEVICE_SDK_H
/* MIT — Copyright (c) 2026 Peerloom contributors.
 * Native ABI v1, currently validated on Linux only. C11/C++17.
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
#define DP_CAP_RELIABLE_MESSAGE UINT64_C(1)
#define DP_CAP_ASYNC_CAS_STORE UINT64_C(2)
#define DP_CAP_EXPLICIT_MEMORY_STORE UINT64_C(4)
#define DP_CAP_RESET_IDENTITY UINT64_C(8)

typedef struct dp_event {
    uint32_t abi_version;
    uint32_t kind;
    uint64_t request_id;
    uint64_t connection;
    uint32_t status;
    uint32_t struct_size;
    const uint8_t *payload;
    size_t payload_len;
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
 * Max16 instances; capacity1 connection and1 reliable-message channel each.
 * Inputs copied before return; non-null pointers must be valid/aligned as appropriate.
 * Immediate error => output0, no asynchronous completion. No callbacks on create failure.
 * On success, callback code must remain loaded until release succeeds.
 */
uint32_t dp_sdk_create(const uint8_t *json, size_t len, dp_callback callback,
                       uint64_t context, uint64_t *out_sdk);
/* <=32 admitted operations, each reserves one terminal completion credit until callback
 * returns. Successful admission => unique request ID and exactly one COMPLETE event.
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
 * Unknown operation (streams/multichannel included) returns UNSUPPORTED.
 */
uint32_t dp_sdk_submit(uint64_t sdk, uint32_t operation, uint64_t connection,
                       const uint8_t *input, size_t len, uint64_t *out_request);
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
