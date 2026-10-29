/* MIT — Copyright (c) 2026 Peerloom contributors.
 * The sole PC calls the real C ABI through this C11 translation unit.
 * Only the canonical public header defines the production ABI.
 */
#include "device_sdk.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

typedef void (*capacity_sink)(uint64_t, uint32_t, uint64_t, uint64_t,
                              uint32_t, uint64_t, const uint8_t *, size_t);
static capacity_sink sink;
static atomic_uint shutdown_seen;
/* Test-feature-only observation, not part of the shipping header or ABI. */
extern uint64_t dp_test_pending_stream_reads(uint64_t sdk);
extern uint64_t dp_test_ffi_resource_bytes(uint64_t sdk, uint32_t field);

static void require(int condition) {
    if (!condition) {
        fputs("capacity C ABI contract violation\n", stderr);
        abort();
    }
}
static uint32_t checked(uint32_t status, uint64_t value, uint64_t *out) {
    require(out != NULL);
    require((status == DP_OK && value != 0) || (status != DP_OK && value == 0));
    *out = value;
    return status;
}
static void callback(uint64_t context, const dp_event *event) {
    require(sink != NULL && event != NULL && event->abi_version == 1);
    require(event->struct_size >= sizeof(dp_event));
    require(event->payload_len <= 65536 && (event->payload_len == 0 || event->payload != NULL));
    require(atomic_load(&shutdown_seen) == 0);
    if (event->kind == DP_EVENT_COMPLETE || event->kind == DP_EVENT_SHUTDOWN)
        require(event->request_id != 0);
    if (event->kind == DP_EVENT_SHUTDOWN)
        require(atomic_exchange(&shutdown_seen, 1) == 0);
    /* Rust copies the borrowed bytes before returning. No dp_event layout is
       redeclared in Rust, and this callback never waits for another callback. */
    sink(context, event->kind, event->request_id, event->connection,
         event->status, event->channel, event->payload, event->payload_len);
}
uint32_t capacity_create(const uint8_t *json, size_t len, capacity_sink collector,
                         uint64_t context, uint64_t *out) {
    require(sink == NULL && collector != NULL);
    require(dp_abi_version() == 1 && (dp_capabilities() & DP_CAP_RELIABLE_STREAM) != 0);
    sink = collector;
    uint64_t value = UINT64_MAX;
    uint32_t status = dp_sdk_create(json, len, callback, context, &value);
    return checked(status, value, out);
}
uint32_t capacity_submit(uint64_t sdk, uint32_t op, uint64_t connection,
                         const uint8_t *bytes, size_t len, uint64_t *out) {
    uint64_t value = UINT64_MAX;
    uint32_t status = dp_sdk_submit(sdk, op, connection, bytes, len, &value);
    return checked(status, value, out);
}
uint32_t capacity_channel(uint64_t sdk, uint64_t connection, uint64_t channel,
                          uint32_t op, const uint8_t *bytes, size_t len, uint64_t *out) {
    uint64_t value = UINT64_MAX;
    uint32_t status = dp_channel_submit(sdk, connection, channel, op, bytes, len, &value);
    return checked(status, value, out);
}
uint32_t capacity_cancel(uint64_t sdk, uint64_t request) { return dp_sdk_cancel(sdk, request); }
uint32_t capacity_storage(uint64_t sdk, uint64_t request, uint32_t status,
                          const uint8_t *json, size_t len) {
    return dp_storage_complete(sdk, request, status, json, len);
}
uint32_t capacity_shutdown(uint64_t sdk, uint64_t *out) {
    uint64_t value = UINT64_MAX;
    uint32_t status = dp_sdk_shutdown(sdk, &value);
    return checked(status, value, out);
}
uint32_t capacity_release(uint64_t sdk) { return dp_sdk_release(sdk); }
uint32_t capacity_state(uint64_t sdk) { return dp_sdk_state(sdk); }
uint32_t capacity_connection_valid(uint64_t sdk, uint64_t connection) {
    return dp_connection_is_valid(sdk, connection);
}
uint32_t capacity_channel_valid(uint64_t sdk, uint64_t connection, uint64_t channel) {
    return dp_channel_is_valid(sdk, connection, channel);
}
uint64_t capacity_pending_reads(uint64_t sdk) { return dp_test_pending_stream_reads(sdk); }

uint64_t capacity_resource_bytes(uint64_t sdk, uint32_t field) {
    return dp_test_ffi_resource_bytes(sdk, field);
}
