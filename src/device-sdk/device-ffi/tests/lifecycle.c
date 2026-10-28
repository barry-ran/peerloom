#define _POSIX_C_SOURCE 200809L
#include "device_sdk.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

_Static_assert(sizeof(((dp_event *)0)->request_id) == 8, "request ABI");
_Static_assert(offsetof(dp_event, connection) == 16, "connection ABI");
_Static_assert(offsetof(dp_event, payload) == 32, "payload ABI");
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static uint64_t sdk, storage_id, terminal_id;
static uint64_t completed[32];
static unsigned completions, cancelled, shutdowns, reentrant_checks;
static int callback_blocked = 1;
static pthread_t callback_thread;
static int callback_seen;
static void callback(uint64_t context, const dp_event *event) {
    assert(context == 721);
    assert(event && event->abi_version == 1 && event->struct_size >= sizeof(dp_event));
    pthread_mutex_lock(&lock);
    if (callback_seen) assert(pthread_equal(callback_thread, pthread_self()));
    else { callback_seen = 1; callback_thread = pthread_self(); }
    assert(!shutdowns);
    if (event->kind == DP_EVENT_STORAGE_REQUEST) {
        storage_id = event->request_id;
        assert(event->payload_len && event->payload);
        pthread_cond_broadcast(&changed);
        while (callback_blocked) pthread_cond_wait(&changed, &lock);
    } else if (event->kind == DP_EVENT_COMPLETE) {
        assert(completions < 32);
        for (unsigned i = 0; i < completions; ++i) assert(completed[i] != event->request_id);
        completed[completions++] = event->request_id;
        if (event->status == DP_CANCELLED) ++cancelled;
    } else if (event->kind == DP_EVENT_SHUTDOWN) {
        assert(completions == 32);
        terminal_id = event->request_id;
        ++shutdowns;
    } else assert(!"unexpected lifecycle event");
    /* Reentry never joins this callback thread or blocks waiting for itself. */
    assert(dp_sdk_release(sdk) == DP_BUSY);
    ++reentrant_checks;
    pthread_cond_broadcast(&changed);
    pthread_mutex_unlock(&lock);
}
static void wait_storage(void) {
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until); until.tv_sec += 10;
    pthread_mutex_lock(&lock);
    while (!storage_id) assert(!pthread_cond_timedwait(&changed, &lock, &until));
    pthread_mutex_unlock(&lock);
}
int main(void) {
    const char config[] = "{\"abi_version\":1,\"origin\":\"http://127.0.0.1:1\",\"application_id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"storage\":\"external\",\"development_loopback\":true}";
    assert(dp_abi_version() == 1);
    assert(dp_capabilities() == 15);
    uint64_t bad = 99;
    assert(dp_sdk_create(NULL, 1, callback, 721, &bad) == DP_INVALID_ARGUMENT && bad == 0);
    assert(dp_sdk_create((const uint8_t *)config, sizeof(config)-1, callback, 721, &sdk) == DP_OK && sdk);
    assert(dp_sdk_release(sdk) == DP_BUSY);
    uint64_t first = 0, op = 0;
    assert(dp_sdk_submit(sdk, 99, 0, NULL, 0, &op) == DP_UNSUPPORTED && !op);
    assert(dp_sdk_submit(sdk, DP_OP_START, 0, NULL, 1, &op) == DP_INVALID_ARGUMENT && !op);
    assert(dp_sdk_submit(sdk, DP_OP_START, 0, (const uint8_t *)"x", 16385, &op) == DP_INVALID_ARGUMENT && !op);
    assert(dp_sdk_submit(sdk, DP_OP_START, 0, (const uint8_t *)"{}", 2, &first) == DP_OK);
    wait_storage();
    assert(dp_sdk_cancel(sdk, first) == DP_BUSY); /* running load is not fictitiously rolled back */
    for (unsigned i = 0; i < 31; ++i) {
        assert(dp_sdk_submit(sdk, DP_OP_CONNECT, 0, (const uint8_t *)"{}", 2, &op) == DP_OK);
        assert(dp_sdk_cancel(sdk, op) == DP_OK);
        assert(dp_sdk_cancel(sdk, op) == DP_OK);
    }
    assert(dp_sdk_submit(sdk, DP_OP_CONNECT, 0, NULL, 0, &op) == DP_BUFFER_FULL && !op);
    uint64_t shutdown_id;
    assert(dp_sdk_shutdown(sdk, &shutdown_id) == DP_OK && shutdown_id);
    assert(dp_sdk_submit(sdk, DP_OP_START, 0, NULL, 0, &op) == DP_CLOSED && !op);
    const char reply[] = "{\"revision\":0,\"identity\":null}";
    assert(dp_storage_complete(sdk + 99999, storage_id, DP_OK, (const uint8_t *)reply, sizeof(reply)-1) == DP_INVALID_HANDLE);
    assert(dp_storage_complete(sdk, storage_id, DP_OK, (const uint8_t *)reply, sizeof(reply)-1) == DP_OK);
    assert(dp_storage_complete(sdk, storage_id, DP_OK, (const uint8_t *)reply, sizeof(reply)-1) == DP_INVALID_HANDLE);
    assert(dp_sdk_release(sdk) == DP_BUSY); /* host callback remains deliberately stalled */
    pthread_mutex_lock(&lock); callback_blocked = 0; pthread_cond_broadcast(&changed);
    struct timespec until; clock_gettime(CLOCK_REALTIME, &until); until.tv_sec += 10;
    while (!shutdowns) assert(!pthread_cond_timedwait(&changed, &lock, &until));
    assert(terminal_id == shutdown_id && cancelled == 31 && reentrant_checks == 34);
    pthread_mutex_unlock(&lock);
    uint32_t released = DP_BUSY;
    for (unsigned i = 0; i < 10000 && released == DP_BUSY; ++i) {
        released = dp_sdk_release(sdk);
        if (released == DP_BUSY) { struct timespec pause = {0,1000000}; nanosleep(&pause,NULL); }
    }
    assert(released == DP_OK);
    assert(dp_sdk_release(sdk) == DP_INVALID_HANDLE);
    assert(dp_sdk_state(sdk) == 3);
    assert(dp_sdk_submit(sdk, DP_OP_START, 0, NULL, 0, &op) == DP_INVALID_HANDLE && !op);
    puts("C ABI lifecycle: 32 exactly-once completions, queued cancellation, async storage, stalled callback, reentry and safe release PASS");
    return 0;
}
