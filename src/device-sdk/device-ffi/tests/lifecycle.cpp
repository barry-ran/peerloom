// MIT. Portable C++17 ABI lifecycle probe: native Windows/MSVC and native Linux.
#include "device_sdk.h"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#define CHECK(expression) do { if (!(expression)) { std::fprintf(stderr, "ABI assertion failed at line %d: %s\n", __LINE__, #expression); std::abort(); } } while (false)
static_assert(sizeof(((dp_event *)nullptr)->request_id) == 8, "request ABI");
static_assert(offsetof(dp_event, connection) == 16, "connection ABI");
static_assert(offsetof(dp_event, payload) == 32, "payload ABI");
namespace {
std::mutex mutex;
std::condition_variable changed;
std::atomic<std::uint64_t> sdk{0};
std::array<std::uint64_t, 32> accepted{};
std::array<std::uint64_t, 32> completed{};
std::size_t admissions = 0, completions = 0, cancelled = 0, shutdowns = 0, reentrant_checks = 0;
std::uint64_t storage_id = 0, terminal_id = 0;
bool callback_blocked = true, callback_seen = false;
std::thread::id callback_thread;
void record(std::uint64_t id) {
    std::lock_guard<std::mutex> guard(mutex);
    CHECK(id != 0 && admissions < accepted.size());
    for (std::size_t i = 0; i < admissions; ++i) CHECK(accepted[i] != id);
    accepted[admissions++] = id;
}
void callback(std::uint64_t context, const dp_event *event) noexcept {
    CHECK(context == 721 && event != nullptr);
    CHECK(event->abi_version == 1 && event->struct_size >= sizeof(dp_event));
    std::unique_lock<std::mutex> guard(mutex);
    if (callback_seen) CHECK(callback_thread == std::this_thread::get_id());
    else { callback_seen = true; callback_thread = std::this_thread::get_id(); }
    CHECK(shutdowns == 0);
    if (event->kind == DP_EVENT_STORAGE_REQUEST) {
        CHECK(storage_id == 0 && event->payload != nullptr && event->payload_len != 0);
        storage_id = event->request_id;
        changed.notify_all();
        changed.wait(guard, [] { return !callback_blocked; });
    } else if (event->kind == DP_EVENT_COMPLETE) {
        CHECK(completions < completed.size());
        bool admitted = false;
        for (std::size_t i = 0; i < admissions; ++i) admitted = admitted || accepted[i] == event->request_id;
        CHECK(admitted);
        for (std::size_t i = 0; i < completions; ++i) CHECK(completed[i] != event->request_id);
        completed[completions++] = event->request_id;
        if (event->status == DP_CANCELLED) ++cancelled;
    } else if (event->kind == DP_EVENT_SHUTDOWN) {
        CHECK(admissions == 32 && completions == admissions);
        terminal_id = event->request_id;
        ++shutdowns;
    } else { CHECK(false); }
    // Reentry must never join this callback thread or wait synchronously on itself.
    CHECK(dp_sdk_release(sdk.load()) == DP_BUSY);
    ++reentrant_checks;
    changed.notify_all();
}
std::uint64_t wait_storage() {
    std::unique_lock<std::mutex> guard(mutex);
    CHECK(changed.wait_for(guard, std::chrono::seconds(10), [] { return storage_id != 0; }));
    return storage_id;
}
} // namespace
int main() {
    char config[] = "{\"abi_version\":1,\"origin\":\"http://127.0.0.1:1\",\"application_id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"storage\":\"external\",\"development_loopback\":true}";
    CHECK(dp_abi_version() == 1 && dp_capabilities() == 255);
    std::uint64_t handle = 99;
    CHECK(dp_sdk_create(nullptr, 1, callback, 721, &handle) == DP_INVALID_ARGUMENT && handle == 0);
    CHECK(dp_sdk_create(reinterpret_cast<const std::uint8_t *>(config), sizeof(config) - 1, callback, 721, &handle) == DP_OK && handle != 0);
    sdk.store(handle);
    std::memset(config, 'x', sizeof(config)); // caller input need not remain valid
    CHECK(dp_sdk_release(handle) == DP_BUSY);
    std::uint64_t first = 0, operation = 0;
    CHECK(dp_sdk_submit(handle, 99, 0, nullptr, 0, &operation) == DP_UNSUPPORTED && operation == 0);
    CHECK(dp_sdk_submit(handle, DP_OP_START, 0, nullptr, 1, &operation) == DP_INVALID_ARGUMENT && operation == 0);
    const auto input = reinterpret_cast<const std::uint8_t *>("{}");
    CHECK(dp_sdk_submit(handle, DP_OP_START, 0, input, 16385, &operation) == DP_INVALID_ARGUMENT && operation == 0);
    CHECK(dp_sdk_submit(handle, DP_OP_START, 0, input, 2, &first) == DP_OK); record(first);
    const auto storage = wait_storage();
    CHECK(dp_sdk_cancel(handle, first) == DP_BUSY);
    for (unsigned i = 0; i < 31; ++i) {
        CHECK(dp_sdk_submit(handle, DP_OP_CONNECT, 0, input, 2, &operation) == DP_OK); record(operation);
        CHECK(dp_sdk_cancel(handle, operation) == DP_OK);
        CHECK(dp_sdk_cancel(handle, operation) == DP_OK);
    }
    CHECK(dp_sdk_submit(handle, DP_OP_CONNECT, 0, nullptr, 0, &operation) == DP_BUFFER_FULL && operation == 0);
    std::uint64_t shutdown_id = 0;
    CHECK(dp_sdk_shutdown(handle, &shutdown_id) == DP_OK && shutdown_id != 0);
    CHECK(dp_sdk_submit(handle, DP_OP_START, 0, nullptr, 0, &operation) == DP_CLOSED && operation == 0);
    const char reply[] = "{\"revision\":0,\"identity\":null}";
    const auto response = reinterpret_cast<const std::uint8_t *>(reply);
    CHECK(dp_storage_complete(handle + 99999, storage, DP_OK, response, sizeof(reply) - 1) == DP_INVALID_HANDLE);
    CHECK(dp_storage_complete(handle, storage, DP_OK, response, sizeof(reply) - 1) == DP_OK);
    CHECK(dp_storage_complete(handle, storage, DP_OK, response, sizeof(reply) - 1) == DP_INVALID_HANDLE);
    CHECK(dp_sdk_release(handle) == DP_BUSY); // callback deliberately remains blocked
    {
        std::unique_lock<std::mutex> guard(mutex);
        callback_blocked = false; changed.notify_all();
        CHECK(changed.wait_for(guard, std::chrono::seconds(10), [] { return shutdowns == 1; }));
        CHECK(terminal_id == shutdown_id && cancelled == 31 && reentrant_checks == 34);
    }
    auto released = DP_BUSY;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (released == DP_BUSY && std::chrono::steady_clock::now() < deadline) {
        released = dp_sdk_release(handle);
        if (released == DP_BUSY) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(released == DP_OK);
    CHECK(dp_sdk_release(handle) == DP_INVALID_HANDLE);
    CHECK(dp_sdk_state(handle) == 3);
    CHECK(dp_sdk_submit(handle, DP_OP_START, 0, nullptr, 0, &operation) == DP_INVALID_HANDLE && operation == 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    { std::lock_guard<std::mutex> guard(mutex); CHECK(shutdowns == 1 && completions == 32 && reentrant_checks == 34); }
    std::puts("C++17 native ABI: accepted IDs, 32 exactly-once completions, cancellation, async storage, callback backpressure, reentry and quiescent release PASS");
}
