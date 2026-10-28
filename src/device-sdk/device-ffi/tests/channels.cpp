// MIT — Copyright (c) 2026 Peerloom contributors.
// Real three-device C ABI acceptance. Secret fixture input is never printed.
#include "device_sdk.h"
#include <array>
#include <algorithm>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

struct Completion {
    uint32_t status;
    uint64_t connection;
    uint64_t channel;
    std::vector<uint8_t> bytes;
};
struct Host {
    uint64_t sdk = 0;
    std::string config, snapshot, incoming;
    unsigned online = 0, shutdown = 0, default_messages = 0;
    std::map<std::string, uint64_t> connections, channels;
    std::map<uint64_t, Completion> completions;
    std::set<uint64_t> seen;
    std::map<uint64_t, std::vector<std::vector<uint8_t>>> messages;
};
static std::array<Host, 3> hosts;
static std::mutex mutex;
static std::condition_variable changed;
static const std::vector<uint8_t> binary{0, 255, 1, 0, 2, 3};
static std::string field(const std::string &json, const char *key) {
    const std::string prefix = std::string("\"") + key + "\":\"";
    const auto start = json.find(prefix);
    assert(start != std::string::npos);
    const auto value = start + prefix.size();
    const auto end = json.find('"', value);
    assert(end != std::string::npos);
    return json.substr(value, end - value);
}
static void callback(uint64_t context, const dp_event *event) noexcept {
    try {
        assert(context < hosts.size() && event && event->abi_version == 1);
        assert(event->struct_size >= sizeof(dp_event) && event->payload_len <= 65536);
        std::unique_lock<std::mutex> lock(mutex);
        auto &host = hosts[context];
        assert(!host.shutdown);
        std::vector<uint8_t> bytes;
        if (event->payload_len) bytes.assign(event->payload, event->payload + event->payload_len);
        const std::string json(bytes.begin(), bytes.end());
        switch (event->kind) {
        case DP_EVENT_STORAGE_REQUEST:
            assert(json.find("\"operation\":\"load\"") != std::string::npos);
            assert(dp_storage_complete(host.sdk, event->request_id, DP_OK,
                reinterpret_cast<const uint8_t *>(host.snapshot.data()), host.snapshot.size()) == DP_OK);
            break;
        case DP_EVENT_COMPLETE:
            assert(event->request_id && host.seen.insert(event->request_id).second);
            assert(host.completions.size() < 128);
            host.completions.emplace(event->request_id, Completion{event->status, event->connection, event->channel, std::move(bytes)});
            break;
        case DP_EVENT_ONLINE: ++host.online; break;
        case DP_EVENT_OFFLINE: break;
        case DP_EVENT_INCOMING: host.incoming = field(json, "session_id"); break;
        case DP_EVENT_CONNECTION_READY:
            assert(event->connection);
            host.connections[field(json, "peer_device_id")] = event->connection;
            break;
        case DP_EVENT_MESSAGE:
            assert(bytes == binary);
            ++host.default_messages;
            break;
        case DP_EVENT_CHANNEL_READY:
            assert(event->connection && event->channel);
            host.channels[field(json, "label")] = event->channel;
            break;
        case DP_EVENT_CHANNEL_MESSAGE:
            assert(bytes == binary);
            assert(host.messages[event->channel].size() < 32);
            host.messages[event->channel].push_back(std::move(bytes));
            break;
        case DP_EVENT_CHANNEL_CLOSED:
        case DP_EVENT_CONNECTION_CLOSED: break;
        case DP_EVENT_SHUTDOWN: assert(event->status == DP_OK); ++host.shutdown; break;
        default: assert(false && "unexpected native channel event");
        }
        changed.notify_all();
    } catch (...) { std::abort(); }
}
template<class Predicate> static void wait(Predicate predicate) {
    std::unique_lock<std::mutex> lock(mutex);
    assert(changed.wait_for(lock, std::chrono::seconds(45), predicate));
}
static Completion completion(Host &host, uint64_t request) {
    wait([&] { return host.completions.count(request) != 0; });
    std::lock_guard<std::mutex> lock(mutex);
    auto value = std::move(host.completions.at(request));
    host.completions.erase(request);
    assert(value.status == DP_OK);
    return value;
}
static uint64_t submit(Host &host, uint32_t kind, uint64_t connection, const std::string &input = {}) {
    uint64_t request = 0;
    assert(dp_sdk_submit(host.sdk, kind, connection, reinterpret_cast<const uint8_t *>(input.data()), input.size(), &request) == DP_OK && request);
    return request;
}
static uint64_t child(Host &host, uint64_t connection, uint64_t channel, uint32_t kind,
    const std::vector<uint8_t> &bytes = {}) {
    uint64_t request = 0;
    assert(dp_channel_submit(host.sdk, connection, channel, kind, bytes.data(), bytes.size(), &request) == DP_OK && request);
    return request;
}
static std::vector<uint8_t> text(const std::string &value) { return {value.begin(), value.end()}; }
static uint64_t open(Host &host, uint64_t connection, const char *mode, const char *label) {
    auto result = completion(host, submit(host, DP_OP_OPEN_CHANNEL, connection,
        std::string("{\"mode\":\"") + mode + "\",\"label\":\"" + label + "\"}"));
    assert(result.connection == connection && result.channel);
    assert(dp_channel_is_valid(host.sdk, connection, result.channel) == DP_OK);
    return result.channel;
}
static uint64_t incoming(Host &host, const char *label) {
    wait([&] { return host.channels.count(label) != 0; });
    std::lock_guard<std::mutex> lock(mutex);
    return host.channels.at(label);
}
static uint64_t read(Host &host, uint64_t connection, uint64_t channel, size_t bytes) {
    return child(host, connection, channel, DP_CHANNEL_READ, text("{\"max_bytes\":" + std::to_string(bytes) + "}"));
}
static size_t written(const Completion &value) {
    const std::string json(value.bytes.begin(), value.bytes.end());
    const auto start = json.find("\"written\":");
    assert(start != std::string::npos);
    return static_cast<size_t>(std::stoull(json.substr(start + 10)));
}
int main() {
    const char *path = std::getenv("TEST_C_CHANNEL_INPUT");
    assert(path);
    std::ifstream input(path);
    assert(input);
    for (auto &host : hosts) { assert(std::getline(input, host.config)); assert(std::getline(input, host.snapshot)); }
    std::array<std::string, 3> devices;
    for (auto &device : devices) assert(std::getline(input, device) && device.size() == 36);
    for (size_t i = 0; i < hosts.size(); ++i) {
        auto &host = hosts[i];
        assert(dp_sdk_create(reinterpret_cast<const uint8_t *>(host.config.data()), host.config.size(), callback, i, &host.sdk) == DP_OK);
        completion(host, submit(host, DP_OP_START, 0, "{}"));
        wait([&] { return host.online == 1; });
    }
    for (size_t i = 1; i < hosts.size(); ++i) {
        completion(hosts[0], submit(hosts[0], DP_OP_CONNECT, 0, "{\"target_device_id\":\"" + devices[i] + "\"}"));
        wait([&] { return !hosts[i].incoming.empty(); });
        std::string session;
        { std::lock_guard<std::mutex> lock(mutex); session = hosts[i].incoming; }
        completion(hosts[i], submit(hosts[i], DP_OP_RESPOND, 0, "{\"session_id\":\"" + session + "\",\"accept\":true}"));
        wait([&] { return hosts[0].connections.count(devices[i]) && hosts[i].connections.count(devices[0]); });
    }
    uint64_t a, b, other;
    { std::lock_guard<std::mutex> lock(mutex); a = hosts[0].connections.at(devices[1]); b = hosts[1].connections.at(devices[0]); other = hosts[0].connections.at(devices[2]); }
    assert(a != other);
    const auto reliable = open(hosts[0], a, "reliable_message", "reliable-a");
    const auto remote_reliable = incoming(hosts[1], "reliable-a");
    const auto low = open(hosts[0], a, "low_latency_message", "low-a");
    const auto remote_low = incoming(hosts[1], "low-a");
    const auto stream = open(hosts[0], a, "reliable_stream", "stream-a");
    const auto remote_stream = incoming(hosts[1], "stream-a");
    uint64_t rejected = 123;
    assert(dp_channel_submit(hosts[0].sdk, other, reliable, DP_CHANNEL_SEND, binary.data(), binary.size(), &rejected) == DP_INVALID_HANDLE && rejected == 0);
    assert(dp_channel_is_valid(hosts[1].sdk, a, reliable) == DP_INVALID_HANDLE);
    completion(hosts[0], child(hosts[0], a, reliable, DP_CHANNEL_SEND, binary));
    wait([&] { return hosts[1].messages[remote_reliable].size() == 1; });
    completion(hosts[1], child(hosts[1], b, remote_reliable, DP_CHANNEL_SEND, binary));
    wait([&] { return hosts[0].messages[reliable].size() == 1; });
    // Fixed workload, no retry-to-green: unreliable mode does not promise all packets arrive.
    for (unsigned i = 0; i < 8; ++i) completion(hosts[0], child(hosts[0], a, low, DP_CHANNEL_SEND, binary));
    wait([&] { return !hosts[1].messages[remote_low].empty(); });
    // A pending reverse read cannot block a forward write on the same byte stream.
    auto pending_reverse = read(hosts[0], a, stream, 64);
    assert(written(completion(hosts[0], child(hosts[0], a, stream, DP_CHANNEL_WRITE, binary))) == binary.size());
    assert(completion(hosts[1], read(hosts[1], b, remote_stream, 64)).bytes == binary);
    assert(written(completion(hosts[1], child(hosts[1], b, remote_stream, DP_CHANNEL_WRITE, binary))) == binary.size());
    assert(completion(hosts[0], pending_reverse).bytes == binary);
    std::vector<uint8_t> transfer(256 * 1024);
    for (size_t i = 0; i < transfer.size(); ++i) transfer[i] = static_cast<uint8_t>(i * 17);
    size_t offset = 0;
    while (offset < transfer.size()) {
        const auto end = (offset + 65536 < transfer.size()) ? offset + 65536 : transfer.size();
        const std::vector<uint8_t> chunk(transfer.begin() + static_cast<ptrdiff_t>(offset), transfer.begin() + static_cast<ptrdiff_t>(end));
        const auto n = written(completion(hosts[0], child(hosts[0], a, stream, DP_CHANNEL_WRITE, chunk)));
        assert(n > 0 && n <= chunk.size());
        size_t received = 0;
        while (received < n) {
            const auto data = completion(hosts[1], read(hosts[1], b, remote_stream, 4093)).bytes;
            assert(!data.empty() && data.size() <= n - received);
            assert(std::equal(data.begin(), data.end(), transfer.begin() + static_cast<ptrdiff_t>(offset + received)));
            received += data.size();
        }
        offset += n;
    }
    completion(hosts[0], child(hosts[0], a, stream, DP_CHANNEL_FINISH_WRITE));
    assert(completion(hosts[1], read(hosts[1], b, remote_stream, 64)).bytes.empty());
    assert(dp_channel_submit(hosts[0].sdk, a, stream, DP_CHANNEL_WRITE, binary.data(), binary.size(), &rejected) == DP_CLOSED && rejected == 0);
    assert(written(completion(hosts[1], child(hosts[1], b, remote_stream, DP_CHANNEL_WRITE, binary))) == binary.size());
    assert(completion(hosts[0], read(hosts[0], a, stream, 64)).bytes == binary);
    completion(hosts[1], child(hosts[1], b, remote_stream, DP_CHANNEL_FINISH_WRITE));
    assert(completion(hosts[0], read(hosts[0], a, stream, 64)).bytes.empty());
    const auto close_child = child(hosts[0], a, reliable, DP_CHANNEL_CLOSE);
    assert(dp_channel_is_valid(hosts[0].sdk, a, reliable) != DP_OK);
    completion(hosts[0], close_child);
    assert(dp_channel_is_valid(hosts[0].sdk, a, stream) == DP_OK);
    completion(hosts[0], submit(hosts[0], DP_OP_CLOSE_CONNECTION, a));
    assert(dp_channel_is_valid(hosts[0].sdk, a, stream) != DP_OK);
    assert(dp_connection_is_valid(hosts[0].sdk, other) == DP_OK);
    uint64_t request = 0;
    assert(dp_sdk_submit(hosts[0].sdk, DP_OP_SEND, other, binary.data(), binary.size(), &request) == DP_OK);
    completion(hosts[0], request);
    wait([&] { return hosts[2].default_messages == 1; });
    for (auto &host : hosts) { assert(dp_sdk_shutdown(host.sdk, &request) == DP_OK); }
    for (auto &host : hosts) {
        wait([&] { return host.shutdown == 1; });
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        uint32_t release_status;
        while ((release_status = dp_sdk_release(host.sdk)) == DP_BUSY) { assert(std::chrono::steady_clock::now() < deadline); }
        assert(release_status == DP_OK);
    }
    std::puts("C ABI three-device/two-connection typed messages + 256KiB stream/duplex/FIN + parent fencing PASS");
}
