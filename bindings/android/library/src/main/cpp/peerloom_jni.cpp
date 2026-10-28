// Copyright (c) 2026 Peerloom contributors. SPDX-License-Identifier: MIT
#include "device_sdk.h"
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <jni.h>
#include <memory>
#include <mutex>
#include <vector>

namespace {
JavaVM *vm = nullptr;
struct Client {
    jobject receiver = nullptr;
    jmethodID method = nullptr;
    uint64_t context = 0;
    std::atomic<uint64_t> sdk{0};
    std::mutex ready_mutex;
    std::condition_variable ready;
};
std::mutex clients_mutex;
std::array<std::shared_ptr<Client>, 16> clients;
uint64_t next_context = 1;
std::shared_ptr<Client> by_context(uint64_t id) {
    std::lock_guard<std::mutex> guard(clients_mutex);
    for (const auto &client : clients) {
        if (client && client->context == id) {
            return client;
        }
    }
    return {};
}
std::shared_ptr<Client> by_sdk(uint64_t id) {
    std::lock_guard<std::mutex> guard(clients_mutex);
    for (const auto &client : clients) {
        if (client && client->sdk.load() == id && id) {
            return client;
        }
    }
    return {};
}
void forget(const std::shared_ptr<Client> &client, JNIEnv *env) {
    {
        std::lock_guard<std::mutex> guard(clients_mutex);
        for (auto &slot : clients) {
            if (slot == client) {
                slot.reset();
            }
        }
    }
    if (client->receiver) {
        env->DeleteGlobalRef(client->receiver);
        client->receiver = nullptr;
    }
}
class Attachment {
  public:
    JNIEnv *env = nullptr;
    bool attached = false;
    Attachment() {
        if (!vm) {
            return;
        }
        const jint status = vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
#ifdef __ANDROID__
            attached = vm->AttachCurrentThread(&env, nullptr) == JNI_OK;
#else
            attached = vm->AttachCurrentThread(reinterpret_cast<void **>(&env), nullptr) == JNI_OK;
#endif
            if (!attached) {
                env = nullptr;
            }
        } else if (status != JNI_OK) {
            env = nullptr;
        }
    }
    ~Attachment() {
        if (attached) {
            vm->DetachCurrentThread();
        }
    }
    Attachment(const Attachment &) = delete;
    Attachment &operator=(const Attachment &) = delete;
};
bool clear_exception(JNIEnv *env) {
    if (!env->ExceptionCheck()) {
        return false;
    }
    // Do not ExceptionDescribe: application exception text can contain credentials.
    env->ExceptionClear();
    return true;
}
void stop(const std::shared_ptr<Client> &client) {
    uint64_t id = 0;
    dp_sdk_shutdown(client->sdk.load(), &id);
}
void callback(uint64_t context, const dp_event *event) noexcept {
    auto client = by_context(context);
    if (!client) {
        return;
    }
    try {
        {
            std::unique_lock<std::mutex> lock(client->ready_mutex);
            client->ready.wait(lock, [&client] { return client->sdk.load() != 0; });
        }
        Attachment attachment;
        JNIEnv *env = attachment.env;
        if (!env || !event || event->abi_version != 1 || event->struct_size < sizeof(dp_event) ||
            event->payload_len > 65536) {
            stop(client);
            return;
        }
        if (env->PushLocalFrame(8) != JNI_OK) {
            clear_exception(env);
            stop(client);
            return;
        }
        jbyteArray payload = env->NewByteArray(static_cast<jsize>(event->payload_len));
        if (payload && event->payload_len) {
            env->SetByteArrayRegion(payload, 0, static_cast<jsize>(event->payload_len),
                                    reinterpret_cast<const jbyte *>(event->payload));
        }
        const bool allocation_failed = clear_exception(env);
        if (!payload || allocation_failed) {
            env->PopLocalFrame(nullptr);
            stop(client);
            return;
        }
        env->CallVoidMethod(
            client->receiver, client->method, static_cast<jlong>(client->sdk.load()),
            static_cast<jint>(event->kind), static_cast<jlong>(event->request_id),
            static_cast<jlong>(event->connection), static_cast<jlong>(event->channel), static_cast<jint>(event->status), payload);
        const bool failed = clear_exception(env);
        env->PopLocalFrame(nullptr);
        if (failed) {
            stop(client);
        }
    } catch (...) {
        stop(client);
    }
}
bool bytes(JNIEnv *env, jbyteArray input, size_t limit, std::vector<uint8_t> &output) {
    if (!input) {
        return false;
    }
    const jsize length = env->GetArrayLength(input);
    if (clear_exception(env) || length < 0 || static_cast<size_t>(length) > limit) {
        return false;
    }
    output.resize(static_cast<size_t>(length));
    if (length) {
        env->GetByteArrayRegion(input, 0, length, reinterpret_cast<jbyte *>(output.data()));
    }
    return !clear_exception(env);
}
jlongArray result(JNIEnv *env, jlongArray array, uint32_t status, uint64_t id) {
    const jlong values[] = {static_cast<jlong>(status), static_cast<jlong>(id)};
    env->SetLongArrayRegion(array, 0, 2, values);
    return array;
}
} // namespace
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *java_vm, void *) {
    vm = java_vm;
    return JNI_VERSION_1_6;
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_initialize(JNIEnv *env, jclass,
                                                                         jobject application) {
    if (!application) {
        return DP_INVALID_ARGUMENT;
    }
#ifdef __ANDROID__
    const uint32_t status = dp_android_tls_initialize(env, application);
    if (clear_exception(env)) {
        return DP_INTERNAL;
    }
    return static_cast<jint>(status);
#else
    (void)env;
    return DP_UNSUPPORTED;
#endif
}
extern "C" JNIEXPORT jlongArray JNICALL Java_io_peerloom_sdk_Native_create(JNIEnv *env, jclass,
                                                                           jbyteArray config,
                                                                           jobject receiver) {
    jlongArray output = env->NewLongArray(2);
    if (!output) {
        return nullptr;
    }
    std::shared_ptr<Client> client;
    try {
        std::vector<uint8_t> input;
        if (!receiver || !bytes(env, config, 16384, input)) {
            return result(env, output, DP_INVALID_ARGUMENT, 0);
        }
        client = std::make_shared<Client>();
        client->receiver = env->NewGlobalRef(receiver);
        bool failed = clear_exception(env);
        if (!client->receiver || failed) {
            forget(client, env);
            return result(env, output, DP_INTERNAL, 0);
        }
        jclass type = env->GetObjectClass(receiver);
        failed = clear_exception(env);
        if (!type || failed) {
            forget(client, env);
            return result(env, output, DP_INTERNAL, 0);
        }
        client->method = env->GetMethodID(type, "onNativeEvent", "(JIJJJI[B)V");
        failed = clear_exception(env);
        env->DeleteLocalRef(type);
        if (!client->method || failed) {
            forget(client, env);
            return result(env, output, DP_INTERNAL, 0);
        }
        bool reserved = false;
        {
            std::lock_guard<std::mutex> guard(clients_mutex);
            if (next_context != UINT64_MAX) {
                for (auto &slot : clients) {
                    if (!slot) {
                        client->context = next_context++;
                        slot = client;
                        reserved = true;
                        break;
                    }
                }
            }
        }
        if (!reserved) {
            forget(client, env);
            return result(env, output, DP_BUFFER_FULL, 0);
        }
        uint64_t sdk = 0;
        const uint32_t status =
            dp_sdk_create(input.data(), input.size(), callback, client->context, &sdk);
        if (status != DP_OK) {
            forget(client, env);
            return result(env, output, status, 0);
        }
        {
            std::lock_guard<std::mutex> lock(client->ready_mutex);
            client->sdk.store(sdk);
        }
        client->ready.notify_all();
        return result(env, output, DP_OK, sdk);
    } catch (...) {
        if (client && !client->sdk.load()) {
            forget(client, env);
        }
        return result(env, output, DP_INTERNAL, 0);
    }
}
extern "C" JNIEXPORT jlongArray JNICALL Java_io_peerloom_sdk_Native_submit(
    JNIEnv *env, jclass, jlong sdk, jint operation, jlong connection, jbyteArray data) {
    jlongArray output = env->NewLongArray(2);
    if (!output) {
        return nullptr;
    }
    try {
        std::vector<uint8_t> input;
        if (!bytes(env, data, operation == DP_OP_SEND ? 65536 : 16384, input)) {
            return result(env, output, DP_INVALID_ARGUMENT, 0);
        }
        uint64_t request = 0;
        const uint32_t status =
            dp_sdk_submit(static_cast<uint64_t>(sdk), static_cast<uint32_t>(operation),
                          static_cast<uint64_t>(connection), input.data(), input.size(), &request);
        return result(env, output, status, request);
    } catch (...) {
        return result(env, output, DP_INTERNAL, 0);
    }
}
extern "C" JNIEXPORT jlongArray JNICALL Java_io_peerloom_sdk_Native_channelSubmit(
    JNIEnv *env, jclass, jlong sdk, jlong connection, jlong channel, jint operation, jbyteArray data) {
    jlongArray output = env->NewLongArray(2);
    if (!output) { return nullptr; }
    try {
        std::vector<uint8_t> input;
        if (!bytes(env, data, 65536, input)) { return result(env, output, DP_INVALID_ARGUMENT, 0); }
        uint64_t request = 0;
        const uint32_t status = dp_channel_submit(static_cast<uint64_t>(sdk), static_cast<uint64_t>(connection),
            static_cast<uint64_t>(channel), static_cast<uint32_t>(operation), input.data(), input.size(), &request);
        return result(env, output, status, request);
    } catch (...) { return result(env, output, DP_INTERNAL, 0); }
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_channelValid(
    JNIEnv *, jclass, jlong sdk, jlong connection, jlong channel) {
    return static_cast<jint>(dp_channel_is_valid(static_cast<uint64_t>(sdk), static_cast<uint64_t>(connection), static_cast<uint64_t>(channel)));
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_cancel(JNIEnv *, jclass, jlong sdk,
                                                                     jlong request) {
    return static_cast<jint>(
        dp_sdk_cancel(static_cast<uint64_t>(sdk), static_cast<uint64_t>(request)));
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_storageComplete(
    JNIEnv *env, jclass, jlong sdk, jlong request, jint status, jbyteArray data) {
    try {
        std::vector<uint8_t> input;
        if (!bytes(env, data, 16384, input)) {
            return DP_INVALID_ARGUMENT;
        }
        return static_cast<jint>(
            dp_storage_complete(static_cast<uint64_t>(sdk), static_cast<uint64_t>(request),
                                static_cast<uint32_t>(status), input.data(), input.size()));
    } catch (...) {
        return DP_INTERNAL;
    }
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_shutdown(JNIEnv *, jclass,
                                                                       jlong sdk) {
    uint64_t id = 0;
    return static_cast<jint>(dp_sdk_shutdown(static_cast<uint64_t>(sdk), &id));
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_release(JNIEnv *env, jclass,
                                                                      jlong sdk) {
    auto client = by_sdk(static_cast<uint64_t>(sdk));
    if (!client) {
        return DP_INVALID_HANDLE;
    }
    const uint32_t status = dp_sdk_release(static_cast<uint64_t>(sdk));
    if (status == DP_OK) {
        forget(client, env);
    }
    return static_cast<jint>(status);
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_connectionValid(JNIEnv *, jclass,
                                                                              jlong sdk,
                                                                              jlong connection) {
    return static_cast<jint>(
        dp_connection_is_valid(static_cast<uint64_t>(sdk), static_cast<uint64_t>(connection)));
}
extern "C" JNIEXPORT jint JNICALL Java_io_peerloom_sdk_Native_liveClients(JNIEnv *, jclass) {
    std::lock_guard<std::mutex> guard(clients_mutex);
    jint count = 0;
    for (const auto &client : clients) {
        if (client) {
            ++count;
        }
    }
    return count;
}
