package io.peerloom.sdk

import android.content.Context
import java.nio.charset.StandardCharsets.UTF_8
import java.util.ArrayDeque
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject

class PeerloomException(val status: Int) : Exception("Peerloom status $status")

data class Completion(val status: Int, val payload: ByteArray, val channel: Channel? = null)

data class Event(
    val kind: Int,
    val connection: Connection?,
    val status: Int,
    val payload: ByteArray,
    val channel: Channel? = null,
)

class Operation
internal constructor(
    private val sdk: PeerloomSdk,
    val requestId: Long,
    val completion: CompletableFuture<Completion>,
) {
    /** Only queued work can be cancelled. Busy is not remote rollback. */
    fun cancelQueued(): Int = sdk.cancel(requestId)
}

class Connection internal constructor(private val sdk: PeerloomSdk, internal val handle: Long) {
    fun isValid(): Boolean = sdk.valid(handle)

    fun send(data: ByteArray): Operation = sdk.submit(4, handle, data)

    fun close(): Operation = sdk.submit(6, handle, byteArrayOf())

    fun openChannel(
        mode: ChannelMode,
        label: String,
        queue: MessageQueueOptions? = null,
    ): Operation {
        val input = JSONObject().put("mode", mode.wire).put("label", label)
        if (queue != null) input.put("queue", queue.json())
        return sdk.submit(8, handle, input.toString().toByteArray(UTF_8))
    }
}

/**
 * Bounded multiple connections and typed channels. Explicit asynchronous close is mandatory. No
 * finalizer blocks a UI thread. Do not block native callback completion continuations; use
 * CompletableFuture's asynchronous continuation methods with your own executor.
 */
class PeerloomSdk
private constructor(
    private val store: IdentityStorage,
    private val listener: (Event) -> Unit,
    private val applicationExecutor: Executor,
) {
    @Volatile private var handle: Long = 0
    private val operations = HashMap<Long, CompletableFuture<Completion>>()
    private val operationLock = Any()
    private val operationKinds = HashMap<Long, Int>()
    private val hostReads = AtomicInteger(0)
    private val channels = HashMap<Long, Channel>()
    private val closing = AtomicBoolean(false)
    private val released = CompletableFuture<Unit>()
    private val nativeReleased = AtomicBoolean(false)
    @Volatile private var shutdownStatus = 0
    private val events = ArrayDeque<Event>()
    private var scheduled = false
    private val eventLock = Any()

    companion object {
        private val work =
            ThreadPoolExecutor(
                2,
                4,
                30,
                TimeUnit.SECONDS,
                ArrayBlockingQueue(64),
                { task -> Thread(task, "peerloom-host-io").apply { isDaemon = true } },
                ThreadPoolExecutor.AbortPolicy(),
            )
        private val releasePoller =
            Executors.newSingleThreadScheduledExecutor { task ->
                Thread(task, "peerloom-release").apply { isDaemon = true }
            }

        /**
         * Configure origin/application_id; storage is always Android Keystore-backed external.
         * Omitted or zero max_connections/max_channels_per_connection/
         * max_channel_creations_per_connection removes the optional application count cap.
         * Positive values retain explicit caps; protocol limits and bounded queues still apply.
         * Caller-supplied executor receives at most one queued drain task; data queue is bounded32.
         */
        fun create(
            context: Context,
            config: JSONObject,
            applicationExecutor: Executor,
            listener: (Event) -> Unit,
        ): CompletableFuture<PeerloomSdk> =
            createInternal(context, config, applicationExecutor, null, listener)

        /** Explicit custom encrypted CAS store; no automatic plaintext/memory fallback. */
        fun createWithStore(
            context: Context,
            config: JSONObject,
            applicationExecutor: Executor,
            storage: IdentityStorage,
            listener: (Event) -> Unit,
        ): CompletableFuture<PeerloomSdk> =
            createInternal(context, config, applicationExecutor, storage, listener)

        private fun createInternal(
            context: Context,
            config: JSONObject,
            applicationExecutor: Executor,
            storage: IdentityStorage?,
            listener: (Event) -> Unit,
        ): CompletableFuture<PeerloomSdk> {
            val result = CompletableFuture<PeerloomSdk>()
            val application = context.applicationContext
            val encoded =
                JSONObject(config.toString())
                    .put("abi_version", 1)
                    .put("storage", "external")
                    .toString()
                    .toByteArray(UTF_8)
            try {
                work.execute {
                    try {
                        check(android.os.Looper.myLooper() != android.os.Looper.getMainLooper())
                        val initialized = Native.initialize(application)
                        if (initialized != 0) {
                            throw PeerloomException(initialized)
                        }
                        val sdk =
                            PeerloomSdk(
                                storage ?: IdentityStore(application),
                                listener,
                                applicationExecutor,
                            )
                        synchronized(sdk.operationLock) {
                            val created = Native.create(encoded, sdk)
                            if (created[0] != 0L) {
                                throw PeerloomException(created[0].toInt())
                            }
                            sdk.handle = created[1]
                        }
                        if (!result.complete(sdk)) {
                            sdk.close() // cancelled create still releases native ownership
                        }
                    } catch (failure: Throwable) {
                        result.completeExceptionally(failure)
                    }
                }
            } catch (failure: RejectedExecutionException) {
                result.completeExceptionally(failure)
            }
            return result
        }
    }

    fun start(): Operation = submit(1, 0, "{}".toByteArray(UTF_8))

    fun register(registration: JSONObject, idempotencyKey: String): Operation =
        submit(
            1,
            0,
            JSONObject()
                .put("registration", registration)
                .put("idempotency_key", idempotencyKey)
                .toString()
                .toByteArray(UTF_8),
        )

    fun connect(targetDeviceId: String): Operation =
        submit(
            2,
            0,
            JSONObject().put("target_device_id", targetDeviceId).toString().toByteArray(UTF_8),
        )

    fun respond(sessionId: String, accept: Boolean): Operation =
        submit(
            3,
            0,
            JSONObject()
                .put("session_id", sessionId)
                .put("accept", accept)
                .toString()
                .toByteArray(UTF_8),
        )

    fun refreshCredentials(): Operation = submit(5, 0, byteArrayOf())

    fun resetIdentity(expectedDeviceId: String, retry: Boolean = false): Operation =
        submit(
            7,
            0,
            JSONObject()
                .put("expected_device_id", expectedDeviceId)
                .put("retry", retry)
                .toString()
                .toByteArray(UTF_8),
        )

    internal fun submit(kind: Int, connection: Long, data: ByteArray): Operation {
        synchronized(operationLock) {
            if (closing.get() || handle == 0L) {
                throw PeerloomException(5)
            }
            val response = Native.submit(handle, kind, connection, data)
            if (response[0] != 0L) {
                throw PeerloomException(response[0].toInt())
            }
            val future = CompletableFuture<Completion>()
            operations[response[1]] = future
            operationKinds[response[1]] = kind
            return Operation(this, response[1], future)
        }
    }

    internal fun submitChannel(
        connection: Long,
        channel: Long,
        kind: Int,
        data: ByteArray,
    ): Operation {
        synchronized(operationLock) {
            if (closing.get() || handle == 0L) throw PeerloomException(5)
            val response = Native.channelSubmit(handle, connection, channel, kind, data)
            if (response[0] != 0L) throw PeerloomException(response[0].toInt())
            val future = CompletableFuture<Completion>()
            operations[response[1]] = future
            operationKinds[response[1]] = 63 + kind
            return Operation(this, response[1], future)
        }
    }

    internal fun validChannel(connection: Long, channel: Long): Boolean =
        !closing.get() && handle != 0L && Native.channelValid(handle, connection, channel) == 0

    internal fun readChannel(connection: Long, channel: Long, maxBytes: Int): ReadOperation {
        while (true) {
            val current = hostReads.get()
            if (current >= 32) throw PeerloomException(6)
            if (hostReads.compareAndSet(current, current + 1)) break
        }
        val operation =
            try {
                submitChannel(
                    connection,
                    channel,
                    2,
                    JSONObject().put("max_bytes", maxBytes).toString().toByteArray(UTF_8),
                )
            } catch (error: Throwable) {
                hostReads.decrementAndGet()
                throw error
            }
        val result = CompletableFuture<ByteArray>()
        operation.completion.whenComplete { completion, error ->
            try {
                applicationExecutor.execute {
                    try {
                        if (error != null) throw error
                        if (completion.status != 0) throw PeerloomException(completion.status)
                        if (!validChannel(connection, channel)) throw PeerloomException(5)
                        if (!result.complete(completion.payload)) completion.payload.fill(0)
                    } catch (failure: Throwable) {
                        completion?.payload?.fill(0)
                        result.completeExceptionally(failure)
                    } finally {
                        hostReads.decrementAndGet()
                        finishReleaseIfDrained()
                    }
                }
            } catch (failure: RejectedExecutionException) {
                completion?.payload?.fill(0)
                hostReads.decrementAndGet()
                result.completeExceptionally(failure)
                close()
                finishReleaseIfDrained()
            }
        }
        return ReadOperation(operation, result)
    }

    internal fun cancel(request: Long): Int = Native.cancel(handle, request)

    internal fun valid(connection: Long): Boolean =
        !closing.get() && handle != 0L && Native.connectionValid(handle, connection) == 0

    /**
     * Stops admission immediately, then completes only after the final native callback and release.
     * A blocked host callback can delay this indefinitely; no unsafe thread killing is attempted.
     */
    fun close(): CompletableFuture<Unit> {
        if (closing.compareAndSet(false, true)) {
            val status = Native.shutdown(handle)
            if (status != 0 && status != 5) {
                released.completeExceptionally(PeerloomException(status))
            }
            pollRelease()
        }
        return released
    }

    private fun pollRelease() {
        releasePoller.schedule(
            {
                val status = Native.release(handle)
                when (status) {
                    0 -> {
                        handle = 0
                        nativeReleased.set(true)
                        finishReleaseIfDrained()
                    }
                    11 -> pollRelease()
                    else -> released.completeExceptionally(PeerloomException(status))
                }
            },
            10,
            TimeUnit.MILLISECONDS,
        )
    }

    /** Called only on the serial native callback thread. JNI has already copied borrowed bytes. */
    @Suppress("unused")
    private fun onNativeEvent(
        nativeHandle: Long,
        kind: Int,
        request: Long,
        connection: Long,
        channel: Long,
        status: Int,
        payload: ByteArray,
    ) {
        synchronized(operationLock) {
            // Creation holds this lock until its handle is installed, including early runtime
            // failure.
            check(handle == nativeHandle)
        }
        when (kind) {
            1 -> {
                val (future, operationKind) =
                    synchronized(operationLock) {
                        Pair(operations.remove(request), operationKinds.remove(request))
                    }
                try {
                    val opened =
                        if (operationKind == 8 && status == 0 && channel != 0L) {
                            channel(connection, channel, payload).also {
                                synchronized(operationLock) { channels[channel] = it }
                            }
                        } else null
                    future?.complete(Completion(status, payload, opened))
                } catch (failure: Exception) {
                    future?.completeExceptionally(failure)
                    close()
                }
            }
            10 -> {
                val sdk = handle
                try {
                    work.execute {
                        var replyStatus = 0
                        val reply =
                            try {
                                store
                                    .execute(JSONObject(String(payload, UTF_8)))
                                    .toString()
                                    .toByteArray(UTF_8)
                            } catch (_: IdentityStore.Conflict) {
                                replyStatus = 11
                                byteArrayOf()
                            } catch (_: Exception) {
                                replyStatus = 255
                                byteArrayOf()
                            }
                        try {
                            Native.storageComplete(sdk, request, replyStatus, reply)
                        } finally {
                            payload.fill(0)
                            reply.fill(0)
                        }
                    }
                } catch (_: RejectedExecutionException) {
                    Native.storageComplete(sdk, request, 255, byteArrayOf())
                    payload.fill(0)
                }
            }
            9 -> {
                shutdownStatus = status
                deliver(Event(kind, null, status, payload))
                if (closing.compareAndSet(false, true)) {
                    pollRelease()
                }
            }
            else -> {
                val scopedChannel =
                    synchronized(operationLock) {
                        when (kind) {
                            12 ->
                                channel(connection, channel, payload).also {
                                    channels[channel] = it
                                }
                            13 -> channels.remove(channel)
                            14 -> channels[channel] ?: throw PeerloomException(8)
                            7 -> {
                                channels.entries.removeAll { it.value.parent == connection }
                                null
                            }
                            else -> null
                        }
                    }
                deliver(
                    Event(
                        kind,
                        if (connection == 0L) null else Connection(this, connection),
                        status,
                        payload,
                        scopedChannel,
                    )
                )
            }
        }
    }

    private fun deliver(event: Event) {
        synchronized(eventLock) {
            if (events.size >= 32) {
                close()
                return
            }
            events.addLast(event)
            if (scheduled) {
                return
            }
            scheduled = true
        }
        scheduleDrain()
    }

    private fun scheduleDrain() {
        try {
            applicationExecutor.execute { drainOne() }
        } catch (_: RejectedExecutionException) {
            synchronized(eventLock) {
                events.clear()
                scheduled = false
            }
            close()
            // Native release may already have finished while the first host task was paused.
            finishReleaseIfDrained()
        }
    }

    private fun drainOne() {
        val event =
            synchronized(eventLock) {
                if (events.isEmpty()) {
                    null
                } else {
                    events.removeFirst()
                }
            }
        if (
            event != null &&
                (when (event.kind) {
                    5,
                    6 -> event.connection?.isValid() == true
                    12,
                    14 -> event.channel?.isValid() == true
                    else -> true
                })
        ) {
            try {
                listener(event)
            } catch (_: Exception) {
                close()
            }
        }
        val again =
            synchronized(eventLock) {
                if (events.isEmpty()) {
                    scheduled = false
                    false
                } else {
                    true
                }
            }
        if (again) {
            scheduleDrain()
        } else {
            finishReleaseIfDrained()
        }
    }

    private fun finishReleaseIfDrained() {
        val done =
            synchronized(eventLock) {
                nativeReleased.get() && hostReads.get() == 0 && events.isEmpty() && !scheduled
            }
        if (done) {
            if (shutdownStatus == 0) {
                released.complete(Unit)
            } else {
                released.completeExceptionally(PeerloomException(shutdownStatus))
            }
        }
    }
}
