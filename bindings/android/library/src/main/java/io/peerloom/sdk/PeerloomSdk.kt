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
import java.util.concurrent.atomic.AtomicLong
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
    private val budget: HostBudget,
) {
    @Volatile private var handle: Long = 0
    private val operations = HashMap<Long, CompletableFuture<Completion>>()
    private val operationLock = Any()
    private val finalReservation = budget.acquireLifecycle(0)
    private val emptyPayload = byteArrayOf()
    private val operationKinds = HashMap<Long, Int>()
    private var urgentReset: HostBudget.Ticket? = null
    private val operationReservations = HashMap<Long, HostBudget.Ticket>()
    private val readingChannels = HashSet<Long>()
    private val activeConnections = HashSet<Long>()
    private val connectionClosed = HashMap<Long, HostBudget.Ticket>()
    private val channelClosed = HashMap<Long, HostBudget.Ticket>()
    private val hostReads = AtomicLong(0)
    private val channels = HashMap<Long, Channel>()
    private val closing = AtomicBoolean(false)
    private val released = CompletableFuture<Unit>()
    private val nativeReleased = AtomicBoolean(false)
    @Volatile private var shutdownStatus = 0
    private val events = ArrayDeque<Event>()
    private var scheduled = false
    private val eventLock = Any()
    private val eventReservations = java.util.IdentityHashMap<Event, HostBudget.Ticket>()
    private var copiedEventReservation: HostBudget.Ticket? = null
    private val deliveryFailed = AtomicBoolean(false)

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
         * max_channel_creations_per_connection removes the optional application count cap. Positive
         * values retain explicit caps; protocol limits and bounded queues still apply.
         * Caller-supplied executor receives at most one drain task. Host-owned copies use an
         * independent byte budget; a stalled consumer can cause observable resource shutdown, not
         * silent reliable-data loss.
         */
        fun create(
            context: Context,
            config: JSONObject,
            applicationExecutor: Executor,
            listener: (Event) -> Unit,
        ): CompletableFuture<PeerloomSdk> =
            createInternal(context, config, applicationExecutor, null, listener)

        fun create(
            context: Context,
            config: PeerloomConfiguration,
            applicationExecutor: Executor,
            listener: (Event) -> Unit,
        ): CompletableFuture<PeerloomSdk> =
            create(context, config.json(), applicationExecutor, listener)

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
                                HostBudget(config.optLong("ffi_resource_budget_bytes", 134217728L)),
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
            if (kind == 7 && urgentReset != null) throw PeerloomException(11)
            val future = CompletableFuture<Completion>()
            val reservation =
                if (kind == 7) budget.acquireUrgentReset(data.size.toLong() + 256L)
                else
                    budget.acquire(
                        data.size.toLong() + if (kind in setOf(5, 6)) 256L else 65536L,
                        kind in setOf(5, 6),
                    )
            if (kind == 7) urgentReset = reservation
            val response =
                try {
                    Native.submit(handle, kind, connection, data)
                } catch (failure: Throwable) {
                    if (urgentReset === reservation) urgentReset = null
                    reservation.close()
                    throw failure
                }
            if (response[0] != 0L) {
                if (urgentReset === reservation) urgentReset = null
                reservation.close()
                throw PeerloomException(response[0].toInt())
            }
            try {
                operationReservations[response[1]] = reservation
                operations[response[1]] = future
                operationKinds[response[1]] = kind
                return Operation(this, response[1], future)
            } catch (failure: Throwable) {
                if (urgentReset === reservation) urgentReset = null
                operationReservations.remove(response[1])
                operations.remove(response[1])
                operationKinds.remove(response[1])
                reservation.close()
                future.completeExceptionally(PeerloomException(6))
                failOperations()
                throw failure
            }
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
            val future = CompletableFuture<Completion>()
            val reservation =
                budget.acquire(
                    data.size.toLong() + if (kind == 4 || kind == 5) 256L else 65536L,
                    kind == 4 || kind == 5,
                )
            val response =
                try {
                    Native.channelSubmit(handle, connection, channel, kind, data)
                } catch (failure: Throwable) {
                    if (urgentReset === reservation) urgentReset = null
                    reservation.close()
                    throw failure
                }
            if (response[0] != 0L) {
                if (urgentReset === reservation) urgentReset = null
                reservation.close()
                throw PeerloomException(response[0].toInt())
            }
            try {
                operationReservations[response[1]] = reservation
                operations[response[1]] = future
                operationKinds[response[1]] = 63 + kind
                return Operation(this, response[1], future)
            } catch (failure: Throwable) {
                if (urgentReset === reservation) urgentReset = null
                operationReservations.remove(response[1])
                operations.remove(response[1])
                operationKinds.remove(response[1])
                reservation.close()
                future.completeExceptionally(PeerloomException(6))
                failOperations()
                throw failure
            }
        }
    }

    internal fun validChannel(connection: Long, channel: Long): Boolean =
        !closing.get() && handle != 0L && Native.channelValid(handle, connection, channel) == 0

    internal fun readChannel(connection: Long, channel: Long, maxBytes: Int): ReadOperation {
        synchronized(operationLock) {
            if (!readingChannels.add(channel)) throw PeerloomException(11)
            hostReads.updateAndGet { Math.addExact(it, 1L) }
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
                synchronized(operationLock) { readingChannels.remove(channel) }
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
                        releaseRead(operation.requestId, channel)
                        finishReleaseIfDrained()
                    }
                }
            } catch (failure: RejectedExecutionException) {
                completion?.payload?.fill(0)
                releaseRead(operation.requestId, channel)
                result.completeExceptionally(failure)
                close()
                finishReleaseIfDrained()
            }
        }
        return ReadOperation(operation, result)
    }

    private fun updatePopulation() {
        activeConnections.forEach {
            if (!connectionClosed.containsKey(it)) connectionClosed[it] = budget.acquireLifecycle()
        }
        channels.keys.forEach {
            if (!channelClosed.containsKey(it)) channelClosed[it] = budget.acquireLifecycle()
        }
        budget.population(
            activeConnections.size.toLong(),
            channels.values.count { it.mode == ChannelMode.RELIABLE_STREAM }.toLong(),
        )
    }

    private fun releaseRead(request: Long, channel: Long) {
        synchronized(operationLock) {
            operationReservations.remove(request)?.close()
            readingChannels.remove(channel)
        }
        hostReads.decrementAndGet()
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

    /** JNI final path does not allocate/copy a payload or acquire a new credit. */
    @Suppress("unused")
    private fun onNativeFinal(status: Int) {
        if (!deliveryFailed.get()) shutdownStatus = status
        copiedEventReservation = finalReservation
        try {
            deliver(Event(9, null, shutdownStatus, emptyPayload))
        } finally {
            if (closing.compareAndSet(false, true)) pollRelease()
        }
    }

    /** JNI invokes this before allocating a Java copy, on its serial callback thread. */
    @Suppress("unused")
    private fun reserveNativeEvent(
        kind: Int,
        request: Long,
        connection: Long,
        channel: Long,
        length: Long,
    ): Boolean {
        if (length !in 0L..65536L || deliveryFailed.get()) return false
        return try {
            synchronized(operationLock) {
                if (kind == 1) {
                    operationReservations[request]?.permits(length) == true
                } else {
                    check(copiedEventReservation == null)
                    val lifecycle =
                        when {
                            kind == 7 && connection != 0L -> connectionClosed[connection]
                            kind == 13 -> channelClosed[channel]
                            else -> null
                        }
                    // Invalid births can be suppressed natively while Closed remains observable.
                    // Missing pre-ticket uses the same bounded lifecycle fallback, never a new
                    // handle.
                    if (lifecycle != null && !lifecycle.permits(length)) return false
                    copiedEventReservation =
                        lifecycle
                            ?: if (kind == 10) {
                                budget.acquire(length + 16384L, true)
                            } else {
                                if (kind in setOf(4, 5, 6, 12, 14)) budget.acquire(length, false)
                                else budget.acquireLifecycle(length)
                            }
                    true
                }
            }
        } catch (_: Throwable) {
            false
        }
    }

    /** No callback exception or copy failure may leave an accepted future pending forever. */
    @Suppress("unused")
    private fun failedNativeDelivery() {
        copiedEventReservation?.close()
        copiedEventReservation = null
        failOperations()
    }

    private fun failOperations() {
        if (deliveryFailed.compareAndSet(false, true)) {
            shutdownStatus = 6
            synchronized(operationLock) {
                while (operations.isNotEmpty()) {
                    val entry = operations.entries.iterator().next()
                    val id = entry.key
                    val future = entry.value
                    operations.remove(id)
                    if (urgentReset === operationReservations[id]) urgentReset = null
                    if (operationKinds.remove(id) != 65) operationReservations.remove(id)?.close()
                    future.completeExceptionally(PeerloomException(6))
                }
            }
            close()
        }
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
                        val kind = operationKinds.remove(request)
                        if (kind == 7 && urgentReset === operationReservations[request])
                            urgentReset = null
                        Pair(operations.remove(request), kind)
                    }
                try {
                    val opened =
                        if (operationKind == 8 && status == 0 && channel != 0L) {
                            channel(connection, channel, payload).also {
                                synchronized(operationLock) {
                                    channels[channel] = it
                                    updatePopulation()
                                }
                            }
                        } else null
                    future?.complete(Completion(status, payload, opened))
                } catch (failure: Throwable) {
                    future?.completeExceptionally(failure)
                    close()
                } finally {
                    if (operationKind != 65)
                        synchronized(operationLock) {
                            operationReservations.remove(request)?.close()
                        }
                }
            }
            10 -> {
                val storageReservation = copiedEventReservation
                copiedEventReservation = null
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
                            storageReservation?.close()
                        }
                    }
                } catch (_: RejectedExecutionException) {
                    Native.storageComplete(sdk, request, 255, byteArrayOf())
                    payload.fill(0)
                    storageReservation?.close()
                }
            }
            9 -> onNativeFinal(status)
            else -> {
                val scopedChannel =
                    synchronized(operationLock) {
                        when (kind) {
                            5 -> {
                                activeConnections.add(connection)
                                updatePopulation()
                                null
                            }
                            12 ->
                                channel(connection, channel, payload).also {
                                    channels[channel] = it
                                    updatePopulation()
                                }
                            13 -> channels[channel]
                            14 -> channels[channel] ?: throw PeerloomException(8)
                            7 -> {
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
            val reservation =
                copiedEventReservation
                    ?: try {
                        if (event.kind in setOf(4, 5, 6, 12, 14))
                            budget.acquire(event.payload.size.toLong(), false)
                        else budget.acquireLifecycle(event.payload.size.toLong())
                    } catch (_: Exception) {
                        failedNativeDelivery()
                        return
                    }
            copiedEventReservation = null
            try {
                eventReservations[event] = reservation
                events.addLast(event)
            } catch (failure: Throwable) {
                eventReservations.remove(event)
                reservation.close()
                failedNativeDelivery()
                return
            }
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
                eventReservations.values.forEach { it.close() }
                eventReservations.clear()
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
        if (event != null)
            synchronized(operationLock) {
                if (event.kind == 13)
                    event.channel?.let {
                        channels.remove(it.handle)
                        channelClosed.remove(it.handle)
                    }
                if (event.kind == 7)
                    event.connection?.let { parent ->
                        activeConnections.remove(parent.handle)
                        channels.entries.removeAll { it.value.parent == parent.handle }
                    }
                updatePopulation()
            }
        synchronized(eventLock) { if (event != null) eventReservations.remove(event)?.close() }
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
                nativeReleased.get() && hostReads.get() == 0L && events.isEmpty() && !scheduled
            }
        if (done) {
            synchronized(operationLock) {
                connectionClosed.values.forEach { it.close() }
                connectionClosed.clear()
                channelClosed.values.forEach { it.close() }
                channelClosed.clear()
                activeConnections.clear()
                channels.clear()
                finalReservation.close()
            }
            if (shutdownStatus == 0) {
                released.complete(Unit)
            } else {
                released.completeExceptionally(PeerloomException(shutdownStatus))
            }
        }
    }
}
