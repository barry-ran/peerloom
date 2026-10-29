package io.peerloom.sdk

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LifecycleTest {
    @Test
    fun twentyConcurrentInstancesReleaseAllNativeClients() {
        val executor = Executors.newSingleThreadExecutor()
        val clients = mutableListOf<PeerloomSdk>()
        val baseline = Native.liveClients()
        try {
            repeat(20) {
                val config =
                    JSONObject()
                        .put("origin", "http://127.0.0.1:1")
                        .put("application_id", UUID.randomUUID().toString())
                        .put("development_loopback", true)
                clients +=
                    PeerloomSdk.create(
                            ApplicationProvider.getApplicationContext(),
                            config,
                            executor,
                        ) {}
                        .get(20, TimeUnit.SECONDS)
            }
            assertEquals(baseline + 20, Native.liveClients())
        } finally {
            try {
                val closing = clients.map { it.close() }
                closing.forEach { it.get(20, TimeUnit.SECONDS) }
                assertEquals(baseline, Native.liveClients())
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test
    fun optionalCapacityAcceptsOmittedZeroAndFiveHundred() {
        assertNull(targetEpoch(JSONObject("{}")))
        assertEquals(
            "9223372036854775807",
            targetEpoch(
                JSONObject(
                    "{\"exclusive_target\":true,\"exclusive_protocol_version\":1,\"target_epoch\":\"9223372036854775807\"}"
                )
            ),
        )
        for (invalid in
            listOf(
                "{\"target_epoch\":\"1\"}",
                "{\"exclusive_target\":true,\"exclusive_protocol_version\":1.0,\"target_epoch\":\"1\"}",
                "{\"exclusive_target\":true,\"exclusive_protocol_version\":true,\"target_epoch\":\"1\"}",
                "{\"exclusive_target\":true,\"exclusive_protocol_version\":null,\"target_epoch\":\"1\"}",
                "{\"exclusive_target\":null}",
                "{\"exclusive_protocol_version\":null}",
                "{\"target_epoch\":null}",
                "{\"exclusive_target\":true,\"exclusive_protocol_version\":1,\"target_epoch\":null}",
                "{\"exclusive_target\":true,\"exclusive_protocol_version\":2,\"target_epoch\":\"1\"}",
                "{\"exclusive_target\":false,\"exclusive_protocol_version\":1,\"target_epoch\":\"1\"}",
                "{\"exclusive_target\":true,\"exclusive_protocol_version\":1,\"target_epoch\":1}",
            )) assertThrows(PeerloomException::class.java) { targetEpoch(JSONObject(invalid)) }

        val executor = Executors.newSingleThreadExecutor()
        try {
            for (count in listOf<Int?>(null, 0, 500)) {
                val config =
                    JSONObject()
                        .put("origin", "http://127.0.0.1:1")
                        .put("application_id", UUID.randomUUID().toString())
                        .put("development_loopback", true)
                if (count != null) {
                    config
                        .put("max_connections", count)
                        .put("max_channels_per_connection", count)
                        .put("max_channel_creations_per_connection", count)
                }
                val sdk =
                    PeerloomSdk.create(
                            ApplicationProvider.getApplicationContext(),
                            config,
                            executor,
                        ) {}
                        .get(20, TimeUnit.SECONDS)
                assertTrue(Native.capabilities() and 256L != 0L)
                assertEquals(
                    2,
                    sdk.connectPrepared(UUID.randomUUID().toString())
                        .completion
                        .get(20, TimeUnit.SECONDS)
                        .status,
                )
                sdk.close().get(20, TimeUnit.SECONDS)
            }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun pausedThenRejectingExecutorDoesNotStrandClose() {
        val first = java.util.concurrent.ArrayBlockingQueue<Runnable>(1)
        val accepted = java.util.concurrent.atomic.AtomicBoolean(false)
        val executor =
            java.util.concurrent.Executor { task ->
                if (!accepted.compareAndSet(false, true)) {
                    throw java.util.concurrent.RejectedExecutionException("test executor stopped")
                }
                first.add(task)
            }
        val sdk =
            PeerloomSdk.create(
                    ApplicationProvider.getApplicationContext(),
                    JSONObject()
                        .put("origin", "http://127.0.0.1:1")
                        .put("development_loopback", true)
                        .put("application_id", UUID.randomUUID().toString()),
                    executor,
                ) {}
                .get(20, TimeUnit.SECONDS)
        // Inject only host control events; native lifecycle/release still runs normally.
        val deliver = PeerloomSdk::class.java.getDeclaredMethod("deliver", Event::class.java)
        deliver.isAccessible = true
        repeat(2) { deliver.invoke(sdk, Event(9, null, 0, byteArrayOf())) }
        val close = sdk.close()
        val releasedField = PeerloomSdk::class.java.getDeclaredField("nativeReleased")
        releasedField.isAccessible = true
        val released = releasedField.get(sdk) as java.util.concurrent.atomic.AtomicBoolean
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (!released.get() && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue(released.get())
        assertEquals(0, Native.liveClients())
        assertFalse(close.isDone)
        first.poll(5, TimeUnit.SECONDS)!!.run()
        close.get(5, TimeUnit.SECONDS)
    }

    @Test
    fun hostCopyFailureCompletesPendingAndRejectsFurtherCopies() {
        val executor = Executors.newSingleThreadExecutor()
        val sdk =
            PeerloomSdk.create(
                    ApplicationProvider.getApplicationContext(),
                    PeerloomConfiguration(
                        "http://127.0.0.1:1",
                        UUID.randomUUID().toString(),
                        developmentLoopback = true,
                    ),
                    executor,
                ) {}
                .get(20, TimeUnit.SECONDS)
        try {
            // Test only the host correlation state; this is not a synthetic native success.
            fun field(name: String): Any {
                val value = PeerloomSdk::class.java.getDeclaredField(name)
                value.isAccessible = true
                return requireNotNull(value.get(sdk))
            }
            @Suppress("UNCHECKED_CAST")
            val operations =
                field("operations")
                    as MutableMap<Long, java.util.concurrent.CompletableFuture<Completion>>
            @Suppress("UNCHECKED_CAST") val kinds = field("operationKinds") as MutableMap<Long, Int>
            @Suppress("UNCHECKED_CAST")
            val reservations = field("operationReservations") as MutableMap<Long, HostBudget.Ticket>
            val budget = field("budget") as HostBudget
            val result = java.util.concurrent.CompletableFuture<Completion>()
            operations[999] = result
            kinds[999] = 4
            reservations[999] = budget.acquire(65536, false)
            val reserve =
                PeerloomSdk::class
                    .java
                    .getDeclaredMethod(
                        "reserveNativeEvent",
                        Int::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                    )
            reserve.isAccessible = true
            val callback =
                PeerloomSdk::class
                    .java
                    .getDeclaredMethod(
                        "onNativeEvent",
                        Long::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        ByteArray::class.java,
                    )
            callback.isAccessible = true
            val nativeHandle = field("handle") as Long
            // Host-only injection of verified native suppression paths, not a fabricated handshake.
            assertEquals(true, reserve.invoke(sdk, 7, 0L, 99L, 0L, 0L))
            callback.invoke(sdk, nativeHandle, 7, 0L, 99L, 0L, 0, byteArrayOf())
            val failedOpen = java.util.concurrent.CompletableFuture<Completion>()
            operations[1000] = failedOpen
            kinds[1000] = 8
            reservations[1000] = budget.acquire(65536, false)
            assertEquals(true, reserve.invoke(sdk, 1, 1000L, 99L, 88L, 0L))
            callback.invoke(sdk, nativeHandle, 1, 1000L, 99L, 88L, 5, byteArrayOf())
            assertEquals(5, failedOpen.get(5, TimeUnit.SECONDS).status)
            assertEquals(true, reserve.invoke(sdk, 13, 0L, 99L, 88L, 0L))
            callback.invoke(sdk, nativeHandle, 13, 0L, 99L, 88L, 0, byteArrayOf())
            assertTrue((field("activeConnections") as Set<*>).isEmpty())
            assertTrue((field("channels") as Map<*, *>).isEmpty())
            assertTrue((field("readingChannels") as Set<*>).isEmpty())
            assertFalse((field("closing") as java.util.concurrent.atomic.AtomicBoolean).get())
            assertEquals(2, sdk.start().completion.get(20, TimeUnit.SECONDS).status)
            assertEquals(true, reserve.invoke(sdk, 1, 999L, 0L, 0L, 65536L))
            assertEquals(false, reserve.invoke(sdk, 1, 999L, 0L, 0L, 65537L))
            val failed = PeerloomSdk::class.java.getDeclaredMethod("failedNativeDelivery")
            failed.isAccessible = true
            failed.invoke(sdk)
            failed.invoke(sdk)
            assertTrue(result.isCompletedExceptionally)
            assertEquals(false, reserve.invoke(sdk, 6, 0L, 0L, 0L, 1L))
            try {
                sdk.close().get(20, TimeUnit.SECONDS)
                fail("resource failure was hidden")
            } catch (failure: java.util.concurrent.ExecutionException) {
                assertEquals(6, (failure.cause as PeerloomException).status)
            }
            assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
        } finally {
            try {
                sdk.close().get(20, TimeUnit.SECONDS)
            } catch (_: java.util.concurrent.ExecutionException) {}
            executor.shutdownNow()
        }
    }

    @Test
    fun openCompletionErrorStillSettlesRemovedLocalFuture() {
        val executor = Executors.newSingleThreadExecutor()
        val sdk =
            PeerloomSdk.create(
                    ApplicationProvider.getApplicationContext(),
                    PeerloomConfiguration(
                        "http://127.0.0.1:1",
                        UUID.randomUUID().toString(),
                        developmentLoopback = true,
                    ),
                    executor,
                ) {}
                .get(20, TimeUnit.SECONDS)
        try {
            fun field(name: String): java.lang.reflect.Field =
                PeerloomSdk::class.java.getDeclaredField(name).apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val operations =
                field("operations").get(sdk)
                    as MutableMap<Long, java.util.concurrent.CompletableFuture<Completion>>
            @Suppress("UNCHECKED_CAST")
            val kinds = field("operationKinds").get(sdk) as MutableMap<Long, Int>
            @Suppress("UNCHECKED_CAST")
            val reservations =
                field("operationReservations").get(sdk) as MutableMap<Long, HostBudget.Ticket>
            val budget = field("budget").get(sdk) as HostBudget
            val result = java.util.concurrent.CompletableFuture<Completion>()
            operations[1001] = result
            kinds[1001] = 8
            reservations[1001] = budget.acquire(65536, false)
            // Deterministic host registration Error, not real VM memory exhaustion or native
            // success.
            field("channels")
                .set(
                    sdk,
                    object : HashMap<Long, Channel>() {
                        override fun put(key: Long, value: Channel): Channel? {
                            throw AssertionError("injected host registration failure")
                        }
                    },
                )
            val callback =
                PeerloomSdk::class
                    .java
                    .getDeclaredMethod(
                        "onNativeEvent",
                        Long::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        ByteArray::class.java,
                    )
            callback.isAccessible = true
            callback.invoke(
                sdk,
                field("handle").getLong(sdk),
                1,
                1001L,
                42L,
                88L,
                0,
                "{\"mode\":\"reliable_stream\",\"label\":\"fault\"}".toByteArray(),
            )
            try {
                result.get(5, TimeUnit.SECONDS)
                fail("accepted OPEN lost its terminal failure")
            } catch (failure: java.util.concurrent.ExecutionException) {
                assertTrue(failure.cause is AssertionError)
            }
            sdk.close().get(20, TimeUnit.SECONDS)
            assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
        } finally {
            try {
                sdk.close().get(20, TimeUnit.SECONDS)
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test
    fun closeWaitsForRunningHostStorageAfterNativeRelease() {
        assertCloseWaitsForHostStorage(false)
    }

    @Test
    fun closeWaitsForStorageReservationCleanup() {
        assertCloseWaitsForHostStorage(true)
    }

    private fun assertCloseWaitsForHostStorage(blockCleanup: Boolean) {
        val executor = Executors.newSingleThreadExecutor()
        val entered = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        val worker = java.util.concurrent.atomic.AtomicReference<Thread>()
        val sdk =
            PeerloomSdk.createWithStore(
                    ApplicationProvider.getApplicationContext(),
                    JSONObject()
                        .put("origin", "http://127.0.0.1:1")
                        .put("development_loopback", true)
                        .put("application_id", UUID.randomUUID().toString()),
                    executor,
                    IdentityStorage {
                        worker.set(Thread.currentThread())
                        entered.countDown()
                        check(resume.await(20, TimeUnit.SECONDS))
                        JSONObject("{}")
                    },
                ) {}
                .get(20, TimeUnit.SECONDS)
        fun field(name: String): Any =
            requireNotNull(
                PeerloomSdk::class
                    .java
                    .getDeclaredField(name)
                    .apply { isAccessible = true }
                    .get(sdk)
            )
        val budget = field("budget") as HostBudget
        val payload = "{\"op\":\"load\"}".toByteArray()
        val reservation = budget.acquire(payload.size.toLong(), true)
        try {
            // Host-only storage callback injection: no fabricated native CAS success or timeout.
            PeerloomSdk::class.java.getDeclaredField("copiedEventReservation").apply {
                isAccessible = true
                set(sdk, reservation)
            }
            val callback =
                PeerloomSdk::class
                    .java
                    .getDeclaredMethod(
                        "onNativeEvent",
                        Long::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Long::class.javaPrimitiveType,
                        Int::class.javaPrimitiveType,
                        ByteArray::class.java,
                    )
                    .apply { isAccessible = true }
            synchronized(reservation) {
                callback.invoke(sdk, field("handle") as Long, 10, 999L, 0L, 0L, 0, payload)
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                if (blockCleanup) {
                    resume.countDown()
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                    while (
                        worker.get().state != Thread.State.BLOCKED && System.nanoTime() < deadline
                    ) {
                        Thread.yield()
                    }
                    assertEquals(Thread.State.BLOCKED, worker.get().state)
                    assertTrue(payload.all { it == 0.toByte() })
                }
                val closing = sdk.close()
                val nativeReleased =
                    field("nativeReleased") as java.util.concurrent.atomic.AtomicBoolean
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
                while (!nativeReleased.get() && System.nanoTime() < deadline) {
                    Thread.sleep(10)
                }
                assertTrue(nativeReleased.get())
                executor.submit {}.get(5, TimeUnit.SECONDS)
                // Exercise the release predicate after native teardown and event delivery drained.
                PeerloomSdk::class.java.getDeclaredMethod("finishReleaseIfDrained").apply {
                    isAccessible = true
                    invoke(sdk)
                }
                assertFalse("host storage still owns its reservation", closing.isDone)
                assertTrue(budget.usage()[1] > 0L)
                resume.countDown()
            }
            sdk.close().get(20, TimeUnit.SECONDS)
            assertTrue(payload.all { it == 0.toByte() })
            assertEquals(listOf(0L, 0L, 0L, 0L), budget.usage())
        } finally {
            resume.countDown()
            try {
                sdk.close().get(20, TimeUnit.SECONDS)
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test
    fun nativeOwnershipCloseAndInvalidHandle() {
        val events = Executors.newSingleThreadExecutor()
        try {
            repeat(20) {
                val sdk =
                    PeerloomSdk.create(
                            ApplicationProvider.getApplicationContext(),
                            JSONObject()
                                .put("origin", "http://127.0.0.1:1")
                                .put("development_loopback", true)
                                .put("application_id", UUID.randomUUID().toString()),
                            events,
                        ) {}
                        .get(20, TimeUnit.SECONDS)
                assertEquals(2, sdk.start().completion.get(20, TimeUnit.SECONDS).status)
                sdk.close().get(20, TimeUnit.SECONDS)
                assertEquals(0, Native.liveClients())
                try {
                    sdk.start()
                    fail("released SDK accepted operation")
                } catch (expected: PeerloomException) {
                    assertEquals(5, expected.status)
                }
            }
            assertEquals(8, Native.connectionValid(Long.MAX_VALUE, 1))
            assertEquals(8, Native.release(Long.MAX_VALUE))
            assertEquals(8, Native.cancel(Long.MAX_VALUE, 1))
        } finally {
            events.shutdownNow()
        }
    }
}
