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
