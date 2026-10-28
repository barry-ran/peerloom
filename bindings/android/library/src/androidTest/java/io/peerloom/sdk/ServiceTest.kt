package io.peerloom.sdk

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

private const val ORIGIN = "http://127.0.0.1:18080"

private fun config(device: JSONObject) =
    JSONObject()
        .put("origin", ORIGIN)
        .put("development_loopback", true)
        .put("application_id", device.getString("application_id"))

private fun fixture(name: String): JSONObject {
    val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    return JSONObject(context.noBackupFilesDir.resolve(name).readText())
}

private fun next(queue: ArrayBlockingQueue<Event>, kind: Int): Event {
    val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
    while (System.nanoTime() < end) {
        val event = queue.poll(1, TimeUnit.SECONDS) ?: continue
        if (event.kind == kind) {
            return event
        }
        check(event.kind !in listOf(8, 11)) { "unexpected terminal SDK event" }
    }
    error("event deadline kind=$kind")
}

private fun await(operation: Operation): Completion =
    operation.completion.get(30, TimeUnit.SECONDS).also { assertEquals(0, it.status) }

private class PausingExecutor : Executor, AutoCloseable {
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var pause: CountDownLatch? = null
    @Volatile var blocked = CountDownLatch(1)

    override fun execute(command: Runnable) {
        worker.execute {
            pause?.let {
                blocked.countDown()
                check(it.await(20, TimeUnit.SECONDS))
            }
            command.run()
        }
    }

    fun pause() {
        worker.submit {}.get(10, TimeUnit.SECONDS)
        blocked = CountDownLatch(1)
        pause = CountDownLatch(1)
    }

    fun resume() {
        val latch = pause
        pause = null
        latch?.countDown()
    }

    override fun close() {
        resume()
        worker.shutdownNow()
    }
}

@RunWith(AndroidJUnit4::class)
class RegistrationTest {
    @Test
    fun registerPersistAndReload() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val initial = fixture("registration-fixture.json")
        val events = Executors.newSingleThreadExecutor()
        try {
            val sdk =
                PeerloomSdk.create(context, config(initial), events) {}.get(20, TimeUnit.SECONDS)
            val id =
                try {
                    val registration =
                        JSONObject()
                            .put("platform", "android")
                            .put("installation_public_key", "android-disposable-installation")
                            .put("registration_grant", initial.getString("registration_grant"))
                            .put("sdk_version", "0.1.0")
                            .put("metadata", JSONObject())
                    JSONObject(
                            String(
                                await(sdk.register(registration, UUID.randomUUID().toString()))
                                    .payload,
                                Charsets.UTF_8,
                            )
                        )
                        .getString("device_id")
                } finally {
                    sdk.close().get(30, TimeUnit.SECONDS)
                }
            val loaded =
                PeerloomSdk.create(context, config(initial), events) {}.get(20, TimeUnit.SECONDS)
            try {
                assertEquals(
                    id,
                    JSONObject(String(await(loaded.start()).payload, Charsets.UTF_8))
                        .getString("device_id"),
                )
            } finally {
                loaded.close().get(30, TimeUnit.SECONDS)
            }
        } finally {
            events.shutdownNow()
        }
    }
}

@RunWith(AndroidJUnit4::class)
class ServiceTest {
    @Test
    fun authorizedDataRotationAndQueuedDeliveryRevocation() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val pair = fixture("pair-fixture.json")
        val source = pair.getJSONObject("source")
        val target = pair.getJSONObject("target")
        val store = IdentityStore(context)
        for (device in listOf(source, target)) {
            store.execute(
                JSONObject()
                    .put("operation", "save")
                    .put("expected_revision", 0)
                    .put(
                        "scope",
                        JSONObject()
                            .put("server_origin", "$ORIGIN/")
                            .put("application_id", device.getString("application_id")),
                    )
                    .put(
                        "identity",
                        JSONObject()
                            .put("device_id", device.getString("device_id"))
                            .put("device_credential", device.getString("device_credential"))
                            .put("expires_at", device.getString("expires_at")),
                    )
            )
        }
        val sourceQueue = ArrayBlockingQueue<Event>(32)
        val targetQueue = ArrayBlockingQueue<Event>(32)
        val sourceExecutor = Executors.newSingleThreadExecutor()
        PausingExecutor().use { targetExecutor ->
            val a =
                PeerloomSdk.create(context, config(source), sourceExecutor) {
                        check(sourceQueue.offer(it))
                    }
                    .get(20, TimeUnit.SECONDS)
            val b =
                PeerloomSdk.create(context, config(target), targetExecutor) {
                        check(targetQueue.offer(it))
                    }
                    .get(20, TimeUnit.SECONDS)
            try {
                await(a.start())
                await(b.start())
                next(sourceQueue, 2)
                next(targetQueue, 2)
                await(a.connect(target.getString("device_id")))
                val incoming = JSONObject(String(next(targetQueue, 4).payload, Charsets.UTF_8))
                await(b.respond(incoming.getString("session_id"), true))
                val ca = next(sourceQueue, 5).connection!!
                val cb = next(targetQueue, 5).connection!!
                val message = byteArrayOf(0, 1, -1, 2, 0)
                await(ca.send(message))
                assertArrayEquals(message, next(targetQueue, 6).payload)
                await(cb.send(message))
                assertArrayEquals(message, next(sourceQueue, 6).payload)
                await(a.refreshCredentials())
                next(sourceQueue, 2)
                // Proven host-queue negative case: a real message has scheduled a paused
                // application drain, then remote close invalidates its shared native gate.
                targetExecutor.pause()
                await(ca.send(message))
                assertTrue(targetExecutor.blocked.await(10, TimeUnit.SECONDS))
                await(ca.close())
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (cb.isValid() && System.nanoTime() < deadline) Thread.sleep(10)
                assertFalse(cb.isValid())
                targetExecutor.resume()
                var observedClosed = false
                val deliveryDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (!observedClosed && System.nanoTime() < deliveryDeadline) {
                    val event = targetQueue.poll(1, TimeUnit.SECONDS) ?: continue
                    assertNotEquals("revoked queued payload reached application", 6, event.kind)
                    observedClosed = event.kind == 7
                }
                assertTrue(observedClosed)
                assertTrue(targetQueue.none { it.kind == 6 })
            } finally {
                targetExecutor.resume()
                a.close().get(30, TimeUnit.SECONDS)
                b.close().get(30, TimeUnit.SECONDS)
                sourceExecutor.shutdownNow()
            }
        }
        assertEquals(0, Native.liveClients())
    }
}

/** CI force-stops the app between ServiceTest and this class; no fixture token is reimported. */
@RunWith(AndroidJUnit4::class)
class ServiceRestartTest {
    @Test
    fun rotatedIdentitySurvivesActualProcessRestart() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val source = fixture("pair-fixture.json").getJSONObject("source")
        val executor = Executors.newSingleThreadExecutor()
        try {
            val sdk =
                PeerloomSdk.create(context, config(source), executor) {}.get(20, TimeUnit.SECONDS)
            try {
                assertEquals(
                    source.getString("device_id"),
                    JSONObject(String(await(sdk.start()).payload, Charsets.UTF_8))
                        .getString("device_id"),
                )
            } finally {
                sdk.close().get(30, TimeUnit.SECONDS)
            }
        } finally {
            executor.shutdownNow()
        }
    }
}
