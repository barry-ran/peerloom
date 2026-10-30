package io.peerloom.sdk

import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

private const val ORIGIN = "http://127.0.0.1:18080"

private fun config(device: JSONObject) =
    JSONObject()
        .put("origin", ORIGIN)
        .put("development_loopback", true)
        .put("max_channels_per_connection", 4)
        .put("application_id", device.getString("application_id"))

/** Owned host controller accepts only these fixed test phases, not arbitrary commands. */
private fun hostPhase(phase: String) {
    require(phase in listOf("network_pause", "network_resume", "revoke_grant"))
    val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    val request = context.noBackupFilesDir.resolve("acceptance-request")
    val reply = context.noBackupFilesDir.resolve("acceptance-reply")
    val temporary = context.noBackupFilesDir.resolve("acceptance-request.new")
    temporary.writeText(phase + "\n")
    check(temporary.renameTo(request))
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(25)
    while (System.nanoTime() < deadline) {
        if (reply.exists() && reply.readText().trim() == phase) return
        Thread.sleep(25)
    }
    error("owned host phase deadline")
}

private fun finiteBackgroundAndResume() {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    val resumed = BackgroundProbeActivity.resumes.get()
    val stopped = BackgroundProbeActivity.stops.get()
    val intent =
        Intent(context, BackgroundProbeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    val activity = instrumentation.startActivitySync(intent)
    var resumedActivity: android.app.Activity? = null
    try {
        assertTrue(BackgroundProbeActivity.resumes.get() > resumed)
        var moved = false
        instrumentation.runOnMainSync { moved = activity.moveTaskToBack(true) }
        assertTrue(moved)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (
            BackgroundProbeActivity.stops.get() <= stopped && System.nanoTime() < deadline
        ) Thread.sleep(25)
        assertTrue(BackgroundProbeActivity.stops.get() > stopped)
        Thread.sleep(3000) // instrumentation worker, never the application UI thread
        resumedActivity =
            instrumentation.startActivitySync(
                Intent(context, BackgroundProbeActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_MULTIPLE_TASK)
            )
        assertTrue(BackgroundProbeActivity.resumes.get() >= resumed + 2)
    } finally {
        instrumentation.runOnMainSync {
            resumedActivity?.finish()
            activity.finish()
        }
    }
}

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

/** CLOSE 的状态不等于排空；仅此 helper 接受已受理关闭竞态中的 CLOSED。 */
private fun closeChannelAndAwaitDrain(
    local: Channel,
    remote: Channel,
    localConnection: Connection,
    remoteConnection: Connection,
    localQueue: ArrayBlockingQueue<Event>,
    remoteQueue: ArrayBlockingQueue<Event>,
) {
    val operation = local.close()
    assertNotEquals(0L, operation.requestId)
    val completion = operation.completion.get(30, TimeUnit.SECONDS)
    assertTrue(
        "CLOSE completion must be OK or CLOSED",
        completion.status == 0 || completion.status == 5,
    )
    for ((queue, channel, connection) in
        listOf(
            Triple(localQueue, local, localConnection),
            Triple(remoteQueue, remote, remoteConnection),
        )) {
        val closed = next(queue, 13)
        assertSame("CHANNEL_CLOSED must identify the exact channel", channel, closed.channel)
        assertEquals(channel.label, closed.channel!!.label)
        assertTrue(closed.connection!!.sameConnection(connection))
        assertFalse(channel.isValid())
        assertTrue(connection.isValid())
    }
}

/** Test-only inspection: prove the exact real payload is queued before revocation. */
private fun awaitQueuedMessage(sdk: PeerloomSdk, connection: Connection, payload: ByteArray) {
    val lock =
        checkNotNull(
            PeerloomSdk::class
                .java
                .getDeclaredField("eventLock")
                .apply { isAccessible = true }
                .get(sdk)
        )
    val field = PeerloomSdk::class.java.getDeclaredField("events").apply { isAccessible = true }
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
    while (System.nanoTime() < deadline) {
        val found =
            synchronized(lock) {
                val queue = field.get(sdk) as java.util.ArrayDeque<*>
                queue.any {
                    val event = it as Event
                    event.kind == 6 &&
                        event.connection?.sameConnection(connection) == true &&
                        event.payload.contentEquals(payload)
                }
            }
        if (found) {
            return
        }
        Thread.sleep(10)
    }
    fail("exact real message was not queued before revocation")
}

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
    fun authorizedChannelsBackgroundControlPlaneRecoveryAndGrantRevocation() {
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
        val sourceClosed = AtomicInteger(0)
        val targetClosed = AtomicInteger(0)
        val sourceQueue = ArrayBlockingQueue<Event>(32)
        val targetQueue = ArrayBlockingQueue<Event>(32)
        val sourceExecutor = Executors.newSingleThreadExecutor()
        PausingExecutor().use { targetExecutor ->
            val a =
                PeerloomSdk.create(context, config(source), sourceExecutor) {
                        if (it.kind == 7 && it.connection != null) sourceClosed.incrementAndGet()
                        check(sourceQueue.offer(it))
                    }
                    .get(20, TimeUnit.SECONDS)
            val b =
                PeerloomSdk.create(context, config(target), targetExecutor) {
                        if (it.kind == 7 && it.connection != null) targetClosed.incrementAndGet()
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
                val received = next(targetQueue, 6)
                assertArrayEquals(message, received.payload)
                assertNotSame(cb, received.connection)
                assertTrue(received.connection!!.sameConnection(cb))
                assertFalse(received.connection!!.sameConnection(ca))
                await(cb.send(message))
                assertArrayEquals(message, next(sourceQueue, 6).payload)
                val typed =
                    await(ca.openChannel(ChannelMode.RELIABLE_MESSAGE, "typed")).channel
                        as MessageChannel
                val remoteTyped = next(targetQueue, 12).channel as MessageChannel
                assertEquals(
                    SendDisposition.SENT,
                    typed.send(message).completion.get(30, TimeUnit.SECONDS),
                )
                val typedEvent = next(targetQueue, 14)
                assertEquals(remoteTyped.handle, typedEvent.channel!!.handle)
                assertArrayEquals(message, typedEvent.payload)
                val low =
                    await(ca.openChannel(ChannelMode.LOW_LATENCY_MESSAGE, "low")).channel
                        as MessageChannel
                val remoteLow = next(targetQueue, 12).channel as MessageChannel
                assertEquals(ChannelMode.LOW_LATENCY_MESSAGE, remoteLow.mode)
                repeat(8) {
                    assertEquals(
                        SendDisposition.SENT,
                        low.send(message).completion.get(30, TimeUnit.SECONDS),
                    )
                }
                assertArrayEquals(message, next(targetQueue, 14).payload)
                val stream =
                    await(ca.openChannel(ChannelMode.RELIABLE_STREAM, "stream")).channel
                        as ByteStream
                val remoteStream = next(targetQueue, 12).channel as ByteStream
                val pendingReverse = stream.read(4093)
                // A future continuation runs inline before the old read's delivery unwinds.
                // It must admit the next read, not report BUSY or release the new read's guard.
                val nextReverse =
                    pendingReverse.completion.thenApply { payload ->
                        assertArrayEquals(message, payload)
                        stream.read(4093)
                    }
                assertEquals(
                    message.size,
                    stream.write(message).completion.get(30, TimeUnit.SECONDS),
                )
                assertArrayEquals(
                    message,
                    remoteStream.read(4093).completion.get(30, TimeUnit.SECONDS),
                )
                assertEquals(
                    message.size,
                    remoteStream.write(message).completion.get(30, TimeUnit.SECONDS),
                )
                assertArrayEquals(message, pendingReverse.completion.get(30, TimeUnit.SECONDS))
                await(stream.finishWrite())
                assertEquals(0, remoteStream.read(4093).completion.get(30, TimeUnit.SECONDS).size)
                // FIN must not close the reverse direction.
                assertEquals(
                    message.size,
                    remoteStream.write(message).completion.get(30, TimeUnit.SECONDS),
                )
                assertArrayEquals(
                    message,
                    nextReverse.get(30, TimeUnit.SECONDS).completion.get(30, TimeUnit.SECONDS),
                )
                await(remoteStream.finishWrite())
                assertEquals(0, stream.read(4093).completion.get(30, TimeUnit.SECONDS).size)
                closeChannelAndAwaitDrain(typed, remoteTyped, ca, cb, sourceQueue, targetQueue)
                assertTrue(low.isValid())
                assertTrue(remoteLow.isValid())
                assertTrue(stream.isValid())
                assertTrue(remoteStream.isValid())
                closeChannelAndAwaitDrain(low, remoteLow, ca, cb, sourceQueue, targetQueue)
                assertTrue(stream.isValid())
                assertTrue(remoteStream.isValid())
                closeChannelAndAwaitDrain(stream, remoteStream, ca, cb, sourceQueue, targetQueue)
                finiteBackgroundAndResume()
                await(ca.send(message))
                assertArrayEquals(message, next(targetQueue, 6).payload)
                await(cb.send(message))
                assertArrayEquals(message, next(sourceQueue, 6).payload)
                hostPhase("network_pause")
                next(sourceQueue, 3)
                next(targetQueue, 3)
                // Only WSS is interrupted: healthy peer data and existing lease must survive.
                assertTrue(ca.isValid())
                assertTrue(cb.isValid())
                await(ca.send(message))
                assertArrayEquals(message, next(targetQueue, 6).payload)
                hostPhase("network_resume")
                next(sourceQueue, 2)
                next(targetQueue, 2)
                assertTrue(ca.isValid())
                assertTrue(cb.isValid())
                await(ca.send(message))
                assertArrayEquals(message, next(targetQueue, 6).payload)
                await(cb.send(message))
                assertArrayEquals(message, next(sourceQueue, 6).payload)
                await(a.refreshCredentials())
                next(sourceQueue, 2)
                // Proven host-queue negative case: a real message has scheduled a paused
                // application drain, then real management grant revocation invalidates its gate.
                targetExecutor.pause()
                await(ca.send(message))
                assertTrue(targetExecutor.blocked.await(10, TimeUnit.SECONDS))
                awaitQueuedMessage(b, cb, message)
                hostPhase("revoke_grant")
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while ((ca.isValid() || cb.isValid()) && System.nanoTime() < deadline) Thread.sleep(
                    10
                )
                assertFalse(ca.isValid())
                assertFalse(cb.isValid())
                targetExecutor.resume()
                var observedClosed = false
                val deliveryDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (!observedClosed && System.nanoTime() < deliveryDeadline) {
                    val event = targetQueue.poll(1, TimeUnit.SECONDS) ?: continue
                    assertNotEquals("revoked queued payload reached application", 6, event.kind)
                    observedClosed = event.kind == 7
                    if (observedClosed) {
                        assertNotSame(cb, event.connection)
                        assertTrue(event.connection!!.sameConnection(cb))
                        assertFalse(event.connection!!.isValid())
                    }
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
        assertEquals(1, sourceClosed.get())
        assertEquals(1, targetClosed.get())
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
