package io.peerloom.sdk

import android.app.Service
import android.content.*
import android.os.*
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Only own process data; invoked on the instrumentation/worker thread, never the UI thread. */
private fun logStoreProcessMemory(context: Context, phase: String) {
    try {
        val self = android.app.ActivityManager.RunningAppProcessInfo()
        android.app.ActivityManager.getMyMemoryState(self)
        val activity = context.getSystemService(android.app.ActivityManager::class.java)
        val own =
            activity.runningAppProcesses.orEmpty().filter {
                it.uid == android.os.Process.myUid() &&
                    (it.processName == context.packageName ||
                        it.processName == context.packageName + ":storeProbe")
            }
        val callers = own.count { it.processName == context.packageName }
        val probes = own.count { it.processName == context.packageName + ":storeProbe" }
        android.util.Log.i(
            "PeerloomTestDiag",
            "store-memory phase=$phase pid=${android.os.Process.myPid()} " +
                "pss_kib=${Debug.getPss()} importance=${self.importance} " +
                "caller_count=$callers probe_count=$probes",
        )
    } catch (_: Exception) {
        // Observation failure must not replace the lock/liveness assertion.
        android.util.Log.i("PeerloomTestDiag", "store-memory unavailable")
    }
}

/** Test APK only: never exported, never included in the release AAR. */
class StoreProbeService : Service() {
    private val work = Executors.newSingleThreadExecutor()
    private val handler =
        Messenger(
            Handler(Looper.getMainLooper()) { message ->
                if (message.what == 3) {
                    check(message.arg1 > 0 && message.arg1 != android.os.Process.myPid())
                    check(android.app.Application.getProcessName().endsWith(":storeProbe"))
                    android.util.Log.i(
                        "PeerloomTestDiag",
                        "store-probe-kill pid=${android.os.Process.myPid()}",
                    )
                    android.os.Process.killProcess(android.os.Process.myPid())
                } else {
                    val kind = message.what
                    android.util.Log.i(
                        "PeerloomTestDiag",
                        "store-probe-request kind=$kind pid=${android.os.Process.myPid()}",
                    )
                    val reply = message.replyTo
                    val data = Bundle(message.data)
                    work.execute {
                        val result =
                            Message.obtain().apply {
                                what = kind
                                arg2 = android.os.Process.myPid()
                            }
                        try {
                            if (kind == 2) {
                                val file =
                                    noBackupFilesDir
                                        .resolve("peerloom-identity-v1")
                                        .resolve(data.getString("lock")!!)
                                require(file.name.matches(Regex("[a-f0-9]{64}\\.lock")))
                                FileOutputStream(file, true).use { output ->
                                    output.channel.lock().use {
                                        logStoreProcessMemory(this, "probe-lock-held")
                                        result.arg1 = 0
                                        reply.send(result)
                                        // Parent kills this isolated process to test OS lock
                                        // release.
                                        CountDownLatch(1).await()
                                    }
                                }
                            } else {
                                val start = data.getLong("start")
                                while (SystemClock.elapsedRealtime() < start) {
                                    Thread.sleep(1)
                                }
                                android.util.Log.i(
                                    "PeerloomTestDiag",
                                    "store-probe-cas-start pid=${android.os.Process.myPid()}",
                                )
                                IdentityStore(this).execute(JSONObject(data.getString("request")!!))
                                android.util.Log.i(
                                    "PeerloomTestDiag",
                                    "store-probe-cas-success pid=${android.os.Process.myPid()}",
                                )
                                result.arg1 = 0
                                reply.send(result)
                            }
                        } catch (_: IdentityStore.Conflict) {
                            android.util.Log.i(
                                "PeerloomTestDiag",
                                "store-probe-cas-conflict pid=${android.os.Process.myPid()}",
                            )
                            result.arg1 = 11
                            reply.send(result)
                        } catch (error: Exception) {
                            android.util.Log.i(
                                "PeerloomTestDiag",
                                "store-probe-error category=${error.javaClass.simpleName} pid=${android.os.Process.myPid()}",
                            )
                            result.arg1 = 255
                            reply.send(result)
                        }
                    }
                }
                true
            }
        )

    override fun onBind(intent: Intent): IBinder {
        android.util.Log.i(
            "PeerloomTestDiag",
            "store-probe-bound pid=${android.os.Process.myPid()}",
        )
        return handler.binder
    }

    override fun onDestroy() {
        work.shutdownNow()
        super.onDestroy()
    }
}

@RunWith(AndroidJUnit4::class)
class StoreProcessTest {
    @Test
    fun crossProcessCasAndKilledLockOwner() {
        val started = System.currentTimeMillis()
        val context = ApplicationProvider.getApplicationContext<Context>()
        val instrumentation =
            context.packageManager.getInstrumentationInfo(
                ComponentName(context, "androidx.test.runner.AndroidJUnitRunner"),
                0,
            )
        android.util.Log.i(
            "PeerloomTestDiag",
            "store-process instrumentation_targets=${instrumentation.targetProcesses ?: "<default>"}",
        )
        logStoreProcessMemory(context, "before-bind")
        val connected = CountDownLatch(1)
        val disconnected = CountDownLatch(1)
        val responses = LinkedBlockingQueue<Triple<Int, Int, Int>>()
        val replies =
            Messenger(
                Handler(Looper.getMainLooper()) { message ->
                    responses.offer(Triple(message.what, message.arg1, message.arg2))
                    true
                }
            )
        lateinit var remote: Messenger
        val connection =
            object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) {
                    remote = Messenger(binder)
                    connected.countDown()
                }

                override fun onServiceDisconnected(name: ComponentName) {
                    disconnected.countDown()
                }
            }
        assertTrue(
            context.bindService(
                Intent(context, StoreProbeService::class.java),
                connection,
                // This test depends on the remote lock owner while its client is active.
                // Match client importance; do not prefer killing the client (ABOVE_CLIENT).
                Context.BIND_AUTO_CREATE or Context.BIND_IMPORTANT,
            )
        )
        var completed = false
        try {
            assertTrue(connected.await(10, TimeUnit.SECONDS))
            // Keep this generation: AUTO_CREATE may reconnect a different process after death.
            val probe = remote
            val lockOwnerBinder = probe.binder
            logStoreProcessMemory(context, "bound")
            android.util.Log.i(
                "PeerloomTestDiag",
                "store-process bound caller_pid=${android.os.Process.myPid()}",
            )
            val app = UUID.randomUUID().toString()
            val store = IdentityStore(context)
            val keys = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val before = keys.aliases().toList().toSet()
            store.execute(storageRequest(app, "save"))
            val alias = keys.aliases().toList().single { it !in before }
            val request = storageRequest(app, "save", 1)
            val start = SystemClock.elapsedRealtime() + 500
            probe.send(
                Message.obtain().apply {
                    what = 1
                    replyTo = replies
                    data =
                        Bundle().apply {
                            putString("request", request.toString())
                            putLong("start", start)
                        }
                }
            )
            while (SystemClock.elapsedRealtime() < start) {
                Thread.sleep(1)
            }
            val local =
                try {
                    store.execute(request)
                    0
                } catch (_: IdentityStore.Conflict) {
                    11
                }
            val other = responses.poll(10, TimeUnit.SECONDS)
            if (other == null) {
                fail("probe CAS response deadline; disconnected=${disconnected.count == 0L}")
                return
            }
            assertEquals(1, other.first)
            assertTrue(
                "probe must be a distinct process",
                other.third != android.os.Process.myPid(),
            )
            android.util.Log.i(
                "PeerloomTestDiag",
                "store-process CAS local=$local remote=${other.second} remote_pid=${other.third}",
            )
            assertEquals(setOf(0, 11), setOf(local, other.second))
            assertEquals(2L, store.execute(storageRequest(app, "load")).getLong("revision"))
            probe.send(
                Message.obtain().apply {
                    what = 2
                    replyTo = replies
                    data =
                        Bundle().apply {
                            putString(
                                "lock",
                                alias.removePrefix("io.peerloom.identity.v1.") + ".lock",
                            )
                        }
                }
            )
            assertEquals(Triple(2, 0, other.third), responses.poll(10, TimeUnit.SECONDS))
            android.util.Log.i("PeerloomTestDiag", "store-process remote-lock-held")
            logStoreProcessMemory(context, "caller-lock-held")
            assertTrue(
                "remote lock owner must be alive before contention",
                lockOwnerBinder.pingBinder(),
            )
            android.util.Log.i(
                "PeerloomTestDiag",
                "store-alive phase=before-contention pid=${other.third}",
            )
            try {
                store.execute(storageRequest(app, "save", 2))
                fail("another process holds the lock")
            } catch (_: IllegalStateException) {}
            assertTrue(
                "remote lock owner must remain alive after timeout",
                lockOwnerBinder.pingBinder(),
            )
            android.util.Log.i(
                "PeerloomTestDiag",
                "store-alive phase=after-timeout pid=${other.third}",
            )
            android.util.Log.i("PeerloomTestDiag", "store-process local-lock-timeout-confirmed")
            probe.send(
                Message.obtain().apply {
                    what = 3
                    arg1 = android.os.Process.myPid()
                }
            )
            assertTrue(disconnected.await(10, TimeUnit.SECONDS))
            android.util.Log.i("PeerloomTestDiag", "store-process remote-disconnected")
            assertFalse(
                "the original explicitly killed Binder must remain dead",
                lockOwnerBinder.pingBinder(),
            )
            assertEquals(3L, store.execute(storageRequest(app, "save", 2)).getLong("revision"))
            logStoreProcessMemory(context, "after-kill-recovery")
            completed = true
        } finally {
            if (!completed) {
                // Capture before unbind/runner cleanup can obscure the original failure.
                // Own UID/package only: no description, trace, arbitrary text or credentials.
                try {
                    val activity = context.getSystemService(android.app.ActivityManager::class.java)
                    val deadline = SystemClock.elapsedRealtime() + 2000
                    do {
                        val exits =
                            activity
                                .getHistoricalProcessExitReasons(context.packageName, 0, 8)
                                .filter {
                                    it.processName == context.packageName + ":storeProbe" &&
                                        it.timestamp >= started
                                }
                        for (exit in exits) {
                            android.util.Log.i(
                                "PeerloomTestDiag",
                                "store-probe-exit pid=${exit.pid} reason=${exit.reason} status=${exit.status} importance=${exit.importance}",
                            )
                        }
                        if (exits.isNotEmpty()) break
                        Thread.sleep(100)
                    } while (SystemClock.elapsedRealtime() < deadline)
                } catch (error: Exception) {
                    // Diagnostics must not replace the original assertion or trigger a retry.
                    android.util.Log.i(
                        "PeerloomTestDiag",
                        "store-probe-error category=${error.javaClass.simpleName} pid=${android.os.Process.myPid()}",
                    )
                }
            }
            context.unbindService(connection)
            logStoreProcessMemory(context, "after-unbind")
        }
    }
}
