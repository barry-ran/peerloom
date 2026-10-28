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
                Context.BIND_AUTO_CREATE,
            )
        )
        try {
            assertTrue(connected.await(10, TimeUnit.SECONDS))
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
            remote.send(
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
                // Own package/UID only; no trace, description, credential or arbitrary log text.
                val activity = context.getSystemService(android.app.ActivityManager::class.java)
                for (exit in activity.getHistoricalProcessExitReasons(context.packageName, 0, 8)) {
                    if (
                        exit.processName == context.packageName + ":storeProbe" &&
                            exit.timestamp >= started
                    ) {
                        android.util.Log.i(
                            "PeerloomTestDiag",
                            "store-probe-exit pid=${exit.pid} reason=${exit.reason} status=${exit.status} importance=${exit.importance}",
                        )
                    }
                }
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
            remote.send(
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
            try {
                store.execute(storageRequest(app, "save", 2))
                fail("another process holds the lock")
            } catch (_: IllegalStateException) {}
            android.util.Log.i("PeerloomTestDiag", "store-process local-lock-timeout-confirmed")
            remote.send(
                Message.obtain().apply {
                    what = 3
                    arg1 = android.os.Process.myPid()
                }
            )
            assertTrue(disconnected.await(10, TimeUnit.SECONDS))
            android.util.Log.i("PeerloomTestDiag", "store-process remote-disconnected")
            assertEquals(3L, store.execute(storageRequest(app, "save", 2)).getLong("revision"))
        } finally {
            context.unbindService(connection)
        }
    }
}
