package io.peerloom.sdk

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

internal fun storageRequest(app: String, operation: String, revision: Long = 0): JSONObject =
    JSONObject()
        .put("operation", operation)
        .put(
            "scope",
            JSONObject()
                .put("server_origin", "https://persistence.example.invalid/")
                .put("application_id", app),
        )
        .put("expected_revision", revision)
        .put(
            "identity",
            JSONObject()
                .put("device_id", "11111111-1111-4111-8111-111111111111")
                .put("device_credential", "dev_" + "a".repeat(43))
                .put("expires_at", "2030-01-01T00:00:00Z"),
        )

@RunWith(AndroidJUnit4::class)
class StoreTest {
    @Test
    fun renameFailureAndLinkedFilesFailClosed() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val keys = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val before = keys.aliases().toList().toSet()
        val app = UUID.randomUUID().toString()
        val store = IdentityStore(context)
        store.execute(storageRequest(app, "save"))
        val alias = keys.aliases().toList().single { it !in before }
        val file =
            context.noBackupFilesDir
                .resolve("peerloom-identity-v1")
                .resolve(alias.removePrefix("io.peerloom.identity.v1.") + ".enc")
        val failing =
            IdentityStore(context) { _, _ -> throw java.io.IOException("injected rename failure") }
        try {
            failing.execute(storageRequest(app, "save", 1))
            fail("failed rename acknowledged CAS")
        } catch (_: java.io.IOException) {}
        assertEquals(1L, store.execute(storageRequest(app, "load")).getLong("revision"))
        val sentinel = context.noBackupFilesDir.resolve("sentinel-" + UUID.randomUUID())
        sentinel.writeText("unchanged")
        val temporary = java.io.File(file.path + ".new")
        android.system.Os.symlink(sentinel.path, temporary.path)
        try {
            try {
                store.execute(storageRequest(app, "save", 1))
                fail("linked temporary accepted")
            } catch (_: android.system.ErrnoException) {}
            assertEquals("unchanged", sentinel.readText())
        } finally {
            android.system.Os.remove(temporary.path)
        }
        val original = java.io.File(file.path + ".original")
        android.system.Os.rename(file.path, original.path)
        android.system.Os.symlink(original.path, file.path)
        try {
            try {
                store.execute(storageRequest(app, "load"))
                fail("linked identity accepted")
            } catch (_: IllegalStateException) {}
        } finally {
            android.system.Os.remove(file.path)
            android.system.Os.rename(original.path, file.path)
            sentinel.delete()
        }
    }

    @Test
    fun keyLossAndCiphertextTamperingNeverCreateFreshIdentity() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val keys = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        for (loseKey in listOf(true, false)) {
            val before = keys.aliases().toList().toSet()
            val store = IdentityStore(context)
            val app = UUID.randomUUID().toString()
            store.execute(storageRequest(app, "save"))
            val newAliases = keys.aliases().toList().filter { it !in before }
            assertEquals(1, newAliases.size)
            val alias = newAliases.single()
            assertNull(keys.getKey(alias, null).encoded)
            val file =
                context.noBackupFilesDir
                    .resolve("peerloom-identity-v1")
                    .resolve(alias.removePrefix("io.peerloom.identity.v1.") + ".enc")
            assertTrue(file.isFile)
            if (loseKey) {
                keys.deleteEntry(alias)
            } else {
                val bytes = file.readBytes()
                bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
                file.writeBytes(bytes)
            }
            try {
                store.execute(storageRequest(app, "load"))
                fail("unavailable identity silently recreated")
            } catch (_: Exception) {}
            assertTrue(file.isFile)
            if (loseKey) {
                assertFalse(keys.containsAlias(alias))
            }
        }
    }

    @Test
    fun atomicCasTombstoneAndNoPlaintext() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val store = IdentityStore(context)
        val app = UUID.randomUUID().toString()
        assertEquals(0L, store.execute(storageRequest(app, "load")).getLong("revision"))
        assertEquals(1L, store.execute(storageRequest(app, "save")).getLong("revision"))
        val pool = Executors.newFixedThreadPool(2)
        try {
            val start = CountDownLatch(1)
            val outcomes =
                (0..1).map {
                    pool.submit<Boolean> {
                        start.await()
                        try {
                            IdentityStore(context).execute(storageRequest(app, "save", 1))
                            true
                        } catch (_: IdentityStore.Conflict) {
                            false
                        }
                    }
                }
            start.countDown()
            assertEquals(1, outcomes.count { it.get(20, TimeUnit.SECONDS) })
        } finally {
            pool.shutdownNow()
        }
        assertEquals(3L, store.execute(storageRequest(app, "delete", 2)).getLong("revision"))
        assertTrue(store.execute(storageRequest(app, "load")).isNull("identity"))
        try {
            store.execute(storageRequest(app, "save", 0))
            fail("ABA accepted")
        } catch (_: IdentityStore.Conflict) {}
        context.noBackupFilesDir.resolve("peerloom-identity-v1").listFiles()!!.forEach { file ->
            assertFalse(
                String(file.readBytes(), Charsets.ISO_8859_1).contains("dev_" + "a".repeat(43))
            )
        }
    }
}

/**
 * CI invokes these methods in separate instrumentation processes with an intervening force-stop.
 */
@RunWith(AndroidJUnit4::class)
class PersistenceTest {
    private val app = "22222222-2222-4222-8222-222222222222"

    @Test
    fun writePhase() {
        val store = IdentityStore(ApplicationProvider.getApplicationContext())
        assertEquals(0L, store.execute(storageRequest(app, "load")).getLong("revision"))
        assertEquals(1L, store.execute(storageRequest(app, "save")).getLong("revision"))
    }

    @Test
    fun readPhase() {
        val store = IdentityStore(ApplicationProvider.getApplicationContext())
        val loaded = store.execute(storageRequest(app, "load"))
        assertEquals(1L, loaded.getLong("revision"))
        assertEquals(
            "dev_" + "a".repeat(43),
            loaded.getJSONObject("identity").getString("device_credential"),
        )
    }
}
