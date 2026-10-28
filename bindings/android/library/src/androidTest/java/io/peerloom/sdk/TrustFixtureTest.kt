package io.peerloom.sdk

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exists in the disposable instrumentation APK only, never the AAR or sample APK. */
class TestCertificateAdmin : DeviceAdminReceiver()

@RunWith(AndroidJUnit4::class)
class TrustFixtureTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val manager = context.getSystemService(DevicePolicyManager::class.java)
    private val admin = ComponentName(context, TestCertificateAdmin::class.java)

    private fun certificate(): ByteArray {
        check(context.packageName == "io.peerloom.sdk.test")
        check(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val expected = InstrumentationRegistry.getArguments().getString("peerloom_test_ca_sha256")!!
        check(expected.matches(Regex("[a-f0-9]{64}")))
        val id = context.resources.getIdentifier("peerloom_test_ca", "raw", context.packageName)
        val bytes = context.resources.openRawResource(id).use { it.readBytes() }
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream())
        val actual =
            MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") {
                "%02x".format(it)
            }
        check(actual == expected)
        return bytes
    }

    private fun present(bytes: ByteArray): Boolean {
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream())
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        return store.aliases().toList().any {
            store.getCertificate(it)?.encoded?.contentEquals(cert.encoded) == true
        }
    }

    private fun awaitPresent(bytes: ByteArray, expected: Boolean) {
        val deadline = android.os.SystemClock.elapsedRealtime() + 10000
        while (present(bytes) != expected && android.os.SystemClock.elapsedRealtime() < deadline) {
            Thread.sleep(100)
        }
        assertEquals("exact fixture CA presence", expected, present(bytes))
    }

    @Test
    fun install() {
        val bytes = certificate()
        check(manager.isDeviceOwnerApp(context.packageName) && manager.isAdminActive(admin))
        assertFalse("never replace a pre-existing CA", present(bytes))
        assertTrue(manager.installCaCert(admin, bytes))
        assertTrue(manager.hasCaCertInstalled(admin, bytes))
        awaitPresent(bytes, true)
    }

    @Test
    fun remove() {
        val bytes = certificate()
        if (manager.isDeviceOwnerApp(context.packageName)) {
            // Only this exact fixture certificate; never clear other user CAs.
            manager.uninstallCaCert(admin, bytes)
            assertFalse(manager.hasCaCertInstalled(admin, bytes))
        }
        awaitPresent(bytes, false)
    }

    @Test
    fun verifyReleased() {
        val bytes = certificate()
        assertFalse(manager.isDeviceOwnerApp(context.packageName))
        assertFalse(manager.isAdminActive(admin))
        awaitPresent(bytes, false)
    }
}
