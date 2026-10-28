package io.peerloom.sdk

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class TlsTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private fun serverContext(kind: String): SSLContext {
        val keys = KeyStore.getInstance("PKCS12")
        context.assets.open("$kind.p12").use { keys.load(it, "peerloom-test-only".toCharArray()) }
        if (kind == "valid") {
            val chain =
                keys
                    .getCertificateChain(keys.aliases().nextElement())
                    .map { it as java.security.cert.X509Certificate }
                    .toTypedArray()
            val androidStore = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            for ((label, trustStore) in
                listOf("application-policy" to null, "android-ca-store" to androidStore)) {
                val trust =
                    javax.net.ssl.TrustManagerFactory.getInstance(
                        javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
                    )
                trust.init(trustStore as KeyStore?)
                val manager =
                    trust.trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>().single()
                val outcome =
                    try {
                        android.net.http
                            .X509TrustManagerExtensions(manager)
                            .checkServerTrusted(chain, "RSA", "127.0.0.1")
                        "trusted"
                    } catch (error: java.security.cert.CertificateException) {
                        error.javaClass.simpleName
                    }
                println("TLS fixture trust policy=$label outcome=$outcome")
            }
        }
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        managers.init(keys, "peerloom-test-only".toCharArray())
        return SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) }
    }

    private fun exchange(
        listener: ServerSocket,
        tls: SSLContext,
        status: Int,
        body: String,
    ): Boolean {
        listener.soTimeout = 15000
        listener.accept().use { raw ->
            val socket =
                tls.socketFactory.createSocket(raw, "127.0.0.1", listener.localPort, true)
                    as SSLSocket
            socket.use {
                it.useClientMode = false
                it.soTimeout = 5000
                try {
                    it.startHandshake()
                    val input = it.inputStream.bufferedReader()
                    var total = 0
                    while (true) {
                        val line = input.readLine() ?: return false
                        total += line.length
                        check(total < 16384)
                        if (line.isEmpty()) {
                            break
                        }
                    }
                    val bytes = body.toByteArray(Charsets.UTF_8)
                    it.outputStream.write(
                        "HTTP/1.1 $status Test\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n"
                            .toByteArray(Charsets.US_ASCII)
                    )
                    it.outputStream.write(bytes)
                    it.outputStream.flush()
                    return true
                } catch (error: java.io.IOException) {
                    // Test fixtures only: exception classes, never request headers or payloads.
                    println(
                        "TLS test server rejected: ${error.javaClass.simpleName}; cause=${error.cause?.javaClass?.simpleName}"
                    )
                    return false
                }
            }
        }
    }

    private fun seed(origin: String, app: String, device: String) {
        IdentityStore(context)
            .execute(
                JSONObject()
                    .put("operation", "save")
                    .put("expected_revision", 0)
                    .put(
                        "scope",
                        JSONObject().put("server_origin", "$origin/").put("application_id", app),
                    )
                    .put(
                        "identity",
                        JSONObject()
                            .put("device_id", device)
                            .put("device_credential", "dev_" + "b".repeat(43))
                            .put("expires_at", "2030-01-01T00:00:00Z"),
                    )
            )
    }

    @Test
    fun httpsTrustedHostAndWrongHostAndUntrusted() {
        for (kind in listOf("valid", "wrong", "untrusted")) {
            ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")).use { listener ->
                val origin = "https://127.0.0.1:${listener.localPort}"
                val app = UUID.randomUUID().toString()
                seed(origin, app, UUID.randomUUID().toString())
                val server = Executors.newSingleThreadExecutor()
                val events = Executors.newSingleThreadExecutor()
                try {
                    val response =
                        server.submit<Boolean> {
                            exchange(
                                listener,
                                serverContext(kind),
                                401,
                                "{\"code\":\"UNAUTHORIZED\"}",
                            )
                        }
                    val sdk =
                        PeerloomSdk.create(
                                context,
                                JSONObject()
                                    .put("origin", origin)
                                    .put("application_id", app)
                                    .put("development_loopback", true)
                                    .put("auto_reconnect", false),
                                events,
                            ) {}
                            .get(20, TimeUnit.SECONDS)
                    try {
                        val status = sdk.start().completion.get(20, TimeUnit.SECONDS).status
                        val exchanged = response.get(20, TimeUnit.SECONDS)
                        assertEquals(
                            "HTTPS fixture=$kind exchanged=$exchanged",
                            if (kind == "valid") 3 else 10,
                            status,
                        )
                        assertEquals(kind == "valid", exchanged)
                    } finally {
                        sdk.close().get(20, TimeUnit.SECONDS)
                    }
                } finally {
                    server.shutdownNow()
                    events.shutdownNow()
                }
            }
        }
    }

    @Test
    fun wssUsesSameTrustPolicyAfterSuccessfulHttps() {
        for (kind in listOf("valid", "wrong", "untrusted")) {
            ServerSocket(0, 8, InetAddress.getByName("127.0.0.1")).use { listener ->
                val origin = "https://127.0.0.1:${listener.localPort}"
                val app = UUID.randomUUID().toString()
                val device = UUID.randomUUID().toString()
                seed(origin, app, device)
                val server = Executors.newSingleThreadExecutor()
                val events = Executors.newSingleThreadExecutor()
                val stopped = ArrayBlockingQueue<Int>(1)
                try {
                    val response =
                        server.submit<Boolean> {
                            val body =
                                JSONObject()
                                    .put("device_id", device)
                                    .put("application_id", app)
                                    .put("tenant_id", UUID.randomUUID().toString())
                                    .put("platform", "android")
                                    .put("metadata", JSONObject())
                                    .toString()
                            check(exchange(listener, serverContext("valid"), 200, body))
                            exchange(
                                listener,
                                serverContext(kind),
                                401,
                                "{\"code\":\"UNAUTHORIZED\"}",
                            )
                        }
                    val sdk =
                        PeerloomSdk.create(
                                context,
                                JSONObject()
                                    .put("origin", origin)
                                    .put("application_id", app)
                                    .put("development_loopback", true)
                                    .put("auto_reconnect", false),
                                events,
                            ) { event ->
                                if (event.kind == 11) {
                                    stopped.offer(event.status)
                                }
                            }
                            .get(20, TimeUnit.SECONDS)
                    try {
                        assertEquals(0, sdk.start().completion.get(20, TimeUnit.SECONDS).status)
                        assertEquals(
                            if (kind == "valid") {
                                3
                            } else {
                                255
                            },
                            stopped.poll(20, TimeUnit.SECONDS),
                        )
                        assertEquals(kind == "valid", response.get(20, TimeUnit.SECONDS))
                    } finally {
                        sdk.close().get(20, TimeUnit.SECONDS)
                    }
                } finally {
                    server.shutdownNow()
                    events.shutdownNow()
                }
            }
        }
    }
}
