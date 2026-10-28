package io.peerloom.sdk

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.UTF_8
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.concurrent.withLock
import org.json.JSONObject

/**
 * Must be invoked off UI. All processes using this adapter share the OS file lock. No plaintext
 * persistence or key-loss reset. Deletion writes an encrypted tombstone.
 */
class IdentityStore
internal constructor(context: Context, private val rename: (String, String) -> Unit) :
    IdentityStorage {
    constructor(context: Context) : this(context, { source, target -> Os.rename(source, target) })

    private val directory =
        File(context.applicationContext.noBackupFilesDir, "peerloom-identity-v1")

    companion object {
        private val processLock = ReentrantLock()
        private const val MAX_BYTES = 65536
        private val MAGIC = byteArrayOf(80, 76, 73, 68, 1)
    }

    class Conflict : Exception()

    override fun execute(request: JSONObject): JSONObject =
        processLock.withLock {
            check(android.os.Looper.myLooper() != android.os.Looper.getMainLooper()) {
                "storage requires worker thread"
            }
            val scope = request.getJSONObject("scope")
            val origin = scope.getString("server_origin")
            val application = scope.getString("application_id")
            require(origin.length in 1..2048 && application.length in 1..128)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("peerloom-android-identity-v1\u0000".toByteArray(UTF_8))
            for (part in listOf(origin, application)) {
                val bytes = part.toByteArray(UTF_8)
                digest.update(ByteBuffer.allocate(4).putInt(bytes.size).array())
                digest.update(bytes)
            }
            val hash = digest.digest().joinToString("") { "%02x".format(it) }
            check(directory.exists() || directory.mkdirs())
            val directoryInfo = Os.lstat(directory.path)
            check(
                OsConstants.S_ISDIR(directoryInfo.st_mode) &&
                    directoryInfo.st_uid == android.os.Process.myUid()
            )
            Os.chmod(directory.path, 448) // 0700, app-private and never auto-backed-up.
            val descriptor =
                Os.open(
                    File(directory, "$hash.lock").path,
                    OsConstants.O_RDWR or
                        OsConstants.O_CREAT or
                        OsConstants.O_NOFOLLOW or
                        OsConstants.O_CLOEXEC,
                    384,
                )
            FileOutputStream(descriptor).use { stream ->
                val lockInfo = Os.fstat(descriptor)
                check(
                    OsConstants.S_ISREG(lockInfo.st_mode) &&
                        lockInfo.st_uid == android.os.Process.myUid() &&
                        lockInfo.st_nlink == 1L &&
                        (lockInfo.st_mode and 511) == 384
                )
                val until = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2)
                var acquired: java.nio.channels.FileLock? = null
                while (acquired == null && System.nanoTime() < until) {
                    acquired = stream.channel.tryLock()
                    if (acquired == null) {
                        Thread.sleep(10)
                    }
                }
                checkNotNull(acquired) { "identity storage lock unavailable" }
                    .use {
                        val file = File(directory, "$hash.enc")
                        val alias = "io.peerloom.identity.v1.$hash"
                        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                        val exists = regularFileExists(file)
                        val hasKey = keys.containsAlias(alias)
                        check(exists == hasKey) {
                            "identity/key pair unavailable; explicit recovery required"
                        }
                        val current =
                            if (exists) {
                                decrypt(file, keys.getKey(alias, null) as SecretKey, hash)
                            } else {
                                JSONObject().put("revision", 0).put("identity", JSONObject.NULL)
                            }
                        when (request.getString("operation")) {
                            "load" -> current
                            "save",
                            "delete" -> {
                                val expected = request.getLong("expected_revision")
                                require(expected >= 0 && expected < Long.MAX_VALUE)
                                if (current.getLong("revision") != expected) {
                                    throw Conflict()
                                }
                                val next =
                                    JSONObject()
                                        .put("revision", expected + 1)
                                        .put(
                                            "identity",
                                            if (request.getString("operation") == "save") {
                                                request.getJSONObject("identity")
                                            } else {
                                                JSONObject.NULL
                                            },
                                        )
                                val secret =
                                    if (hasKey) {
                                        keys.getKey(alias, null) as SecretKey
                                    } else {
                                        val generator =
                                            KeyGenerator.getInstance(
                                                KeyProperties.KEY_ALGORITHM_AES,
                                                "AndroidKeyStore",
                                            )
                                        generator.init(
                                            KeyGenParameterSpec.Builder(
                                                    alias,
                                                    KeyProperties.PURPOSE_ENCRYPT or
                                                        KeyProperties.PURPOSE_DECRYPT,
                                                )
                                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                                .setEncryptionPaddings(
                                                    KeyProperties.ENCRYPTION_PADDING_NONE
                                                )
                                                .setKeySize(256)
                                                .setRandomizedEncryptionRequired(true)
                                                .build()
                                        )
                                        generator.generateKey()
                                    }
                                encrypt(file, secret, hash, next)
                                JSONObject().put("revision", expected + 1)
                            }
                            else -> throw IllegalArgumentException("unsupported storage operation")
                        }
                    }
            }
        }

    private fun validateFile(info: android.system.StructStat) {
        check(
            OsConstants.S_ISREG(info.st_mode) &&
                info.st_uid == android.os.Process.myUid() &&
                info.st_nlink == 1L &&
                (info.st_mode and 511) == 384
        )
    }

    private fun regularFileExists(file: File): Boolean {
        return try {
            validateFile(Os.lstat(file.path))
            true
        } catch (failure: ErrnoException) {
            if (failure.errno == OsConstants.ENOENT) {
                false
            } else {
                throw failure
            }
        }
    }

    private fun decrypt(file: File, key: SecretKey, scope: String): JSONObject {
        val bytes =
            FileInputStream(
                    Os.open(
                        file.path,
                        OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
                        0,
                    )
                )
                .use { input ->
                    validateFile(Os.fstat(input.fd))
                    val output = ByteArrayOutputStream()
                    val chunk = ByteArray(4096)
                    while (true) {
                        val count = input.read(chunk)
                        if (count < 0) {
                            break
                        }
                        check(output.size() + count <= MAX_BYTES)
                        output.write(chunk, 0, count)
                    }
                    output.toByteArray()
                }
        check(
            bytes.size >= MAGIC.size + 12 + 16 &&
                bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(128, bytes.copyOfRange(MAGIC.size, MAGIC.size + 12)),
        )
        cipher.updateAAD(scope.toByteArray(UTF_8))
        val plain = cipher.doFinal(bytes, MAGIC.size + 12, bytes.size - MAGIC.size - 12)
        return try {
            JSONObject(String(plain, UTF_8)).also { check(it.getLong("revision") > 0) }
        } finally {
            plain.fill(0)
        }
    }

    private fun encrypt(file: File, key: SecretKey, scope: String, snapshot: JSONObject) {
        val plain = snapshot.toString().toByteArray(UTF_8)
        require(plain.size <= MAX_BYTES - 64)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        check(cipher.iv.size == 12)
        cipher.updateAAD(scope.toByteArray(UTF_8))
        val encrypted =
            try {
                cipher.doFinal(plain)
            } finally {
                plain.fill(0)
            }
        // O_EXCL/NOFOLLOW reject stale or linked temporary paths instead of following them.
        val temporary = File(file.path + ".new")
        val descriptor =
            Os.open(
                temporary.path,
                OsConstants.O_WRONLY or
                    OsConstants.O_CREAT or
                    OsConstants.O_EXCL or
                    OsConstants.O_NOFOLLOW or
                    OsConstants.O_CLOEXEC,
                384,
            )
        try {
            FileOutputStream(descriptor).use { output ->
                validateFile(Os.fstat(output.fd))
                output.write(MAGIC)
                output.write(cipher.iv)
                output.write(encrypted)
                output.fd.sync()
            }
            // Unlike AtomicFile.finishWrite, Os.rename reports failure to the caller.
            rename(temporary.path, file.path)
        } finally {
            // Only this operation's exclusive-created ciphertext is eligible for cleanup.
            try {
                Os.remove(temporary.path)
            } catch (failure: ErrnoException) {
                if (failure.errno != OsConstants.ENOENT) {
                    throw failure
                }
            }
        }
        val dir =
            Os.open(
                directory.path,
                OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC,
                0,
            )
        try {
            check(OsConstants.S_ISDIR(Os.fstat(dir).st_mode))
            Os.fsync(dir)
        } finally {
            Os.close(dir)
        }
    }
}
