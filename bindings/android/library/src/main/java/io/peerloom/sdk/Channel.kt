package io.peerloom.sdk

import java.nio.charset.StandardCharsets.UTF_8
import java.util.concurrent.CompletableFuture
import org.json.JSONObject

enum class ChannelMode(val wire: String) {
    RELIABLE_MESSAGE("reliable_message"),
    LOW_LATENCY_MESSAGE("low_latency_message"),
    RELIABLE_STREAM("reliable_stream"),
}

data class MessageQueueOptions(
    val maxMessages: Int = 256,
    val maxBytes: Int = 1048576,
    val ttlMillis: Long = 30000,
    val overflow: String = "fail",
) {
    internal fun json(): JSONObject =
        JSONObject()
            .put("max_messages", maxMessages)
            .put("max_bytes", maxBytes)
            .put("ttl_ms", ttlMillis)
            .put("overflow", overflow)
}

sealed class Channel
protected constructor(
    protected val sdk: PeerloomSdk,
    internal val parent: Long,
    internal val handle: Long,
    val label: String,
    val mode: ChannelMode,
    val targetEpoch: String? = null,
) {
    fun isValid(): Boolean = sdk.validChannel(parent, handle)

    fun close(): Operation = sdk.submitChannel(parent, handle, 5, byteArrayOf())
}

class MessageChannel
internal constructor(
    sdk: PeerloomSdk,
    parent: Long,
    handle: Long,
    label: String,
    mode: ChannelMode,
    targetEpoch: String? = null,
) : Channel(sdk, parent, handle, label, mode, targetEpoch) {
    /** Completion JSON distinguishes local send from explicit policy drop; not peer receipt. */
    fun send(message: ByteArray): SendOperation {
        val operation = sdk.submitChannel(parent, handle, 1, message)
        return SendOperation(
            operation,
            operation.completion.thenApply { result ->
                if (result.status != 0) throw PeerloomException(result.status)
                when (JSONObject(String(result.payload, UTF_8)).getString("disposition")) {
                    "sent" -> SendDisposition.SENT
                    "dropped" -> SendDisposition.DROPPED
                    else -> error("Unknown send disposition")
                }
            },
        )
    }
}

class ByteStream
internal constructor(
    sdk: PeerloomSdk,
    parent: Long,
    handle: Long,
    label: String,
    targetEpoch: String? = null,
) : Channel(sdk, parent, handle, label, ChannelMode.RELIABLE_STREAM, targetEpoch) {
    /** Empty successful read means EOF. Pending read never blocks independent writes. */
    fun read(maxBytes: Int): ReadOperation {
        require(maxBytes in 1..65536)
        return sdk.readChannel(parent, handle, maxBytes)
    }

    /** Inspect completion JSON written count; advance by that count, never retry unknown writes. */
    fun write(bytes: ByteArray): WriteOperation {
        val operation = sdk.submitChannel(parent, handle, 3, bytes)
        return WriteOperation(
            operation,
            operation.completion.thenApply { result ->
                if (result.status != 0) throw PeerloomException(result.status)
                val written = JSONObject(String(result.payload, UTF_8)).getInt("written")
                check(written in 0..bytes.size)
                written
            },
        )
    }

    /** One-way FIN: the reverse read direction remains open. */
    fun finishWrite(): Operation = sdk.submitChannel(parent, handle, 4, byteArrayOf())
}

enum class SendDisposition {
    SENT,
    DROPPED,
}

class SendOperation
internal constructor(
    private val operation: Operation,
    val completion: CompletableFuture<SendDisposition>,
) {
    val requestId: Long
        get() = operation.requestId

    fun cancelQueued(): Int = operation.cancelQueued()
}

class WriteOperation
internal constructor(private val operation: Operation, val completion: CompletableFuture<Int>) {
    val requestId: Long
        get() = operation.requestId

    fun cancelQueued(): Int = operation.cancelQueued()
}

class ReadOperation
internal constructor(
    private val operation: Operation,
    val completion: CompletableFuture<ByteArray>,
) {
    val requestId: Long
        get() = operation.requestId

    fun cancelQueued(): Int = operation.cancelQueued()
}

internal fun PeerloomSdk.channel(parent: Long, handle: Long, payload: ByteArray): Channel {
    val value = JSONObject(String(payload, UTF_8))
    val mode = ChannelMode.entries.single { it.wire == value.getString("mode") }
    val label = value.getString("label")
    val epoch = targetEpoch(value)
    return if (mode == ChannelMode.RELIABLE_STREAM) {
        ByteStream(this, parent, handle, label, epoch)
    } else {
        MessageChannel(this, parent, handle, label, mode, epoch)
    }
}
