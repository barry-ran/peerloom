package io.peerloom.sdk

import android.content.Context

/** Internal bridge; consumers use PeerloomSdk. Kept from shrinking by consumer rules. */
object Native {
    init {
        System.loadLibrary("peerloom_android")
    }

    @JvmStatic external fun initialize(application: Context): Int

    @JvmStatic external fun create(config: ByteArray, receiver: PeerloomSdk): LongArray

    @JvmStatic
    external fun submit(sdk: Long, operation: Int, connection: Long, input: ByteArray): LongArray

    @JvmStatic
    external fun channelSubmit(
        sdk: Long,
        connection: Long,
        channel: Long,
        operation: Int,
        input: ByteArray,
    ): LongArray

    @JvmStatic external fun channelValid(sdk: Long, connection: Long, channel: Long): Int

    @JvmStatic external fun cancel(sdk: Long, request: Long): Int

    @JvmStatic
    external fun storageComplete(sdk: Long, request: Long, status: Int, input: ByteArray): Int

    @JvmStatic external fun shutdown(sdk: Long): Int

    @JvmStatic external fun release(sdk: Long): Int

    @JvmStatic external fun connectionValid(sdk: Long, connection: Long): Int

    @JvmStatic external fun liveClients(): Int
}
