package io.peerloom.sdk

import org.json.JSONObject

/**
 * Count caps are optional; the resource budget is separately applied to native and host storage.
 */
data class PeerloomConfiguration(
    val origin: String,
    val applicationId: String,
    val developmentLoopback: Boolean = false,
    val autoReconnect: Boolean = true,
    val maxConnections: Long = 0,
    val maxChannelsPerConnection: Long = 0,
    val maxChannelCreationsPerConnection: Long = 0,
    val ffiResourceBudgetBytes: Long = 134217728L,
) {
    init {
        require(
            maxConnections >= 0 &&
                maxChannelsPerConnection >= 0 &&
                maxChannelCreationsPerConnection >= 0
        )
        require(ffiResourceBudgetBytes >= 2097152L)
    }

    fun json(): JSONObject =
        JSONObject()
            .put("origin", origin)
            .put("application_id", applicationId)
            .put("development_loopback", developmentLoopback)
            .put("auto_reconnect", autoReconnect)
            .put("max_connections", maxConnections)
            .put("max_channels_per_connection", maxChannelsPerConnection)
            .put("max_channel_creations_per_connection", maxChannelCreationsPerConnection)
            .put("ffi_resource_budget_bytes", ffiResourceBudgetBytes)
}
