package io.peerloom.sdk

import org.json.JSONObject
import org.json.JSONArray

/** 原生库统一校验 URL 和支持的传输类型；诊断文本不包含凭据。 */
class PeerloomIceServer(
    val urls: List<String>,
    val username: String? = null,
    val credential: String? = null,
) {
    internal fun json(): JSONObject = JSONObject()
        .put("urls", JSONArray(urls))
        .apply {
            username?.let { put("username", it) }
            credential?.let { put("credential", it) }
        }

    override fun toString(): String = "PeerloomIceServer(redacted)"
}

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
    /** null 保持托管配置；空列表只使用 host 候选。 */
    val iceServers: List<PeerloomIceServer>? = null,
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
            .apply {
                iceServers?.let { servers ->
                    put("ice_servers", JSONArray().apply {
                        servers.forEach { put(it.json()) }
                    })
                }
            }
}
