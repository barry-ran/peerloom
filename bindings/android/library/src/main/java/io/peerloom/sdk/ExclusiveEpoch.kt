package io.peerloom.sdk

import org.json.JSONObject

// Metadata is descriptive only. Native validity remains the authorization gate.
internal fun canonicalTargetEpoch(value: String): Boolean {
    val epoch = value.toLongOrNull() ?: return false
    return epoch > 0 && epoch.toString() == value
}

internal fun targetEpoch(value: JSONObject): String? {
    val fields = arrayOf("exclusive_target", "exclusive_protocol_version", "target_epoch")
    if (fields.none { value.has(it) }) return null
    if (fields.any { !value.has(it) || value.isNull(it) }) throw PeerloomException(1)
    val flag = value.get("exclusive_target")
    val version = value.get("exclusive_protocol_version")
    val epoch = value.get("target_epoch")
    if (
        flag != true ||
            (version !is Int && version !is Long) ||
            (version as Number).toLong() != 1L ||
            epoch !is String ||
            !canonicalTargetEpoch(epoch)
    ) {
        throw PeerloomException(1)
    }
    return epoch
}

internal fun requireExclusiveCapability(capabilities: Long) {
    if (capabilities and 256L == 0L) throw PeerloomException(7)
}
