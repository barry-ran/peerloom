package io.peerloom.sdk

import org.json.JSONObject

/**
 * Explicit host storage injection. The SDK invokes this on its bounded IO pool, never the UI
 * thread. Implement whole-record encrypted load/save/delete CAS; delete retains a tombstone
 * revision. Throw IdentityStore.Conflict only for a revision conflict. Other errors fail closed.
 * Native timeout does not roll back a possibly committed operation: a later load must return the
 * old or complete new snapshot, never partial state. Never log request credentials or auto-reset
 * missing keys. The default adapter remains Android Keystore, without plaintext fallback.
 */
fun interface IdentityStorage {
    fun execute(request: JSONObject): JSONObject
}
