package io.peerloom.sdk

import org.junit.Assert.*
import org.junit.Test

class ConfigurationTest {
    @Test
    fun customIceEncodingAndRedaction() {
        val config = PeerloomConfiguration("https://localhost", "test")
        assertFalse(config.json().has("ice_servers"))
        assertEquals(0, config.copy(iceServers = emptyList()).json().getJSONArray("ice_servers").length())
        val server = PeerloomIceServer(listOf("turn:example.com:3478"), "test-user", "test-only")
        val custom = config.copy(iceServers = listOf(server))
        assertEquals("test-only", custom.json().getJSONArray("ice_servers").getJSONObject(0).getString("credential"))
        assertFalse(server.toString().contains("test-only"))
        assertFalse(custom.toString().contains("test-only"))
    }
}
