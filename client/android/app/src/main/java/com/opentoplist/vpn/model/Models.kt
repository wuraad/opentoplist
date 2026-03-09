package com.opentoplist.vpn.model

data class LoginRequest(val user_id: String, val password: String, val device_id: String)
data class RegisterRequest(val user_id: String, val password: String, val plan: String = "free")

data class AuthResponse(val ok: Boolean, val token: String? = null, val jwt: String? = null, val message: String? = null)
data class ApiResponse(val ok: Boolean, val message: String? = null)

data class VpnNode(
    val node_id: String,
    val region: String,
    val endpoint: String,
    val capacity: Int,
    val current_load: Int,
    val avg_latency_ms: Int,
    val healthy: Boolean
)

data class PeerConfig(
    val address: String,
    val dns: String,
    val serverPublicKey: String,
    val endpoint: String,
    val allowedIps: String,
    val keepalive: Int
)

data class SessionInfo(val session_id: String, val node_id: String, val egress_ip: String)

enum class ConnectionState {
    DISCONNECTED, AUTHENTICATING, FETCHING_NODE, ALLOCATING_PEER,
    CONNECTING, CONNECTED, DISCONNECTING, ERROR
}
