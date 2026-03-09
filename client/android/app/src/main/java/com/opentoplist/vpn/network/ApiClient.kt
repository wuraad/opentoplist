package com.opentoplist.vpn.network

import com.opentoplist.vpn.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

class ApiClient(private val baseUrl: String) {

    private var token: String? = null

    fun setToken(t: String) { token = t }
    fun clearToken() { token = null }
    fun hasToken(): Boolean = token != null

    // ── Auth ─────────────────────────────────────────────────

    suspend fun register(userId: String, password: String, plan: String = "free"): AuthResponse {
        val body = JSONObject().apply {
            put("user_id", userId); put("password", password); put("plan", plan)
        }
        val resp = post("/v1/auth/register", body, auth = false)
        return AuthResponse(
            ok = resp.optBoolean("ok"),
            message = resp.optString("message", null)
        )
    }

    suspend fun login(userId: String, password: String, deviceId: String): AuthResponse {
        val body = JSONObject().apply {
            put("user_id", userId); put("password", password); put("device_id", deviceId)
        }
        val resp = post("/v1/auth/token", body, auth = false)
        val authResp = AuthResponse(
            ok = resp.optBoolean("ok"),
            token = resp.optString("token", null),
            jwt = resp.optString("jwt", null),
            message = resp.optString("message", null)
        )
        if (authResp.ok) {
            token = authResp.jwt ?: authResp.token
        }
        return authResp
    }

    suspend fun logout(): ApiResponse {
        val resp = post("/v1/auth/logout", JSONObject())
        clearToken()
        return ApiResponse(ok = resp.optBoolean("ok"))
    }

    suspend fun changePassword(oldPassword: String, newPassword: String): ApiResponse {
        val body = JSONObject().apply {
            put("old_password", oldPassword); put("new_password", newPassword)
        }
        val resp = post("/v1/auth/change-password", body)
        return ApiResponse(ok = resp.optBoolean("ok"), message = resp.optString("message", null))
    }

    // ── Nodes ────────────────────────────────────────────────

    suspend fun routeNode(region: String? = null): VpnNode? {
        val path = if (region != null) "/v1/nodes/route?region=$region" else "/v1/nodes/route"
        val resp = get(path)
        if (!resp.optBoolean("ok")) return null
        val n = resp.getJSONObject("node")
        return VpnNode(
            node_id = n.getString("node_id"), region = n.getString("region"),
            endpoint = n.getString("endpoint"), capacity = n.getInt("capacity"),
            current_load = n.getInt("current_load"),
            avg_latency_ms = n.getInt("avg_latency_ms"),
            healthy = n.getBoolean("healthy")
        )
    }

    // ── Gateway ──────────────────────────────────────────────

    suspend fun allocatePeer(nodeId: String, clientPublicKey: String, deviceId: String): PeerConfig? {
        val body = JSONObject().apply {
            put("node_id", nodeId); put("client_public_key", clientPublicKey); put("device_id", deviceId)
        }
        val resp = post("/v1/gateway/peers/allocate", body)
        if (!resp.optBoolean("ok")) return null
        val iface = resp.getJSONObject("interface")
        val peer = resp.getJSONObject("peer")
        return PeerConfig(
            address = iface.getString("address"),
            dns = iface.getString("dns"),
            serverPublicKey = peer.getString("public_key"),
            endpoint = peer.getString("endpoint"),
            allowedIps = peer.getString("allowed_ips"),
            keepalive = peer.getInt("persistent_keepalive")
        )
    }

    suspend fun revokePeer(nodeId: String, deviceId: String): ApiResponse {
        val body = JSONObject().apply { put("node_id", nodeId); put("device_id", deviceId) }
        val resp = post("/v1/gateway/peers/revoke", body)
        return ApiResponse(ok = resp.optBoolean("ok"))
    }

    // ── Sessions ─────────────────────────────────────────────

    suspend fun registerSession(nodeId: String, egressIp: String): SessionInfo? {
        val body = JSONObject().apply { put("node_id", nodeId); put("egress_ip", egressIp) }
        val resp = post("/v1/sessions/register", body)
        return SessionInfo(
            session_id = resp.optString("session_id", ""),
            node_id = resp.optString("node_id", ""),
            egress_ip = resp.optString("egress_ip", "")
        )
    }

    suspend fun endSession(sessionId: String): ApiResponse {
        val body = JSONObject().apply { put("session_id", sessionId) }
        val resp = post("/v1/sessions/end", body)
        return ApiResponse(ok = resp.optBoolean("ok"))
    }

    // ── HTTP ─────────────────────────────────────────────────

    private suspend fun get(path: String): JSONObject = withContext(Dispatchers.IO) {
        request("GET", path, null)
    }

    private suspend fun post(path: String, body: JSONObject, auth: Boolean = true): JSONObject =
        withContext(Dispatchers.IO) { request("POST", path, body, auth) }

    private fun request(method: String, path: String, body: JSONObject?, auth: Boolean = true): JSONObject {
        val conn = (URL("$baseUrl$path").openConnection() as HttpURLConnection).apply {
            requestMethod = method
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = 10_000
            readTimeout = 10_000
            if (auth) token?.let { setRequestProperty("Authorization", "Bearer $it") }
            if (body != null && method == "POST") {
                doOutput = true
                OutputStreamWriter(outputStream).use { it.write(body.toString()) }
            }
        }
        val stream = try { conn.inputStream } catch (_: Exception) { conn.errorStream }
        val raw = BufferedReader(InputStreamReader(stream ?: return JSONObject())).use { it.readText() }
        return try { JSONObject(raw) } catch (_: Exception) { JSONObject().put("raw", raw) }
    }
}
