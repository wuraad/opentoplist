package com.opentoplist.vpn

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

data class ApiResult(
    val ok: Boolean,
    val statusCode: Int,
    val body: Map<String, Any?>,
    val rawBody: String
)

class VpnApiClient(
    private val baseUrl: String = "https://api.opentoplist.com",
    private var token: String? = null
) {
    fun setToken(t: String) { token = t }
    fun clearToken() { token = null }

    fun register(userId: String, password: String, plan: String = "free"): ApiResult {
        return post("/v1/auth/register", mapOf("user_id" to userId, "password" to password, "plan" to plan))
    }

    fun login(userId: String, password: String, deviceId: String): ApiResult {
        val result = post("/v1/auth/token", mapOf(
            "user_id" to userId, "password" to password, "device_id" to deviceId
        ))
        if (result.ok) {
            (result.body["token"] as? String)?.let { setToken(it) }
            (result.body["jwt"] as? String)?.let { setToken(it) }
        }
        return result
    }

    fun logout(): ApiResult = post("/v1/auth/logout", emptyMap())

    fun changePassword(oldPassword: String, newPassword: String): ApiResult {
        return post("/v1/auth/change-password", mapOf("old_password" to oldPassword, "new_password" to newPassword))
    }

    fun listNodes(region: String? = null): ApiResult {
        val path = if (region != null) "/v1/nodes?region=$region" else "/v1/nodes"
        return get(path)
    }

    fun routeNode(region: String? = null): ApiResult {
        val path = if (region != null) "/v1/nodes/route?region=$region" else "/v1/nodes/route"
        return get(path)
    }

    fun registerSession(nodeId: String, egressIp: String): ApiResult {
        return post("/v1/sessions/register", mapOf("node_id" to nodeId, "egress_ip" to egressIp))
    }

    fun endSession(sessionId: String): ApiResult {
        return post("/v1/sessions/end", mapOf("session_id" to sessionId))
    }

    fun allocatePeer(nodeId: String, clientPublicKey: String, deviceId: String = "default"): ApiResult {
        return post("/v1/gateway/peers/allocate", mapOf(
            "node_id" to nodeId, "client_public_key" to clientPublicKey, "device_id" to deviceId
        ))
    }

    fun revokePeer(nodeId: String, deviceId: String = "default"): ApiResult {
        return post("/v1/gateway/peers/revoke", mapOf("node_id" to nodeId, "device_id" to deviceId))
    }

    fun getPolicy(): ApiResult = get("/v1/users/me/policy")

    private fun get(path: String): ApiResult = request("GET", path)
    private fun post(path: String, body: Map<String, Any?>): ApiResult = request("POST", path, body)

    private fun request(method: String, path: String, body: Map<String, Any?>? = null): ApiResult {
        val url = URL("$baseUrl$path")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.setRequestProperty("Content-Type", "application/json")
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000

        token?.let { conn.setRequestProperty("Authorization", "Bearer $it") }

        if (body != null && method == "POST") {
            conn.doOutput = true
            OutputStreamWriter(conn.outputStream).use { it.write(toJson(body)) }
        }

        val statusCode = conn.responseCode
        val stream = if (statusCode < 400) conn.inputStream else conn.errorStream
        val rawBody = BufferedReader(InputStreamReader(stream ?: conn.inputStream)).use { it.readText() }

        val parsed = parseJson(rawBody)
        val ok = parsed["ok"] as? Boolean ?: (statusCode in 200..299)
        return ApiResult(ok = ok, statusCode = statusCode, body = parsed, rawBody = rawBody)
    }

    private fun toJson(map: Map<String, Any?>): String {
        return "{" + map.entries.joinToString(",") { (k, v) ->
            "\"$k\":${valueToJson(v)}"
        } + "}"
    }

    private fun valueToJson(v: Any?): String = when (v) {
        null -> "null"
        is String -> "\"$v\""
        is Number -> v.toString()
        is Boolean -> v.toString()
        else -> "\"$v\""
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseJson(raw: String): Map<String, Any?> {
        return try {
            org.json.JSONObject(raw).toMap()
        } catch (_: Exception) {
            mapOf("raw" to raw)
        }
    }

    private fun org.json.JSONObject.toMap(): Map<String, Any?> {
        val map = mutableMapOf<String, Any?>()
        keys().forEach { key -> map[key] = get(key) }
        return map
    }
}
