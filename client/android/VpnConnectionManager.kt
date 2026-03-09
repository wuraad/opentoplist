package com.opentoplist.vpn

import kotlinx.coroutines.*

class VpnConnectionManager(
    private val api: VpnApiClient,
    private val eventSink: EventSink? = null
) {
    private val stateMachine = ConnectionStateMachine(eventSink = eventSink)
    private var currentSessionId: String? = null
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    val state: ConnectionState get() = stateMachine.state

    fun connect(userId: String, password: String, deviceId: String, preferRegion: String? = null) {
        scope.launch {
            stateMachine.onStartConnect()

            val loginResult = api.login(userId, password, deviceId)
            if (!loginResult.ok) {
                stateMachine.onFatalError(loginResult.body["message"] as? String)
                return@launch
            }
            stateMachine.onAuthSuccess()

            val routeResult = api.routeNode(preferRegion)
            if (!routeResult.ok) {
                stateMachine.onFatalError(routeResult.body["message"] as? String)
                return@launch
            }

            @Suppress("UNCHECKED_CAST")
            val node = routeResult.body["node"] as? Map<String, Any?> ?: run {
                stateMachine.onFatalError("no_node_data")
                return@launch
            }
            val nodeId = node["node_id"] as? String ?: return@launch
            stateMachine.onNodeFetched(nodeId)

            val peerResult = api.allocatePeer(nodeId, generateKeyPlaceholder(), deviceId)
            if (!peerResult.ok) {
                stateMachine.onConnectFailure("peer_allocation_failed")
                retryLoop(userId, password, deviceId, preferRegion)
                return@launch
            }

            val sessionResult = api.registerSession(nodeId, "auto")
            currentSessionId = sessionResult.body["session_id"] as? String

            stateMachine.onConnected()
        }
    }

    fun disconnect() {
        scope.launch {
            currentSessionId?.let { api.endSession(it) }
            currentSessionId = null
            api.logout()
        }
    }

    private suspend fun retryLoop(
        userId: String, password: String, deviceId: String, preferRegion: String?
    ) {
        while (stateMachine.state == ConnectionState.RETRY_WAITING) {
            val delayMs = stateMachine.retryDelayMs()
            delay(delayMs)
            stateMachine.onRetryReady()

            val routeResult = api.routeNode(preferRegion)
            if (routeResult.ok) {
                @Suppress("UNCHECKED_CAST")
                val node = routeResult.body["node"] as? Map<String, Any?>
                val nodeId = node?.get("node_id") as? String
                if (nodeId != null) {
                    val peerResult = api.allocatePeer(nodeId, generateKeyPlaceholder(), deviceId)
                    if (peerResult.ok) {
                        stateMachine.onNodeFetched(nodeId)
                        stateMachine.onConnected()
                        return
                    }
                }
            }
            stateMachine.onConnectFailure("retry_failed")

            if (stateMachine.state == ConnectionState.SWITCHING_NODE) {
                val switchResult = api.routeNode(null)
                if (switchResult.ok) {
                    @Suppress("UNCHECKED_CAST")
                    val newNode = switchResult.body["node"] as? Map<String, Any?>
                    stateMachine.onNodeSwitchDone(newNode?.get("node_id") as? String)
                } else {
                    stateMachine.onFatalError("all_nodes_exhausted")
                    return
                }
            }
        }
    }

    private fun generateKeyPlaceholder(): String = "placeholder-public-key-${System.currentTimeMillis()}"
}
