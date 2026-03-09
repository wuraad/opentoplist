package com.opentoplist.vpn

import kotlin.math.min

enum class ConnectionState {
    IDLE,
    AUTHENTICATING,
    FETCHING_NODE,
    CONNECTING,
    CONNECTED,
    RETRY_WAITING,
    SWITCHING_NODE,
    FAILED
}

data class NetworkMetrics(
    val latencyMs: Int,
    val packetLossRatio: Double,
    val jitterMs: Int
)

data class NodeCandidate(
    val nodeId: String,
    val region: String,
    val endpoint: String,
    val latencyMs: Int,
    val packetLossRatio: Double,
    val jitterMs: Int
) {
    fun score(): Double =
        latencyMs * 0.5 + packetLossRatio * 40.0 + jitterMs * 0.5
}

data class ObservabilityEvent(
    val event: String,
    val nodeId: String? = null,
    val errorCode: String? = null,
    val latencyMs: Int? = null,
    val packetLoss: Double? = null,
    val networkType: String? = null,
    val extra: Map<String, String> = emptyMap()
)

interface EventSink {
    fun emit(event: ObservabilityEvent)
}

class ConnectionStateMachine(
    private val maxRetry: Int = 4,
    private val baseRetryMs: Long = 1000,
    private val maxRetryMs: Long = 20000,
    private val weakNetworkSustainMs: Long = 10000,
    private val eventSink: EventSink? = null
) {
    var state: ConnectionState = ConnectionState.IDLE
        private set

    private var retryCount: Int = 0
    private var weakNetworkSince: Long = 0
    private var currentNodeId: String? = null

    fun onStartConnect() {
        retryCount = 0
        weakNetworkSince = 0
        state = ConnectionState.AUTHENTICATING
        emit("vpn_connect_start")
    }

    fun onAuthSuccess() {
        state = ConnectionState.FETCHING_NODE
    }

    fun onNodeFetched(nodeId: String) {
        currentNodeId = nodeId
        state = ConnectionState.CONNECTING
    }

    fun onConnected() {
        state = ConnectionState.CONNECTED
        retryCount = 0
        emit("vpn_connect_success", nodeId = currentNodeId)
    }

    fun onConnectFailure(errorCode: String? = null) {
        retryCount += 1
        emit("vpn_connect_fail", nodeId = currentNodeId, errorCode = errorCode)
        state = if (retryCount <= maxRetry) {
            ConnectionState.RETRY_WAITING
        } else {
            ConnectionState.SWITCHING_NODE
        }
    }

    fun retryDelayMs(): Long {
        val delay = baseRetryMs * (1L shl (retryCount - 1).coerceAtLeast(0))
        return min(delay, maxRetryMs)
    }

    fun onRetryReady() {
        state = ConnectionState.CONNECTING
    }

    fun onNodeSwitchDone(newNodeId: String? = null) {
        emit("vpn_node_switch", nodeId = newNodeId)
        retryCount = 0
        currentNodeId = newNodeId
        state = ConnectionState.CONNECTING
    }

    fun onFatalError(errorCode: String? = null) {
        emit("vpn_connect_fail", nodeId = currentNodeId, errorCode = errorCode)
        state = ConnectionState.FAILED
    }

    fun shouldSwitchForWeakNetwork(metrics: NetworkMetrics, nowMs: Long): Boolean {
        val isWeak = metrics.latencyMs > 350 ||
                metrics.packetLossRatio > 0.08 ||
                metrics.jitterMs > 80

        if (!isWeak) {
            weakNetworkSince = 0
            return false
        }

        if (weakNetworkSince == 0L) {
            weakNetworkSince = nowMs
            emit(
                "vpn_weak_network_detected",
                nodeId = currentNodeId,
                latencyMs = metrics.latencyMs,
                packetLoss = metrics.packetLossRatio
            )
        }

        return (nowMs - weakNetworkSince) >= weakNetworkSustainMs
    }

    private fun emit(
        event: String,
        nodeId: String? = currentNodeId,
        errorCode: String? = null,
        latencyMs: Int? = null,
        packetLoss: Double? = null
    ) {
        eventSink?.emit(
            ObservabilityEvent(
                event = event,
                nodeId = nodeId,
                errorCode = errorCode,
                latencyMs = latencyMs,
                packetLoss = packetLoss
            )
        )
    }

    companion object {
        fun selectBestNode(
            candidates: List<NodeCandidate>,
            preferRegion: String? = null
        ): NodeCandidate? {
            if (candidates.isEmpty()) return null

            val sorted = candidates.sortedWith(
                compareBy<NodeCandidate> { it.score() }
                    .thenBy { if (it.region == preferRegion) 0 else 1 }
            )

            return sorted.first()
        }
    }
}
