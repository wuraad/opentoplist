package com.opentoplist.vpn

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

class ConnectionStateMachine(
    private val maxRetry: Int = 4
) {
    var state: ConnectionState = ConnectionState.IDLE
        private set

    private var retryCount: Int = 0

    fun onStartConnect() {
        retryCount = 0
        state = ConnectionState.AUTHENTICATING
    }

    fun onAuthSuccess() {
        state = ConnectionState.FETCHING_NODE
    }

    fun onNodeFetched() {
        state = ConnectionState.CONNECTING
    }

    fun onConnected() {
        state = ConnectionState.CONNECTED
    }

    fun onConnectFailure() {
        retryCount += 1
        state = if (retryCount <= maxRetry) {
            ConnectionState.RETRY_WAITING
        } else {
            ConnectionState.SWITCHING_NODE
        }
    }

    fun onNodeSwitchDone() {
        retryCount = 0
        state = ConnectionState.CONNECTING
    }

    fun onFatalError() {
        state = ConnectionState.FAILED
    }

    fun shouldSwitchForWeakNetwork(metrics: NetworkMetrics): Boolean {
        return metrics.latencyMs > 350 || metrics.packetLossRatio > 0.08 || metrics.jitterMs > 80
    }
}
