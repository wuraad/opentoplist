package com.opentoplist.vpn.vpn

import android.content.Context
import android.content.Intent
import com.opentoplist.vpn.model.*
import com.opentoplist.vpn.network.ApiClient
import com.wireguard.crypto.KeyPair
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.math.min

class VpnConnectionManager(
    private val context: Context,
    private val api: ApiClient
) {
    private val _state = MutableStateFlow(ConnectionState.DISCONNECTED)
    val state: StateFlow<ConnectionState> = _state

    private val _statusText = MutableStateFlow("")
    val statusText: StateFlow<String> = _statusText

    private var currentNode: VpnNode? = null
    private var currentSession: SessionInfo? = null
    private var currentPeer: PeerConfig? = null
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var retryCount = 0
    private val maxRetries = 4

    fun connect(preferRegion: String? = null) {
        scope.launch {
            retryCount = 0
            doConnect(preferRegion)
        }
    }

    private suspend fun doConnect(preferRegion: String?) {
        _state.value = ConnectionState.FETCHING_NODE
        _statusText.value = "正在选择最优节点..."

        val node = api.routeNode(preferRegion)
        if (node == null) {
            _state.value = ConnectionState.ERROR
            _statusText.value = "无可用节点"
            return
        }
        currentNode = node
        _statusText.value = "节点: ${node.region} (${node.node_id})"

        _state.value = ConnectionState.ALLOCATING_PEER
        _statusText.value = "正在分配隧道..."

        val keyPair = KeyPair()
        val deviceId = android.os.Build.MODEL.replace(" ", "-")
        val peer = api.allocatePeer(node.node_id, keyPair.publicKey.toBase64(), deviceId)
        if (peer == null) {
            handleConnectFailure(preferRegion)
            return
        }
        currentPeer = peer

        _state.value = ConnectionState.CONNECTING
        _statusText.value = "正在建立隧道..."

        val wgConfig = OpenTopVpnService.buildWgConfig(peer, keyPair.privateKey.toBase64())
        val intent = Intent(context, OpenTopVpnService::class.java).apply {
            action = OpenTopVpnService.ACTION_CONNECT
            putExtra(OpenTopVpnService.EXTRA_CONFIG, wgConfig)
        }
        context.startForegroundService(intent)

        val session = api.registerSession(node.node_id, peer.address.split("/")[0])
        currentSession = session

        _state.value = ConnectionState.CONNECTED
        _statusText.value = "已连接 ${node.region.uppercase()} · ${peer.address}"
    }

    private suspend fun handleConnectFailure(preferRegion: String?) {
        retryCount++
        if (retryCount > maxRetries) {
            _state.value = ConnectionState.ERROR
            _statusText.value = "连接失败，已重试 $maxRetries 次"
            return
        }
        val delayMs = min(1000L * (1L shl (retryCount - 1)), 20_000L)
        _statusText.value = "重试中 ($retryCount/$maxRetries)..."
        delay(delayMs)
        doConnect(preferRegion)
    }

    fun disconnect() {
        scope.launch {
            _state.value = ConnectionState.DISCONNECTING
            _statusText.value = "正在断开..."

            currentSession?.let { api.endSession(it.session_id) }
            currentNode?.let { node ->
                val deviceId = android.os.Build.MODEL.replace(" ", "-")
                api.revokePeer(node.node_id, deviceId)
            }

            val intent = Intent(context, OpenTopVpnService::class.java).apply {
                action = OpenTopVpnService.ACTION_DISCONNECT
            }
            context.startService(intent)

            currentNode = null
            currentSession = null
            currentPeer = null
            _state.value = ConnectionState.DISCONNECTED
            _statusText.value = "已断开"
        }
    }
}
