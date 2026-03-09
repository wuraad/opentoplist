package com.opentoplist.vpn.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.opentoplist.vpn.model.PeerConfig
import com.wireguard.android.backend.GoBackend
import com.wireguard.config.Config
import com.wireguard.config.InetEndpoint
import com.wireguard.config.InetNetwork
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyPair

class OpenTopVpnService : VpnService() {

    private var tunnel: GoBackend.VpnService? = null
    private var backend: GoBackend? = null
    private var currentKeyPair: KeyPair? = null

    override fun onCreate() {
        super.onCreate()
        backend = GoBackend(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val configStr = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                connect(configStr)
            }
            ACTION_DISCONNECT -> disconnect()
        }
        return START_STICKY
    }

    fun generateKeyPair(): KeyPair {
        val kp = KeyPair()
        currentKeyPair = kp
        return kp
    }

    fun getPublicKey(): String = currentKeyPair?.publicKey?.toBase64() ?: ""

    private fun connect(configString: String) {
        try {
            val config = Config.parse(configString.byteInputStream())
            backend?.setState(
                object : com.wireguard.android.backend.Tunnel {
                    override fun getName() = "opentoplist"
                    override fun onStateChange(newState: com.wireguard.android.backend.Tunnel.State) {}
                },
                com.wireguard.android.backend.Tunnel.State.UP,
                config
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun disconnect() {
        try {
            backend?.setState(
                object : com.wireguard.android.backend.Tunnel {
                    override fun getName() = "opentoplist"
                    override fun onStateChange(newState: com.wireguard.android.backend.Tunnel.State) {}
                },
                com.wireguard.android.backend.Tunnel.State.DOWN,
                null
            )
        } catch (e: Exception) {
            e.printStackTrace()
        }
        stopSelf()
    }

    override fun onDestroy() {
        disconnect()
        super.onDestroy()
    }

    companion object {
        const val ACTION_CONNECT = "com.opentoplist.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.opentoplist.vpn.DISCONNECT"
        const val EXTRA_CONFIG = "wg_config"

        fun buildWgConfig(peerConfig: PeerConfig, privateKey: String): String {
            return """
                |[Interface]
                |PrivateKey = $privateKey
                |Address = ${peerConfig.address}
                |DNS = ${peerConfig.dns}
                |
                |[Peer]
                |PublicKey = ${peerConfig.serverPublicKey}
                |Endpoint = ${peerConfig.endpoint}
                |AllowedIPs = ${peerConfig.allowedIps}
                |PersistentKeepalive = ${peerConfig.keepalive}
            """.trimMargin()
        }
    }
}
