package com.opentoplist.vpn.ui

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.ArrayAdapter
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.opentoplist.vpn.R
import com.opentoplist.vpn.VpnApp
import com.opentoplist.vpn.databinding.ActivityMainBinding
import com.opentoplist.vpn.model.ConnectionState
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val regions = listOf("自动选择" to null, "新加坡" to "sg", "日本" to "jp", "美国" to "us")
    private var connected = false

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpn()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        val userId = getSharedPreferences("vpn", MODE_PRIVATE).getString("user_id", "用户") ?: "用户"
        binding.tvWelcome.text = "欢迎, $userId"

        binding.spinnerRegion.adapter = ArrayAdapter(
            this, android.R.layout.simple_spinner_dropdown_item,
            regions.map { it.first }
        )

        binding.btnConnect.setOnClickListener {
            if (connected) {
                VpnApp.connectionManager.disconnect()
            } else {
                requestVpnPermission()
            }
        }

        binding.btnLogout.setOnClickListener {
            lifecycleScope.launch {
                if (connected) VpnApp.connectionManager.disconnect()
                VpnApp.api.logout()
                getSharedPreferences("vpn", MODE_PRIVATE).edit().clear().apply()
                startActivity(Intent(this@MainActivity, LoginActivity::class.java))
                finish()
            }
        }

        observeState()
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermission.launch(intent)
        } else {
            startVpn()
        }
    }

    private fun startVpn() {
        val selectedRegion = regions[binding.spinnerRegion.selectedItemPosition].second
        VpnApp.connectionManager.connect(selectedRegion)
    }

    private fun observeState() {
        lifecycleScope.launch {
            VpnApp.connectionManager.state.collectLatest { state ->
                runOnUiThread {
                    connected = state == ConnectionState.CONNECTED
                    binding.btnConnect.text = if (connected) "断  开" else "连  接"
                    binding.tvState.text = when (state) {
                        ConnectionState.DISCONNECTED -> "未连接"
                        ConnectionState.AUTHENTICATING -> "认证中..."
                        ConnectionState.FETCHING_NODE -> "选择节点..."
                        ConnectionState.ALLOCATING_PEER -> "分配隧道..."
                        ConnectionState.CONNECTING -> "建立连接..."
                        ConnectionState.CONNECTED -> "已连接"
                        ConnectionState.DISCONNECTING -> "断开中..."
                        ConnectionState.ERROR -> "连接失败"
                    }
                    binding.ivStatus.setColorFilter(
                        getColor(if (connected) R.color.connected else R.color.text_secondary)
                    )
                }
            }
        }
        lifecycleScope.launch {
            VpnApp.connectionManager.statusText.collectLatest { text ->
                runOnUiThread { binding.tvStatusDetail.text = text }
            }
        }
    }
}
