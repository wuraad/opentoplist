package com.opentoplist.vpn.ui

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.opentoplist.vpn.BuildConfig
import com.opentoplist.vpn.VpnApp
import com.opentoplist.vpn.databinding.ActivityLoginBinding
import kotlinx.coroutines.launch

class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        if (VpnApp.api.hasToken()) {
            startMain()
            return
        }

        binding.btnLogin.setOnClickListener { doLogin() }
        binding.btnRegister.setOnClickListener { doRegister() }
    }

    private fun doLogin() {
        val userId = binding.etUserId.text.toString().trim()
        val password = binding.etPassword.text.toString()

        if (userId.isBlank() || password.isBlank()) {
            showError("请输入用户名和密码")
            return
        }

        setLoading(true)
        lifecycleScope.launch {
            try {
                val deviceId = "${android.os.Build.MANUFACTURER}-${android.os.Build.MODEL}"
                    .replace(" ", "-").take(32)
                val result = VpnApp.api.login(userId, password, deviceId)
                if (result.ok) {
                    getSharedPreferences("vpn", MODE_PRIVATE).edit()
                        .putString("user_id", userId)
                        .apply()
                    startMain()
                } else {
                    showError(when (result.message) {
                        "invalid_credentials" -> "用户名或密码错误"
                        "device_limit_exceeded" -> "设备数量已达上限（最多3台）"
                        else -> result.message ?: "登录失败"
                    })
                }
            } catch (e: Exception) {
                showError("网络连接失败: ${e.message}")
            } finally {
                setLoading(false)
            }
        }
    }

    private fun doRegister() {
        val userId = binding.etUserId.text.toString().trim()
        val password = binding.etPassword.text.toString()

        if (userId.isBlank() || password.isBlank()) {
            showError("请输入用户名和密码")
            return
        }
        if (password.length < 6) {
            showError("密码至少6位")
            return
        }

        setLoading(true)
        lifecycleScope.launch {
            try {
                val result = VpnApp.api.register(userId, password)
                if (result.ok) {
                    showError("")
                    doLogin()
                } else {
                    showError(when (result.message) {
                        "user_already_exists" -> "用户名已被注册"
                        else -> result.message ?: "注册失败"
                    })
                    setLoading(false)
                }
            } catch (e: Exception) {
                showError("网络连接失败: ${e.message}")
                setLoading(false)
            }
        }
    }

    private fun startMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }

    private fun setLoading(loading: Boolean) {
        runOnUiThread {
            binding.progress.visibility = if (loading) View.VISIBLE else View.GONE
            binding.btnLogin.isEnabled = !loading
            binding.btnRegister.isEnabled = !loading
        }
    }

    private fun showError(msg: String) {
        runOnUiThread {
            binding.tvError.text = msg
            binding.tvError.visibility = if (msg.isNotBlank()) View.VISIBLE else View.GONE
        }
    }
}
