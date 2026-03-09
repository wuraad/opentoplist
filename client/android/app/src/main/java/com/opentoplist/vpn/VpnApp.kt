package com.opentoplist.vpn

import android.app.Application
import com.opentoplist.vpn.network.ApiClient
import com.opentoplist.vpn.vpn.VpnConnectionManager

class VpnApp : Application() {
    companion object {
        lateinit var api: ApiClient
            private set
        lateinit var connectionManager: VpnConnectionManager
            private set
    }

    override fun onCreate() {
        super.onCreate()
        api = ApiClient(BuildConfig.API_BASE_URL)
        connectionManager = VpnConnectionManager(this, api)
    }
}
