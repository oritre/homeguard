package com.oritre.homeguard

import android.content.Context

/** Settings entered once by a parent on the setup screen. */
class Prefs(context: Context) {
    private val sp = context.createDeviceProtectedStorageContext()
        .getSharedPreferences("homeguard", Context.MODE_PRIVATE)

    var homeUrl: String
        get() = sp.getString("home_url", "") ?: ""
        set(v) = sp.edit().putString("home_url", v.trim().trimEnd('/')).apply()

    var remoteUrl: String
        get() = sp.getString("remote_url", "") ?: ""
        set(v) = sp.edit().putString("remote_url", v.trim().trimEnd('/')).apply()

    var token: String
        get() = sp.getString("token", "") ?: ""
        set(v) = sp.edit().putString("token", v.trim()).apply()

    var deviceName: String
        get() = sp.getString("device", "") ?: ""
        set(v) = sp.edit().putString("device", v.trim()).apply()

    var parentPin: String
        get() = sp.getString("pin", "") ?: ""
        set(v) = sp.edit().putString("pin", v.trim()).apply()

    var upstreamDns: String
        get() = sp.getString("dns", "1.1.1.3") ?: "1.1.1.3"
        set(v) = sp.edit().putString("dns", v.trim()).apply()

    val configured: Boolean
        get() = token.isNotEmpty() && deviceName.isNotEmpty() && (homeUrl.isNotEmpty() || remoteUrl.isNotEmpty())
}
