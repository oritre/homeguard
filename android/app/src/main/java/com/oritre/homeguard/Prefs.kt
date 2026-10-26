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

    /** Apps we suspended (blocked) ourselves, so we know what to release again. */
    var suspendedApps: Set<String>
        get() = sp.getStringSet("suspended", emptySet())?.toSet() ?: emptySet()
        set(v) = sp.edit().putStringSet("suspended", v).apply()

    /** "Works even without internet" apps; kept so the rule holds after a restart, before the server answers. */
    var alwaysApps: Set<String>
        get() = sp.getStringSet("always_apps", emptySet())?.toSet() ?: emptySet()
        set(v) = sp.edit().putStringSet("always_apps", v).apply()

    /** Last /update request from the bot that this device has handled. */
    var updateSeq: Int
        get() = sp.getInt("update_seq", -1)
        set(v) = sp.edit().putInt("update_seq", v).apply()

    var lastUpdateCheck: Long
        get() = sp.getLong("update_check", 0)
        set(v) = sp.edit().putLong("update_check", v).apply()

    /** Wall clock of the last poll, to notice when HomeGuard wasn't running ([LockWatch]). */
    var lastAlive: Long
        get() = sp.getLong("last_alive", 0)
        set(v) = sp.edit().putLong("last_alive", v).apply()

    /** Wall clock when the last approved time ends (or ended). */
    var sessionEnds: Long
        get() = sp.getLong("session_ends", 0)
        set(v) = sp.edit().putLong("session_ends", v).apply()

    val configured: Boolean
        get() = token.isNotEmpty() && deviceName.isNotEmpty() && (homeUrl.isNotEmpty() || remoteUrl.isNotEmpty())
}
