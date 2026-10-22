package com.oritre.homeguard

import android.app.Activity
import android.content.pm.LauncherApps
import android.os.Bundle
import android.util.Log

/**
 * "Add to home screen" requests reach the default launcher, which is [HomeGate]. Without this,
 * Android reports pinning as unsupported and Chrome hides "Install app" for web apps. We accept
 * the request right away; an installed web app (WebAPK) shows up in the phone's own app drawer.
 */
class PinShortcutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            val request = getSystemService(LauncherApps::class.java).getPinItemRequest(intent)
            if (request != null && request.isValid) request.accept()
        } catch (e: Exception) {
            Log.w("HomeGuard", "pin shortcut", e)
        }
        finish()
    }
}
