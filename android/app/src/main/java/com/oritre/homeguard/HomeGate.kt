package com.oritre.homeguard

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.TextView

/**
 * HomeGuard's home screen (set for good by the device owner). After a restart, and on every
 * press of the home button, the device lands here first: this starts the guard right away and,
 * while the device is locked, stays as a locked screen. Once a parent approves, it hands over
 * to the phone's own launcher.
 */
class HomeGate : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private val check = object : Runnable {
        override fun run() {
            if (!locked()) forward() else main.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "🛡️ המכשיר נעול"
            textSize = 28f
            setTextColor(Color.parseColor("#F2F4F8"))
            setBackgroundColor(Color.parseColor("#1D2433"))
            gravity = Gravity.CENTER
        })
    }

    override fun onResume() {
        super.onResume()
        val prefs = Prefs(this)
        if (!prefs.configured) { forward(); return }
        try { GuardService.start(this) } catch (_: Exception) {}
        main.removeCallbacks(check)
        if (locked()) main.postDelayed(check, 1000) else forward()
    }

    override fun onPause() {
        main.removeCallbacks(check)
        super.onPause()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() { /* this is the home screen: back does nothing */ }

    private fun locked(): Boolean {
        val svc = GuardService.instance ?: return true
        return svc.vpnRevoked || svc.session() == null
    }

    private fun forward() {
        val launcher = AppControl.realLauncher(this) ?: return
        try {
            startActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
                .setComponent(launcher).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: Exception) {}
    }
}
