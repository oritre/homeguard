package com.oritre.homeguard

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast

/** Parent-only setup screen: server address, token, device name, permissions. PIN protected. */
class SetupActivity : Activity() {
    companion object {
        const val EXTRA_FIX_VPN = "fix_vpn"
        private const val REQ_VPN = 10
    }

    private lateinit var prefs: Prefs
    private lateinit var box: LinearLayout
    private var unlocked = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        val scroll = ScrollView(this)
        box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 64, 48, 64)
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        scroll.addView(box)
        setContentView(scroll)
        if (intent.getBooleanExtra(EXTRA_FIX_VPN, false)) {
            requestVpn() // anyone may turn protection back on
        }
        if (prefs.parentPin.isEmpty()) {
            unlocked = true
            renderForm()
        } else {
            renderPin()
        }
    }

    override fun onResume() {
        super.onResume()
        if (unlocked) renderForm()
    }

    private fun title(t: String) = TextView(this).apply {
        text = t; textSize = 24f; setTextColor(Color.BLACK); setPadding(0, 0, 0, 24)
    }

    private fun label(t: String) = TextView(this).apply { text = t; textSize = 14f; setPadding(0, 20, 0, 4) }

    private fun field(value: String, hint: String, kind: Int = InputType.TYPE_CLASS_TEXT) = EditText(this).apply {
        setText(value); this.hint = hint; inputType = kind; setSingleLine()
        layoutDirection = View.LAYOUT_DIRECTION_LTR
        gravity = Gravity.START
    }

    private fun button(t: String, onClick: () -> Unit) = Button(this).apply { text = t; setOnClickListener { onClick() } }

    private fun renderPin() {
        box.removeAllViews()
        box.addView(title("🛡️ HomeGuard"))
        box.addView(label("קוד הורים"))
        val pin = field("", "קוד", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
        box.addView(pin)
        box.addView(button("כניסה להגדרות") {
            if (pin.text.toString() == prefs.parentPin) { unlocked = true; renderForm() }
            else Toast.makeText(this, "קוד שגוי", Toast.LENGTH_SHORT).show()
        })
    }

    private fun renderForm() {
        box.removeAllViews()
        box.addView(title("🛡️ הגדרות HomeGuard"))
        box.addView(label("כתובת השרת בבית"))
        val home = field(prefs.homeUrl.ifEmpty { "http://192.168.33.6:8800" }, "http://192.168.1.10:8800", InputType.TYPE_TEXT_VARIATION_URI)
        box.addView(home)
        box.addView(label("כתובת השרת מחוץ לבית (Tailscale Funnel)"))
        val remote = field(prefs.remoteUrl, "https://desktop.tailXXXX.ts.net", InputType.TYPE_TEXT_VARIATION_URI)
        box.addView(remote)
        box.addView(label("Agent token"))
        val token = field(prefs.token, "מהתקנת השרת")
        box.addView(token)
        box.addView(label("שם המכשיר (יופיע בטלגרם)"))
        val name = field(prefs.deviceName.ifEmpty { Build.MODEL }, "טלפון של אביתר")
        name.layoutDirection = View.LAYOUT_DIRECTION_RTL
        box.addView(name)
        box.addView(label("קוד הורים לפתיחת המסך הזה"))
        val pin = field(prefs.parentPin, "4 ספרות לפחות", InputType.TYPE_CLASS_NUMBER)
        box.addView(pin)

        box.addView(label("הרשאות (צריך את כולן)"))
        val overlayOk = Settings.canDrawOverlays(this)
        val vpnOk = VpnService.prepare(this) == null
        val pm = getSystemService(PowerManager::class.java)
        val batteryOk = pm.isIgnoringBatteryOptimizations(packageName)
        box.addView(button((if (overlayOk) "✅ " else "1. ") + "הצגה מעל אפליקציות") {
            startActivity(Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")))
        })
        box.addView(button((if (vpnOk) "✅ " else "2. ") + "סינון אתרים (VPN)") { requestVpn() })
        box.addView(button((if (batteryOk) "✅ " else "3. ") + "לרוץ תמיד ברקע (סוללה)") {
            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
        })
        if (Build.VERSION.SDK_INT >= 33) {
            box.addView(button("4. התראות (טיימר)") {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 11)
            })
        }
        box.addView(label(AdminReceiver.harden(this)))

        box.addView(button("💾 שמירה והפעלה") {
            if (pin.text.toString().length < 4) {
                Toast.makeText(this, "צריך קוד הורים של 4 ספרות לפחות", Toast.LENGTH_LONG).show(); return@button
            }
            prefs.homeUrl = home.text.toString()
            prefs.remoteUrl = remote.text.toString()
            prefs.token = token.text.toString()
            prefs.deviceName = name.text.toString()
            prefs.parentPin = pin.text.toString()
            if (!prefs.configured) {
                Toast.makeText(this, "חסרים כתובת, טוקן או שם מכשיר", Toast.LENGTH_LONG).show(); return@button
            }
            GuardService.start(this)
            val check = Thread {
                val st = Api(prefs).state()
                runOnUiThread {
                    Toast.makeText(this, if (st != null && !st.has("error")) "מחובר לשרת ✅" else
                        (st?.optString("error") ?: "השרת לא עונה. בדקו כתובת ו-Wi-Fi."), Toast.LENGTH_LONG).show()
                }
            }
            check.start()
        })
        if (AdminReceiver.isOwner(this)) {
            box.addView(button("הסרת ההגנה מהמכשיר") {
                AdminReceiver.release(this)
                Toast.makeText(this, "אפשר עכשיו להסיר את האפליקציה", Toast.LENGTH_LONG).show()
                renderForm()
            })
        }
    }

    private fun requestVpn() {
        val i = VpnService.prepare(this)
        if (i != null) startActivityForResult(i, REQ_VPN)
        else GuardService.instance?.pollOnceAsync()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN && resultCode == RESULT_OK) {
            GuardService.instance?.pollOnceAsync()
            if (!unlocked) finish()
        }
    }
}
