package com.oritre.homeguard

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** Opened from the timer notification while a kid is in: ask for new access (with a note), more time, or log out. */
class RequestActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private lateinit var box: LinearLayout
    private var status = ""

    private val bg = Color.parseColor("#1D2433")
    private val fg = Color.parseColor("#F2F4F8")
    private val muted = Color.parseColor("#AAB3C5")
    private val accent = Color.parseColor("#4F8CFF")
    private val modeNames = mapOf("full" to "🌐 אינטרנט מלא", "allowlist" to "✅ אתרים מאושרים",
        "offline" to "🚫 בלי אינטרנט", "open" to "🔓 פתוח")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val scroll = ScrollView(this).apply { setBackgroundColor(bg); isFillViewport = true }
        box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(64, 96, 64, 96)
            layoutDirection = View.LAYOUT_DIRECTION_RTL
        }
        scroll.addView(box)
        setContentView(scroll)
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun text(t: String, size: Float, color: Int = fg, bold: Boolean = false) = TextView(this).apply {
        text = t
        textSize = size
        setTextColor(color)
        gravity = Gravity.CENTER
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
        setPadding(0, 8, 0, 8)
    }

    private fun button(t: String, primary: Boolean = true, onClick: () -> Unit) = Button(this).apply {
        text = t
        textSize = 16f
        setTextColor(Color.WHITE)
        setBackgroundColor(if (primary) accent else Color.parseColor("#39445A"))
        setOnClickListener { onClick() }
    }

    private fun add(v: View, top: Int = 12) {
        val lp = LinearLayout.LayoutParams(-1, -2)
        lp.topMargin = top
        box.addView(v, lp)
    }

    private fun render() {
        box.removeAllViews()
        val svc = GuardService.instance
        val s = svc?.session()
        if (svc == null || s == null) {
            finish() // locked: the lock screen handles requests
            return
        }
        val left = if (s.optBoolean("unlimited")) "ללא הגבלת זמן" else "נשארו ${s.optLong("remaining") / 60} דק'"
        add(text("שלום ${s.optString("display")} 👋", 28f, bold = true))
        add(text("${modeNames[s.optString("mode")] ?: ""} · $left", 16f, muted))

        add(text("בקשה חדשה מאבא/אמא", 20f, bold = true), 40)
        add(text("כתבו מה אתם צריכים, למשל: אינטרנט מלא לשיעורי בית, עוד שעה, משחק מסוים", 14f, muted))
        val note = EditText(this).apply {
            hint = "מה תרצו לבקש?"
            setHintTextColor(muted)
            setTextColor(fg)
            textSize = 18f
            minLines = 2
            maxLines = 4
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        }
        add(note, 16)
        val pending = svc.accessPending()
        add(button(if (pending) "שליחה מחדש (מחליפה את הבקשה הקודמת)" else "שליחת בקשה") {
            val n = note.text.toString().trim()
            status = "שולחים..."
            render()
            svc.background {
                val r = svc.api.rerequest(n)
                main.post {
                    status = when {
                        r == null -> "אין חיבור לשרת"
                        !r.optBoolean("ok") -> r.optString("error", "שגיאה")
                        else -> "הבקשה נשלחה ✅ הזמן הנוכחי ממשיך עד שאבא או אמא יענו"
                    }
                    svc.pollOnceAsync()
                    render()
                }
            }
        }, 16)
        if (pending && status.isEmpty()) status = "⏳ יש בקשה שמחכה לתשובה"
        if (status.isNotEmpty()) add(text(status, 15f, muted), 16)

        if (!s.optBoolean("unlimited")) add(button("⏳ עוד זמן", false) { svc.askMore() }, 40)
        add(button("🚪 התנתקות (סיימתי)", false) {
            svc.done()
            finish()
        }, if (s.optBoolean("unlimited")) 40 else 12)
        add(button("סגירה", false) { finish() })
    }
}
