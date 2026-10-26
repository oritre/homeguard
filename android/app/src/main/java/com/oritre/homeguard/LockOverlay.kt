package com.oritre.homeguard

import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject

/** Full-screen lock drawn above every app until a parent approves in Telegram. */
class LockOverlay(private val svc: GuardService) {
    private val wm = svc.getSystemService(WindowManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val root = ScrollView(svc)
    private val box = LinearLayout(svc)
    private var shown = false
    /** On the screen now (the system drops the window if the overlay permission is taken away). */
    val visible get() = shown && root.isAttachedToWindow

    private enum class Screen { LOGIN, NOTE, MASTER, WAITING, NEW_PASSWORD, CHANGE_PASSWORD, PROTECTION_OFF }
    private var kids: List<Pair<String, String>> = emptyList()
    private var passwordless = false
    private var screen = Screen.LOGIN
    private var requestId = 0
    private var user = ""
    private var pickedUsername = ""
    private var tempPassword = ""
    private var message = ""
    private var pollWaiting: Runnable? = null

    private val bg = Color.parseColor("#1D2433")
    private val fg = Color.parseColor("#F2F4F8")
    private val muted = Color.parseColor("#AAB3C5")
    private val accent = Color.parseColor("#4F8CFF")
    private val danger = Color.parseColor("#FFB4A8")

    init {
        root.setBackgroundColor(bg)
        root.isFillViewport = true
        box.orientation = LinearLayout.VERTICAL
        box.gravity = Gravity.CENTER
        box.setPadding(64, 96, 64, 96)
        box.layoutDirection = View.LAYOUT_DIRECTION_RTL
        root.addView(box, LinearLayout.LayoutParams(-1, -1))
        render()
    }

    fun show() {
        if (!svc.canDrawOverlay()) return
        if (svc.vpnRevoked && screen != Screen.PROTECTION_OFF) go(Screen.PROTECTION_OFF)
        if (!svc.vpnRevoked && screen == Screen.PROTECTION_OFF) go(Screen.LOGIN)
        if (shown && root.isAttachedToWindow) return
        if (shown) { try { wm.removeView(root) } catch (_: Exception) {} }
        shown = false
        val lp = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON,
            PixelFormat.OPAQUE)
        lp.softInputMode = WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE
        try {
            wm.addView(root, lp)
            shown = true
        } catch (e: Exception) {
            shown = false
        }
    }

    fun hide() {
        if (!shown) return
        try { wm.removeView(root) } catch (_: Exception) {}
        shown = false
        if (screen == Screen.WAITING) go(Screen.LOGIN)
    }

    fun setKids(list: List<Pair<String, String>>, noPasswords: Boolean) {
        if (list == kids && noPasswords == passwordless) return
        kids = list
        passwordless = noPasswords
        if (screen == Screen.LOGIN) render()
    }

    fun update(session: JSONObject?, extendPending: Boolean, online: Boolean) {
        if (session == null && screen == Screen.LOGIN && !online && message.isEmpty()) {
            message = "אין חיבור לשרת כרגע"
            render()
        } else if (online && message == "אין חיבור לשרת כרגע") {
            message = ""
            render()
        }
    }

    // ------------------------------------------------------------------ views
    private fun go(s: Screen, msg: String = "") {
        screen = s
        message = msg
        render()
    }

    private fun text(t: String, size: Float, color: Int = fg, bold: Boolean = false): TextView =
        TextView(svc).apply {
            text = t
            textSize = size
            setTextColor(color)
            gravity = Gravity.CENTER
            if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, 8, 0, 8)
        }

    private fun field(hint: String, password: Boolean): EditText = EditText(svc).apply {
        this.hint = hint
        setHintTextColor(muted)
        setTextColor(fg)
        textSize = 18f
        gravity = Gravity.CENTER
        setSingleLine()
        inputType = if (password) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    }

    private fun button(t: String, primary: Boolean = true, onClick: () -> Unit): Button = Button(svc).apply {
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
        when (screen) {
            Screen.LOGIN -> if (passwordless && kids.isNotEmpty()) renderPickName() else renderLogin()
            Screen.NOTE -> renderNote()
            Screen.MASTER -> renderLogin()
            Screen.WAITING -> renderWaiting()
            Screen.NEW_PASSWORD -> renderNewPassword()
            Screen.CHANGE_PASSWORD -> renderChangePassword()
            Screen.PROTECTION_OFF -> renderProtectionOff()
        }
        if (message.isNotEmpty()) add(text(message, 15f, danger), 24)
    }

    private fun renderPickName() {
        add(text("🛡️ המכשיר נעול", 30f, bold = true))
        add(text("מי נכנס? לחצו על השם שלכם, ואבא או אמא יאשרו בטלגרם", 15f, muted))
        var first = true
        for ((username, display) in kids) {
            add(button(display) {
                user = display
                pickedUsername = username
                go(Screen.NOTE)
            }, if (first) 32 else 12)
            first = false
        }
        add(button("כניסת מאסטר", false) { go(Screen.MASTER) }, 32)
    }

    private fun noteField(): EditText = field("מה תרצו לעשות? (לא חובה)", false).apply {
        textSize = 16f
        setSingleLine(false)
        minLines = 2
        maxLines = 4
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
    }

    private fun renderNote() {
        add(text("שלום $user 👋", 28f, bold = true))
        add(text("כתבו לאבא ואמא מה אתם רוצים לעשות, למשל: שיעורי בית, יוטיוב, משחק", 15f, muted))
        val note = noteField()
        add(note, 32)
        add(button("שליחת בקשה") {
            val n = note.text.toString().trim()
            val name = pickedUsername
            message = "שולחים..."
            render()
            svc.background {
                val r = svc.api.login(name, "", n)
                main.post { onLogin(r, "") }
            }
        }, 24)
        add(button("חזרה", false) { go(Screen.LOGIN) })
    }

    private fun renderLogin() {
        val master = screen == Screen.MASTER
        add(text(if (master) "כניסת מאסטר" else "🛡️ המכשיר נעול", 30f, bold = true))
        add(text(if (master) "שם משתמש וסיסמה של חשבון המאסטר"
                 else "הכניסו שם משתמש וסיסמה, ואבא או אמא יאשרו בטלגרם", 15f, muted))
        val u = field("שם משתמש", false).also { it.setText(user) }
        val p = field("סיסמה", true)
        add(u, 32); add(p)
        val note = if (master) null else noteField().also { add(it) }
        add(button("בקשו כניסה") {
            val name = u.text.toString().trim()
            val pass = p.text.toString()
            val n = note?.text?.toString()?.trim() ?: ""
            if (name.isEmpty() || pass.isEmpty()) {
                go(Screen.LOGIN, "צריך שם משתמש וסיסמה"); return@button
            }
            user = name
            message = "שולחים..."
            render()
            svc.background {
                val r = svc.api.login(name, pass, n)
                main.post { onLogin(r, pass) }
            }
        }, 24)
        if (master) add(button("חזרה", false) { go(Screen.LOGIN) })
        else add(button("שינוי סיסמה", false) { go(Screen.CHANGE_PASSWORD) })
    }

    private fun onLogin(r: JSONObject?, pass: String) {
        when {
            r == null -> go(Screen.LOGIN, "אין חיבור לשרת. נסו שוב עוד רגע.")
            r.optBoolean("need_new_password") -> { tempPassword = pass; go(Screen.NEW_PASSWORD) }
            !r.optBoolean("ok") -> go(Screen.LOGIN, r.optString("error", "שגיאה"))
            r.optBoolean("approved") -> { go(Screen.LOGIN); svc.background { svc.pollOnce() } }
            else -> {
                requestId = r.optInt("request_id")
                user = r.optString("display", user)
                go(Screen.WAITING)
                waitForAnswer()
            }
        }
    }

    private fun waitForAnswer() {
        pollWaiting?.let { main.removeCallbacks(it) }
        val r = object : Runnable {
            override fun run() {
                if (screen != Screen.WAITING) return
                val id = requestId
                svc.background {
                    val st = svc.api.requestStatus(id)?.optString("status")
                    main.post {
                        if (screen != Screen.WAITING || id != requestId) return@post
                        when (st) {
                            "approved" -> { go(Screen.LOGIN); svc.background { svc.pollOnce() } }
                            "denied" -> go(Screen.LOGIN, "אבא/אמא אמרו לא עכשיו 🙁")
                            "cancelled" -> go(Screen.LOGIN)
                            else -> main.postDelayed(this, 2500)
                        }
                    }
                }
            }
        }
        pollWaiting = r
        main.postDelayed(r, 2500)
    }

    private fun renderWaiting() {
        add(text("שלום $user 👋", 28f, bold = true))
        add(text("שלחנו בקשה לאבא ואמא בטלגרם. מחכים לאישור...", 16f, muted))
        add(button("ביטול", false) {
            val id = requestId
            svc.background { svc.api.cancel(id) }
            go(Screen.LOGIN)
        }, 32)
    }

    private fun renderNewPassword() {
        add(text("בחרו סיסמה אישית", 26f, bold = true))
        add(text("זו הכניסה הראשונה שלכם. בחרו סיסמה שרק אתם תדעו (4 תווים לפחות).", 15f, muted))
        val p1 = field("סיסמה חדשה", true)
        val p2 = field("שוב את הסיסמה החדשה", true)
        add(p1, 32); add(p2)
        add(button("שמירה והמשך") {
            val a = p1.text.toString()
            if (a != p2.text.toString()) { go(Screen.NEW_PASSWORD, "הסיסמאות לא זהות"); return@button }
            val name = user
            val old = tempPassword
            svc.background {
                val r = svc.api.passwd(name, old, a)
                val l = if (r?.optBoolean("ok") == true) svc.api.login(name, a) else null
                main.post {
                    when {
                        r == null -> go(Screen.NEW_PASSWORD, "אין חיבור לשרת")
                        !r.optBoolean("ok") -> go(Screen.NEW_PASSWORD, r.optString("error", "שגיאה"))
                        else -> { tempPassword = ""; onLogin(l, a) }
                    }
                }
            }
        }, 24)
        add(button("חזרה", false) { go(Screen.LOGIN) })
    }

    private fun renderChangePassword() {
        add(text("שינוי סיסמה", 26f, bold = true))
        val u = field("שם משתמש", false).also { it.setText(user) }
        val old = field("סיסמה נוכחית", true)
        val p1 = field("סיסמה חדשה", true)
        val p2 = field("שוב את הסיסמה החדשה", true)
        add(u, 32); add(old); add(p1); add(p2)
        add(button("שמירה") {
            val name = u.text.toString().trim()
            val a = p1.text.toString()
            if (a != p2.text.toString()) { go(Screen.CHANGE_PASSWORD, "הסיסמאות לא זהות"); return@button }
            user = name
            val o = old.text.toString()
            svc.background {
                val r = svc.api.passwd(name, o, a)
                main.post {
                    when {
                        r == null -> go(Screen.CHANGE_PASSWORD, "אין חיבור לשרת")
                        !r.optBoolean("ok") -> go(Screen.CHANGE_PASSWORD, r.optString("error", "שגיאה"))
                        else -> go(Screen.LOGIN, "הסיסמה הוחלפה ✅")
                    }
                }
            }
        }, 24)
        add(button("חזרה", false) { go(Screen.LOGIN) })
    }

    private fun renderProtectionOff() {
        add(text("🛡️ ההגנה כבויה", 28f, bold = true))
        add(text("המכשיר נעול עד שההגנה של HomeGuard תופעל שוב.", 16f, muted))
        add(button("הפעלת ההגנה") {
            svc.hiddenUntil = android.os.SystemClock.elapsedRealtime() + 20_000 // leave room for the VPN dialog
            hide()
            val i = Intent(svc, SetupActivity::class.java)
                .putExtra(SetupActivity.EXTRA_FIX_VPN, true)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            svc.startActivity(i)
            main.postDelayed({ svc.background { svc.pollOnce() } }, 15_000)
        }, 32)
    }
}
