package com.oritre.homeguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.RemoteInput
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import org.json.JSONObject

/**
 * Always-running heart of the app: asks the server what is allowed every few seconds,
 * shows the lock screen when there's no approved time, drives the filtering VPN and
 * keeps a notification with the timer and buttons.
 */
class GuardService : Service() {

    companion object {
        private const val TAG = "HomeGuard"
        const val CH_STATUS = "status"
        const val CH_ALERT = "alerts"
        const val NOTIF_ID = 1
        const val ALERT_ID = 2
        @Volatile var instance: GuardService? = null

        fun start(ctx: Context) {
            val i = Intent(ctx, GuardService::class.java)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }
    }

    lateinit var prefs: Prefs
    lateinit var api: Api
    private val main = Handler(Looper.getMainLooper())
    private var overlay: LockOverlay? = null
    private var poller: Thread? = null

    @Volatile private var lastState: JSONObject? = null
    @Volatile private var lastStateAt = 0L
    @Volatile var vpnRevoked = false
    private var warned = mutableSetOf<Int>()
    private var lastSessionId = -1
    @Volatile var hiddenUntil = 0L // only while the VPN permission dialog is up
    @Volatile private var kidsFetchedAt = -1_000_000L
    @Volatile private var appsReportedAt = -1_000_000L
    private var reportedApps = ""
    private var lastLocked: Boolean? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        prefs = Prefs(this)
        api = Api(prefs)
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_STATUS, "מצב HomeGuard", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(CH_ALERT, "התראות זמן", NotificationManager.IMPORTANCE_HIGH))
        val n = buildNotification("🛡️ HomeGuard פועל", null)
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, n)
        }
        overlay = LockOverlay(this)
        // Lock right away (e.g. straight after a restart), before the server has even answered.
        FilterVpn.bypassApps = prefs.alwaysApps
        if (prefs.configured) {
            AdminReceiver.harden(this) // also after an update, so new protections take effect without a cable
            apply()
        }
        startPolling()
        Updater.schedule(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onDestroy() {
        poller?.interrupt()
        try { unregisterReceiver(screenOn) } catch (_: Exception) {}
        main.post { overlay?.hide() }
        instance = null
        super.onDestroy()
    }

    // ------------------------------------------------------------------ polling
    // Every 4 seconds while the screen is on; once a minute while it's off, so the Wi-Fi can sleep.
    // Turning the screen on polls right away, so the lock and approvals are never stale.
    private val wake = Object()
    private val screenOn = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            synchronized(wake) { wake.notifyAll() }
        }
    }

    private fun startPolling() {
        registerReceiver(screenOn, IntentFilter(Intent.ACTION_SCREEN_ON))
        val power = getSystemService(PowerManager::class.java)
        val t = Thread {
            while (!Thread.currentThread().isInterrupted) {
                try {
                    pollOnce()
                } catch (e: Exception) {
                    Log.w(TAG, "poll failed", e)
                }
                val delay = if (power.isInteractive) 4_000L else 60_000L
                try { synchronized(wake) { wake.wait(delay) } } catch (_: InterruptedException) { break }
            }
        }
        poller = t
        t.start()
    }

    fun pollOnce() {
        if (!prefs.configured) {
            main.post { overlay?.hide() }
            return
        }
        if (SystemClock.elapsedRealtime() - kidsFetchedAt > 30_000) {
            api.kids()?.let { k ->
                kidsFetchedAt = SystemClock.elapsedRealtime()
                val arr = k.optJSONArray("kids")
                val list = if (arr == null) emptyList() else (0 until arr.length()).map {
                    val o = arr.getJSONObject(it)
                    o.optString("username") to o.optString("display")
                }
                val passwordless = !k.optBoolean("require_password", true)
                main.post { overlay?.setKids(list, passwordless) }
            }
        }
        val st = api.state(Updater.currentVersion(this))
        if (st != null && !st.has("error")) {
            lastState = st
            lastStateAt = SystemClock.elapsedRealtime()
            Updater.onServerSeq(this, st.optInt("update_seq", 0))
        }
        apply()
        reportApps()
    }

    /** Tell the server which apps are installed, so parents can block them from the bot. */
    private fun reportApps() {
        if (SystemClock.elapsedRealtime() - appsReportedAt < 60_000) return
        appsReportedAt = SystemClock.elapsedRealtime()
        val apps = AppControl.launchable(this)
        val sig = apps.joinToString("|") { it.first }
        if (sig == reportedApps) return
        val r = api.apps(apps)
        if (r?.optBoolean("ok") == true) reportedApps = sig
    }

    /** Current approved session, counting down locally when the server can't be reached. */
    fun session(): JSONObject? {
        val st = lastState ?: return null
        val s = st.optJSONObject("session") ?: return null
        val elapsed = (SystemClock.elapsedRealtime() - lastStateAt) / 1000
        val remaining = s.optLong("remaining") - elapsed
        if (remaining <= 0) return null
        return JSONObject(s.toString()).put("remaining", remaining)
    }

    private fun list(name: String): List<String> {
        val arr = lastState?.optJSONArray(name) ?: return emptyList()
        return (0 until arr.length()).map { arr.optString(it) }
    }

    private fun apply() {
        val s = session()
        val mode = s?.optString("mode", "offline") ?: "offline"
        FilterVpn.allow = list("allowlist")
        FilterVpn.block = list("blocklist")
        val always = list("alwayslist")
        val shapeChanged = FilterVpn.always.isEmpty() != always.isEmpty()
        FilterVpn.always = always
        FilterVpn.upstream = prefs.upstreamDns.ifEmpty { "1.1.1.3" }
        // Master ("open") sessions are exempt from per-app blocking, like from site rules.
        // Before the server first answers (e.g. right after a restart) the last known rules stay in place.
        var appsChanged = false
        if (lastState != null) {
            appsChanged = AppControl.apply(this,
                blocked = if (mode == "open") emptySet() else list("apps_blocked").toSet(),
                always = list("apps_always").toSet(),
                offline = s != null && mode == "offline",
                alwaysSites = always.isNotEmpty())
        }
        val changed = FilterVpn.mode != mode || shapeChanged || appsChanged
        FilterVpn.mode = mode
        ensureVpn(changed)

        val sid = s?.optInt("id", -1) ?: -1
        if (sid != lastSessionId) {
            warned.clear()
            lastSessionId = sid
        }
        if (s != null) {
            val rem = s.optLong("remaining").toInt()
            val unlimited = s.optBoolean("unlimited")
            if (!unlimited) for (w in listOf(300, 60)) {
                if (rem <= w && w !in warned) {
                    warned += w
                    alert(if (w == 300) "⏳ נשארו 5 דקות" else "⏳ נשארה דקה אחת", "אפשר לבקש עוד זמן מההתראה של HomeGuard")
                }
            }
        }
        val locked = s == null || vpnRevoked
        if (locked != lastLocked) {
            lastLocked = locked
            AppControl.setLockedChrome(this, locked)
        }
        main.post {
            overlay?.update(s, lastState?.optBoolean("extend_pending") ?: false, api.online)
            if (locked && SystemClock.elapsedRealtime() > hiddenUntil) overlay?.show() else overlay?.hide()
            updateNotification(s)
        }
    }

    private fun ensureVpn(modeChanged: Boolean) {
        if (VpnService.prepare(this) != null) {
            vpnRevoked = true // no permission: stay locked until a parent re-enables protection
            return
        }
        vpnRevoked = false
        if (!FilterVpn.running || modeChanged) {
            try {
                startService(Intent(this, FilterVpn::class.java))
            } catch (e: Exception) {
                Log.w(TAG, "vpn start failed", e)
            }
        }
    }

    fun onVpnRevoked() {
        vpnRevoked = true
        alert("🛡️ ההגנה כובתה", "המכשיר ננעל עד שההגנה תופעל מחדש")
        apply()
    }

    // ------------------------------------------------------------ kid actions
    fun background(block: () -> Unit) = Thread { try { block() } catch (e: Exception) { Log.w(TAG, "action", e) } }.start()

    fun askMore() = background {
        val r = api.extend()
        toast(if (r?.optBoolean("ok") == true) "ביקשנו עוד זמן ⏳" else r?.optString("error", "אין חיבור") ?: "אין חיבור")
    }

    fun done() = background {
        api.end()
        pollOnce()
    }

    fun requestSite(domain: String) = background {
        val r = api.site(domain)
        toast(if (r?.optBoolean("ok") == true) "ביקשנו את $domain מאבא/אמא" else r?.optString("error", "אין חיבור") ?: "אין חיבור")
    }

    fun pollOnceAsync() = background { pollOnce() }

    fun accessPending() = lastState?.optBoolean("access_pending") ?: false

    fun toast(text: String) = main.post { android.widget.Toast.makeText(this, text, android.widget.Toast.LENGTH_LONG).show() }

    // ------------------------------------------------------------ notification
    private fun pending(action: String, code: Int): PendingIntent =
        PendingIntent.getBroadcast(this, code, Intent(this, ActionReceiver::class.java).setAction(action),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)

    private fun buildNotification(title: String, s: JSONObject?): Notification {
        val b = Notification.Builder(this, CH_STATUS)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
        if (s != null) {
            val open = PendingIntent.getActivity(this, 4,
                Intent(this, RequestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            b.setContentIntent(open)
            b.setContentText(if (accessPending()) "⏳ הבקשה החדשה מחכה לאבא/אמא" else "לחצו כאן לבקשה חדשה או להתנתקות")
            if (!s.optBoolean("unlimited")) {
                b.setUsesChronometer(true)
                b.setChronometerCountDown(true)
                b.setWhen(System.currentTimeMillis() + s.optLong("remaining") * 1000)
                b.addAction(Notification.Action.Builder(null, "עוד זמן", pending(ActionReceiver.MORE, 1)).build())
            }
            val input = RemoteInput.Builder(ActionReceiver.KEY_SITE).setLabel("כתובת האתר, למשל youtube.com").build()
            b.addAction(Notification.Action.Builder(null, "בקשת אתר", pending(ActionReceiver.SITE, 2))
                .addRemoteInput(input).build())
            b.addAction(Notification.Action.Builder(null, "התנתקות", pending(ActionReceiver.DONE, 3)).build())
        }
        return b.build()
    }

    private val modeNames = mapOf("full" to "🌐 אינטרנט מלא", "allowlist" to "✅ אתרים מאושרים",
        "offline" to "🚫 בלי אינטרנט", "open" to "🔓 פתוח")

    private fun updateNotification(s: JSONObject?) {
        val title = when {
            vpnRevoked -> "🛡️ ההגנה כבויה, המכשיר נעול"
            s == null -> "🔒 נעול"
            s.optBoolean("unlimited") -> "${s.optString("display")} · ${modeNames[s.optString("mode")] ?: ""} · ללא הגבלת זמן"
            else -> "${s.optString("display")} · ${modeNames[s.optString("mode")] ?: ""}"
        }
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification(title, s))
    }

    private fun alert(title: String, text: String) {
        val n = Notification.Builder(this, CH_ALERT)
            .setSmallIcon(android.R.drawable.ic_lock_idle_alarm)
            .setContentTitle(title)
            .setContentText(text)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(ALERT_ID, n)
    }

    fun canDrawOverlay() = Settings.canDrawOverlays(this)
}
