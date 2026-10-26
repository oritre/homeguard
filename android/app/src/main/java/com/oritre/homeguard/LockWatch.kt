package com.oritre.homeguard

import android.app.AppOpsManager
import android.app.KeyguardManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock

/**
 * Notices when the device is in use although it should be locked, and tells the parents in the bot:
 * - the lock screen isn't on the screen (e.g. the "draw over apps" permission was taken away),
 *   with the apps that were in front meanwhile;
 * - apps were used while HomeGuard itself wasn't running (found when it runs again).
 * While the lock screen is up nothing else can be used, so apps behind it don't count.
 * Which apps were used needs "usage access" (setup screen); without it the alert still comes.
 * The server sends at most one message per device every 10 minutes.
 */
object LockWatch {
    private const val EVERY_MS = 20_000L
    private const val GRACE_MS = 15_000L      // the lock screen takes a moment to come up
    private const val MIN_FOREGROUND_MS = 60_000L
    private const val GAP_MS = 3 * 60_000L    // HomeGuard silent for this long = it wasn't running

    // Apps that may come to the front by themselves: calls and alarms.
    private val IGNORE = setOf("com.android.systemui", "android", "com.android.server.telecom",
        "com.android.incallui", "com.samsung.android.incallui", "com.google.android.dialer",
        "com.samsung.android.dialer", "com.android.dialer", "com.android.deskclock",
        "com.google.android.deskclock", "com.sec.android.app.clockpackage",
        "com.google.android.permissioncontroller", "com.android.permissioncontroller")

    private var checkedAt = -EVERY_MS
    private var lockedSince = 0L           // wall clock; 0 = not in a locked, screen-on stretch
    private val reported = mutableSetOf<String>()  // what we already told about in this stretch
    private var pending: String? = null    // waits for the server to be reachable

    fun usageAllowed(ctx: Context): Boolean {
        val ops = ctx.getSystemService(AppOpsManager::class.java)
        @Suppress("DEPRECATION")
        val mode = if (Build.VERSION.SDK_INT >= 29)
            ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        else ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /** Called after every poll. */
    @Synchronized
    fun check(svc: GuardService, locked: Boolean, lockShown: Boolean) {
        val prefs = svc.prefs
        val now = System.currentTimeMillis()
        val lastAlive = prefs.lastAlive
        prefs.lastAlive = now
        // Only the part of the gap after the last approved time ended counts.
        val gapFrom = maxOf(lastAlive, prefs.sessionEnds)
        if (lastAlive > 0 && now - lastAlive > GAP_MS && now > gapFrom) gap(svc, gapFrom, now)
        flush(svc)

        val interactive = svc.getSystemService(PowerManager::class.java).isInteractive &&
            !svc.getSystemService(KeyguardManager::class.java).isKeyguardLocked
        if (!locked || !interactive) {
            lockedSince = 0
            reported.clear()
            return
        }
        if (lockedSince == 0L) lockedSince = now
        val elapsed = SystemClock.elapsedRealtime()
        if (elapsed - checkedAt < EVERY_MS || now - lockedSince < GRACE_MS) return
        checkedAt = elapsed

        if (lockShown) return
        val found = mutableListOf<String>()
        if ("overlay" !in reported) {
            reported += "overlay"
            found += if (!svc.canDrawOverlay()) "מסך הנעילה לא יכול להופיע: בוטלה ההרשאה 'הצגה מעל אפליקציות'"
            else "מסך הנעילה לא מוצג"
            if (!usageAllowed(svc)) found += "(כדי לדעת באילו אפליקציות השתמשו, אשרו 'גישה לנתוני שימוש' במסך ההגדרות של HomeGuard)"
        }
        val apps = foreground(svc, lockedSince, now)
            .filter { it.value >= MIN_FOREGROUND_MS && it.key !in reported }
        reported += apps.keys
        if (apps.isNotEmpty()) found += "בשימוש: " + describe(svc, apps)
        if (found.isNotEmpty()) report(svc, found.joinToString("\n"))
    }

    /** HomeGuard wasn't running for a while (crash, update gone wrong...): were apps used meanwhile? */
    private fun gap(svc: GuardService, from: Long, to: Long) {
        val apps = foreground(svc, from, to).filter { it.value >= MIN_FOREGROUND_MS }
        if (apps.isEmpty()) return
        report(svc, "HomeGuard לא פעל בין ${hhmm(from)} ל-${hhmm(to)}, ובזמן הזה היה שימוש ב: " + describe(svc, apps))
    }

    private fun report(svc: GuardService, what: String) {
        pending = if (pending == null) what else pending + "\n" + what
        flush(svc)
    }

    private fun flush(svc: GuardService) {
        val what = pending ?: return
        val r = svc.api.activity(what)
        if (r != null && !r.has("error")) pending = null
    }

    /**
     * Milliseconds in front per app between [from] and [to], without HomeGuard, launchers and calls.
     * An app already open at [from] counts from [from].
     */
    private fun foreground(ctx: Context, from: Long, to: Long): Map<String, Long> {
        if (!usageAllowed(ctx) || to <= from) return emptyMap()
        val skip = IGNORE + ctx.packageName + launchers(ctx)
        val usm = ctx.getSystemService(UsageStatsManager::class.java)
        val events = try { usm.queryEvents(from - 3 * 60 * 60_000L, to) } catch (_: Exception) { return emptyMap() }
        val since = mutableMapOf<String, Long>()
        val total = mutableMapOf<String, Long>()
        val e = UsageEvents.Event()
        while (events.hasNextEvent()) {
            events.getNextEvent(e)
            val pkg = e.packageName ?: continue
            if (pkg in skip) continue
            @Suppress("DEPRECATION")
            when (e.eventType) {
                UsageEvents.Event.MOVE_TO_FOREGROUND -> since[pkg] = maxOf(e.timeStamp, from)
                UsageEvents.Event.MOVE_TO_BACKGROUND -> since.remove(pkg)?.let {
                    if (e.timeStamp > it) total[pkg] = (total[pkg] ?: 0) + (e.timeStamp - it)
                }
            }
        }
        for ((pkg, t) in since) total[pkg] = (total[pkg] ?: 0) + (to - t)
        return total
    }

    private fun launchers(ctx: Context): Set<String> {
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
        return ctx.packageManager.queryIntentActivities(i, 0).map { it.activityInfo.packageName }.toSet()
    }

    private fun describe(ctx: Context, apps: Map<String, Long>): String {
        val pm = ctx.packageManager
        return apps.entries.sortedByDescending { it.value }.take(5).joinToString(", ") { (pkg, ms) ->
            val name = try { pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString() } catch (_: Exception) { pkg }
            "$name (${(ms / 60_000).coerceAtLeast(1)} דק')"
        }
    }

    private fun hhmm(t: Long) = java.text.SimpleDateFormat("HH:mm", java.util.Locale.US).format(java.util.Date(t))
}
