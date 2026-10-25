package com.oritre.homeguard

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.util.Log

/**
 * Per-app rules from the parents (needs device owner for blocking):
 * - blocked apps are suspended: their icon turns grey and they won't open;
 * - "always" apps open in every mode and stay outside the [FilterVpn] tunnel (their own internet);
 * - all other apps are suspended while the kid's session has no internet.
 * Also keeps HomeGuard as the home screen, so a restart or the home button always comes back to us.
 */
object AppControl {
    private const val TAG = "HomeGuard"

    private fun dpm(ctx: Context) = ctx.getSystemService(DevicePolicyManager::class.java)

    /** Apps with an icon in the launcher, as (package, name), without HomeGuard itself. */
    fun launchable(ctx: Context): List<Pair<String, String>> {
        val pm = ctx.packageManager
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(i, 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != ctx.packageName }
            .distinctBy { it.first }
            .sortedBy { it.second }
    }

    /** The phone's own launcher (Samsung One UI Home etc.), which [HomeGate] hands over to. */
    fun realLauncher(ctx: Context): ComponentName? {
        val pm = ctx.packageManager
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
        val others = pm.queryIntentActivities(i, 0).filter { it.activityInfo.packageName != ctx.packageName }
        val pick = others.firstOrNull { it.activityInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0 }
            ?: others.firstOrNull() ?: return null
        return ComponentName(pick.activityInfo.packageName, pick.activityInfo.name)
    }

    private fun defaultBrowser(ctx: Context): String? {
        val i = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://example.com"))
        val pkg = ctx.packageManager.resolveActivity(i, 0)?.activityInfo?.packageName
        return if (pkg == null || pkg == "android") "com.android.chrome" else pkg // "android" = chooser
    }

    /** Packages we never suspend: ourselves, the system UI and the launchers. */
    private fun untouchable(ctx: Context): Set<String> {
        val pm = ctx.packageManager
        val home = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
        return pm.queryIntentActivities(home, 0).map { it.activityInfo.packageName }.toSet() +
            setOf(ctx.packageName, "com.android.systemui")
    }

    private var launchableCache: Set<String> = emptySet()
    private var launchableAt = -1_000_000L

    /**
     * blocked: never open. always: open in every mode and keep their own internet (outside the VPN).
     * Every other app opens only while the kid has approved internet, so in a "no internet"
     * session ([offline]) they are suspended too. Returns true when the always-set changed.
     */
    @Synchronized
    fun apply(ctx: Context, blocked: Set<String>, always: Set<String>, offline: Boolean,
              alwaysSites: Boolean = false): Boolean {
        val prefs = Prefs(ctx)
        val alwaysChanged = FilterVpn.bypassApps != always
        FilterVpn.bypassApps = always
        if (prefs.alwaysApps != always) prefs.alwaysApps = always

        if (!AdminReceiver.isOwner(ctx)) return alwaysChanged
        var wantAll = blocked
        if (offline) {
            val now = android.os.SystemClock.elapsedRealtime()
            if (now - launchableAt > 60_000) {
                launchableCache = launchable(ctx).map { it.first }.toSet()
                launchableAt = now
            }
            // With always-open sites, the browser stays usable for just those sites
            // (web apps added to the home screen run inside it), still filtered by the VPN.
            val browser = if (alwaysSites) defaultBrowser(ctx) else null
            wantAll = wantAll + (launchableCache - always - setOfNotNull(browser))
        }
        val want = wantAll - untouchable(ctx)
        val had = prefs.suspendedApps
        if (want == had) return alwaysChanged
        val admin = AdminReceiver.component(ctx)
        val dpm = dpm(ctx)
        try {
            val release = (had - want).toTypedArray()
            if (release.isNotEmpty()) dpm.setPackagesSuspended(admin, release, false)
            val add = (want - had).toTypedArray()
            val failed = if (add.isNotEmpty()) dpm.setPackagesSuspended(admin, add, true).toSet() else emptySet()
            prefs.suspendedApps = want - failed
        } catch (e: Exception) {
            Log.w(TAG, "suspend apps", e)
        }
        return alwaysChanged
    }

    /** While locked, the notification shade can't be pulled down (device owner only). */
    fun setLockedChrome(ctx: Context, locked: Boolean) {
        if (!AdminReceiver.isOwner(ctx)) return
        try { dpm(ctx).setStatusBarDisabled(AdminReceiver.component(ctx), locked) } catch (e: Exception) {
            Log.w(TAG, "status bar", e)
        }
    }

    /** Make [HomeGate] the home screen for good, so the phone starts into HomeGuard. */
    fun claimHome(ctx: Context) {
        val f = IntentFilter(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_HOME)
            addCategory(Intent.CATEGORY_DEFAULT)
        }
        dpm(ctx).addPersistentPreferredActivity(AdminReceiver.component(ctx), f,
            ComponentName(ctx, HomeGate::class.java))
    }

    /** Undo everything this object changed (used when removing the protection). */
    fun releaseAll(ctx: Context) {
        val prefs = Prefs(ctx)
        val admin = AdminReceiver.component(ctx)
        val dpm = dpm(ctx)
        try {
            val had = prefs.suspendedApps.toTypedArray()
            if (had.isNotEmpty()) dpm.setPackagesSuspended(admin, had, false)
            prefs.suspendedApps = emptySet()
        } catch (_: Exception) {}
        try { dpm.setStatusBarDisabled(admin, false) } catch (_: Exception) {}
        try { dpm.clearPackagePersistentPreferredActivities(admin, ctx.packageName) } catch (_: Exception) {}
    }
}
