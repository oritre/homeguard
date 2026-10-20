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
 * - "no internet" apps get "no such site" for every lookup in [FilterVpn].
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

    /** Packages we never suspend: ourselves, the system UI and the launchers. */
    private fun untouchable(ctx: Context): Set<String> {
        val pm = ctx.packageManager
        val home = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
        return pm.queryIntentActivities(home, 0).map { it.activityInfo.packageName }.toSet() +
            setOf(ctx.packageName, "com.android.systemui")
    }

    @Synchronized
    fun apply(ctx: Context, blocked: Set<String>, noNet: Set<String>) {
        val prefs = Prefs(ctx)
        FilterVpn.noNetApps = noNet
        if (prefs.noNetApps != noNet) prefs.noNetApps = noNet

        if (!AdminReceiver.isOwner(ctx)) return
        val want = blocked - untouchable(ctx)
        val had = prefs.suspendedApps
        if (want == had) return
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
