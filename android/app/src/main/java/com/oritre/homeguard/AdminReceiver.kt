package com.oritre.homeguard

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.UserManager
import android.util.Log

/**
 * When HomeGuard is the device owner (set once with adb on a freshly reset device),
 * it can't be uninstalled, its VPN can't be turned off and safe mode is disabled.
 */
class AdminReceiver : DeviceAdminReceiver() {
    companion object {
        fun component(ctx: Context) = ComponentName(ctx, AdminReceiver::class.java)

        // No VPN changes, no safe mode, no extra users, and no factory reset from Settings
        // (a reset would wipe HomeGuard; parents first use "remove protection" in the setup screen).
        private val RESTRICTIONS = listOf(UserManager.DISALLOW_CONFIG_VPN, UserManager.DISALLOW_SAFE_BOOT,
            UserManager.DISALLOW_ADD_USER, UserManager.DISALLOW_FACTORY_RESET)

        fun isOwner(ctx: Context): Boolean =
            ctx.getSystemService(DevicePolicyManager::class.java).isDeviceOwnerApp(ctx.packageName)

        /** Apply all protections we can. Safe to call repeatedly. Returns a short report. */
        fun harden(ctx: Context): String {
            val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
            if (!dpm.isDeviceOwnerApp(ctx.packageName)) return "לא מוגדר כמנהל המכשיר (הגנה בסיסית בלבד)"
            val admin = component(ctx)
            val done = mutableListOf<String>()
            fun attempt(name: String, block: () -> Unit) {
                try { block(); done += name } catch (e: Exception) { Log.w("HomeGuard", "harden $name", e) }
            }
            attempt("חסימת הסרה") { dpm.setUninstallBlocked(admin, ctx.packageName, true) }
            attempt("VPN קבוע") { dpm.setAlwaysOnVpnPackage(admin, ctx.packageName, false) }
            for (r in RESTRICTIONS) {
                attempt(r) { dpm.addUserRestriction(admin, r) }
            }
            attempt("מסך הבית") { AppControl.claimHome(ctx) }
            if (Build.VERSION.SDK_INT >= 29) {
                attempt("DNS פרטי") {
                    dpm.setGlobalPrivateDnsModeOpportunistic(admin)
                    dpm.addUserRestriction(admin, UserManager.DISALLOW_CONFIG_PRIVATE_DNS)
                }
            }
            return "מנהל המכשיר ✅ (" + done.size + " הגנות פעילות)"
        }

        /** Undo everything, so the app can be removed (used from the PIN-protected setup screen). */
        fun release(ctx: Context) {
            val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
            if (!dpm.isDeviceOwnerApp(ctx.packageName)) return
            val admin = component(ctx)
            try { dpm.setUninstallBlocked(admin, ctx.packageName, false) } catch (_: Exception) {}
            try { dpm.setAlwaysOnVpnPackage(admin, null, false) } catch (_: Exception) {}
            AppControl.releaseAll(ctx)
            for (r in RESTRICTIONS + UserManager.DISALLOW_CONFIG_PRIVATE_DNS) {
                try { dpm.clearUserRestriction(admin, r) } catch (_: Exception) {}
            }
            try { dpm.clearDeviceOwnerApp(ctx.packageName) } catch (_: Exception) {}
        }
    }

    override fun onEnabled(context: Context, intent: Intent) {
        harden(context)
    }
}
