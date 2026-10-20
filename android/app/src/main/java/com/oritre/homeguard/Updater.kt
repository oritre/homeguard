package com.oritre.homeguard

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Updates the app by itself, without a cable: checks the GitHub releases a few times a day
 * (and right away when a parent sends /update in the bot) and installs a newer homeguard.apk.
 * As device owner the install is silent; every build is signed with the same key.
 */
object Updater {
    private const val TAG = "HomeGuardUpdate"
    private const val RELEASES = "https://api.github.com/repos/oritre/homeguard/releases/latest"
    private const val EVERY_MS = 6 * 60 * 60 * 1000L
    @Volatile private var busy = false

    fun currentVersion(ctx: Context): Int {
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, 0)
        @Suppress("DEPRECATION")
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode.toInt() else info.versionCode
    }

    /** Background loop: a first check a minute after start, then every 6 hours. */
    fun schedule(svc: GuardService) {
        val t = Thread {
            try { Thread.sleep(60_000) } catch (_: InterruptedException) { return@Thread }
            while (GuardService.instance === svc) {
                if (System.currentTimeMillis() - svc.prefs.lastUpdateCheck > EVERY_MS) check(svc)
                try { Thread.sleep(30 * 60_000L) } catch (_: InterruptedException) { break }
            }
        }
        t.isDaemon = true
        t.start()
    }

    /** The server counts /update presses; a new number means "check now". */
    fun onServerSeq(svc: GuardService, seq: Int) {
        val prefs = svc.prefs
        if (seq == prefs.updateSeq) return
        val first = prefs.updateSeq == -1
        prefs.updateSeq = seq
        if (!first) svc.background { check(svc, fromBot = true) }
    }

    fun check(svc: GuardService, fromBot: Boolean = false) {
        if (busy) return
        busy = true
        try {
            svc.prefs.lastUpdateCheck = System.currentTimeMillis()
            val rel = JSONObject(get(RELEASES))
            val latest = Regex("""android-v(\d+)""").find(rel.optString("tag_name"))?.groupValues?.get(1)?.toInt() ?: return
            val mine = currentVersion(svc)
            if (latest <= mine) {
                if (fromBot) svc.api.notice("📲 '${svc.prefs.deviceName}' כבר בגרסה האחרונה ($mine)")
                return
            }
            val assets = rel.optJSONArray("assets") ?: return
            val url = (0 until assets.length()).map { assets.getJSONObject(it) }
                .firstOrNull { it.optString("name") == "homeguard.apk" }?.optString("browser_download_url") ?: return
            val apk = File(svc.cacheDir, "update.apk")
            download(url, apk)
            if (!AdminReceiver.isOwner(svc)) {
                svc.api.notice("📲 יש גרסה חדשה ($latest) ל-'${svc.prefs.deviceName}', אבל בלי מנהל מכשיר צריך להתקין ידנית")
                return
            }
            svc.api.notice("📲 '${svc.prefs.deviceName}' מתעדכן מגרסה $mine לגרסה $latest")
            install(svc, apk)
        } catch (e: Exception) {
            Log.w(TAG, "update check failed", e)
            if (fromBot) svc.api.notice("⚠️ העדכון של '${svc.prefs.deviceName}' נכשל: ${e.message ?: e.javaClass.simpleName}")
        } finally {
            busy = false
        }
    }

    private fun open(url: String): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 30_000
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", "HomeGuard-Android")
            setRequestProperty("Accept", "application/vnd.github+json")
        }

    private fun get(url: String): String {
        val c = open(url)
        try {
            if (c.responseCode != 200) throw IllegalStateException("GitHub ${c.responseCode}")
            return c.inputStream.bufferedReader().use { it.readText() }
        } finally { c.disconnect() }
    }

    private fun download(url: String, dest: File) {
        val c = open(url)
        try {
            if (c.responseCode != 200) throw IllegalStateException("הורדה ${c.responseCode}")
            c.inputStream.use { input -> dest.outputStream().use { input.copyTo(it) } }
        } finally { c.disconnect() }
    }

    private fun install(ctx: Context, apk: File) {
        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(ctx.packageName)
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            session.openWrite("homeguard.apk", 0, apk.length()).use { out ->
                apk.inputStream().use { it.copyTo(out) }
                session.fsync(out)
            }
            val pi = PendingIntent.getBroadcast(ctx, 7, Intent(ctx, Result::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
            session.commit(pi.intentSender)
        }
    }

    /** Install result. On success the app restarts by itself (MY_PACKAGE_REPLACED). */
    class Result : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
            if (status == PackageInstaller.STATUS_SUCCESS || status == PackageInstaller.STATUS_PENDING_USER_ACTION) return
            val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "status $status"
            Log.w(TAG, "install failed: $msg")
            val prefs = Prefs(context)
            Thread { Api(prefs).notice("⚠️ העדכון של '${prefs.deviceName}' נכשל: $msg") }.start()
        }
    }
}
