package com.oritre.homeguard

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** Talks to the HomeGuard server: the home address first, the outside address as fallback. */
class Api(private val prefs: Prefs) {
    @Volatile var online = false
        private set
    @Volatile private var preferRemote = false

    private fun urls(): List<String> {
        val all = listOf(prefs.homeUrl, prefs.remoteUrl).filter { it.isNotEmpty() }
        return if (preferRemote) all.reversed() else all
    }

    private fun call(method: String, path: String, body: JSONObject?): JSONObject? {
        for (base in urls()) {
            try {
                val conn = URL(base + path).openConnection() as HttpURLConnection
                conn.requestMethod = method
                conn.connectTimeout = 4000
                conn.readTimeout = 8000
                conn.setRequestProperty("X-Agent-Token", prefs.token)
                conn.setRequestProperty("Content-Type", "application/json")
                if (body != null) {
                    conn.doOutput = true
                    conn.outputStream.use { it.write(body.toString().toByteArray()) }
                }
                val code = conn.responseCode
                val text = (if (code < 400) conn.inputStream else conn.errorStream)?.bufferedReader()?.use { it.readText() } ?: "{}"
                conn.disconnect()
                if (code == 401) return JSONObject().put("ok", false).put("error", "טוקן שגוי. בקשו מאבא/אמא לבדוק את ההגדרות.")
                online = true
                preferRemote = base == prefs.remoteUrl && prefs.homeUrl != prefs.remoteUrl
                return JSONObject(text)
            } catch (e: Exception) {
                // try the next address
            }
        }
        online = false
        return null
    }

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    fun state(): JSONObject? = call("GET", "/api/state?pc=${enc(prefs.deviceName)}&user=android", null)
    fun kids(): JSONObject? = call("GET", "/api/kids", null)
    fun requestStatus(id: Int): JSONObject? = call("GET", "/api/request?id=$id", null)

    private fun post(path: String, vararg kv: Pair<String, Any>): JSONObject? {
        val body = JSONObject().put("pc", prefs.deviceName)
        kv.forEach { body.put(it.first, it.second) }
        return call("POST", path, body)
    }

    fun login(user: String, pass: String) = post("/api/login", "username" to user, "password" to pass)
    fun cancel(id: Int) = post("/api/cancel", "request_id" to id)
    fun extend() = post("/api/extend")
    fun end() = post("/api/end")
    fun site(domain: String) = post("/api/site", "domain" to domain)
    fun passwd(user: String, old: String, new: String) = post("/api/passwd", "username" to user, "old" to old, "new" to new)
}
