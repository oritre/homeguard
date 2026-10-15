package com.oritre.homeguard

/** Same site rules as the Windows agent (agent/dnsfilter.py). */
object Policy {
    private val DEPENDENCIES = mapOf(
        "youtube.com" to listOf("ytimg.com", "googlevideo.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com"),
        "google.com" to listOf("gstatic.com", "googleapis.com", "googleusercontent.com", "google.co.il"),
        "wikipedia.org" to listOf("wikimedia.org"),
        "khanacademy.org" to listOf("kastatic.org", "kasandbox.org"),
        "scratch.mit.edu" to listOf("scratch.org"),
        "microsoft.com" to listOf("live.com", "microsoftonline.com", "msauth.net", "msftauth.net"),
        "office.com" to listOf("office.net", "live.com", "microsoftonline.com", "msauth.net", "msftauth.net", "officeapps.live.com"),
    )
    // Android's connectivity check and clock, so the phone doesn't show "no internet" errors.
    private val ESSENTIAL = listOf("connectivitycheck.gstatic.com", "connectivitycheck.android.com",
        "clients3.google.com", "time.android.com")

    fun matches(domain: String, patterns: Collection<String>): Boolean {
        val d = domain.lowercase().trimEnd('.')
        return patterns.any { raw ->
            val p = raw.lowercase().trim('.')
            p.isNotEmpty() && (d == p || d.endsWith(".$p"))
        }
    }

    fun expand(allow: List<String>): List<String> {
        val out = allow.toMutableList()
        out += ESSENTIAL
        for (d in allow) for ((base, deps) in DEPENDENCIES) {
            if (d == base || d.endsWith(".$base") || base.endsWith(".$d")) out += deps
        }
        return out
    }

    /** mode: open (master), full, allowlist, offline */
    fun allowed(domain: String, mode: String, allow: List<String>, block: List<String>): Boolean = when (mode) {
        "open" -> true
        "offline" -> matches(domain, ESSENTIAL)
        "allowlist" -> !matches(domain, block) && matches(domain, expand(allow))
        else -> !matches(domain, block)
    }
}
