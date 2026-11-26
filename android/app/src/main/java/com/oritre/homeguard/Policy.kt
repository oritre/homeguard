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
    // Services that belong only to a site, so blocking the site blocks them too. Without this the YouTube app
    // kept working with youtube.com blocked: it talks to youtubei.googleapis.com, which "always: googleapis.com"
    // let through. These win over a broader "always" entry; an equally specific one still wins over them.
    private val BLOCK_DEPENDENCIES = mapOf(
        "youtube.com" to listOf("youtu.be", "ytimg.com", "googlevideo.com", "ggpht.com", "youtube-nocookie.com",
            "youtubekids.com", "youtubei.googleapis.com", "youtube.googleapis.com",
            "youtubeembeddedplayer.googleapis.com"),
        "tiktok.com" to listOf("tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "ttwstatic.com", "byteoversea.com",
            "ibytedtos.com", "musical.ly"),
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

    /** Length of the most specific pattern the domain falls under, or -1. */
    fun bestMatch(domain: String, patterns: Collection<String>): Int {
        val d = domain.lowercase().trimEnd('.')
        var best = -1
        for (raw in patterns) {
            val p = raw.lowercase().trim('.')
            if (p.isNotEmpty() && (d == p || d.endsWith(".$p"))) best = maxOf(best, p.length)
        }
        return best
    }

    fun blockDependencies(block: List<String>): List<String> {
        val out = mutableListOf<String>()
        for (raw in block) {
            val d = raw.lowercase().trim('.')
            for ((base, deps) in BLOCK_DEPENDENCIES) if (d == base || base.endsWith(".$d")) out += deps
        }
        return out
    }

    fun expand(allow: List<String>): List<String> {
        val out = allow.toMutableList()
        out += ESSENTIAL
        for (d in allow) for ((base, deps) in DEPENDENCIES) {
            if (d == base || d.endsWith(".$base") || base.endsWith(".$d")) out += deps
        }
        return out
    }

    /** Sites the parents keep open in every mode, with what they need to load. */
    fun alwaysOpen(domain: String, always: List<String>): Boolean =
        always.isNotEmpty() && matches(domain, expand(always))

    /** mode: open (master), full, allowlist, offline. always: sites the parents keep open in every mode. */
    fun allowed(domain: String, mode: String, allow: List<String>, block: List<String>,
                always: List<String> = emptyList()): Boolean {
        if (mode == "open") return true
        val alwaysHit = if (always.isEmpty()) -1 else bestMatch(domain, expand(always))
        val depHit = bestMatch(domain, blockDependencies(block))
        if (depHit > alwaysHit) return false // a blocked site's own service (YouTube app's API, videos)
        return when {
            alwaysHit >= 0 -> true
            mode == "offline" -> matches(domain, ESSENTIAL)
            mode == "allowlist" -> !matches(domain, block) && matches(domain, expand(allow))
            else -> !matches(domain, block)
        }
    }
}
