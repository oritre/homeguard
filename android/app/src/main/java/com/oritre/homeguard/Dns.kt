package com.oritre.homeguard

/** Minimal IPv4/UDP/DNS packet handling for the filtering VPN. */
object Dns {
    class Query(val srcIp: ByteArray, val dstIp: ByteArray, val srcPort: Int, val dstPort: Int, val payload: ByteArray)

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    /** An IPv4 UDP packet to port 53, or null for anything else. */
    fun udpQuery(p: ByteArray): Query? {
        if (p.size < 28 || (p[0].toInt() shr 4) != 4) return null
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (p[9].toInt() != 17 || p.size < ihl + 8) return null
        val dstPort = u16(p, ihl + 2)
        if (dstPort != 53) return null
        val total = minOf(u16(p, 2), p.size)
        val udpLen = u16(p, ihl + 4)
        val end = minOf(ihl + udpLen, total)
        if (end <= ihl + 8) return null
        return Query(p.copyOfRange(12, 16), p.copyOfRange(16, 20), u16(p, ihl), dstPort, p.copyOfRange(ihl + 8, end))
    }

    /** IPv4/UDP packet carrying [answer] back to whoever sent [q]. */
    fun udpReply(q: Query, answer: ByteArray): ByteArray {
        val total = 20 + 8 + answer.size
        val p = ByteArray(total)
        p[0] = 0x45
        p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[6] = 0x40 // don't fragment
        p[8] = 64 // ttl
        p[9] = 17 // udp
        System.arraycopy(q.dstIp, 0, p, 12, 4)
        System.arraycopy(q.srcIp, 0, p, 16, 4)
        var sum = 0
        for (i in 0 until 20 step 2) sum += u16(p, i)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val cks = sum.inv() and 0xFFFF
        p[10] = (cks shr 8).toByte(); p[11] = cks.toByte()
        p[20] = (q.dstPort shr 8).toByte(); p[21] = q.dstPort.toByte()
        p[22] = (q.srcPort shr 8).toByte(); p[23] = q.srcPort.toByte()
        val udpLen = 8 + answer.size
        p[24] = (udpLen shr 8).toByte(); p[25] = udpLen.toByte()
        // UDP checksum 0 = "not computed", allowed on IPv4
        System.arraycopy(answer, 0, p, 28, answer.size)
        return p
    }

    fun qname(msg: ByteArray): String? {
        if (msg.size < 12) return null
        var i = 12
        val sb = StringBuilder()
        while (i < msg.size) {
            val n = msg[i].toInt() and 0xFF
            if (n == 0) return sb.toString()
            if (n and 0xC0 != 0 || i + 1 + n > msg.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(msg, i + 1, n, Charsets.US_ASCII))
            i += 1 + n
        }
        return null
    }

    /** "No such site" answer for a query. */
    fun nxdomain(query: ByteArray): ByteArray? {
        var i = 12
        while (i < query.size && query[i].toInt() != 0) i += 1 + (query[i].toInt() and 0xFF)
        val end = i + 5 // zero label + qtype + qclass
        if (end > query.size) return null
        val out = ByteArray(end)
        System.arraycopy(query, 0, out, 0, end)
        val flags = u16(query, 2)
        val r = 0x8000 or (flags and 0x7900) or 0x0080 or 3
        out[2] = (r shr 8).toByte(); out[3] = r.toByte()
        out[4] = 0; out[5] = 1 // qdcount
        for (k in 6 until 12) out[k] = 0
        return out
    }
}
