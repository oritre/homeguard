package com.oritre.homeguard

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors

/**
 * Local VPN that filters websites by name (DNS), like the Windows agent's DNS filter.
 *
 * - full / allowlist / open: only DNS goes through the tunnel; every lookup is checked
 *   against the site lists and either forwarded upstream or answered "no such site".
 * - offline: all traffic goes into the tunnel and is dropped (no internet at all).
 * Well-known public DNS servers are routed into the tunnel too, so apps can't skip the filter.
 */
class FilterVpn : VpnService() {

    companion object {
        private const val TAG = "HomeGuardVpn"
        private const val TUN_ADDR = "10.111.0.1"
        private const val DNS_ADDR = "10.111.0.2"
        private val PUBLIC_DNS = listOf("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
            "149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15")

        @Volatile var mode = "offline"
        @Volatile var allow: List<String> = emptyList()
        @Volatile var block: List<String> = emptyList()
        @Volatile var upstream = "1.1.1.3"
        @Volatile var running = false
        @Volatile var instance: FilterVpn? = null

        fun upstreamFor(mode: String) = if (mode == "open") "1.1.1.1" else upstream
    }

    private var tun: ParcelFileDescriptor? = null
    private var tunnelMode: String? = null
    private var reader: Thread? = null
    private val pool = Executors.newFixedThreadPool(8)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        instance = this
        applyMode()
        return START_STICKY
    }

    /** (Re)build the tunnel when switching between "DNS only" and "block everything". */
    @Synchronized
    fun applyMode() {
        val wantAll = mode == "offline"
        val shape = if (wantAll) "all" else "dns"
        if (tun != null && tunnelMode == shape) return
        val b = Builder()
            .setSession("HomeGuard")
            .addAddress(TUN_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            .setBlocking(true)
        try {
            b.addDisallowedApplication(packageName) // our own app always reaches the server
        } catch (e: Exception) { Log.w(TAG, "disallow self", e) }
        if (wantAll) {
            b.addRoute("0.0.0.0", 0)
            b.addAddress("fd11:1::1", 128)
            b.addRoute("::", 0)
        } else {
            b.addRoute(DNS_ADDR, 32)
            PUBLIC_DNS.forEach { b.addRoute(it, 32) }
        }
        val fresh = b.establish() ?: run {
            Log.w(TAG, "establish returned null (no VPN permission)")
            running = false
            return
        }
        val old = tun
        tun = fresh
        tunnelMode = shape
        running = true
        startReader(fresh)
        try { old?.close() } catch (_: Exception) {}
    }

    private fun startReader(fd: ParcelFileDescriptor) {
        val t = Thread {
            val input = FileInputStream(fd.fileDescriptor)
            val output = FileOutputStream(fd.fileDescriptor)
            val buf = ByteArray(32767)
            while (tun === fd) {
                val n = try { input.read(buf) } catch (e: Exception) { -1 }
                if (n <= 0) {
                    if (tun !== fd) break
                    continue
                }
                val packet = buf.copyOf(n)
                val q = Dns.udpQuery(packet) ?: continue // anything that isn't DNS is dropped
                pool.execute {
                    val answer = resolve(q.payload) ?: return@execute
                    val reply = Dns.udpReply(q, answer)
                    synchronized(output) {
                        try { output.write(reply) } catch (_: Exception) {}
                    }
                }
            }
        }
        reader = t
        t.start()
    }

    private fun resolve(query: ByteArray): ByteArray? {
        val name = Dns.qname(query) ?: return null
        val m = mode
        if (!Policy.allowed(name, m, allow, block)) return Dns.nxdomain(query)
        return try {
            DatagramSocket().use { s ->
                protect(s)
                s.soTimeout = 3000
                val up = InetAddress.getByName(upstreamFor(m))
                s.send(DatagramPacket(query, query.size, up, 53))
                val resp = ByteArray(4096)
                val p = DatagramPacket(resp, resp.size)
                s.receive(p)
                resp.copyOf(p.length)
            }
        } catch (e: Exception) {
            null
        }
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN revoked")
        stopTunnel()
        GuardService.instance?.onVpnRevoked()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        instance = null
        pool.shutdownNow()
        super.onDestroy()
    }

    @Synchronized
    private fun stopTunnel() {
        running = false
        val old = tun
        tun = null
        tunnelMode = null
        try { old?.close() } catch (_: Exception) {}
    }
}
