"""Tiny filtering DNS forwarder (UDP + TCP) used by the HomeGuard agent.

The PC's network adapters point at 127.0.0.1 / ::1, so every name lookup passes
through here. Depending on the current mode a lookup is forwarded to the
upstream resolver or answered with NXDOMAIN ("this site doesn't exist").
"""
from __future__ import annotations

import logging
import socket
import socketserver
import struct
import threading

log = logging.getLogger("homeguard.dns")

# Domains a site in the allowlist needs to actually work (CDNs, logins, images).
DEPENDENCIES = {
    "youtube.com": ["ytimg.com", "googlevideo.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com"],
    "google.com": ["gstatic.com", "googleapis.com", "googleusercontent.com", "google.co.il"],
    "wikipedia.org": ["wikimedia.org"],
    "khanacademy.org": ["kastatic.org", "kasandbox.org"],
    "scratch.mit.edu": ["scratch.org"],
    "microsoft.com": ["live.com", "microsoftonline.com", "msauth.net", "msftauth.net"],
    "office.com": ["office.net", "live.com", "microsoftonline.com", "msauth.net", "msftauth.net", "officeapps.live.com"],
}
# Always resolvable, so Windows doesn't show "no internet" and keeps the clock right.
ESSENTIAL = ["msftconnecttest.com", "msftncsi.com", "time.windows.com"]


def matches(domain: str, patterns) -> bool:
    domain = domain.lower().rstrip(".")
    for p in patterns:
        p = p.lower().strip(".")
        if domain == p or domain.endswith("." + p):
            return True
    return False


def expand_allowlist(allow: list[str]) -> list[str]:
    out = list(allow) + ESSENTIAL
    for d in allow:
        for base, deps in DEPENDENCIES.items():
            if d == base or d.endswith("." + base) or base.endswith("." + d):
                out.extend(deps)
    return out


def is_allowed(domain: str, mode: str, allow: list[str], block: list[str], always=()) -> bool:
    """mode: 'open' (parent, no filtering), 'full', 'allowlist', 'offline'.
    always: sites the parents keep open in every mode, even with the internet off."""
    if mode == "open":
        return True
    if always and matches(domain, expand_allowlist(list(always))):
        return True
    if mode == "offline":
        return matches(domain, ESSENTIAL)
    if matches(domain, block):
        return False
    if mode == "allowlist":
        return matches(domain, expand_allowlist(allow))
    return True  # full


def parse_qname(packet: bytes) -> tuple[str, int]:
    """Return (name, offset just after QTYPE/QCLASS) of the first question."""
    if len(packet) < 12:
        raise ValueError("short packet")
    i = 12
    labels = []
    while True:
        n = packet[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0:
            raise ValueError("compressed qname")
        labels.append(packet[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(labels), i + 4


def _skip_name(packet: bytes, i: int) -> int:
    while True:
        n = packet[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


def answer_ips(packet: bytes) -> list[str]:
    """IPv4/IPv6 addresses in the answer section of a DNS response ([] if it can't be read)."""
    try:
        qd, an = struct.unpack(">HH", packet[4:8])
        i = 12
        for _ in range(qd):
            i = _skip_name(packet, i) + 4
        ips = []
        for _ in range(an):
            i = _skip_name(packet, i)
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", packet[i:i + 10])
            i += 10
            data = packet[i:i + rdlen]
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, data))
            elif rtype == 28 and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, data))
            i += rdlen
        return ips
    except (IndexError, struct.error, OSError, ValueError):
        return []


def nxdomain(query: bytes) -> bytes:
    _, end = parse_qname(query)
    qid, flags = struct.unpack(">HH", query[:4])
    rflags = 0x8000 | (flags & 0x7900) | 0x0080 | 3  # QR, opcode+RD, RA, NXDOMAIN
    return struct.pack(">HHHHHH", qid, rflags, 1, 0, 0, 0) + query[12:end]


class DnsFilter:
    def __init__(self, decide, upstream, port: int = 53, on_answer=None):
        """decide(domain) -> bool ; upstream() -> ip of resolver to forward to ;
        on_answer(domain, response) runs before the answer is handed back."""
        self.decide = decide
        self.upstream = upstream
        self.port = port
        self.on_answer = on_answer
        self.servers = []

    def resolve(self, query: bytes, tcp: bool = False) -> bytes | None:
        try:
            name, _ = parse_qname(query)
        except (ValueError, IndexError):
            return None
        if not self.decide(name):
            log.debug("blocked %s", name)
            return nxdomain(query)
        up = self.upstream()
        fam = socket.AF_INET6 if ":" in up else socket.AF_INET
        try:
            if tcp:
                with socket.create_connection((up, 53), timeout=4) as s:
                    s.sendall(struct.pack(">H", len(query)) + query)
                    ln = struct.unpack(">H", _recv_exact(s, 2))[0]
                    data = _recv_exact(s, ln)
            else:
                with socket.socket(fam, socket.SOCK_DGRAM) as s:
                    s.settimeout(3)
                    s.sendto(query, (up, 53))
                    data, _ = s.recvfrom(4096)
        except OSError as e:
            log.debug("upstream failed for %s: %s", name, e)
            return None
        if self.on_answer:
            try:
                self.on_answer(name, data)
            except Exception as e:  # never break name lookups
                log.warning("on_answer %s: %s", name, e)
        return data

    def start(self, hosts=("127.0.0.1", "::1")) -> None:
        flt = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                resp = flt.resolve(data)
                if resp:
                    sock.sendto(resp, self.client_address)

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    ln = struct.unpack(">H", _recv_exact(self.request, 2))[0]
                    resp = flt.resolve(_recv_exact(self.request, ln), tcp=True)
                    if resp:
                        self.request.sendall(struct.pack(">H", len(resp)) + resp)
                except (OSError, struct.error):
                    pass

        for host in hosts:
            v6 = ":" in host
            for base, handler in ((socketserver.ThreadingUDPServer, UDP), (socketserver.ThreadingTCPServer, TCP)):
                cls = type("S", (base,), {"address_family": socket.AF_INET6 if v6 else socket.AF_INET,
                                          "daemon_threads": True, "allow_reuse_address": True})
                try:
                    srv = cls((host, self.port), handler)
                except OSError as e:
                    log.error("DNS bind %s:%s failed: %s", host, self.port, e)
                    continue
                self.servers.append(srv)
                threading.Thread(target=srv.serve_forever, daemon=True).start()
        log.info("DNS filter listening on %s port %s", hosts, self.port)

    def stop(self) -> None:
        for s in self.servers:
            s.shutdown()
            s.server_close()


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf
