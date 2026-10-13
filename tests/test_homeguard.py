"""End-to-end tests that run on any OS (Windows calls become dry-run logs).

    python -m unittest discover -s tests -v
"""
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
sys.path.insert(0, os.path.join(ROOT, "agent"))

import dnsfilter  # noqa: E402
import homeguard_agent  # noqa: E402
import homeguard_server as hs  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def dns_query(name: str, qid: int = 0x1234) -> bytes:
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)


class FakeTelegram:
    def __init__(self):
        self.calls = []
        self.next_id = 100

    def call(self, method, **params):
        self.calls.append((method, params))
        self.next_id += 1
        return {"message_id": self.next_id}

    def sent(self, method="sendMessage"):
        return [p for m, p in self.calls if m == method]


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        cfg = dict(hs.DEFAULT_CONFIG, parent_chat_ids=[1, 2], agent_token="t", db=os.path.join(self.tmp, "db"))
        self.db = hs.DB(cfg["db"])
        self.db.add_kid("Noam", "1234", "נועם")
        self.tg = FakeTelegram()
        self.hg = hs.HomeGuard(cfg, self.db, self.tg)

    def test_login_sends_request_to_both_parents(self):
        res = self.hg.login("salon", "noam", "1234")
        self.assertTrue(res["ok"])
        msgs = self.tg.sent()
        self.assertEqual([m["chat_id"] for m in msgs], [1, 2])
        buttons = [b["callback_data"] for row in msgs[0]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn(f"ap:{res['request_id']}:full:60", buttons)
        self.assertIn(f"dn:{res['request_id']}", buttons)

    def test_wrong_password(self):
        self.assertFalse(self.hg.login("salon", "noam", "nope")["ok"])
        self.assertEqual(self.tg.sent(), [])

    def test_too_many_failures_alerts_parents(self):
        for _ in range(5):
            self.hg.login("salon", "noam", "x")
        self.assertIn("ניסיונות", self.tg.sent()[0]["text"])
        self.assertFalse(self.hg.login("salon", "noam", "1234")["ok"])  # locked out for now

    def test_approve_creates_session_and_edits_both_messages(self):
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        self.assertEqual(self.hg.decide(f"ap:{rid}:allowlist:30", "אורי"), "אושר")
        st = self.hg.state("salon", "kids")
        self.assertEqual(st["session"]["mode"], "allowlist")
        self.assertGreater(st["session"]["remaining"], 29 * 60)
        self.assertEqual(len(self.tg.sent("editMessageText")), 2)
        # second parent pressing a button later is ignored
        self.assertEqual(self.hg.decide(f"dn:{rid}", "wife"), "כבר טופל")

    def test_deny(self):
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        self.hg.decide(f"dn:{rid}", "אורי")
        self.assertEqual(self.hg.request_status(rid)["status"], "denied")
        self.assertIsNone(self.hg.state("salon")["session"])

    def test_extension_flow(self):
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        self.hg.decide(f"ap:{rid}:full:30", "אורי")
        self.hg.request_extension("salon")
        self.assertTrue(self.hg.state("salon")["extend_pending"])
        ext = self.db.q("SELECT id FROM requests WHERE kind='extend'")[0]["id"]
        self.hg.decide(f"ex:{ext}:15", "אורי")
        self.assertGreater(self.hg.state("salon")["session"]["remaining"], 44 * 60)

    def test_expiry_and_lock(self):
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        self.hg.decide(f"ap:{rid}:full:30", "אורי")
        self.db.x("UPDATE sessions SET ends=?", (time.time() - 1,))
        self.hg.tick()
        self.assertIsNone(self.hg.state("salon")["session"])
        self.assertIn("נגמר", self.tg.sent()[-1]["text"])

    def test_telegram_commands(self):
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "/allow https://www.Wikipedia.org/wiki/X"}})
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "/block tiktok.com"}})
        self.assertEqual(self.db.sites("allow"), ["wikipedia.org"])
        self.assertEqual(self.db.sites("block"), ["tiktok.com"])
        # strangers only get their chat id back
        self.hg.handle_update({"message": {"chat": {"id": 99}, "text": "/block google.com"}})
        self.assertEqual(self.db.sites("block"), ["tiktok.com"])

    def test_lock_via_callback(self):
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        self.hg.decide(f"ap:{rid}:full:30", "אורי")
        self.hg.handle_update({"callback_query": {"id": "c", "from": {"id": 2, "first_name": "W"},
                                                  "message": {"chat": {"id": 2}}, "data": "lk:salon"}})
        self.assertIsNone(self.hg.state("salon")["session"])


class DnsTest(unittest.TestCase):
    def test_policy(self):
        allow, block = ["wikipedia.org", "youtube.com"], ["tiktok.com"]
        self.assertTrue(dnsfilter.is_allowed("he.wikipedia.org", "allowlist", allow, block))
        self.assertTrue(dnsfilter.is_allowed("i.ytimg.com", "allowlist", allow, block))
        self.assertFalse(dnsfilter.is_allowed("facebook.com", "allowlist", allow, block))
        self.assertTrue(dnsfilter.is_allowed("facebook.com", "full", allow, block))
        self.assertFalse(dnsfilter.is_allowed("www.tiktok.com", "full", allow, block))
        self.assertFalse(dnsfilter.is_allowed("wikipedia.org", "offline", allow, block))
        self.assertTrue(dnsfilter.is_allowed("tiktok.com", "open", allow, block))
        self.assertFalse(dnsfilter.is_allowed("notwikipedia.org", "allowlist", allow, block))

    def test_nxdomain_packet(self):
        q = dns_query("tiktok.com")
        r = dnsfilter.nxdomain(q)
        qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", r[:12])
        self.assertEqual((qid, flags & 0x8000, flags & 0xF, qd, an), (0x1234, 0x8000, 3, 1, 0))
        self.assertEqual(r[12:], q[12:])

    def test_forwarder_blocks_and_forwards(self):
        # fake upstream resolver that answers every query with a marker
        port = free_port()
        upstream_port = free_port()
        fake = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fake.bind(("127.0.0.1", upstream_port))

        def serve():
            while True:
                try:
                    data, addr = fake.recvfrom(4096)
                except OSError:
                    return
                fake.sendto(data[:2] + b"UPSTREAM", addr)

        threading.Thread(target=serve, daemon=True).start()
        flt = dnsfilter.DnsFilter(lambda d: not d.endswith("tiktok.com"), lambda: "127.0.0.1", port)
        orig = socket.socket.sendto

        def redirect(sock, data, addr):  # send "port 53" traffic to the fake upstream
            if addr == ("127.0.0.1", 53):
                addr = ("127.0.0.1", upstream_port)
            return orig(sock, data, addr)

        socket.socket.sendto = redirect
        try:
            flt.start(hosts=("127.0.0.1",))
            c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c.settimeout(3)
            c.sendto(dns_query("tiktok.com"), ("127.0.0.1", port))
            blocked, _ = c.recvfrom(512)
            self.assertEqual(struct.unpack(">H", blocked[2:4])[0] & 0xF, 3)
            c.sendto(dns_query("wikipedia.org"), ("127.0.0.1", port))
            ok, _ = c.recvfrom(512)
            self.assertEqual(ok[2:], b"UPSTREAM")
        finally:
            socket.socket.sendto = orig
            flt.stop()
            fake.close()


class AgentEndToEnd(unittest.TestCase):
    """Real server HTTP API + real agent loop + local API the lock screen uses."""

    def setUp(self):
        tmp = tempfile.mkdtemp()
        sport = free_port()
        cfg = dict(hs.DEFAULT_CONFIG, parent_chat_ids=[1], agent_token="secret", db=os.path.join(tmp, "db"))
        db = hs.DB(cfg["db"])
        db.add_kid("noam", "1234", "נועם")
        db.add_site("wikipedia.org", "allow")
        self.hg = hs.HomeGuard(cfg, db, FakeTelegram())
        self.srv = ThreadingHTTPServer(("127.0.0.1", sport), hs.make_handler(self.hg))
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

        self.lport = free_port()
        acfg = dict(homeguard_agent.DEFAULT_CONFIG, server_url=f"http://127.0.0.1:{sport}", agent_token="secret",
                    pc_name="salon", exempt_users=["Ori"], local_port=self.lport)
        self.agent = homeguard_agent.Agent(acfg)
        self.user = "kid"
        homeguard_agent.winctl.console_session = lambda: (1, self.user)
        self.logoffs = []
        homeguard_agent.winctl.logoff = self.logoffs.append
        self.local = ThreadingHTTPServer(("127.0.0.1", self.lport), homeguard_agent.make_local_handler(self.agent))
        threading.Thread(target=self.local.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.local.shutdown()

    def local_call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{self.lport}{path}", data=data, method=method)
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def test_full_flow(self):
        self.agent.poll_once()
        self.assertEqual(self.agent.mode, "offline")
        self.assertFalse(self.agent.applied_internet)

        res = self.local_call("POST", "/login", {"username": "noam", "password": "1234"})
        self.assertTrue(res["ok"])
        self.assertEqual(self.local_call("GET", f"/request?id={res['request_id']}")["status"], "pending")

        self.hg.decide(f"ap:{res['request_id']}:allowlist:60", "אורי")
        self.assertEqual(self.local_call("GET", f"/request?id={res['request_id']}")["status"], "approved")
        st = self.local_call("GET", "/state")
        self.assertEqual(st["session"]["display"], "נועם")
        self.assertEqual(self.agent.mode, "allowlist")
        self.assertTrue(self.agent.applied_internet)
        self.assertTrue(self.agent.dns_decide("he.wikipedia.org"))
        self.assertFalse(self.agent.dns_decide("roblox.com"))

        self.hg.lock("salon")  # parent presses "lock" in Telegram
        self.agent.poll_once()
        self.assertEqual(self.agent.mode, "offline")
        self.assertIsNone(self.local_call("GET", "/state")["session"])

    def test_parent_is_exempt(self):
        self.user = "ori"
        self.agent.poll_once()
        self.assertEqual(self.agent.mode, "open")
        self.assertTrue(self.local_call("GET", "/state")["exempt"])

    def test_watchdog_logs_off_without_lockscreen(self):
        self.agent.poll_once()
        self.agent.user_since -= 1000
        self.agent.poll_once()
        self.assertEqual(self.logoffs, [1])

    def test_server_down_keeps_counting_locally(self):
        res = self.local_call("POST", "/login", {"username": "noam", "password": "1234"})
        self.hg.decide(f"ap:{res['request_id']}:full:30", "אורי")
        self.agent.poll_once()
        self.srv.shutdown()
        self.srv.server_close()
        self.agent.state_time -= 31 * 60  # pretend 31 minutes passed offline
        self.agent.poll_once()
        self.assertEqual(self.agent.mode, "offline")


if __name__ == "__main__":
    unittest.main()
