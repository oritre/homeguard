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

# Never touch the real firewall/DNS of the machine running the tests (on Windows too).
homeguard_agent.winctl.IS_WIN = False


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
        self.db.set_setting("require_password", "1")  # these tests cover the password flow
        self.db.add_kid("Noam", "1234", "נועם")
        self.tg = FakeTelegram()
        self.hg = hs.HomeGuard(cfg, self.db, self.tg)

    def test_login_sends_request_to_both_parents(self):
        res = self.hg.login("salon", "noam", "1234")
        self.assertTrue(res["ok"])
        msgs = self.tg.sent()
        self.assertEqual([m["chat_id"] for m in msgs], [1, 2])
        buttons = [b["callback_data"] for row in msgs[0]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn(f"ap:{res['request_id']}:allowlist:60", buttons)
        self.assertNotIn(f"ap:{res['request_id']}:full:60", buttons)  # default: approved sites only
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

    def cmd(self, text):
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": text}})
        return self.tg.sent()[-1]["text"]

    def test_temp_password_then_kid_picks_own(self):
        self.assertIn("סיסמה זמנית", self.cmd("/addkid Reei רעי"))
        temp = self.db.kid("reei")["pw_plain"]
        res = self.hg.login("salon", "reei", temp)
        self.assertTrue(res["need_new_password"])
        self.assertEqual(self.db.q("SELECT COUNT(*) c FROM requests")[0]["c"], 0)  # no request until it's set
        self.assertFalse(self.hg.change_password("salon", "reei", temp, "12")["ok"])  # too short
        self.assertTrue(self.hg.change_password("salon", "reei", temp, "secret9")["ok"])
        self.assertIn("secret9", self.tg.sent()[-1]["text"])  # parents get the new password
        self.assertIn("secret9", self.cmd("/kids"))
        self.assertTrue(self.hg.login("salon", "reei", "secret9")["request_id"])
        self.assertFalse(self.hg.change_password("salon", "reei", "wrong", "abcd")["ok"])

    def test_parent_account_controls(self):
        self.cmd("/setpw noam 9999")
        self.assertTrue(self.hg.login("salon", "noam", "9999")["ok"])
        self.cmd("/disable noam")
        self.assertIn("מושבת", self.hg.login("salon", "noam", "9999")["error"])
        self.cmd("/enable noam")
        self.cmd("/resetpw noam")
        self.assertTrue(self.hg.login("salon", "noam", self.db.kid("noam")["pw_plain"])["need_new_password"])
        self.cmd("/rmkid noam")
        self.assertIsNone(self.db.kid("noam"))

    def test_disable_locks_running_session(self):
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        self.hg.decide(f"ap:{rid}:full:30", "אורי")
        self.cmd("/disable noam")
        self.assertIsNone(self.hg.state("salon")["session"])

    def test_master_gets_open_unlimited_without_approval(self):
        self.db.add_kid("hagit", "pw12", "חגית", "master")
        res = self.hg.login("salon", "hagit", "pw12")
        self.assertTrue(res["approved"])
        s = self.hg.state("salon")["session"]
        self.assertEqual((s["mode"], s["unlimited"]), ("open", True))
        self.assertEqual(self.tg.sent("sendMessage")[-1].get("reply_markup"), None)  # just a notice
        self.hg.tick()
        self.assertIsNotNone(self.hg.state("salon")["session"])
        self.cmd("/lock hagit")
        self.assertIsNone(self.hg.state("salon")["session"])

    def test_unlimited_full_internet(self):
        self.db.set_setting("full_internet", "1")
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        buttons = [b["callback_data"] for row in self.tg.sent()[0]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn(f"ap:{rid}:full:0", buttons)
        self.assertNotIn(f"ap:{rid}:offline:0", buttons)
        self.hg.decide(f"ap:{rid}:full:0", "אורי")
        self.assertTrue(self.hg.state("salon")["session"]["unlimited"])
        self.assertIn("ללא הגבלת זמן", self.hg.status_text())

    def test_temporary_site_overrides_block_then_expires(self):
        self.cmd("/block youtube.com")
        self.cmd("/allow youtube.com 30")
        st = self.hg.state("salon")
        self.assertIn("youtube.com", st["allowlist"])
        self.assertNotIn("youtube.com", st["blocklist"])
        self.assertIn("זמני", self.cmd("/sites"))
        self.db.x("UPDATE sites SET expires=? WHERE list='allow'", (time.time() - 1,))
        self.hg.tick()
        st = self.hg.state("salon")
        self.assertNotIn("youtube.com", st["allowlist"])
        self.assertIn("youtube.com", st["blocklist"])
        # a permanent allow replaces the block
        self.cmd("/allow youtube.com")
        self.assertEqual(self.db.sites("block"), [])

    def test_kid_requests_site(self):
        self.assertFalse(self.hg.request_site("salon", "scratch.mit.edu")["ok"])  # no active session
        rid = self.hg.login("salon", "noam", "1234")["request_id"]
        self.hg.decide(f"ap:{rid}:allowlist:60", "אורי")
        self.assertFalse(self.hg.request_site("salon", "not a site")["ok"])
        self.assertTrue(self.hg.request_site("salon", "https://Scratch.mit.edu/projects")["ok"])
        self.hg.request_site("salon", "scratch.mit.edu")  # duplicate while pending
        site_req = self.db.q("SELECT id FROM requests WHERE kind='site'")
        self.assertEqual(len(site_req), 1)
        self.assertEqual(self.hg.decide(f"st:{site_req[0]['id']}:30", "אורי"), "אושר")
        self.assertIn("scratch.mit.edu", self.hg.state("salon")["allowlist"])
        self.assertIsNotNone(self.db.site_rows("allow")[0]["expires"])

    def test_old_database_is_migrated(self):
        import sqlite3
        path = os.path.join(self.tmp, "old")
        con = sqlite3.connect(path)
        con.executescript("CREATE TABLE kids (username TEXT PRIMARY KEY, display TEXT NOT NULL, "
                          "salt TEXT NOT NULL, pw_hash TEXT NOT NULL);"
                          "CREATE TABLE sites (domain TEXT NOT NULL, list TEXT NOT NULL, PRIMARY KEY (domain, list));")
        con.close()
        db = hs.DB(path)
        db.add_kid("a", "1234", "A")
        db.add_site("x.com", "allow", 5)
        self.assertEqual(db.kid("a")["role"], "kid")


class SiteApprovalTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        cfg = dict(hs.DEFAULT_CONFIG, parent_chat_ids=[1], agent_token="t", db=os.path.join(tmp, "db"))
        self.db = hs.DB(cfg["db"])
        self.db.add_kid("reei", "1111", "רעי")
        self.tg = FakeTelegram()
        self.hg = hs.HomeGuard(cfg, self.db, self.tg)
        rid = self.hg.login("salon", "reei", "")["request_id"]
        self.hg.decide(f"ap:{rid}:allowlist:60", "אורי")

    def ask(self, domain="scratch.mit.edu"):
        self.assertTrue(self.hg.request_site("salon", domain)["ok"])
        return self.db.q("SELECT id FROM requests WHERE kind='site' ORDER BY id DESC")[0]["id"]

    def cmd(self, text):
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": text}})
        return self.tg.sent()[-1]["text"]

    def test_buttons(self):
        rid = self.ask()
        buttons = [b["callback_data"] for row in self.tg.sent()[-1]["reply_markup"]["inline_keyboard"] for b in row]
        for data in (f"st:{rid}:s", f"st:{rid}:30", f"st:{rid}:0", f"cs:{rid}", f"dn:{rid}"):
            self.assertIn(data, buttons)

    def test_until_session_end_follows_extension_and_lock(self):
        rid = self.ask()
        self.assertEqual(self.hg.decide(f"st:{rid}:s", "אורי"), "אושר")
        self.assertIn("scratch.mit.edu", self.hg.state("salon")["allowlist"])
        self.assertIn("סוף הזמן", self.cmd("/sites"))
        self.hg.extend("salon", 30)
        row = self.db.q("SELECT expires FROM sites")[0]
        self.assertAlmostEqual(row["expires"], self.db.active_session("salon")["ends"], delta=1)
        self.hg.lock("salon")
        self.assertNotIn("scratch.mit.edu", self.hg.state("salon")["allowlist"])
        self.hg.tick()
        self.assertEqual(self.db.q("SELECT * FROM sites"), [])

    def test_until_clock_time(self):
        rid = self.ask()
        self.hg.handle_update({"callback_query": {"id": "c", "from": {"id": 1, "first_name": "אורי"},
                                                  "message": {"chat": {"id": 1}}, "data": f"cs:{rid}"}})
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "2 שעות"}})
        row = self.db.q("SELECT expires, session_id FROM sites")[0]
        self.assertIsNone(row["session_id"])
        self.assertAlmostEqual(row["expires"], time.time() + 7200, delta=5)

    def test_permanent_survives_session(self):
        self.hg.decide(f"st:{self.ask()}:0", "אורי")
        self.hg.lock("salon")
        self.assertIn("scratch.mit.edu", self.hg.state("salon")["allowlist"])

    def test_parent_allow_command(self):
        self.cmd("/allow a.com b.com 18:30")
        rows = self.db.site_rows("allow")
        self.assertEqual([r["domain"] for r in rows], ["a.com", "b.com"])
        self.assertTrue(all(r["expires"] for r in rows))
        self.cmd("/allow c.com 1.5 שעות")
        self.assertAlmostEqual(self.db.q("SELECT expires FROM sites WHERE domain='c.com'")[0]["expires"],
                               time.time() + 5400, delta=5)
        self.assertIn("לא הבנתי", self.cmd("/allow d.com מחר"))
        self.cmd("/allow e.com")
        self.assertIsNone(self.db.q("SELECT expires FROM sites WHERE domain='e.com'")[0]["expires"])

    def test_fullnet_toggle(self):
        self.assertIn("ברירת מחדל", self.cmd("/fullnet"))
        self.cmd("/fullnet on")
        rid = self.hg.login("salon", "reei", "")["request_id"]
        buttons = [b["callback_data"] for row in self.tg.sent()[-1]["reply_markup"]["inline_keyboard"] for b in row]
        self.assertIn(f"ap:{rid}:full:60", buttons)


class PasswordlessTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        cfg = dict(hs.DEFAULT_CONFIG, parent_chat_ids=[1, 2], agent_token="t", db=os.path.join(tmp, "db"))
        self.db = hs.DB(cfg["db"])
        self.db.add_kid("evyatar", "1111", "אביתר", must_set=True)
        self.db.add_kid("hagit", "secret", "חגית", role="master")
        self.tg = FakeTelegram()
        self.hg = hs.HomeGuard(cfg, self.db, self.tg)

    def test_default_is_passwordless(self):
        self.assertFalse(self.hg.passwords_required())
        lst = self.hg.kids_for_lock_screen()
        self.assertEqual([k["username"] for k in lst["kids"]], ["evyatar"])  # master not listed
        self.assertFalse(lst["require_password"])

    def test_kid_logs_in_with_name_only_and_parent_approves(self):
        res = self.hg.login("salon", "evyatar", "")
        self.assertTrue(res["ok"])
        self.assertNotIn("need_new_password", res)
        self.assertEqual([m["chat_id"] for m in self.tg.sent()], [1, 2])
        self.hg.decide(f"ap:{res['request_id']}:full:30", "אורי")
        self.assertEqual(self.hg.state("salon")["session"]["kid"], "evyatar")

    def test_master_still_needs_password(self):
        self.assertFalse(self.hg.login("salon", "hagit", "")["ok"])
        self.assertTrue(self.hg.login("salon", "hagit", "secret")["approved"])

    def test_disabled_kid_hidden_and_refused(self):
        self.db.x("UPDATE kids SET disabled=1 WHERE username='evyatar'")
        self.assertEqual(self.hg.kids_for_lock_screen()["kids"], [])
        self.assertFalse(self.hg.login("salon", "evyatar", "")["ok"])

    def test_bot_toggle(self):
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "/passwords on"}})
        self.assertTrue(self.hg.passwords_required())
        self.assertFalse(self.hg.login("salon", "evyatar", "")["ok"])
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "/passwords off"}})
        self.assertFalse(self.hg.passwords_required())


class CustomTimeTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.mkdtemp()
        cfg = dict(hs.DEFAULT_CONFIG, parent_chat_ids=[1], agent_token="t", db=os.path.join(tmp, "db"))
        self.db = hs.DB(cfg["db"])
        self.db.add_kid("reei", "1111", "רעי")
        self.hg = hs.HomeGuard(cfg, self.db, FakeTelegram())

    def test_parse(self):
        from datetime import datetime
        now = datetime(2026, 10, 15, 17, 0).timestamp()
        self.assertEqual(hs.parse_duration("45", now), 45)
        self.assertEqual(hs.parse_duration("2 שעות", now), 120)
        self.assertEqual(hs.parse_duration("1.5ש", now), 90)
        self.assertEqual(hs.parse_duration("עד 18:30", now), 90)
        self.assertEqual(hs.parse_duration("16:00", now), 23 * 60)
        self.assertEqual(hs.parse_duration("מחר", now), 0)

    def cb(self, data):
        self.hg.handle_update({"callback_query": {"id": "c", "from": {"id": 1, "first_name": "אורי"},
                                                  "message": {"chat": {"id": 1}}, "data": data}})

    def test_custom_login_time(self):
        rid = self.hg.login("salon", "reei", "")["request_id"]
        self.cb(f"cu:{rid}:allowlist")
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "abc"}})  # not understood, still waiting
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "45"}})
        s = self.hg.state("salon")["session"]
        self.assertEqual(s["mode"], "allowlist")
        self.assertTrue(44 * 60 < s["remaining"] <= 45 * 60)

    def test_custom_extension(self):
        rid = self.hg.login("salon", "reei", "")["request_id"]
        self.hg.decide(f"ap:{rid}:full:30", "אורי")
        self.hg.request_extension("salon")
        ext = self.db.q("SELECT id FROM requests WHERE kind='extend'")[0]["id"]
        self.cb(f"cx:{ext}")
        self.hg.handle_update({"message": {"chat": {"id": 1}, "text": "2 שעות"}})
        self.assertGreater(self.hg.state("salon")["session"]["remaining"], 149 * 60)


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
        db.set_setting("require_password", "1")
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

    def test_master_login_opens_dns_immediately(self):
        self.hg.db.add_kid("hagit", "pw12", "חגית", "master")
        self.agent.poll_once()
        res = self.local_call("POST", "/login", {"username": "hagit", "password": "pw12"})
        self.assertTrue(res["approved"])
        self.assertEqual(self.agent.mode, "open")
        self.assertTrue(self.agent.dns_decide("anything.example"))
        self.assertTrue(self.local_call("GET", "/state")["session"]["unlimited"])

    def test_password_and_site_through_local_api(self):
        self.hg.db.add_kid("iftach", "0000", "יפתח", must_set=True)
        self.assertTrue(self.local_call("POST", "/login", {"username": "iftach", "password": "0000"})
                        ["need_new_password"])
        self.assertTrue(self.local_call("POST", "/passwd", {"username": "iftach", "old": "0000", "new": "abcd"})["ok"])
        res = self.local_call("POST", "/login", {"username": "iftach", "password": "abcd"})
        self.hg.decide(f"ap:{res['request_id']}:allowlist:60", "אורי")
        self.agent.poll_once()
        self.assertFalse(self.agent.dns_decide("scratch.mit.edu"))
        self.assertTrue(self.local_call("POST", "/site", {"domain": "scratch.mit.edu"})["ok"])
        rid = self.hg.db.q("SELECT id FROM requests WHERE kind='site'")[0]["id"]
        self.hg.decide(f"st:{rid}:30", "אורי")
        self.agent.poll_once()
        self.assertTrue(self.agent.dns_decide("scratch.mit.edu"))

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
