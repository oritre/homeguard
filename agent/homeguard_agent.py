"""HomeGuard agent: runs on each kid PC as SYSTEM (scheduled task at startup).

- asks the HomeGuard server what is allowed on this PC right now
- turns internet on/off with the Windows firewall
- filters websites with a local DNS forwarder
- serves a local API on 127.0.0.1 for the lock screen
- logs a kid out if the lock screen is closed or killed

Config: C:\\ProgramData\\HomeGuard\\agent.json (readable only by SYSTEM/Administrators).
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dnsfilter  # noqa: E402
import winctl  # noqa: E402

log = logging.getLogger("homeguard")

DEFAULT_CONFIG = {
    "server_url": "http://192.168.1.10:8800",
    "agent_token": "",
    "pc_name": os.environ.get("COMPUTERNAME", "pc"),
    "exempt_users": [],               # parents' Windows accounts: never locked or filtered
    "upstream_dns": "1.1.1.3",        # Cloudflare for Families (blocks malware + adult content)
    "upstream_dns_exempt": "1.1.1.1",
    "local_port": 8765,
    "dns_port": 53,
    "poll_seconds": 5,
    "lockscreen_timeout": 45,         # seconds without a lock-screen heartbeat before logoff
    "logon_grace": 120,               # seconds after a kid logs in before the watchdog acts
    "harden_kid_accounts": True,
}


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.RLock()
        self.server_state: dict | None = None
        self.state_time = 0.0
        self.server_online = False
        self.user = ""
        self.session_id = None
        self.user_since = 0.0
        self.last_heartbeat = 0.0
        self.applied_internet: bool | None = None
        self.mode = "offline"
        self.hardened: set[str] = set()
        self.poll_lock = threading.Lock()

    # ------------------------------------------------------------ server calls
    def _call(self, method: str, path: str, body: dict | None = None, params: dict | None = None):
        url = self.cfg["server_url"].rstrip("/") + path
        if params:
            url += "?" + urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "X-Agent-Token": self.cfg["agent_token"], "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read())

    def server(self, method: str, path: str, body: dict | None = None, params: dict | None = None):
        try:
            res = self._call(method, path, body, params)
            self.server_online = True
            return res
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.server_online = False
            log.warning("server %s %s failed: %s", method, path, e)
            return None

    # ------------------------------------------------------------- decisions
    def is_exempt(self, user: str) -> bool:
        return user.lower() in {u.lower() for u in self.cfg["exempt_users"]}

    def session(self) -> dict | None:
        """Current approved session, counting down locally if the server is unreachable."""
        with self.lock:
            st = self.server_state
            if not st or not st.get("session"):
                return None
            s = dict(st["session"])
            s["remaining"] = int(s["remaining"] - (time.time() - self.state_time))
            return s if s["remaining"] > 0 else None

    def current_mode(self) -> str:
        if self.user and self.is_exempt(self.user):
            return "open"
        if not self.user:
            return "offline"
        s = self.session()
        return s["mode"] if s else "offline"

    def dns_decide(self, domain: str) -> bool:
        with self.lock:
            st = self.server_state or {}
            mode = self.mode
        return dnsfilter.is_allowed(domain, mode, st.get("allowlist", []), st.get("blocklist", []))

    def upstream(self) -> str:
        return self.cfg["upstream_dns_exempt"] if self.mode == "open" else self.cfg["upstream_dns"]

    # ------------------------------------------------------------- main loop
    def poll_once(self) -> None:
        with self.poll_lock:
            self._poll()

    def _poll(self) -> None:
        sid, user = winctl.console_session()
        if user != self.user:
            log.info("console user: %r -> %r", self.user, user)
            self.user, self.session_id, self.user_since = user, sid, time.time()
            if user and not self.is_exempt(user) and self.cfg["harden_kid_accounts"] and user not in self.hardened:
                winctl.harden_user(user)
                self.hardened.add(user)
        self.session_id = sid
        st = self.server("GET", "/api/state", params={"pc": self.cfg["pc_name"], "user": user})
        if st is not None:
            with self.lock:
                self.server_state, self.state_time = st, time.time()
        self.apply()
        self.watchdog()

    def apply(self) -> None:
        mode = self.current_mode()
        if mode != self.mode:
            log.info("mode %s -> %s", self.mode, mode)
            self.mode = mode
            winctl.flush_dns()
        want_internet = mode != "offline"
        if want_internet != self.applied_internet:
            winctl.internet(want_internet)
            self.applied_internet = want_internet

    def watchdog(self) -> None:
        """A kid is at the PC but the lock screen isn't running: log them off."""
        if not self.user or self.is_exempt(self.user):
            return
        now = time.time()
        if now - self.user_since < self.cfg["logon_grace"]:
            return
        if now - self.last_heartbeat > self.cfg["lockscreen_timeout"]:
            log.warning("lock screen missing for %s, logging off", self.user)
            winctl.logoff(self.session_id)
            self.user_since = now  # don't hammer while the logoff happens

    def local_state(self) -> dict:
        self.last_heartbeat = time.time()
        with self.lock:
            st = self.server_state or {}
        return {"user": self.user, "exempt": bool(self.user) and self.is_exempt(self.user),
                "session": self.session(), "extend_pending": st.get("extend_pending", False),
                "server_online": self.server_online, "pc": self.cfg["pc_name"]}

    def run(self) -> None:
        server_ip = urlparse(self.cfg["server_url"]).hostname or ""
        winctl.firewall_setup(server_ip)
        winctl.internet(False)
        self.applied_internet = False
        winctl.point_dns_to_local()
        dns = dnsfilter.DnsFilter(self.dns_decide, self.upstream, self.cfg["dns_port"])
        dns.start()
        local = ThreadingHTTPServer(("127.0.0.1", self.cfg["local_port"]), make_local_handler(self))
        threading.Thread(target=local.serve_forever, daemon=True).start()
        log.info("agent running for pc %s", self.cfg["pc_name"])
        last_dns_fix = time.time()
        while True:
            try:
                self.poll_once()
                if time.time() - last_dns_fix > 600:
                    winctl.point_dns_to_local()  # new Wi-Fi / adapter
                    last_dns_fix = time.time()
            except Exception:
                log.exception("poll failed")
            time.sleep(self.cfg["poll_seconds"])


def make_local_handler(agent: Agent):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, obj, code: int = 200) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            qs = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/state":
                self._send(agent.local_state())
            elif u.path == "/kids":
                agent.last_heartbeat = time.time()
                self._send(agent.server("GET", "/api/kids") or {"kids": [], "require_password": True})
            elif u.path == "/request":
                agent.last_heartbeat = time.time()
                res = agent.server("GET", "/api/request", params={"id": qs.get("id", "0")})
                if res and res.get("status") == "approved":
                    agent.poll_once()  # pick the new session up immediately
                self._send(res or {"status": "offline"})
            else:
                self._send({"error": "not found"}, 404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                body = {}
            agent.last_heartbeat = time.time()
            pc = agent.cfg["pc_name"]
            path = urlparse(self.path).path
            if path == "/login":
                res = agent.server("POST", "/api/login", {"pc": pc, "username": body.get("username", ""),
                                                          "password": body.get("password", "")})
                if res and res.get("approved"):
                    agent.poll_once()  # master account: open right away
                self._send(res or {"ok": False, "error": "אין חיבור לשרת. בקשו מאבא/אמא לבדוק."})
            elif path == "/passwd":
                res = agent.server("POST", "/api/passwd", {"pc": pc, "username": body.get("username", ""),
                                                           "old": body.get("old", ""), "new": body.get("new", "")})
                self._send(res or {"ok": False, "error": "אין חיבור לשרת"})
            elif path == "/site":
                self._send(agent.server("POST", "/api/site", {"pc": pc, "domain": body.get("domain", "")})
                           or {"ok": False, "error": "אין חיבור לשרת"})
            elif path == "/cancel":
                agent.server("POST", "/api/cancel", {"pc": pc, "request_id": body.get("request_id", 0)})
                self._send({"ok": True})
            elif path == "/extend":
                self._send(agent.server("POST", "/api/extend", {"pc": pc}) or {"ok": False, "error": "אין חיבור"})
            elif path == "/end":
                agent.server("POST", "/api/end", {"pc": pc})
                agent.poll_once()
                self._send({"ok": True})
            else:
                self._send({"error": "not found"}, 404)

    return Handler


def main() -> None:
    base = os.path.join(os.environ.get("ProgramData", "."), "HomeGuard")
    os.makedirs(base, exist_ok=True)
    cfg_path = os.environ.get("HOMEGUARD_AGENT_CONFIG", os.path.join(base, "agent.json"))
    handler = logging.handlers.RotatingFileHandler(os.path.join(base, "agent.log"), maxBytes=1_000_000,
                                                   backupCount=3, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[handler, logging.StreamHandler()])
    cfg = dict(DEFAULT_CONFIG)
    with open(cfg_path, encoding="utf-8") as f:
        cfg.update(json.load(f))
    if len(sys.argv) > 1 and sys.argv[1] == "uninstall":
        winctl.restore_defaults()
        return
    Agent(cfg).run()


if __name__ == "__main__":
    main()
