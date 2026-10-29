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
import socket
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
    "lock_as_shell": True,             # kids' sign-in starts the lock screen instead of the Windows desktop
    "diag_upload": True,               # send the agent log to the server, for troubleshooting from afar
    "home_wifi": [],                   # home Wi-Fi names to rejoin when the PC isn't connected (also learned)
    "kid_desktops": True,              # a Windows account per kid; a locked kid's programs are frozen, not closed
    "admins_exempt": True,             # Windows administrators (the parents' account) are never locked
}

# Windows' own parts of a session, RustDesk (remote help) and the lock screen's Python: never frozen.
KEEP_RUNNING = {
    "explorer.exe", "sihost.exe", "svchost.exe", "ctfmon.exe", "conhost.exe", "runtimebroker.exe",
    "taskhostw.exe", "dllhost.exe", "dwm.exe", "fontdrvhost.exe", "searchhost.exe", "searchapp.exe",
    "searchui.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe",
    "lockapp.exe", "logonui.exe", "winlogon.exe", "csrss.exe", "userinit.exe", "smartscreen.exe",
    "securityhealthsystray.exe", "applicationframehost.exe", "useroobebroker.exe", "rustdesk.exe",
    "pythonw.exe", "python.exe",
}


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.lock = threading.RLock()
        self.always_ips: set[str] = set()
        self.applied_always: tuple = ()
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
        self.log_path = ""
        self.home_wifi: list[str] = list(cfg.get("home_wifi") or [])
        self.signin_at = 0.0  # when the current kid signed in, until the lock screen first answers
        self.kid_users: dict[str, str] = {}  # HomeGuard kid -> display name; each has a Windows account
        self.kids_checked = 0.0
        self.accounts_made: set[str] = set()
        self.frozen: dict[str, dict] = {}  # Windows user -> {"session": id, "pids": [[pid, name], ...]}
        self.admins: dict[str, bool] = {}
        self.unhardened: set[str] = set()
        self.console_since = 0.0  # when whoever is at the screen signed in (user_since also moves on logoff)
        app = os.path.dirname(os.path.abspath(__file__))
        exe = sys.executable
        if exe.lower().endswith("python.exe"):
            exe = exe[:-len("python.exe")] + "pythonw.exe"
        self.app_dir = app
        self.lock_cmd = f'"{exe}" "{os.path.join(app, "lockscreen.pyw")}"'

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
        if user.lower() in {u.lower() for u in self.cfg["exempt_users"]}:
            return True
        if not user or not self.cfg["admins_exempt"] or not self.cfg["kid_desktops"] or self.is_kid(user):
            return False
        key = user.lower()
        if key not in self.admins:
            self.admins[key] = winctl.is_admin(user)
            if self.admins[key]:
                log.info("%s is a Windows administrator: never locked", user)
        return self.admins[key]

    def is_kid(self, user: str) -> bool:
        """A kid's own Windows account (same name as their HomeGuard user)."""
        return self.cfg["kid_desktops"] and bool(user) and user.lower() in self.kid_users

    def session_for(self, user: str) -> dict | None:
        """The approved session, if it belongs to whoever is signed in to Windows as `user`. A kid's own
        account never gets a brother's session; the shared account and a master sign-in work as before."""
        s = self.session()
        if s and self.is_kid(user) and s["kid"].lower() != user.lower() and s["kid"].lower() in self.kid_users:
            return None
        return s

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
        s = self.session_for(self.user)
        return s["mode"] if s else "offline"

    def dns_decide(self, domain: str) -> bool:
        with self.lock:
            st = self.server_state or {}
            mode = self.mode
        return dnsfilter.is_allowed(domain, mode, st.get("allowlist", []), st.get("blocklist", []),
                                    st.get("alwayslist", []))

    def dns_answer(self, domain: str, response: bytes) -> None:
        """Internet off (firewall blocks everything): let through the addresses of always-open sites,
        before the browser gets the answer and connects. Windows' own "is there internet" check
        (msftconnecttest.com) is let through too: when it fails, Windows drops the Wi-Fi."""
        with self.lock:
            always = (self.server_state or {}).get("alwayslist", [])
            if self.mode != "offline":
                return
            if not dnsfilter.matches(domain, dnsfilter.expand_allowlist(always)):  # includes ESSENTIAL
                return
            new = [ip for ip in dnsfilter.answer_ips(response) if ip not in self.always_ips]
            if not new:
                return
            self.always_ips.update(new)
            ips = sorted(self.always_ips)
        log.info("always-open %s: allowing %s", domain, ", ".join(new))
        winctl.allow_ips(ips)

    def upstream(self) -> str:
        return self.cfg["upstream_dns_exempt"] if self.mode == "open" else self.cfg["upstream_dns"]

    # ------------------------------------------------------------- main loop
    def poll_once(self) -> None:
        with self.poll_lock:
            self._poll()

    def _poll(self) -> None:
        if time.time() - self.kids_checked > 600:
            self.refresh_kids()
        sid, user = winctl.console_session()
        if user != self.user:
            log.info("console user: %r -> %r", self.user, user)
            prev = self.user
            s = self.session()
            if self.is_kid(prev) and s and s["kid"].lower() == prev.lower():
                # The kid left their seat (switched user): their time ends, their programs wait frozen.
                log.info("%s switched away: ending their session", prev)
                self.server("POST", "/api/end", {"pc": self.cfg["pc_name"]})
                with self.lock:
                    self.server_state = None
            self.user, self.session_id, self.user_since = user, sid, time.time()
            self.console_since = self.user_since
            if user and not self.is_exempt(user) and self.cfg["harden_kid_accounts"] and user not in self.hardened:
                winctl.harden_user(user, self.lock_cmd if self.cfg["lock_as_shell"] else "")
                self.hardened.add(user)
            elif user and self.is_exempt(user) and user not in self.unhardened:
                winctl.unharden_user(user)  # a parent's account: normal desktop from the next sign-in
                self.unhardened.add(user)
        self.session_id = sid
        st = self.server("GET", "/api/state", params={"pc": self.cfg["pc_name"], "user": user})
        if st is not None:
            with self.lock:
                self.server_state, self.state_time = st, time.time()
        self.apply()
        self.watchdog()
        self.enforce_desktops()

    # --------------------------------------------------------- kids' desktops
    def _data_path(self, name: str) -> str:
        return os.path.join(os.path.dirname(self.log_path), name) if self.log_path else ""

    def _save(self, name: str, obj) -> None:
        path = self._data_path(name)
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False)
        except OSError as e:
            log.warning("saving %s failed: %s", name, e)

    def _load(self, name: str, default):
        try:
            with open(self._data_path(name), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError, TypeError):
            return default

    def refresh_kids(self) -> None:
        """The kids' list from the server (kept on disk for when it's away), and a Windows account for each."""
        self.kids_checked = time.time()
        if not self.cfg["kid_desktops"]:
            return
        res = self.server("GET", "/api/kids")
        if res and not res.get("offline") and isinstance(res.get("kids"), list):
            kids = {str(k["username"]).lower(): str(k.get("display") or k["username"]) for k in res["kids"]}
            if kids != self.kid_users:
                self.kid_users = kids
                self._save("kids.json", kids)
        elif not self.kid_users:
            self.kid_users = self._load("kids.json", {})
        for name, display in self.kid_users.items():
            if name not in self.accounts_made:
                if winctl.ensure_kid_account(name, display):
                    log.info("Windows account created for %s (%s)", name, display)
                self.accounts_made.add(name)

    def enforce_desktops(self) -> None:
        """Every kid's Windows session is frozen unless that kid is at the screen with approved time.
        Frozen programs keep their windows and work but play nothing and use no network."""
        if not self.cfg["kid_desktops"] or not self.kid_users:
            return
        live = winctl.sessions()
        changed = False
        for user, f in list(self.frozen.items()):
            if live.get(f["session"], "").lower() != user:  # signed out or restarted since
                del self.frozen[user]
                changed = True
        for sid, name in live.items():
            user = name.lower()
            if user not in self.kid_users:
                continue
            active = sid == self.session_id and self.user.lower() == user and self.session_for(user) is not None
            if active and user in self.frozen:
                pids = self.frozen.pop(user)["pids"]
                for pid, _ in pids:
                    winctl.suspend(pid, resume=True)
                log.info("unfroze %d programs of %s", len(pids), user)
                changed = True
            elif not active and user not in self.frozen:
                at_screen = sid == self.session_id and self.user.lower() == user
                if at_screen and time.time() - self.console_since < self.cfg["logon_grace"]:
                    continue  # just signed in, nothing of theirs is running yet: let Windows finish setting up
                pids = [[pid, prog] for pid, prog in winctl.session_processes(sid, name)
                        if prog.lower() not in KEEP_RUNNING and winctl.suspend(pid)]
                self.frozen[user] = {"session": sid, "pids": pids}
                log.info("froze %d programs of %s (session %s): %s", len(pids), user, sid,
                         ", ".join(sorted({p for _, p in pids}))[:300])
                changed = True
        if changed:
            self._save("frozen.json", self.frozen)

    def apply(self) -> None:
        mode = self.current_mode()
        if mode != self.mode:
            log.info("mode %s -> %s", self.mode, mode)
            self.mode = mode
            winctl.flush_dns()
        always = tuple((self.server_state or {}).get("alwayslist", []))
        if always != self.applied_always:  # the list changed: start over, addresses come back on lookup
            self.applied_always = always
            with self.lock:
                self.always_ips.clear()
            winctl.allow_ips([])
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
            if not self.session():  # nothing approved: someone got past the lock screen
                self.server("POST", "/api/activity", {
                    "pc": self.cfg["pc_name"],
                    "what": f"מסך הנעילה נסגר בזמן ש-{self.user} מחובר/ת, אז ניתקתי את המשתמש"})
            winctl.logoff(self.session_id)
            self.user_since = now  # don't hammer while the logoff happens

    def lockscreen_guard(self) -> None:
        """Bring the lock screen up within a second of a kid signing in, or of it being closed, so the
        Windows desktop isn't visible while waiting for the logon task (which re-runs only every minute)."""
        last_launch = 0.0
        seen = (None, "")
        retry_until = 0.0  # after a sign-in, keep trying for a while even if the heartbeat looks fresh
        while True:
            time.sleep(0.3)
            try:
                sid, user = winctl.console_session()
                now = time.time()
                if (sid, user) != seen:
                    seen = (sid, user)
                    retry_until = now + 20  # the heartbeat may still be from the previous kid
                    if user and not self.is_exempt(user):
                        log.info("sign-in: %s (session %s)", user, sid)
                        self.signin_at = now
                if not user or self.is_exempt(user):
                    continue
                if now >= retry_until and (now - self.last_heartbeat < 10 or now - last_launch < 8):
                    continue
                if now < retry_until and now - last_launch < 1:
                    continue
                last_launch = now
                log.info("starting the lock screen for %s", user)
                # Right after sign-in Windows may not hand out the user's token yet; it tries again in a second
                if winctl.launch_in_session(sid, self.lock_cmd, self.app_dir):
                    retry_until = 0.0
                    log.info("lock screen process started")
            except Exception:
                log.exception("lockscreen guard failed")

    def network_watch(self) -> None:
        """Log the network, firewall and real reachability whenever they change, so a "no internet" report
        can be traced to its cause (no address yet, firewall still closed, names not resolving...)."""
        server_ip = urlparse(self.cfg["server_url"]).hostname or ""
        last_route, last = "", {}
        last_test = ("", "")
        tick = no_route = 0
        self.load_home_wifi()
        while True:
            try:
                # Every 2 seconds (it sends nothing): shows how long after a restart the PC has a network.
                route = self.route_to(server_ip)
                if route != last_route:
                    log.info("route to server %s: %s", server_ip, route)
                    last_route = route
                if route.startswith("via"):
                    if no_route or tick % 30 == 0:
                        self.learn_home_wifi()
                    no_route = 0
                else:
                    # Windows doesn't always rejoin the Wi-Fi after a restart; after 10s do it ourselves.
                    no_route += 1
                    if no_route >= 5 and (no_route - 5) % 8 == 0:
                        self.rejoin_wifi((no_route - 5) // 8, no_route * 2)
                if tick % 8 == 0:
                    st = winctl.network_status(full=tick % 32 == 0)
                    if "windows" not in st and "windows" in last:
                        st["windows"] = last["windows"]
                    if st != last:
                        log.info("network: %s", "; ".join(f"{k}={v}" for k, v in st.items()))
                        last = st
                    test = (self.mode, self.reachability()) if self.mode != "offline" else ("offline", "")
                    if test != last_test:
                        if test[1]:
                            log.info("internet check (mode %s): %s", *test)
                        last_test = test
            except Exception:
                log.exception("network watch failed")
            tick += 1
            time.sleep(2)

    def _home_wifi_path(self) -> str:
        return os.path.join(os.path.dirname(self.log_path), "home_wifi.json") if self.log_path else ""

    def load_home_wifi(self) -> None:
        path = self._home_wifi_path()
        try:
            with open(path, encoding="utf-8") as f:
                for name in json.load(f):
                    if name not in self.home_wifi:
                        self.home_wifi.append(name)
        except (OSError, ValueError, TypeError):
            pass
        saved = winctl.wifi_profiles()
        log.info("saved wi-fi: %s; home: %s", ", ".join(f"{n} ({m})" for n, m in saved) or "none",
                 ", ".join(self.home_wifi) or "not known yet")
        for name, mode in saved:
            if name in self.home_wifi and mode != "auto":
                winctl.wifi_set_auto(name)
                log.info("wi-fi %s set to connect automatically", name)

    def learn_home_wifi(self) -> None:
        """The Wi-Fi we're on reaches the HomeGuard server, so it's a home network: remember it and make
        sure Windows joins it by itself."""
        saved = dict(winctl.wifi_profiles())
        for name in winctl.connected_networks():
            if name not in saved:
                continue
            if name not in self.home_wifi:
                self.home_wifi.insert(0, name)
                log.info("home wi-fi learned: %s", name)
                try:
                    with open(self._home_wifi_path(), "w", encoding="utf-8") as f:
                        json.dump(self.home_wifi, f, ensure_ascii=False)
                except OSError as e:
                    log.warning("saving home wi-fi failed: %s", e)
            if saved[name] != "auto":
                winctl.wifi_set_auto(name)
                log.info("wi-fi %s set to connect automatically", name)

    def rejoin_wifi(self, attempt: int, down_for: int) -> None:
        names = self.home_wifi or [n for n, _ in winctl.wifi_profiles()]
        if not names:
            log.info("no network for %ds and no saved wi-fi to join", down_for)
            return
        name = names[attempt % len(names)]
        log.info("no network for %ds: joining wi-fi %s -> %s", down_for, name, winctl.wifi_connect(name))

    @staticmethod
    def route_to(ip: str) -> str:
        """Which local address would talk to `ip` (no packet is sent), or why there's no way to it."""
        if not ip:
            return "no server address"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((ip, 9))
                return "via " + s.getsockname()[0]
        except OSError as e:
            return f"NONE ({e.strerror or e})"

    @staticmethod
    def reachability() -> str:
        """Can this PC reach the internet right now? Name lookup and a connection, checked separately."""
        out = []
        try:
            ip = socket.getaddrinfo("www.google.com", 443, socket.AF_INET)[0][4][0]
            out.append("dns ok")
        except OSError as e:
            ip = ""
            out.append(f"dns FAILED ({e})")
        for name, addr in (("google", ip), ("1.1.1.1", "1.1.1.1")):
            if not addr:
                continue
            try:
                with socket.create_connection((addr, 443), timeout=4):
                    out.append(f"{name} ok")
            except OSError as e:
                out.append(f"{name} FAILED ({e})")
        return ", ".join(out)

    def diag_upload(self) -> None:
        """Send new lines of the agent log (and the auto-update log) to the server every half minute."""
        base = os.path.dirname(self.log_path) if self.log_path else ""
        pos = os.path.getsize(self.log_path) if self.log_path and os.path.exists(self.log_path) else 0
        pos = max(0, pos - 200_000)  # start with recent history
        update_mtime = 0.0
        while True:
            try:
                text, new_pos = "", pos
                if self.log_path and os.path.exists(self.log_path):
                    size = os.path.getsize(self.log_path)
                    if size < pos:  # rotated
                        pos = 0
                    with open(self.log_path, "rb") as f:
                        f.seek(pos)
                        text = f.read(250_000).decode("utf-8", "replace")
                        new_pos = f.tell()
                upd = os.path.join(base, "update.log")
                if base and os.path.exists(upd) and os.path.getmtime(upd) != update_mtime:
                    with open(upd, encoding="utf-8", errors="replace") as f:
                        text += "---- update.log ----\n" + f.read(20_000) + "\n---- end update.log ----\n"
                if text:
                    # Straight to the server, not via server(): an older server without /api/diag
                    # must not make the PC look offline.
                    self._call("POST", "/api/diag", {"pc": self.cfg["pc_name"], "text": text})
                    pos = new_pos
                    if base and os.path.exists(upd):
                        update_mtime = os.path.getmtime(upd)
            except (urllib.error.URLError, OSError, ValueError):
                pass  # the server is away or doesn't take diagnostics yet: try again later
            except Exception:
                log.exception("diag upload failed")
            time.sleep(30)

    def local_state(self, user: str = "", sid: str = "") -> dict:
        if sid.isdigit() and self.session_id is not None and int(sid) != self.session_id:
            # A lock screen in a session that isn't at the screen (a kid who switched user): it stays locked.
            return {"user": user, "exempt": False, "session": None, "extend_pending": False, "background": True,
                    "server_online": self.server_online, "pc": self.cfg["pc_name"]}
        self.last_heartbeat = time.time()
        if self.signin_at:
            log.info("lock screen answered %.1fs after sign-in", self.last_heartbeat - self.signin_at)
            self.signin_at = 0.0
        with self.lock:
            st = self.server_state or {}
        return {"user": self.user, "exempt": bool(self.user) and self.is_exempt(self.user),
                "session": self.session_for(self.user), "extend_pending": st.get("extend_pending", False),
                "server_online": self.server_online, "pc": self.cfg["pc_name"]}

    def run(self) -> None:
        server_ip = urlparse(self.cfg["server_url"]).hostname or ""
        self.kid_users = self._load("kids.json", {})
        self.frozen = self._load("frozen.json", {})
        winctl.keep_wifi_connected()
        winctl.firewall_setup(server_ip, self.cfg["upstream_dns"])
        winctl.internet(False)
        self.applied_internet = False
        winctl.point_dns_to_local()
        dns = dnsfilter.DnsFilter(self.dns_decide, self.upstream, self.cfg["dns_port"], self.dns_answer)
        dns.start()
        local = ThreadingHTTPServer(("127.0.0.1", self.cfg["local_port"]), make_local_handler(self))
        threading.Thread(target=local.serve_forever, daemon=True).start()
        threading.Thread(target=self.lockscreen_guard, daemon=True).start()
        threading.Thread(target=self.network_watch, daemon=True).start()
        if self.cfg["diag_upload"]:
            threading.Thread(target=self.diag_upload, daemon=True).start()
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
                self._send(agent.local_state(qs.get("user", ""), qs.get("sid", "")))
            elif u.path == "/kids":
                agent.last_heartbeat = time.time()
                self._send(agent.server("GET", "/api/kids") or {"kids": [], "require_password": True, "offline": True})
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
                                                          "password": body.get("password", ""),
                                                          "note": body.get("note", "")})
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
            elif path == "/rerequest":
                self._send(agent.server("POST", "/api/rerequest", {"pc": pc, "note": body.get("note", "")})
                           or {"ok": False, "error": "אין חיבור לשרת"})
            elif path == "/cancel":
                agent.server("POST", "/api/cancel", {"pc": pc, "request_id": body.get("request_id", 0)})
                self._send({"ok": True})
            elif path == "/extend":
                self._send(agent.server("POST", "/api/extend", {"pc": pc}) or {"ok": False, "error": "אין חיבור"})
            elif path == "/switch":
                sid = body.get("sid")
                if isinstance(sid, int):
                    winctl.disconnect(sid)
                self._send({"ok": True})
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
    agent = Agent(cfg)
    agent.log_path = handler.baseFilename
    agent.run()


if __name__ == "__main__":
    main()
