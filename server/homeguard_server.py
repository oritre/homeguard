"""HomeGuard server: Telegram bot for the parents + HTTP API for the PC agents.

Pure standard library (Python 3.10+). Runs on any always-on machine in the house
(a parent's PC, a Raspberry Pi, a NAS). Usage:

    python homeguard_server.py run                      # start bot + API
    python homeguard_server.py kid add noam 1234 "נועם"   # add a kid
    python homeguard_server.py kid new noam "נועם"        # temporary password, kid picks their own
    python homeguard_server.py kid new mom "אמא" --master # master: no approval, no filtering, no time limit
    python homeguard_server.py kid list
    python homeguard_server.py kid passwd noam 5678
    python homeguard_server.py kid remove noam
    python homeguard_server.py site allow wikipedia.org [minutes]
    python homeguard_server.py site block tiktok.com
    python homeguard_server.py gen-token

Add --config <path> to any command to use a config.json elsewhere.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

log = logging.getLogger("homeguard")

MODES = {
    "full": "🌐 אינטרנט מלא",
    "allowlist": "✅ רק אתרים מאושרים",
    "offline": "🚫 בלי אינטרנט",
    "open": "🔓 פתוח לגמרי (מאסטר)",
}
MODE_SHORT = {"full": "🌐", "allowlist": "✅", "offline": "🚫", "open": "🔓"}
FOREVER = 4102444800.0  # 2100-01-01: sessions that end only when someone locks them

DEFAULT_CONFIG = {
    "telegram_token": "",
    "parent_chat_ids": [],
    "agent_token": "",
    "listen": "0.0.0.0",
    "port": 8800,
    "db": "homeguard.db",
    "durations": [30, 60, 120],
    "extend_options": [15, 30, 60],
    "max_failed_logins": 5,
}


def load_config(path: str) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg.update(json.load(f))
    return cfg


def fmt_min(minutes: int) -> str:
    if minutes <= 0:
        return "ללא הגבלה"
    if minutes % 60 == 0:
        h = minutes // 60
        return "שעה" if h == 1 else ("שעתיים" if h == 2 else f"{h} שעות")
    return f"{minutes} דק'"


def hhmm(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M")


def normalize_domain(d: str) -> str:
    d = d.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0].split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    return d.strip(".")


def valid_domain(d: str) -> bool:
    return "." in d and len(d) <= 253 and all(c.isalnum() or c in "-." for c in d)


def until(ends: float) -> str:
    return "ללא הגבלת זמן" if ends >= FOREVER else f"עד {hhmm(ends)}"


def temp_password() -> str:
    return f"{secrets.randbelow(10000):04d}"


# --------------------------------------------------------------------------- DB

class DB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS kids (
                    username TEXT PRIMARY KEY, display TEXT NOT NULL,
                    salt TEXT NOT NULL, pw_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS pcs (
                    name TEXT PRIMARY KEY, last_seen REAL, win_user TEXT,
                    lock_now INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                    pc TEXT NOT NULL, kid TEXT NOT NULL, created REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', session_id INTEGER,
                    decided_by TEXT, messages TEXT DEFAULT '[]');
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, pc TEXT NOT NULL,
                    kid TEXT NOT NULL, mode TEXT NOT NULL, started REAL NOT NULL,
                    ends REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                    warned INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS sites (
                    domain TEXT NOT NULL, list TEXT NOT NULL,
                    PRIMARY KEY (domain, list));
                CREATE TABLE IF NOT EXISTS failed_logins (
                    pc TEXT NOT NULL, ts REAL NOT NULL);
                """
            )
            for table, col, decl in (("kids", "pw_plain", "TEXT"),
                                     ("kids", "role", "TEXT NOT NULL DEFAULT 'kid'"),
                                     ("kids", "must_set", "INTEGER NOT NULL DEFAULT 0"),
                                     ("kids", "disabled", "INTEGER NOT NULL DEFAULT 0"),
                                     ("sites", "expires", "REAL"),
                                     ("requests", "detail", "TEXT")):
                if col not in {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
            self.conn.commit()

    def q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def x(self, sql: str, args: tuple = ()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur.lastrowid

    # kids
    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()

    def add_kid(self, username: str, password: str, display: str, role: str = "kid",
                must_set: bool = False) -> None:
        salt = secrets.token_hex(16)
        self.x("INSERT INTO kids (username, display, salt, pw_hash, pw_plain, role, must_set) "
               "VALUES (?,?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET display=excluded.display, "
               "salt=excluded.salt, pw_hash=excluded.pw_hash, pw_plain=excluded.pw_plain, "
               "role=excluded.role, must_set=excluded.must_set",
               (username.lower(), display, salt, self._hash(password, salt), password, role, int(must_set)))

    def set_password(self, username: str, password: str, must_set: bool = False) -> bool:
        salt = secrets.token_hex(16)
        self.x("UPDATE kids SET salt=?, pw_hash=?, pw_plain=?, must_set=? WHERE username=?",
               (salt, self._hash(password, salt), password, int(must_set), username.lower()))
        return bool(self.kid(username))

    def kid(self, username: str):
        rows = self.q("SELECT * FROM kids WHERE username=?", (username.strip().lower(),))
        return rows[0] if rows else None

    def check_kid(self, username: str, password: str):
        row = self.kid(username)
        if row and hmac.compare_digest(row["pw_hash"], self._hash(password, row["salt"])):
            return row
        return None

    def kid_display(self, username: str) -> str:
        rows = self.q("SELECT display FROM kids WHERE username=?", (username,))
        return rows[0]["display"] if rows else username

    # sites
    def site_rows(self, lst: str) -> list[sqlite3.Row]:
        return self.q("SELECT domain, expires FROM sites WHERE list=? AND (expires IS NULL OR expires>?) "
                      "ORDER BY domain", (lst, time.time()))

    def sites(self, lst: str) -> list[str]:
        return [r["domain"] for r in self.site_rows(lst)]

    def add_site(self, domain: str, lst: str, minutes: int | None = None) -> None:
        """minutes=None: permanent, and replaces the opposite list's entry.
        A temporary allow keeps any block and overrides it until it expires."""
        d = normalize_domain(domain)
        if minutes:
            self.x("INSERT INTO sites (domain, list, expires) VALUES (?,?,?) ON CONFLICT(domain, list) DO UPDATE "
                   "SET expires=CASE WHEN expires IS NULL THEN NULL ELSE MAX(expires, excluded.expires) END",
                   (d, lst, time.time() + minutes * 60))
            return
        self.x("INSERT INTO sites (domain, list, expires) VALUES (?,?,NULL) "
               "ON CONFLICT(domain, list) DO UPDATE SET expires=NULL", (d, lst))
        self.x("DELETE FROM sites WHERE domain=? AND list=?", (d, "block" if lst == "allow" else "allow"))

    def remove_site(self, domain: str, lst: str) -> None:
        self.x("DELETE FROM sites WHERE domain=? AND list=?", (normalize_domain(domain), lst))

    # sessions
    def active_session(self, pc: str):
        rows = self.q("SELECT * FROM sessions WHERE pc=? AND active=1 ORDER BY id DESC LIMIT 1", (pc,))
        return rows[0] if rows else None

    def end_sessions(self, pc: str) -> None:
        self.x("UPDATE sessions SET active=0, ends=MIN(ends, ?) WHERE pc=? AND active=1", (time.time(), pc))

    def start_session(self, pc: str, kid: str, mode: str, minutes: int) -> tuple[int, float]:
        """minutes <= 0: no time limit, until someone locks it."""
        now = time.time()
        ends = FOREVER if minutes <= 0 else now + minutes * 60
        self.end_sessions(pc)
        sid = self.x("INSERT INTO sessions (pc, kid, mode, started, ends) VALUES (?,?,?,?,?)",
                     (pc, kid, mode, now, ends))
        return sid, ends


# --------------------------------------------------------------------- Telegram

class Telegram:
    def __init__(self, token: str):
        self.base = f"https://api.telegram.org/bot{token}/"

    def call(self, method: str, **params):
        data = json.dumps(params).encode()
        req = urllib.request.Request(self.base + method, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=params.get("timeout", 0) + 15) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read() or b"{}")
        if not body.get("ok"):
            log.warning("telegram %s failed: %s", method, body)
            return None
        return body["result"]


# ------------------------------------------------------------------------- Core

class HomeGuard:
    def __init__(self, cfg: dict, db: DB, tg: Telegram | None):
        self.cfg = cfg
        self.db = db
        self.tg = tg
        self.parents = [int(c) for c in cfg["parent_chat_ids"]]

    # ---- messaging helpers
    def notify(self, text: str, keyboard=None) -> list[list[int]]:
        sent = []
        if not self.tg:
            log.info("NOTIFY: %s", text)
            return sent
        for chat in self.parents:
            params = {"chat_id": chat, "text": text}
            if keyboard:
                params["reply_markup"] = {"inline_keyboard": keyboard}
            res = self.tg.call("sendMessage", **params)
            if res:
                sent.append([chat, res["message_id"]])
        return sent

    def edit_all(self, messages: list, text: str) -> None:
        if not self.tg:
            return
        for chat, mid in messages:
            self.tg.call("editMessageText", chat_id=chat, message_id=mid, text=text)

    def reply(self, chat: int, text: str, keyboard=None) -> None:
        if not self.tg:
            log.info("REPLY %s: %s", chat, text)
            return
        params = {"chat_id": chat, "text": text}
        if keyboard:
            params["reply_markup"] = {"inline_keyboard": keyboard}
        self.tg.call("sendMessage", **params)

    # ---- agent API
    def login(self, pc: str, username: str, password: str) -> dict:
        now = time.time()
        recent = self.db.q("SELECT COUNT(*) c FROM failed_logins WHERE pc=? AND ts>?", (pc, now - 600))[0]["c"]
        if recent >= self.cfg["max_failed_logins"]:
            return {"ok": False, "error": "יותר מדי ניסיונות. נסו שוב בעוד כמה דקות."}
        kid = self.db.check_kid(username, password)
        if not kid:
            self.db.x("INSERT INTO failed_logins VALUES (?,?)", (pc, now))
            if recent + 1 == self.cfg["max_failed_logins"]:
                self.notify(f"⚠️ {self.cfg['max_failed_logins']} ניסיונות כניסה שגויים במחשב '{pc}' "
                            f"(שם משתמש אחרון: {username})")
            return {"ok": False, "error": "שם משתמש או סיסמה שגויים"}
        name = kid["username"]
        if kid["disabled"]:
            return {"ok": False, "error": "החשבון מושבת. דברו עם אבא/אמא."}
        if kid["must_set"]:
            return {"ok": False, "need_new_password": True, "display": kid["display"]}
        if kid["role"] == "master":
            self.db.start_session(pc, name, "open", 0)
            rid = self.db.x("INSERT INTO requests (kind, pc, kid, created, status, decided_by) "
                            "VALUES ('login',?,?,?,'approved','master')", (pc, name, now))
            self.notify(f"🔓 {kid['display']} נכנס/ה למחשב '{pc}' עם חשבון מאסטר ({hhmm(now)})")
            return {"ok": True, "request_id": rid, "display": kid["display"], "approved": True}
        # One pending login request per pc: cancel older ones.
        for old in self.db.q("SELECT * FROM requests WHERE pc=? AND kind='login' AND status='pending'", (pc,)):
            self.db.x("UPDATE requests SET status='cancelled' WHERE id=?", (old["id"],))
            self.edit_all(json.loads(old["messages"]), f"↩️ בקשה בוטלה ({self.db.kid_display(old['kid'])}, {pc})")
        rid = self.db.x("INSERT INTO requests (kind, pc, kid, created) VALUES ('login',?,?,?)", (pc, name, now))
        kb = []
        for mode in ("full", "allowlist", "offline"):
            options = list(self.cfg["durations"]) + ([0] if mode != "offline" else [])
            kb.append([{"text": f"{MODE_SHORT[mode]} {fmt_min(m) if m else '♾️'}",
                        "callback_data": f"ap:{rid}:{mode}:{m}"} for m in options])
        kb.append([{"text": "❌ לא עכשיו", "callback_data": f"dn:{rid}"}])
        text = (f"🧒 {kid['display']} מבקש/ת להיכנס למחשב '{pc}' ({hhmm(now)})\n"
                f"{MODE_SHORT['full']} אינטרנט מלא · {MODE_SHORT['allowlist']} אתרים מאושרים · "
                f"{MODE_SHORT['offline']} בלי אינטרנט · ♾️ ללא הגבלת זמן")
        msgs = self.notify(text, kb)
        self.db.x("UPDATE requests SET messages=? WHERE id=?", (json.dumps(msgs), rid))
        return {"ok": True, "request_id": rid, "display": kid["display"]}

    def request_status(self, rid: int) -> dict:
        rows = self.db.q("SELECT * FROM requests WHERE id=?", (rid,))
        if not rows:
            return {"status": "unknown"}
        return {"status": rows[0]["status"]}

    def change_password(self, pc: str, username: str, old: str, new: str) -> dict:
        now = time.time()
        recent = self.db.q("SELECT COUNT(*) c FROM failed_logins WHERE pc=? AND ts>?", (pc, now - 600))[0]["c"]
        if recent >= self.cfg["max_failed_logins"]:
            return {"ok": False, "error": "יותר מדי ניסיונות. נסו שוב בעוד כמה דקות."}
        kid = self.db.check_kid(username, old)
        if not kid:
            self.db.x("INSERT INTO failed_logins VALUES (?,?)", (pc, now))
            return {"ok": False, "error": "שם משתמש או סיסמה נוכחית שגויים"}
        if not 4 <= len(new) <= 32:
            return {"ok": False, "error": "הסיסמה החדשה צריכה להיות באורך 4 עד 32 תווים"}
        if new == old:
            return {"ok": False, "error": "הסיסמה החדשה צריכה להיות שונה מהקודמת"}
        self.db.set_password(kid["username"], new)
        self.notify(f"🔑 {kid['display']} ({kid['username']}) קבע/ה סיסמה חדשה: {new}")
        return {"ok": True}

    def request_site(self, pc: str, domain: str) -> dict:
        s = self.db.active_session(pc)
        if not s or s["ends"] <= time.time():
            return {"ok": False, "error": "אין זמן פעיל"}
        d = normalize_domain(domain)
        if not valid_domain(d):
            return {"ok": False, "error": "כתובת אתר לא תקינה"}
        if self.db.q("SELECT 1 FROM requests WHERE kind='site' AND pc=? AND detail=? AND status='pending'", (pc, d)):
            return {"ok": True}
        rid = self.db.x("INSERT INTO requests (kind, pc, kid, created, session_id, detail) VALUES ('site',?,?,?,?,?)",
                        (pc, s["kid"], time.time(), s["id"], d))
        kb = [[{"text": fmt_min(m), "callback_data": f"st:{rid}:{m}"} for m in self.cfg["durations"]],
              [{"text": "♾️ תמיד", "callback_data": f"st:{rid}:0"}, {"text": "❌ לא", "callback_data": f"dn:{rid}"}]]
        msgs = self.notify(f"🌐 {self.db.kid_display(s['kid'])} מבקש/ת גישה לאתר {d} (מחשב '{pc}')", kb)
        self.db.x("UPDATE requests SET messages=? WHERE id=?", (json.dumps(msgs), rid))
        return {"ok": True}

    def cancel_request(self, rid: int) -> None:
        rows = self.db.q("SELECT * FROM requests WHERE id=? AND status='pending'", (rid,))
        if rows:
            self.db.x("UPDATE requests SET status='cancelled' WHERE id=?", (rid,))
            self.edit_all(json.loads(rows[0]["messages"]),
                          f"↩️ {self.db.kid_display(rows[0]['kid'])} ביטל/ה את הבקשה ({rows[0]['pc']})")

    def state(self, pc: str, win_user: str = "") -> dict:
        now = time.time()
        self.db.x("INSERT INTO pcs (name, last_seen, win_user) VALUES (?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen, win_user=excluded.win_user",
                  (pc, now, win_user))
        s = self.db.active_session(pc)
        session = None
        if s and s["ends"] > now:
            session = {"id": s["id"], "kid": s["kid"], "display": self.db.kid_display(s["kid"]),
                       "mode": s["mode"], "remaining": int(s["ends"] - now), "unlimited": s["ends"] >= FOREVER}
        pending_ext = bool(s and self.db.q(
            "SELECT 1 FROM requests WHERE kind='extend' AND session_id=? AND status='pending'", (s["id"],)))
        allow = self.db.site_rows("allow")
        temp_allowed = {r["domain"] for r in allow if r["expires"] is not None}
        return {"session": session, "extend_pending": pending_ext,
                "allowlist": [r["domain"] for r in allow],
                "blocklist": [d for d in self.db.sites("block") if d not in temp_allowed],
                "server_time": now}

    def request_extension(self, pc: str) -> dict:
        s = self.db.active_session(pc)
        if not s:
            return {"ok": False, "error": "אין זמן פעיל"}
        if self.db.q("SELECT 1 FROM requests WHERE kind='extend' AND session_id=? AND status='pending'", (s["id"],)):
            return {"ok": True}
        rid = self.db.x("INSERT INTO requests (kind, pc, kid, created, session_id) VALUES ('extend',?,?,?,?)",
                        (pc, s["kid"], time.time(), s["id"]))
        left = max(0, int((s["ends"] - time.time()) // 60))
        kb = [[{"text": f"+{fmt_min(m)}", "callback_data": f"ex:{rid}:{m}"} for m in self.cfg["extend_options"]],
              [{"text": "❌ לא", "callback_data": f"dn:{rid}"}]]
        msgs = self.notify(f"⏳ {self.db.kid_display(s['kid'])} מבקש/ת עוד זמן במחשב '{pc}' (נשארו {left} דק')", kb)
        self.db.x("UPDATE requests SET messages=? WHERE id=?", (json.dumps(msgs), rid))
        return {"ok": True}

    def end_by_kid(self, pc: str) -> None:
        s = self.db.active_session(pc)
        if s:
            self.db.end_sessions(pc)
            self.notify(f"👋 {self.db.kid_display(s['kid'])} סיים/ה במחשב '{pc}'")

    # ---- parent actions (Telegram callbacks)
    def decide(self, data: str, who: str) -> str:
        parts = data.split(":")
        kind = parts[0]
        rid = int(parts[1])
        rows = self.db.q("SELECT * FROM requests WHERE id=?", (rid,))
        if not rows:
            return "הבקשה לא נמצאה"
        r = rows[0]
        if r["status"] != "pending":
            return "כבר טופל"
        msgs = json.loads(r["messages"])
        display = self.db.kid_display(r["kid"])
        if kind == "dn":
            self.db.x("UPDATE requests SET status='denied', decided_by=? WHERE id=?", (who, rid))
            self.edit_all(msgs, f"❌ {display} ({r['pc']}): נדחה ע\"י {who}")
            return "נדחה"
        if kind == "ap":
            mode, minutes = parts[2], int(parts[3])
            sid, ends = self.db.start_session(r["pc"], r["kid"], mode, minutes)
            self.db.x("UPDATE requests SET status='approved', decided_by=?, session_id=? WHERE id=?", (who, sid, rid))
            length = "ללא הגבלת זמן" if minutes <= 0 else f"ל{fmt_min(minutes)}, עד {hhmm(ends)}"
            self.edit_all(msgs, f"✅ {display} ({r['pc']}): {MODES[mode]} {length} · אושר ע\"י {who}")
            return "אושר"
        if kind == "st":
            minutes = int(parts[2])
            self.db.add_site(r["detail"], "allow", minutes or None)
            self.db.x("UPDATE requests SET status='approved', decided_by=? WHERE id=?", (who, rid))
            length = "תמיד" if minutes <= 0 else f"ל{fmt_min(minutes)}"
            self.edit_all(msgs, f"🌐 {r['detail']} אושר {length} ({display}, {r['pc']}) · {who}")
            return "אושר"
        if kind == "ex":
            minutes = int(parts[2])
            s = self.db.q("SELECT * FROM sessions WHERE id=?", (r["session_id"],))
            if not s or not s[0]["active"]:
                self.db.x("UPDATE requests SET status='cancelled' WHERE id=?", (rid,))
                self.edit_all(msgs, f"↩️ {display} ({r['pc']}): הזמן כבר נגמר")
                return "הזמן כבר נגמר"
            new_end = max(s[0]["ends"], time.time()) + minutes * 60
            self.db.x("UPDATE sessions SET ends=?, warned=0 WHERE id=?", (new_end, s[0]["id"]))
            self.db.x("UPDATE requests SET status='approved', decided_by=? WHERE id=?", (who, rid))
            self.edit_all(msgs, f"⏳ {display} ({r['pc']}): +{fmt_min(minutes)}, {until(new_end)} · {who}")
            return "הוארך"
        return "?"

    def lock(self, pc: str) -> bool:
        s = self.db.active_session(pc)
        self.db.end_sessions(pc)
        return bool(s)

    def lock_kid(self, username: str) -> list[str]:
        pcs = [s["pc"] for s in self.db.q("SELECT DISTINCT pc FROM sessions WHERE kid=? AND active=1",
                                          (username.lower(),))]
        for pc in pcs:
            self.db.end_sessions(pc)
        return pcs

    def extend(self, pc: str, minutes: int) -> bool:
        s = self.db.active_session(pc)
        if not s:
            return False
        self.db.x("UPDATE sessions SET ends=?, warned=0 WHERE id=?", (max(s["ends"], time.time()) + minutes * 60, s["id"]))
        return True

    def status_text(self) -> str:
        now = time.time()
        lines = ["📊 מצב המחשבים:"]
        pcs = self.db.q("SELECT * FROM pcs ORDER BY name")
        if not pcs:
            return "עוד לא התחבר אף מחשב."
        for p in pcs:
            online = p["last_seen"] and now - p["last_seen"] < 90
            dot = "🟢" if online else "⚫"
            s = self.db.active_session(p["name"])
            if s and s["ends"] > now:
                left = ("ללא הגבלת זמן" if s["ends"] >= FOREVER
                        else f"נשארו {int((s['ends'] - now) // 60)} דק' (עד {hhmm(s['ends'])})")
                lines.append(f"{dot} {p['name']}: {self.db.kid_display(s['kid'])} · {MODES[s['mode']]} · {left}")
            else:
                seen = "" if online else f" (נראה לאחרונה {hhmm(p['last_seen'])})" if p["last_seen"] else ""
                lines.append(f"{dot} {p['name']}: נעול{seen}")
        return "\n".join(lines)

    # ---- background: expire sessions and send warnings
    def tick(self) -> None:
        now = time.time()
        for s in self.db.q("SELECT * FROM sessions WHERE active=1"):
            if s["ends"] <= now:
                self.db.x("UPDATE sessions SET active=0 WHERE id=?", (s["id"],))
                self.notify(f"⏰ הזמן של {self.db.kid_display(s['kid'])} במחשב '{s['pc']}' נגמר. המחשב ננעל.")
        for site in self.db.q("SELECT domain FROM sites WHERE expires IS NOT NULL AND expires<=?", (now,)):
            self.notify(f"⌛ הגישה הזמנית ל-{site['domain']} הסתיימה")
        self.db.x("DELETE FROM sites WHERE expires IS NOT NULL AND expires<=?", (now,))
        self.db.x("DELETE FROM failed_logins WHERE ts<?", (now - 3600,))

    # ---- Telegram update handling
    def handle_update(self, upd: dict) -> None:
        if "callback_query" in upd:
            cq = upd["callback_query"]
            chat = cq["message"]["chat"]["id"] if "message" in cq else cq["from"]["id"]
            if chat not in self.parents:
                return
            who = cq["from"].get("first_name", "הורה")
            data = cq.get("data", "")
            if data.startswith("lk:"):
                pc = data[3:]
                answer = "ננעל" if self.lock(pc) else "כבר נעול"
            else:
                answer = self.decide(data, who)
            if self.tg:
                self.tg.call("answerCallbackQuery", callback_query_id=cq["id"], text=answer)
            return
        msg = upd.get("message")
        if not msg or "text" not in msg:
            return
        chat = msg["chat"]["id"]
        text = msg["text"].strip()
        cmd, _, arg = text.partition(" ")
        cmd = cmd.split("@")[0].lower()
        arg = arg.strip()
        if chat not in self.parents:
            if cmd == "/start":
                self.reply(chat, f"שלום! מזהה הצ'אט שלך: {chat}\n"
                                 "כדי לקבל בקשות, הוסיפו אותו ל-parent_chat_ids בקובץ config.json של השרת והפעילו מחדש.")
            return
        self.handle_command(chat, cmd, arg)

    def handle_command(self, chat: int, cmd: str, arg: str) -> None:
        if cmd in ("/start", "/help"):
            self.reply(chat, HELP)
        elif cmd == "/status":
            now = time.time()
            kb = [[{"text": f"🔒 נעל {p['name']}", "callback_data": f"lk:{p['name']}"}]
                  for p in self.db.q("SELECT name FROM pcs ORDER BY name")
                  if (s := self.db.active_session(p["name"])) and s["ends"] > now]
            self.reply(chat, self.status_text(), kb or None)
        elif cmd == "/lock":
            if arg and self.db.kid(arg):
                locked = self.lock_kid(arg)
            else:
                pcs = [p["name"] for p in self.db.q("SELECT name FROM pcs")] if arg in ("", "all", "הכל") else [arg]
                locked = [pc for pc in pcs if self.lock(pc)]
            self.reply(chat, "🔒 ננעל: " + ", ".join(locked) if locked else "לא היה מחשב פתוח.")
        elif cmd == "/extend":
            parts = arg.split()
            if len(parts) != 2 or not parts[1].isdigit():
                self.reply(chat, "שימוש: /extend <שם מחשב> <דקות>")
            elif self.extend(parts[0], int(parts[1])):
                self.reply(chat, f"⏳ נוספו {parts[1]} דק' ל-{parts[0]}")
            else:
                self.reply(chat, f"אין זמן פעיל במחשב {parts[0]}")
        elif cmd in ("/allow", "/block", "/unallow", "/unblock"):
            if not arg:
                self.reply(chat, f"שימוש: {cmd} example.com" + (" [דקות]" if cmd == "/allow" else ""))
                return
            lst = "allow" if "allow" in cmd else "block"
            words = arg.replace(",", " ").split()
            minutes = int(words.pop()) if cmd == "/allow" and len(words) > 1 and words[-1].isdigit() else None
            for d in words:
                if cmd.startswith("/un"):
                    self.db.remove_site(d, lst)
                else:
                    self.db.add_site(d, lst, minutes)
            self.reply(chat, self.sites_text())
        elif cmd == "/sites":
            self.reply(chat, self.sites_text())
        elif cmd == "/kids":
            self.reply(chat, self.kids_text())
        elif cmd in ("/addkid", "/addmaster"):
            parts = arg.split(maxsplit=1)
            if not parts:
                self.reply(chat, f"שימוש: {cmd} <שם משתמש באנגלית> [שם לתצוגה]")
                return
            pw = temp_password()
            self.db.add_kid(parts[0], pw, parts[1] if len(parts) > 1 else parts[0],
                            "master" if cmd == "/addmaster" else "kid", must_set=True)
            self.reply(chat, f"נוסף {parts[0].lower()} עם סיסמה זמנית {pw}. בכניסה הראשונה תתבקש סיסמה אישית.")
        elif cmd in ("/setpw", "/resetpw", "/disable", "/enable", "/rmkid"):
            parts = arg.split()
            if not parts or not self.db.kid(parts[0]) or (cmd == "/setpw" and len(parts) != 2):
                usage = "שימוש: /setpw <משתמש> <סיסמה>" if cmd == "/setpw" else f"שימוש: {cmd} <משתמש>"
                self.reply(chat, usage + "\n\n" + self.kids_text())
                return
            user = parts[0].lower()
            if cmd == "/setpw":
                self.db.set_password(user, parts[1])
                self.reply(chat, f"🔑 הסיסמה של {user} עודכנה ל-{parts[1]}")
            elif cmd == "/resetpw":
                pw = temp_password()
                self.db.set_password(user, pw, must_set=True)
                self.reply(chat, f"🔑 סיסמה זמנית ל-{user}: {pw}. בכניסה הבאה תתבקש סיסמה אישית חדשה.")
            elif cmd == "/disable":
                self.db.x("UPDATE kids SET disabled=1 WHERE username=?", (user,))
                locked = self.lock_kid(user)
                self.reply(chat, f"⛔ {user} מושבת" + (f" (ננעל: {', '.join(locked)})" if locked else ""))
            elif cmd == "/enable":
                self.db.x("UPDATE kids SET disabled=0 WHERE username=?", (user,))
                self.reply(chat, f"✅ {user} פעיל שוב")
            else:
                self.lock_kid(user)
                self.db.x("DELETE FROM kids WHERE username=?", (user,))
                self.reply(chat, f"🗑 {user} הוסר")
        else:
            self.reply(chat, HELP)

    def sites_text(self) -> str:
        allow = [r["domain"] + (f" (זמני, עד {hhmm(r['expires'])})" if r["expires"] else "")
                 for r in self.db.site_rows("allow")]
        block = self.db.sites("block")
        return ("✅ אתרים מאושרים (במצב 'רק אתרים מאושרים'. אישור זמני גובר גם על חסימה):\n" +
                ("\n".join(allow) or "—") + "\n\n⛔ אתרים חסומים (תמיד):\n" + ("\n".join(block) or "—"))

    def kids_text(self) -> str:
        lines = []
        for k in self.db.q("SELECT * FROM kids ORDER BY role DESC, username"):
            flags = []
            if k["role"] == "master":
                flags.append("👑 מאסטר")
            if k["must_set"]:
                flags.append("סיסמה זמנית, עוד לא נבחרה אישית")
            if k["disabled"]:
                flags.append("⛔ מושבת")
            pw = k["pw_plain"] if k["pw_plain"] is not None else "לא ידועה"
            lines.append(f"🧒 {k['display']} ({k['username']}) · סיסמה: {pw}" +
                         (" · " + ", ".join(flags) if flags else ""))
        return "\n".join(lines) or "אין חשבונות מוגדרים"


HELP = """🛡️ HomeGuard – פקודות:
/status – מי מחובר ולכמה זמן
/lock <מחשב> – לנעול עכשיו (בלי שם = כל המחשבים)
/extend <מחשב> <דקות> – להוסיף זמן
/allow site.com – להוסיף לרשימת האתרים המאושרים
/allow site.com 30 – לאשר אתר ל-30 דקות (גובר גם על חסימה)
/unallow site.com – להסיר מהמאושרים
/block site.com – לחסום אתר תמיד
/unblock site.com – לבטל חסימה
/sites – הרשימות

👧 חשבונות:
/kids – כל החשבונות והסיסמאות
/addkid <משתמש> [שם] – ילד חדש עם סיסמה זמנית (בוחר/ת סיסמה אישית בכניסה הראשונה)
/addmaster <משתמש> [שם] – חשבון מאסטר: בלי אישור, בלי סינון, בלי הגבלת זמן
/setpw <משתמש> <סיסמה> – לקבוע סיסמה
/resetpw <משתמש> – סיסמה זמנית חדשה
/disable <משתמש> · /enable <משתמש> – להשבית / להחזיר חשבון
/rmkid <משתמש> – למחוק חשבון
/lock <משתמש> – לנעול את המחשב שבו הוא/היא מחובר/ת

בקשות כניסה מגיעות לכאן עם כפתורים: בוחרים סוג גישה ומשך זמן בלחיצה אחת (♾️ = בלי הגבלת זמן, עד שנועלים).
ילדים יכולים לבקש אתר מסוים מתוך הטיימר, ומקבלים כאן כפתורים לאשר אותו לזמן מוגבל או תמיד."""


# ------------------------------------------------------------------- HTTP API

def make_handler(hg: HomeGuard):
    token = hg.cfg["agent_token"]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            log.debug("http: " + fmt, *args)

        def _send(self, code: int, obj) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self) -> bool:
            if not hmac.compare_digest(self.headers.get("X-Agent-Token", ""), token):
                self._send(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self._auth():
                return
            u = urlparse(self.path)
            qs = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/api/state":
                self._send(200, hg.state(qs.get("pc", ""), qs.get("user", "")))
            elif u.path == "/api/request":
                self._send(200, hg.request_status(int(qs.get("id", "0"))))
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._auth():
                return
            length = int(self.headers.get("Content-Length", "0") or 0)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._send(400, {"error": "bad json"})
                return
            path = urlparse(self.path).path
            pc = str(body.get("pc", ""))
            if path == "/api/login":
                self._send(200, hg.login(pc, str(body.get("username", "")), str(body.get("password", ""))))
            elif path == "/api/cancel":
                hg.cancel_request(int(body.get("request_id", 0)))
                self._send(200, {"ok": True})
            elif path == "/api/extend":
                self._send(200, hg.request_extension(pc))
            elif path == "/api/passwd":
                self._send(200, hg.change_password(pc, str(body.get("username", "")), str(body.get("old", "")),
                                                   str(body.get("new", ""))))
            elif path == "/api/site":
                self._send(200, hg.request_site(pc, str(body.get("domain", ""))))
            elif path == "/api/end":
                hg.end_by_kid(pc)
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})

    return Handler


# ------------------------------------------------------------------------ main

def run(cfg: dict) -> None:
    if not cfg["telegram_token"] or not cfg["agent_token"]:
        sys.exit("config.json חסר telegram_token או agent_token")
    db = DB(cfg["db"])
    tg = Telegram(cfg["telegram_token"])
    hg = HomeGuard(cfg, db, tg)
    tg.call("setMyCommands", commands=[
        {"command": "status", "description": "מצב המחשבים"},
        {"command": "lock", "description": "נעילת מחשב"},
        {"command": "extend", "description": "הוספת זמן"},
        {"command": "sites", "description": "רשימות אתרים"},
        {"command": "allow", "description": "אישור אתר"},
        {"command": "block", "description": "חסימת אתר"},
        {"command": "kids", "description": "חשבונות וסיסמאות"},
        {"command": "addkid", "description": "הוספת ילד"},
        {"command": "resetpw", "description": "סיסמה זמנית חדשה"},
        {"command": "help", "description": "עזרה"},
    ])

    server = ThreadingHTTPServer((cfg["listen"], int(cfg["port"])), make_handler(hg))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("API listening on %s:%s", cfg["listen"], cfg["port"])

    def ticker():
        while True:
            try:
                hg.tick()
            except Exception:
                log.exception("tick failed")
            time.sleep(10)

    threading.Thread(target=ticker, daemon=True).start()

    offset = 0
    log.info("Telegram bot polling")
    while True:
        try:
            updates = tg.call("getUpdates", offset=offset, timeout=50,
                              allowed_updates=["message", "callback_query"]) or []
            for upd in updates:
                offset = upd["update_id"] + 1
                try:
                    hg.handle_update(upd)
                except Exception:
                    log.exception("update failed")
        except Exception:
            log.exception("polling failed")
            time.sleep(5)


def cli(argv: list[str]) -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.environ.get("HOMEGUARD_CONFIG", os.path.join(here, "config.json"))
    if "--config" in argv:
        i = argv.index("--config")
        cfg_path = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    cfg = load_config(cfg_path)
    if not os.path.isabs(cfg["db"]):
        cfg["db"] = os.path.join(os.path.dirname(cfg_path), cfg["db"])
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if not argv or argv[0] == "run":
        run(cfg)
        return
    db = DB(cfg["db"])
    if argv[0] == "kid" and len(argv) >= 2:
        if argv[1] == "add" and len(argv) >= 4:
            db.add_kid(argv[2], argv[3], argv[4] if len(argv) > 4 else argv[2])
            print("נוסף:", argv[2])
        elif argv[1] == "new" and len(argv) >= 3:
            role = "master" if "--master" in argv else "kid"
            args = [a for a in argv[2:] if a != "--master"]
            pw = temp_password()
            db.add_kid(args[0], pw, args[1] if len(args) > 1 else args[0], role, must_set=True)
            print(f"נוסף: {args[0].lower()} ({role}), סיסמה זמנית: {pw}")
        elif argv[1] == "passwd" and len(argv) == 4:
            print("הסיסמה עודכנה" if db.set_password(argv[2], argv[3]) else "אין משתמש כזה")
        elif argv[1] == "remove" and len(argv) == 3:
            db.x("DELETE FROM kids WHERE username=?", (argv[2].lower(),))
            print("הוסר")
        elif argv[1] == "list":
            for k in db.q("SELECT username, display, role, must_set, disabled FROM kids"):
                print(k["username"], k["display"], k["role"], "temp-pw" if k["must_set"] else "",
                      "disabled" if k["disabled"] else "")
        else:
            print(__doc__)
    elif argv[0] == "site" and len(argv) in (3, 4) and argv[1] in ("allow", "block"):
        db.add_site(argv[2], argv[1], int(argv[3]) if len(argv) == 4 else None)
        print("נוסף")
    elif argv[0] == "gen-token":
        print(secrets.token_urlsafe(32))
    else:
        print(__doc__)


if __name__ == "__main__":
    cli(sys.argv[1:])
