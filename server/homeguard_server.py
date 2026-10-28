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
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
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
MODE_NAMES = {"full": "אינטרנט מלא", "allowlist": "רק אתרים מאושרים", "offline": "בלי אינטרנט"}
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
    "public_url": "",  # e.g. the Tailscale Funnel address, shown by /web
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


def parse_duration(text: str, now: float | None = None) -> int:
    """Minutes from what a parent typed: '45', '90 דק', '2 שעות', '1.5ש', '18:30' / 'עד 18:30'. 0 = not understood."""
    t = text.strip().replace("עד", "").strip()
    m = re.fullmatch(r"(\d{1,2}):(\d{2})", t)
    if m:
        h, mi = int(m.group(1)), int(m.group(2))
        if h > 23 or mi > 59:
            return 0
        now = now or time.time()
        dt = datetime.fromtimestamp(now)
        target = dt.replace(hour=h, minute=mi, second=0, microsecond=0)
        if target.timestamp() <= now:
            target += timedelta(days=1)
        return max(1, int((target.timestamp() - now + 59) // 60))
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(ש|שע|שעה|שעות|h)?\s*'?\s*(דק|דקות|m)?'?", t)
    if not m:
        return 0
    value = float(m.group(1))
    minutes = value * 60 if m.group(2) else value
    minutes = int(round(minutes))
    return minutes if 1 <= minutes <= 7 * 24 * 60 else 0


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
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS failed_logins (
                    pc TEXT NOT NULL, ts REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS messages (
                    chat INTEGER NOT NULL, mid INTEGER NOT NULL, ts REAL NOT NULL,
                    text TEXT NOT NULL, markup TEXT, deleted REAL,
                    PRIMARY KEY (chat, mid));
                CREATE TABLE IF NOT EXISTS apps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, pkg TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL, rule TEXT NOT NULL DEFAULT 'ok', first_seen REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS device_apps (
                    pc TEXT NOT NULL, pkg TEXT NOT NULL, PRIMARY KEY (pc, pkg));
                CREATE TABLE IF NOT EXISTS web_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                    last_used REAL, ip TEXT);
                """
            )
            for table, col, decl in (("kids", "pw_plain", "TEXT"),
                                     ("kids", "role", "TEXT NOT NULL DEFAULT 'kid'"),
                                     ("kids", "must_set", "INTEGER NOT NULL DEFAULT 0"),
                                     ("kids", "disabled", "INTEGER NOT NULL DEFAULT 0"),
                                     ("sites", "expires", "REAL"),
                                     ("sites", "session_id", "INTEGER"),
                                     ("requests", "detail", "TEXT"),
                                     ("pcs", "version", "INTEGER"),
                                     ("web_sessions", "kind", "TEXT NOT NULL DEFAULT 'browser'")):
                if col not in {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                    if col == "kind":
                        self.conn.execute("UPDATE web_sessions SET kind='token' WHERE label LIKE 'טוקן%'")
            # The old "no internet" app rule became "works even without internet".
            self.conn.execute("UPDATE apps SET rule='always' WHERE rule='nonet'")
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

    def setting(self, key: str, default: str = "") -> str:
        rows = self.q("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def set_setting(self, key: str, value: str) -> None:
        self.x("INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def kid_display(self, username: str) -> str:
        rows = self.q("SELECT display FROM kids WHERE username=?", (username,))
        return rows[0]["display"] if rows else username

    # sites
    def site_rows(self, lst: str) -> list[sqlite3.Row]:
        """Live entries: not expired, and a 'for this session' approval only while that session runs."""
        return self.q("SELECT domain, expires, session_id FROM sites WHERE list=? AND (expires IS NULL OR expires>?) "
                      "AND (session_id IS NULL OR session_id IN (SELECT id FROM sessions WHERE active=1)) "
                      "ORDER BY domain", (lst, time.time()))

    def sites(self, lst: str) -> list[str]:
        return [r["domain"] for r in self.site_rows(lst)]

    def add_site(self, domain: str, lst: str, minutes: int | None = None, session=None) -> None:
        """minutes=None and no session: permanent, and replaces the opposite list's entry.
        session: allowed until that session ends (follows its extensions, gone when it is locked).
        A temporary allow keeps any block and overrides it until it expires."""
        d = normalize_domain(domain)
        if minutes or session is not None:
            expires = session["ends"] if session is not None else time.time() + minutes * 60
            sid = session["id"] if session is not None else None
            self.x("INSERT INTO sites (domain, list, expires, session_id) VALUES (?,?,?,?) "
                   "ON CONFLICT(domain, list) DO UPDATE SET "
                   "session_id=CASE WHEN expires IS NULL THEN NULL WHEN excluded.expires>=expires "
                   "THEN excluded.session_id ELSE session_id END, "
                   "expires=CASE WHEN expires IS NULL THEN NULL ELSE MAX(expires, excluded.expires) END",
                   (d, lst, expires, sid))
            return
        self.x("INSERT INTO sites (domain, list, expires, session_id) VALUES (?,?,NULL,NULL) "
               "ON CONFLICT(domain, list) DO UPDATE SET expires=NULL, session_id=NULL", (d, lst))
        for other in {"allow": ("block",), "always": ("block",), "block": ("allow", "always")}[lst]:
            self.x("DELETE FROM sites WHERE domain=? AND list=?", (d, other))

    def remove_site(self, domain: str, lst: str) -> None:
        self.x("DELETE FROM sites WHERE domain=? AND list=?", (normalize_domain(domain), lst))

    # sessions
    def active_session(self, pc: str):
        rows = self.q("SELECT * FROM sessions WHERE pc=? AND active=1 ORDER BY id DESC LIMIT 1", (pc,))
        return rows[0] if rows else None

    def end_sessions(self, pc: str) -> None:
        self.x("UPDATE sessions SET active=0, ends=MIN(ends, ?) WHERE pc=? AND active=1", (time.time(), pc))

    def set_session_end(self, sid: int, ends: float) -> None:
        self.x("UPDATE sessions SET ends=?, warned=0 WHERE id=?", (ends, sid))
        self.x("UPDATE sites SET expires=? WHERE session_id=?", (ends, sid))

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

    def call_raw(self, method: str, **params) -> dict:
        """The whole Telegram reply, including the error description when it fails."""
        data = json.dumps(params).encode()
        req = urllib.request.Request(self.base + method, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=params.get("timeout", 0) + 15) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read() or b"{}")

    def call(self, method: str, **params):
        body = self.call_raw(method, **params)
        if not body.get("ok"):
            log.warning("telegram %s failed: %s", method, body)
            return None
        return body["result"]


# The bot's command menu, shown only in the main parent's chat.
MENU = [
    {"command": "status", "description": "מצב המחשבים"},
    {"command": "lock", "description": "נעילת מחשב"},
    {"command": "extend", "description": "הוספת זמן"},
    {"command": "sites", "description": "רשימות אתרים"},
    {"command": "allow", "description": "אישור אתר"},
    {"command": "block", "description": "חסימת אתר"},
    {"command": "fullnet", "description": "להציע גם אינטרנט מלא"},
    {"command": "apps", "description": "אפליקציות באנדרואיד: לחסום או בלי אינטרנט"},
    {"command": "update", "description": "לעדכן את האפליקציה במכשירים"},
    {"command": "kids", "description": "חשבונות וסיסמאות"},
    {"command": "addkid", "description": "הוספת ילד"},
    {"command": "resetpw", "description": "סיסמה זמנית חדשה"},
    {"command": "web", "description": "ממשק ניהול באינטרנט"},
    {"command": "history", "description": "היסטוריית אירועים"},
    {"command": "audit", "description": "בדיקה אם נמחקו הודעות"},
    {"command": "learn", "description": "סיכום הלמידה של הילדים ויעדים"},
    {"command": "help", "description": "עזרה"},
]


# ------------------------------------------------------------------------- Core

class HomeGuard:
    def __init__(self, cfg: dict, db: DB, tg: Telegram | None):
        self.cfg = cfg
        self.db = db
        self.tg = tg
        self.parents = [int(c) for c in cfg["parent_chat_ids"]]
        self.awaiting_time: dict[int, str] = {}
        self.activity_sent: dict[str, float] = {}  # device -> last "used while locked" alert
        self.web = WebAdmin(self)

    # ---- messaging helpers
    def owner(self) -> int:
        """The main parent: only they get master sign-ins and full-internet approvals (/owner)."""
        return int(self.db.setting("owner_chat", "") or self.parents[0])

    def notify(self, text: str, keyboard=None, chats=None) -> list[list[int]]:
        sent = []
        if not self.tg:
            log.info("NOTIFY: %s", text)
            return sent
        for chat in chats if chats is not None else self.parents:
            mid = self.send(chat, text, {"inline_keyboard": keyboard} if keyboard else None)
            if mid:
                sent.append([chat, mid])
        return sent

    def send(self, chat: int, text: str, markup=None) -> int | None:
        """sendMessage, remembered in the message log when it goes to a parent."""
        params = {"chat_id": chat, "text": text}
        if markup:
            params["reply_markup"] = markup
        res = self.tg.call("sendMessage", **params)
        if not res:
            return None
        if chat in self.parents:
            inline = markup if markup and "inline_keyboard" in markup else None
            self.db.x("INSERT OR REPLACE INTO messages (chat, mid, ts, text, markup) VALUES (?,?,?,?,?)",
                      (chat, res["message_id"], time.time(), text, json.dumps(inline) if inline else None))
        return res["message_id"]

    def edit_all(self, messages: list, text: str) -> None:
        if not self.tg:
            return
        for chat, mid in messages:
            self.tg.call("editMessageText", chat_id=chat, message_id=mid, text=text)
            self.db.x("UPDATE messages SET text=?, markup=NULL WHERE chat=? AND mid=?", (text, chat, mid))

    def reply(self, chat: int, text: str, keyboard=None) -> None:
        if not self.tg:
            log.info("REPLY %s: %s", chat, text)
            return
        self.send(chat, text, {"inline_keyboard": keyboard} if keyboard else None)

    # ---- message log: /history and the check for deleted messages
    def parent_name(self, chat: int) -> str:
        return self.db.setting(f"name:{chat}", str(chat))

    def history_text(self, count: int = 20) -> list[str]:
        """The last events the bot reported, once per event (both parents get the same message)."""
        rows = self.db.q("SELECT * FROM messages ORDER BY ts DESC LIMIT ?", (count * len(self.parents) * 3,))
        events: dict = {}
        for r in rows:
            key = (int(r["ts"]) // 3, r["text"])
            events.setdefault(key, []).append(r)
        lines = []
        for (_, text), copies in list(events.items())[:count]:
            ts = min(c["ts"] for c in copies)
            line = time.strftime("%d/%m %H:%M", time.localtime(ts)) + " · " + text.replace("\n", " ")[:220]
            for c in copies:
                if c["deleted"]:
                    line += f"\n   🗑 נמחקה אצל {self.parent_name(c['chat'])} (התגלה {hhmm(c['deleted'])})"
            lines.append(line)
        if not lines:
            return ["📜 אין עדיין היסטוריה"]
        chunks, cur = [], f"📜 {len(lines)} האירועים האחרונים (מהחדש לישן):"
        for line in lines:
            if len(cur) + len(line) > 3800:
                chunks.append(cur)
                cur = ""
            cur += "\n\n" + line
        chunks.append(cur.strip())
        return chunks

    def message_exists(self, row) -> bool | None:
        """Telegram can't say "was this deleted?", so set the message's buttons to what they already are:
        a message that's still there answers "not modified", a deleted one "not found"."""
        markup = json.loads(row["markup"]) if row["markup"] else {"inline_keyboard": []}
        body = self.tg.call_raw("editMessageReplyMarkup", chat_id=row["chat"], message_id=row["mid"],
                                reply_markup=markup)
        desc = str(body.get("description", "")).lower()
        if body.get("ok") or "not modified" in desc:
            return True
        if "not found" in desc or "message_id_invalid" in desc:
            return False
        log.warning("audit %s/%s: %s", row["chat"], row["mid"], desc)
        return None  # unknown (network, rate limit): try again next time

    def audit(self, days: int = 7) -> tuple[int, list]:
        """Check the last week's messages are still in the parents' chats. Returns (checked, newly deleted)."""
        if not self.tg:
            return 0, []
        rows = self.db.q("SELECT * FROM messages WHERE deleted IS NULL AND ts>? ORDER BY ts DESC LIMIT 400",
                         (time.time() - days * 86400,))
        checked, gone = 0, []
        for r in rows:
            exists = self.message_exists(r)
            if exists is None:
                continue
            checked += 1
            if not exists:
                self.db.x("UPDATE messages SET deleted=? WHERE chat=? AND mid=?", (time.time(), r["chat"], r["mid"]))
                gone.append(r)
            time.sleep(0.05)
        if gone:
            lines = [f"⚠️ בדיקת התאמה: {len(gone)} הודעות של הבוט נמחקו מהצ'אט:"]
            for r in sorted(gone, key=lambda r: r["ts"]):
                lines.append(f"• אצל {self.parent_name(r['chat'])}, " +
                             time.strftime("%d/%m %H:%M", time.localtime(r["ts"])) + ": " +
                             r["text"].replace("\n", " ")[:200])
            self.notify("\n".join(lines)[:3900])
        return checked, gone

    # ---- agent API
    def login(self, pc: str, username: str, password: str, note: str = "") -> dict:
        now = time.time()
        recent = self.db.q("SELECT COUNT(*) c FROM failed_logins WHERE pc=? AND ts>?", (pc, now - 600))[0]["c"]
        if recent >= self.cfg["max_failed_logins"]:
            return {"ok": False, "error": "יותר מדי ניסיונות. נסו שוב בעוד כמה דקות."}
        kid = self.db.check_kid(username, password)
        if not kid and not self.passwords_required():
            # Passwordless mode: a kid only picks their name; the parents' approval is the check.
            k = self.db.kid(username.strip().lower())
            if k and k["role"] != "master":
                kid = k
        if not kid:
            self.db.x("INSERT INTO failed_logins VALUES (?,?)", (pc, now))
            if recent + 1 == self.cfg["max_failed_logins"]:
                self.notify(f"⚠️ {self.cfg['max_failed_logins']} ניסיונות כניסה שגויים במחשב '{pc}' "
                            f"(שם משתמש אחרון: {username})")
            return {"ok": False, "error": "שם משתמש או סיסמה שגויים"}
        name = kid["username"]
        if kid["disabled"]:
            return {"ok": False, "error": "החשבון מושבת. דברו עם אבא/אמא."}
        if kid["must_set"] and self.passwords_required():
            return {"ok": False, "need_new_password": True, "display": kid["display"]}
        if kid["role"] == "master":
            self.db.start_session(pc, name, "open", 0)
            rid = self.db.x("INSERT INTO requests (kind, pc, kid, created, status, decided_by) "
                            "VALUES ('login',?,?,?,'approved','master')", (pc, name, now))
            self.notify(f"🔓 {kid['display']} נכנס/ה למחשב '{pc}' עם חשבון מאסטר ({hhmm(now)})", chats=[self.owner()])
            return {"ok": True, "request_id": rid, "display": kid["display"], "approved": True}
        rid = self._access_request(pc, name, f"🧒 {kid['display']} מבקש/ת להיכנס למחשב '{pc}' ({hhmm(now)})", note)
        return {"ok": True, "request_id": rid, "display": kid["display"]}

    def rerequest(self, pc: str, note: str = "") -> dict:
        """A kid who is already in asks for different access (mode/time). The current session goes on
        until a parent answers, and a "no" leaves it as it is."""
        s = self.db.active_session(pc)
        if not s or s["ends"] <= time.time():
            return {"ok": False, "error": "אין זמן פעיל"}
        k = self.db.kid(s["kid"])
        if k and k["role"] == "master":
            return {"ok": False, "error": "חשבון מאסטר לא צריך אישור"}
        left = "ללא הגבלת זמן" if s["ends"] >= FOREVER else f"נשארו {int((s['ends'] - time.time()) // 60)} דק'"
        head = (f"🔁 {self.db.kid_display(s['kid'])} מבקש/ת הרשאה חדשה במחשב '{pc}' ({hhmm(time.time())})\n"
                f"עכשיו: {MODES[s['mode']]} · {left}")
        return {"ok": True, "request_id": self._access_request(pc, s["kid"], head, note, s["id"])}

    def _access_request(self, pc: str, kid: str, head: str, note: str, session_id=None) -> int:
        """Ask the parents for access (mode x duration buttons). One pending login request per pc."""
        for old in self.db.q("SELECT * FROM requests WHERE pc=? AND kind='login' AND status='pending'", (pc,)):
            self.db.x("UPDATE requests SET status='cancelled' WHERE id=?", (old["id"],))
            self.edit_all(json.loads(old["messages"]), f"↩️ בקשה בוטלה ({self.db.kid_display(old['kid'])}, {pc})")
        note = " ".join(str(note).split())[:300]
        rid = self.db.x("INSERT INTO requests (kind, pc, kid, created, session_id, detail) VALUES ('login',?,?,?,?,?)",
                        (pc, kid, time.time(), session_id, note or None))
        def message(modes):
            kb = []
            for mode in modes:
                options = list(self.cfg["durations"]) + ([0] if mode != "offline" else [])
                kb.append([{"text": f"{MODE_SHORT[mode]} {fmt_min(m) if m else '♾️'}",
                            "callback_data": f"ap:{rid}:{mode}:{m}"} for m in options])
            kb.append([{"text": f"⏱ זמן אחר {MODE_SHORT[mode]}", "callback_data": f"cu:{rid}:{mode}"}
                       for mode in modes])
            kb.append([{"text": "❌ לא עכשיו", "callback_data": f"dn:{rid}"}])
            text = (head + (f"\n💬 {note}" if note else "") + "\n" +
                    " · ".join(f"{MODE_SHORT[m]} {MODE_NAMES[m]}" for m in modes) + " · ♾️ ללא הגבלת זמן")
            return text, kb

        # Full internet is offered only to the main parent; the other parent gets the rest.
        modes = self.login_modes()
        owner = self.owner()
        others = [c for c in self.parents if c != owner]
        msgs = self.notify(*message(modes), chats=[owner])
        if others:
            msgs += self.notify(*message([m for m in modes if m != "full"]), chats=others)
        self.db.x("UPDATE requests SET messages=? WHERE id=?", (json.dumps(msgs), rid))
        return rid

    def full_internet_allowed(self) -> bool:
        return self.db.setting("full_internet", "0") == "1"

    def login_modes(self) -> tuple:
        """Default: only approved sites (or no internet). Full internet only after /fullnet on."""
        return ("allowlist", "full", "offline") if self.full_internet_allowed() else ("allowlist", "offline")

    def passwords_required(self) -> bool:
        return not self.bot_only() and self.db.setting("require_password", "0") == "1"

    def bot_only(self) -> bool:
        """Default: kids get in only by a request the parents approve in the bot, never with a password.
        The master account still signs in with its password."""
        return self.db.setting("bot_only", "1") == "1"

    def kids_for_lock_screen(self) -> dict:
        kids = [{"username": k["username"], "display": k["display"]}
                for k in self.db.q("SELECT username, display FROM kids WHERE role!='master' AND disabled=0 "
                                   "ORDER BY display")]
        return {"kids": kids, "require_password": self.passwords_required()}

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
        kb = [[{"text": f"🧒 עד סוף הזמן שלו/ה ({until(s['ends'])})", "callback_data": f"st:{rid}:s"}],
              [{"text": fmt_min(m), "callback_data": f"st:{rid}:{m}"} for m in self.cfg["durations"]],
              [{"text": "⏱ זמן/שעה אחרת", "callback_data": f"cs:{rid}"}, {"text": "♾️ תמיד", "callback_data": f"st:{rid}:0"}],
              [{"text": "❌ לא", "callback_data": f"dn:{rid}"}]]
        msgs = self.notify(f"🌐 {self.db.kid_display(s['kid'])} מבקש/ת גישה לאתר {d} (מחשב '{pc}')", kb)
        self.db.x("UPDATE requests SET messages=? WHERE id=?", (json.dumps(msgs), rid))
        return {"ok": True}

    def cancel_request(self, rid: int) -> None:
        rows = self.db.q("SELECT * FROM requests WHERE id=? AND status='pending'", (rid,))
        if rows:
            self.db.x("UPDATE requests SET status='cancelled' WHERE id=?", (rid,))
            self.edit_all(json.loads(rows[0]["messages"]),
                          f"↩️ {self.db.kid_display(rows[0]['kid'])} ביטל/ה את הבקשה ({rows[0]['pc']})")

    def state(self, pc: str, win_user: str = "", version: int | None = None) -> dict:
        now = time.time()
        self.db.x("INSERT INTO pcs (name, last_seen, win_user, version) VALUES (?,?,?,?) "
                  "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen, win_user=excluded.win_user, "
                  "version=COALESCE(excluded.version, version)",
                  (pc, now, win_user, version))
        s = self.db.active_session(pc)
        session = None
        if s and s["ends"] > now:
            session = {"id": s["id"], "kid": s["kid"], "display": self.db.kid_display(s["kid"]),
                       "mode": s["mode"], "remaining": int(s["ends"] - now), "unlimited": s["ends"] >= FOREVER}
        pending_ext = bool(s and self.db.q(
            "SELECT 1 FROM requests WHERE kind='extend' AND session_id=? AND status='pending'", (s["id"],)))
        access_pending = bool(s and self.db.q(
            "SELECT 1 FROM requests WHERE kind='login' AND session_id=? AND status='pending'", (s["id"],)))
        allow = self.db.site_rows("allow")
        temp_allowed = {r["domain"] for r in allow if r["expires"] is not None}
        return {"session": session, "extend_pending": pending_ext, "access_pending": access_pending,
                "allowlist": [r["domain"] for r in allow],
                "alwayslist": self.db.sites("always"),
                "blocklist": [d for d in self.db.sites("block") if d not in temp_allowed],
                "apps_blocked": [r["pkg"] for r in self.db.q("SELECT pkg FROM apps WHERE rule='blocked'")],
                "apps_always": [r["pkg"] for r in self.db.q("SELECT pkg FROM apps WHERE rule='always'")],
                "apps_nonet": [],  # rule retired; kept empty for app versions up to 8
                "update_seq": int(self.db.setting("update_seq", "0")),
                "server_time": now}

    # ---- apps on Android devices
    # blocked: never opens (only in a master session). always: opens in every mode and has its own
    # internet. ok (the default): opens only while the kid has approved internet, under the site rules.
    APP_RULES = {"blocked": "⛔ חסומה", "always": "🟢 גם בלי אינטרנט", "ok": "🌐 רק עם אינטרנט"}

    def report_apps(self, pc: str, apps: list) -> dict:
        """The device's launcher apps. A new app on a device we already know is announced with buttons."""
        known_device = bool(self.db.q("SELECT 1 FROM device_apps WHERE pc=? LIMIT 1", (pc,)))
        current = {}
        for a in apps:
            pkg, label = str(a.get("pkg", "")).strip(), str(a.get("label", "")).strip()
            if re.fullmatch(r"[A-Za-z0-9_.]{2,200}", pkg):
                current[pkg] = label[:80] or pkg
        before = {r["pkg"] for r in self.db.q("SELECT pkg FROM device_apps WHERE pc=?", (pc,))}
        for pkg, label in current.items():
            self.db.x("INSERT INTO apps (pkg, label, first_seen) VALUES (?,?,?) "
                      "ON CONFLICT(pkg) DO UPDATE SET label=excluded.label", (pkg, label, time.time()))
        self.db.x("DELETE FROM device_apps WHERE pc=?", (pc,))
        for pkg in current:
            self.db.x("INSERT OR IGNORE INTO device_apps (pc, pkg) VALUES (?,?)", (pc, pkg))
        if known_device:
            for pkg in sorted(set(current) - before):
                app = self.db.q("SELECT * FROM apps WHERE pkg=?", (pkg,))[0]
                self.notify(f"📲 אפליקציה חדשה במכשיר '{pc}': {app['label']} ({pkg})\n"
                            f"מצב כרגע: {self.APP_RULES[app['rule']]}", [self.app_buttons(app)])
        return {"ok": True}

    def app_buttons(self, app) -> list:
        return [{"text": ("• " if app["rule"] == r else "") + name, "callback_data": f"ar:{app['id']}:{r}"}
                for r, name in self.APP_RULES.items()]

    def set_app_rule(self, app_id: int, rule: str) -> str:
        rows = self.db.q("SELECT * FROM apps WHERE id=?", (app_id,))
        if not rows or rule not in self.APP_RULES:
            return "לא נמצא"
        self.db.x("UPDATE apps SET rule=? WHERE id=?", (rule, app_id))
        return f"{rows[0]['label']}: {self.APP_RULES[rule]}"

    def apps_keyboard(self, query: str = "") -> tuple[str, list]:
        """One row per app on any device: its name, then the three rules (the current one marked)."""
        q = query.lower()
        rows = [a for a in self.db.q("SELECT * FROM apps WHERE pkg IN (SELECT pkg FROM device_apps) ORDER BY label")
                if not q or q in a["label"].lower() or q in a["pkg"].lower()]
        if not rows:
            return ("אין עדיין אפליקציות. הן יופיעו כאן אחרי שמכשיר אנדרואיד יתחבר לשרת." if not q
                    else f"לא נמצאה אפליקציה בשם '{query}'"), []
        kb = []
        for a in rows[:24]:
            kb.append([{"text": f"{a['label']}", "callback_data": f"ai:{a['id']}"}])
            kb.append(self.app_buttons(a))
        more = f"\n(מוצגות 24 מתוך {len(rows)}. לחיפוש: /apps <שם>)" if len(rows) > 24 else ""
        return ("📱 אפליקציות באנדרואיד. לוחצים על המצב הרצוי:\n"
                "⛔ חסומה: לא נפתחת בכלל (רק בכניסת מאסטר)\n"
                "🟢 גם בלי אינטרנט: נפתחת תמיד, ויש לה אינטרנט משלה גם כשהאינטרנט חסום (לא לדפדפן)\n"
                "🌐 רק עם אינטרנט: נפתחת רק כשאישרתם אינטרנט, ולפי האתרים המאושרים" + more), kb

    def request_update(self) -> int:
        seq = int(self.db.setting("update_seq", "0")) + 1
        self.db.set_setting("update_seq", str(seq))
        return seq

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
              [{"text": "⏱ זמן אחר", "callback_data": f"cx:{rid}"}, {"text": "❌ לא", "callback_data": f"dn:{rid}"}]]
        msgs = self.notify(f"⏳ {self.db.kid_display(s['kid'])} מבקש/ת עוד זמן במחשב '{pc}' (נשארו {left} דק')", kb)
        self.db.x("UPDATE requests SET messages=? WHERE id=?", (json.dumps(msgs), rid))
        return {"ok": True}

    ACTIVITY_EVERY = 10 * 60  # at most one "used while locked" alert per device in this many seconds

    def report_activity(self, pc: str, what: str) -> dict:
        """The device says it's being used although it should be locked. Tell the parents."""
        now = time.time()
        s = self.db.active_session(pc)
        if s and s["ends"] > now:
            return {"ok": True, "sent": False}  # approved in the meantime
        if now - self.activity_sent.get(pc, 0) < self.ACTIVITY_EVERY:
            return {"ok": True, "sent": False}
        self.activity_sent[pc] = now
        text = f"⚠️ יש פעילות ב'{pc}' למרות שהוא אמור להיות נעול"
        if what:
            text += f"\n{what[:300]}"
        last = self.db.q("SELECT kid, ends FROM sessions WHERE pc=? ORDER BY id DESC LIMIT 1", (pc,))
        if last and last[0]["ends"] < FOREVER:
            text += f"\nהזמן האחרון היה של {self.db.kid_display(last[0]['kid'])}, ונגמר ב-{hhmm(last[0]['ends'])}"
        self.notify(text)
        return {"ok": True, "sent": True}

    def end_by_kid(self, pc: str) -> None:
        s = self.db.active_session(pc)
        if s:
            self.db.end_sessions(pc)
            self.notify(f"👋 {self.db.kid_display(s['kid'])} סיים/ה במחשב '{pc}'")

    # ---- parent actions (Telegram callbacks)
    def decide(self, data: str, who: str, chat: int | None = None) -> str:
        """chat: the parent's Telegram chat (None from the web page, which has its own password)."""
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
            if mode in ("full", "open") and chat is not None and chat != self.owner():
                return f"אינטרנט מלא מאשר/ת רק {self.parent_name(self.owner())}"
            sid, ends = self.db.start_session(r["pc"], r["kid"], mode, minutes)
            self.db.x("UPDATE requests SET status='approved', decided_by=?, session_id=? WHERE id=?", (who, sid, rid))
            length = "ללא הגבלת זמן" if minutes <= 0 else f"ל{fmt_min(minutes)}, עד {hhmm(ends)}"
            self.edit_all(msgs, f"✅ {display} ({r['pc']}): {MODES[mode]} {length} · אושר ע\"י {who}")
            return "אושר"
        if kind == "st":
            if parts[2] == "s":
                s = self.db.q("SELECT * FROM sessions WHERE id=? AND active=1", (r["session_id"],))
                if not s or s[0]["ends"] <= time.time():
                    self.db.x("UPDATE requests SET status='cancelled' WHERE id=?", (rid,))
                    self.edit_all(msgs, f"↩️ {display} ({r['pc']}): הזמן כבר נגמר")
                    return "הזמן כבר נגמר"
                self.db.add_site(r["detail"], "allow", session=s[0])
                length = f"עד סוף הזמן ({until(s[0]['ends'])})"
            else:
                minutes = int(parts[2])
                self.db.add_site(r["detail"], "allow", minutes or None)
                length = "תמיד" if minutes <= 0 else f"ל{fmt_min(minutes)}, עד {hhmm(time.time() + minutes * 60)}"
            self.db.x("UPDATE requests SET status='approved', decided_by=? WHERE id=?", (who, rid))
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
            self.db.set_session_end(s[0]["id"], new_end)
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
        self.db.set_session_end(s["id"], max(s["ends"], time.time()) + minutes * 60)
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
        self.db.x("DELETE FROM sites WHERE session_id IS NOT NULL AND session_id NOT IN "
                  "(SELECT id FROM sessions WHERE active=1)")
        self.db.x("DELETE FROM failed_logins WHERE ts<?", (now - 3600,))
        self.web.drop_idle()

    # ---- Telegram update handling
    def handle_update(self, upd: dict) -> None:
        if "callback_query" in upd:
            cq = upd["callback_query"]
            chat = cq["message"]["chat"]["id"] if "message" in cq else cq["from"]["id"]
            if chat not in self.parents:
                return
            who = cq["from"].get("first_name", "הורה")
            self.remember_name(chat, who)
            data = cq.get("data", "")
            if data.startswith(("cu:", "cx:", "cs:")):
                answer = self.ask_custom_time(chat, data)
            elif data.startswith("lk:"):
                pc = data[3:]
                answer = "ננעל" if self.lock(pc) else "כבר נעול"
            elif data.startswith("ai:"):
                rows = self.db.q("SELECT * FROM apps WHERE id=?", (int(data[3:]),))
                answer = f"{rows[0]['label']}: {self.APP_RULES[rows[0]['rule']]}" if rows else "לא נמצא"
            elif data.startswith("ar:"):
                _, app_id, rule = data.split(":")
                answer = self.set_app_rule(int(app_id), rule)
                self.refresh_app_row(cq, int(app_id))
            else:
                answer = self.decide(data, who, chat)
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
        self.remember_name(chat, msg.get("from", {}).get("first_name", ""))
        if chat in self.awaiting_time and not text.startswith("/"):
            self.answer_custom_time(chat, text)
            return
        self.awaiting_time.pop(chat, None)
        self.handle_command(chat, cmd, arg)

    def refresh_app_row(self, cq: dict, app_id: int) -> None:
        """Move the "•" mark in the tapped message to the rule just chosen."""
        msg = cq.get("message")
        rows = self.db.q("SELECT * FROM apps WHERE id=?", (app_id,))
        if not self.tg or not msg or not rows:
            return
        kb = msg.get("reply_markup", {}).get("inline_keyboard", [])
        new = [self.app_buttons(rows[0]) if any(b.get("callback_data", "").startswith(f"ar:{app_id}:") for b in row)
               else row for row in kb]
        self.tg.call("editMessageReplyMarkup", chat_id=msg["chat"]["id"], message_id=msg["message_id"],
                     reply_markup={"inline_keyboard": new})

    def remember_name(self, chat: int, name: str) -> None:
        if name and self.db.setting(f"name:{chat}") != name:
            self.db.set_setting(f"name:{chat}", name)

    # ---- custom duration: parent taps "other time" and types it
    def ask_custom_time(self, chat: int, data: str) -> str:
        rid = int(data.split(":")[1])
        rows = self.db.q("SELECT status FROM requests WHERE id=?", (rid,))
        if not rows or rows[0]["status"] != "pending":
            return "כבר טופל"
        self.awaiting_time[chat] = data
        if self.tg:
            # No force_reply: Telegram keeps that "reply" box open in the chat every time it's opened.
            self.send(chat, "⏱ כמה זמן? כתבו מספר דקות (45), שעות (2 שעות / 1.5ש) או עד איזו שעה (18:30)")
        return "כתבו את הזמן"

    def answer_custom_time(self, chat: int, text: str) -> None:
        minutes = parse_duration(text)
        if not minutes:
            self.reply(chat, "לא הבנתי 🙂 למשל: 45, 2 שעות, 1.5ש או 18:30")
            return
        data = self.awaiting_time.pop(chat)
        parts = data.split(":")
        who = self.parent_name(chat)
        if parts[0] == "cu":
            result = self.decide(f"ap:{parts[1]}:{parts[2]}:{minutes}", who, chat)
        elif parts[0] == "cs":
            result = self.decide(f"st:{parts[1]}:{minutes}", who, chat)
        else:
            result = self.decide(f"ex:{parts[1]}:{minutes}", who, chat)
        self.reply(chat, f"{result} ({fmt_min(minutes)})")

    def set_menus(self) -> None:
        """Commands are for the main parent only: their chat gets the menu, everyone else none."""
        if not self.tg:
            return
        self.tg.call("setMyCommands", commands=[])
        for chat in self.parents:
            self.tg.call("setMyCommands", commands=MENU if chat == self.owner() else [],
                         scope={"type": "chat", "chat_id": chat})

    def handle_command(self, chat: int, cmd: str, arg: str) -> None:
        if chat != self.owner() and not (cmd == "/owner" and not self.db.setting("owner_chat", "")):
            return  # the other parent only answers requests with the buttons
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
        elif cmd in ("/allow", "/block", "/unallow", "/unblock", "/always", "/unalways"):
            if not arg:
                self.reply(chat, f"שימוש: {cmd} example.com" + (" [דקות]" if cmd == "/allow" else ""))
                return
            lst = "always" if "always" in cmd else "allow" if "allow" in cmd else "block"
            words = arg.replace(",", " ").split()
            domains = [w for w in words if valid_domain(normalize_domain(w)) and not re.fullmatch(r"[\d.]+", w)]
            rest = " ".join(w for w in words if w not in domains)
            minutes = None
            if cmd == "/allow" and rest:
                minutes = parse_duration(rest)
                if not minutes:
                    self.reply(chat, "לא הבנתי את הזמן 🙂 למשל: /allow site.com 30 · /allow site.com 2 שעות · "
                                     "/allow site.com 18:30")
                    return
            if not domains:
                self.reply(chat, f"שימוש: {cmd} example.com")
                return
            for d in domains:
                if cmd.startswith("/un"):
                    self.db.remove_site(d, lst)
                else:
                    self.db.add_site(d, lst, minutes)
            self.reply(chat, self.sites_text())
        elif cmd == "/sites":
            self.reply(chat, self.sites_text())
        elif cmd == "/apps":
            text, kb = self.apps_keyboard(arg)
            self.reply(chat, text, kb or None)
        elif cmd == "/update":
            self.request_update()
            devices = [f"{p['name']} (גרסה {p['version']})" for p in
                       self.db.q("SELECT name, version FROM pcs WHERE version IS NOT NULL AND version>0 ORDER BY name")]
            self.reply(chat, "📲 ביקשתי מהמכשירים לבדוק עדכון עכשיו. כל מכשיר ידווח כאן כשהוא מתעדכן.\n" +
                       ("מכשירים: " + ", ".join(devices) if devices else
                        "עוד אין מכשיר אנדרואיד שמדווח גרסה.") +
                       "\n(בלי /update הם בודקים לבד כל 6 שעות)")
        elif cmd == "/history":
            count = int(arg) if arg.isdigit() else 20
            for chunk in self.history_text(max(1, min(count, 200))):
                self.reply(chat, chunk)
        elif cmd == "/audit":
            self.reply(chat, "🔎 בודק את ההודעות מהשבוע האחרון...")
            checked, gone = self.audit()
            if not gone:
                self.reply(chat, f"✅ בדיקת התאמה: כל {checked} ההודעות מהשבוע האחרון נמצאות בצ'אטים")
        elif cmd == "/fullnet":
            if arg in ("on", "off"):
                self.db.set_setting("full_internet", "1" if arg == "on" else "0")
            self.reply(chat, "🌐 אפשר לאשר גם אינטרנט מלא (בנוסף לאתרים מאושרים)" if self.full_internet_allowed() else
                       "✅ ברירת מחדל: כל האתרים חסומים חוץ מאתרים שאישרתם. אינטרנט מלא לא מוצע בבקשות.\n"
                       "לשינוי: /fullnet on או /fullnet off")
        elif cmd == "/passwords":
            if arg in ("on", "off"):
                self.db.set_setting("require_password", "1" if arg == "on" else "0")
            self.reply(chat, "🔑 כניסה עם סיסמה: פעילה" if self.passwords_required() else
                       "👆 כניסה בלי סיסמה: הילד בוחר את השם שלו ואתם מאשרים. (מאסטר תמיד עם סיסמה)\n"
                       "לשינוי: /passwords on או /passwords off")
        elif cmd == "/owner":
            # The first parent to send it becomes the main parent; after that only they can change it.
            if not self.db.setting("owner_chat", "") or chat == self.owner():
                self.db.set_setting("owner_chat", str(chat))
                self.set_menus()
            self.reply(chat, f"👑 ההורה הראשי: {self.parent_name(self.owner())}. רק אצלו/ה מגיעות כניסות מאסטר "
                             "ואישורי אינטרנט מלא.")
        elif cmd == "/botonly":
            if arg in ("on", "off"):
                self.db.set_setting("bot_only", "1" if arg == "on" else "0")
            self.reply(chat, "🤖 ילדים נכנסים רק בבקשה בבוט, בלי סיסמה. מאסטר נכנס עם שם משתמש וסיסמה."
                       if self.bot_only() else
                       "🔑 כניסת ילדים לפי /passwords\n"
                       "לשינוי: /botonly on או /botonly off")
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
        elif cmd == "/webpass":
            if len(arg) < 8:
                self.reply(chat, "שימוש: /webpass <סיסמה של 8 תווים לפחות>\nזו הסיסמה לממשק הניהול באינטרנט (/web).")
                return
            self.web.set_password(arg)
            self.reply(chat, "🔑 הסיסמה לממשק הניהול נקבעה. כל הכניסות הקודמות נותקו.\n"
                             "כדאי למחוק מהצ'אט את ההודעה עם הסיסמה.\n\n" + self.web.link_text())
        elif cmd == "/web":
            self.reply(chat, self.web.link_text())
        elif cmd == "/learn":
            self.reply(chat, self.learning_command(arg))
        else:
            self.reply(chat, HELP)

    # ---- learning goals from the לימודים app (see learning_goals.py)
    def learning(self):
        code = self.db.setting("learn_code")
        if not code:
            return None
        from learning_goals import LearningGoals
        return LearningGoals(self, code, int(self.db.setting("learn_hour", "20")))

    def learning_command(self, arg: str) -> str:
        parts = arg.split()
        if parts[:1] == ["code"] and len(parts) == 2:
            code = re.sub(r"[^0-9A-Z]", "", parts[1].upper())
            if len(code) != 8:
                return "קוד המשפחה הוא 8 תווים (באפליקציה: הגדרות ← סנכרון)."
            self.db.set_setting("learn_code", code)
            return "📚 מחובר לאפליקציית הלימודים. סיכום כל ערב, והודעה כשילד משיג יעד. /learn לסיכום עכשיו."
        if parts[:1] == ["hour"] and len(parts) == 2 and parts[1].isdigit() and 0 <= int(parts[1]) <= 23:
            self.db.set_setting("learn_hour", parts[1])
            return f"📚 הסיכום היומי יישלח בשעה {int(parts[1])}:00."
        if parts[:1] == ["off"]:
            self.db.set_setting("learn_code", "")
            return "📚 הדיווח על הלמידה כובה."
        lg = self.learning()
        if not lg:
            return "📚 עוד לא מחובר לאפליקציית הלימודים. שולחים: /learn code <קוד המשפחה>"
        try:
            return lg.summary_text(datetime.now().date().isoformat())
        except Exception as e:  # network or Firestore
            log.exception("learning summary failed")
            return f"📚 לא הצלחתי לקרוא את נתוני הלמידה: {e}"

    def sites_text(self) -> str:
        allow = [r["domain"] + ("" if not r["expires"] else
                                f" (עד סוף הזמן של הילד, {until(r['expires'])})" if r["session_id"] else
                                f" (זמני, עד {hhmm(r['expires'])})")
                 for r in self.db.site_rows("allow")]
        block = self.db.sites("block")
        always = self.db.sites("always")
        return ("✅ אתרים מאושרים (במצב 'רק אתרים מאושרים'. אישור זמני גובר גם על חסימה):\n" +
                ("\n".join(allow) or "—") + "\n\n⛔ אתרים חסומים (תמיד):\n" + ("\n".join(block) or "—") +
                "\n\n🟢 פתוחים תמיד (בכל מצב, גם 🚫 בלי אינטרנט):\n" + ("\n".join(always) or "—"))

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


# -------------------------------------------------------------------- web admin

class WebAdmin:
    """The parents' web page (/admin): everything the bot can do, with explanations.

    Behind a password the parents set with /webpass (stored hashed). Signing in gives a random
    token (cookie for the page, or "Authorization: Bearer" for scripts); only its hash is stored.
    A browser sign-in is never remembered: the cookie lives only while the browser is open, the page
    signs out when it is closed, and the server drops it after IDLE_SECONDS without the parent touching
    the page (the page's background refreshes don't count).
    Every web sign-in is reported in Telegram, and too many wrong passwords lock the page for a while."""

    WHO = "ממשק אינטרנט"
    IDLE_SECONDS = 60
    SESSION_HOURS = 12  # hard limit for a browser sign-in, even while in use
    TOKEN_DAYS = 365

    def __init__(self, hg: HomeGuard):
        self.hg = hg
        self.db = hg.db

    # ---- password and tokens
    def password_set(self) -> bool:
        return bool(self.db.setting("web_pw_hash"))

    def set_password(self, password: str) -> None:
        salt = secrets.token_hex(16)
        self.db.set_setting("web_pw_salt", salt)
        self.db.set_setting("web_pw_hash", DB._hash(password, salt))
        self.db.x("DELETE FROM web_sessions")

    def check_password(self, password: str) -> bool:
        stored = self.db.setting("web_pw_hash")
        return bool(stored) and hmac.compare_digest(stored, DB._hash(password, self.db.setting("web_pw_salt")))

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def new_token(self, label: str, seconds: float, ip: str = "", kind: str = "token") -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.db.x("INSERT INTO web_sessions (token_hash, label, created, expires, last_used, ip, kind) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (self._token_hash(token), label[:80], now, now + seconds, now, ip[:64], kind))
        return token

    def session(self, token: str, active: bool = False):
        """The sign-in behind a token, or None. active: the parent did something on the page just now,
        which keeps a browser sign-in alive for another IDLE_SECONDS."""
        if not token:
            return None
        now = time.time()
        rows = self.db.q("SELECT * FROM web_sessions WHERE token_hash=? AND expires>?", (self._token_hash(token), now))
        if not rows:
            return None
        s = rows[0]
        if s["kind"] == "browser":
            if now - (s["last_used"] or 0) > self.IDLE_SECONDS:
                self.db.x("DELETE FROM web_sessions WHERE id=?", (s["id"],))
                return None
            if active:
                self.db.x("UPDATE web_sessions SET last_used=? WHERE id=?", (now, s["id"]))
        elif now - (s["last_used"] or 0) > 60:
            self.db.x("UPDATE web_sessions SET last_used=? WHERE id=?", (now, s["id"]))
        return s

    def drop_idle(self) -> None:
        self.db.x("DELETE FROM web_sessions WHERE kind='browser' AND (last_used IS NULL OR last_used<? OR expires<?)",
                  (time.time() - self.IDLE_SECONDS, time.time()))

    def logout(self, token: str) -> None:
        self.db.x("DELETE FROM web_sessions WHERE token_hash=?", (self._token_hash(token),))

    def login(self, password: str, ip: str, agent: str) -> dict:
        now = time.time()
        limit = self.hg.cfg["max_failed_logins"]
        recent = self.db.q("SELECT COUNT(*) c FROM failed_logins WHERE pc='web' AND ts>?", (now - 600,))[0]["c"]
        if not self.password_set():
            return {"ok": False, "error": "עוד לא נקבעה סיסמה. שלחו לבוט: /webpass <סיסמה>"}
        if recent >= limit:
            return {"ok": False, "error": "יותר מדי ניסיונות. נסו שוב בעוד 10 דקות."}
        if not self.check_password(password):
            self.db.x("INSERT INTO failed_logins VALUES ('web',?)", (now,))
            if recent + 1 == limit:
                self.hg.notify(f"⚠️ {limit} ניסיונות כניסה שגויים לממשק הניהול (אחרון מ-{ip}). "
                               "הממשק חסום ל-10 דקות.")
            return {"ok": False, "error": "סיסמה שגויה"}
        device = " ".join(agent.split())[:80]
        token = self.new_token(f"דפדפן · {device}" if device else "דפדפן", self.SESSION_HOURS * 3600, ip, "browser")
        self.hg.notify(f"🖥 כניסה לממשק הניהול ({hhmm(now)}, {ip})")
        return {"ok": True, "token": token}

    def link_text(self) -> str:
        base = str(self.hg.cfg.get("public_url") or "").rstrip("/")
        lines = ["🖥 ממשק הניהול:"]
        if base:
            lines.append(f"{base}/admin")
        lines.append(f"בבית: http://<כתובת השרת>:{self.hg.cfg['port']}/admin")
        if not self.password_set():
            lines.append("\nעוד לא נקבעה סיסמה: /webpass <סיסמה>")
        return "\n".join(lines)

    # ---- what the page shows
    def snapshot(self) -> dict:
        now = time.time()
        devices = []
        for p in self.db.q("SELECT * FROM pcs ORDER BY name"):
            s = self.db.active_session(p["name"])
            session = None
            if s and s["ends"] > now:
                session = {"kid": s["kid"], "display": self.db.kid_display(s["kid"]), "mode": s["mode"],
                           "mode_name": MODES[s["mode"]], "started": s["started"],
                           "ends": None if s["ends"] >= FOREVER else s["ends"]}
            devices.append({"name": p["name"], "online": bool(p["last_seen"] and now - p["last_seen"] < 90),
                            "last_seen": p["last_seen"], "user": p["win_user"] or "", "version": p["version"],
                            "android": bool(self.db.q("SELECT 1 FROM device_apps WHERE pc=? LIMIT 1", (p["name"],))),
                            "session": session})
        pending = []
        for r in self.db.q("SELECT * FROM requests WHERE status='pending' ORDER BY created DESC"):
            s = self.db.q("SELECT * FROM sessions WHERE id=?", (r["session_id"],)) if r["session_id"] else []
            pending.append({"id": r["id"], "kind": r["kind"], "pc": r["pc"], "kid": r["kid"],
                            "display": self.db.kid_display(r["kid"]), "created": r["created"],
                            "detail": r["detail"] or "",
                            "session_ends": (None if s[0]["ends"] >= FOREVER else s[0]["ends"]) if s else None,
                            "session_mode": s[0]["mode"] if s else None})
        kids = [{"username": k["username"], "display": k["display"], "role": k["role"],
                 "must_set": bool(k["must_set"]), "disabled": bool(k["disabled"]), "password": k["pw_plain"]}
                for k in self.db.q("SELECT * FROM kids ORDER BY role DESC, display")]
        sites = {lst: [{"domain": r["domain"], "expires": r["expires"], "session": bool(r["session_id"])}
                       for r in self.db.site_rows(lst)] for lst in ("allow", "block", "always")}
        apps = [{"id": a["id"], "pkg": a["pkg"], "label": a["label"], "rule": a["rule"],
                 "devices": [d["pc"] for d in self.db.q("SELECT pc FROM device_apps WHERE pkg=?", (a["pkg"],))]}
                for a in self.db.q("SELECT * FROM apps WHERE pkg IN (SELECT pkg FROM device_apps) ORDER BY label")]
        return {"now": now, "devices": devices, "pending": pending, "kids": kids, "sites": sites, "apps": apps,
                "settings": {"fullnet": self.hg.full_internet_allowed(), "passwords": self.hg.passwords_required(),
                             "durations": list(self.hg.cfg["durations"]),
                             "extend_options": list(self.hg.cfg["extend_options"]),
                             "login_modes": list(self.hg.login_modes()), "update_seq": int(self.db.setting("update_seq", "0"))},
                "modes": MODES, "app_rules": HomeGuard.APP_RULES}

    def tokens(self, current_id: int) -> list:
        return [{"id": t["id"], "label": t["label"], "created": t["created"], "expires": t["expires"],
                 "last_used": t["last_used"], "ip": t["ip"] or "", "current": t["id"] == current_id}
                for t in self.db.q("SELECT * FROM web_sessions WHERE expires>? ORDER BY last_used DESC", (time.time(),))]

    def history(self, count: int) -> list:
        rows = self.db.q("SELECT * FROM messages ORDER BY ts DESC LIMIT ?", (count * max(1, len(self.hg.parents)) * 3,))
        events: dict = {}
        for r in rows:
            events.setdefault((int(r["ts"]) // 3, r["text"]), []).append(r)
        out = []
        for (_, text), copies in list(events.items())[:count]:
            out.append({"ts": min(c["ts"] for c in copies), "text": text,
                        "deleted": [{"by": self.hg.parent_name(c["chat"]), "at": c["deleted"]} for c in copies if c["deleted"]]})
        return out

    # ---- what the page can do
    @staticmethod
    def _minutes(value, allow_zero: bool = True) -> int | None:
        """Minutes from a number or what a parent typed ("2 שעות", "18:30"). 0 = no time limit. None = not understood."""
        text = str(value if value is not None else "").strip()
        if text in ("0", "♾️", "ללא") and allow_zero:
            return 0
        m = int(text) if text.isdigit() else parse_duration(text)
        return m if m and m > 0 else None

    def action(self, body: dict, session_id: int) -> dict:
        a = str(body.get("action", ""))
        hg, db = self.hg, self.db
        pc = str(body.get("pc", ""))
        user = str(body.get("username", "")).strip().lower()

        if a == "lock":
            pcs = [p["name"] for p in db.q("SELECT name FROM pcs")] if pc == "*" else [pc]
            locked = [p for p in pcs if hg.lock(p)]
            return {"ok": True, "message": "🔒 ננעל: " + ", ".join(locked) if locked else "לא היה מכשיר פתוח"}
        if a == "extend":
            minutes = self._minutes(body.get("minutes"), allow_zero=False)
            if not minutes:
                return {"ok": False, "error": "לא הבנתי את הזמן. למשל: 30, 2 שעות, 18:30"}
            if not hg.extend(pc, minutes):
                return {"ok": False, "error": f"אין זמן פעיל ב-{pc}"}
            return {"ok": True, "message": f"⏳ נוספו {fmt_min(minutes)} ל-{pc}"}
        if a == "grant":
            kid, mode = db.kid(user), str(body.get("mode", ""))
            minutes = self._minutes(body.get("minutes"))
            if not kid or not db.q("SELECT 1 FROM pcs WHERE name=?", (pc,)):
                return {"ok": False, "error": "מכשיר או ילד לא קיימים"}
            if mode not in ("allowlist", "full", "offline", "open") or minutes is None:
                return {"ok": False, "error": "צריך לבחור סוג גישה וזמן"}
            sid, ends = db.start_session(pc, kid["username"], mode, minutes)
            for old in db.q("SELECT * FROM requests WHERE pc=? AND kind='login' AND status='pending'", (pc,)):
                db.x("UPDATE requests SET status='approved', decided_by=?, session_id=? WHERE id=?", (self.WHO, sid, old["id"]))
                hg.edit_all(json.loads(old["messages"]), f"✅ {kid['display']} ({pc}): טופל ב{self.WHO}")
            length = "ללא הגבלת זמן" if minutes <= 0 else f"ל{fmt_min(minutes)}, עד {hhmm(ends)}"
            hg.notify(f"✅ {kid['display']} ({pc}): {MODES[mode]} {length} · נפתח ב{self.WHO}")
            return {"ok": True, "message": f"נפתח ל{kid['display']}: {MODES[mode]} {length}"}
        if a == "decide":
            rows = db.q("SELECT * FROM requests WHERE id=?", (int(body.get("id", 0) or 0),))
            if not rows:
                return {"ok": False, "error": "הבקשה לא נמצאה"}
            r, choice = rows[0], str(body.get("choice", ""))
            if choice == "deny":
                data = f"dn:{r['id']}"
            elif r["kind"] == "login":
                minutes, mode = self._minutes(body.get("minutes")), str(body.get("mode", ""))
                if minutes is None or mode not in hg.login_modes():
                    return {"ok": False, "error": "צריך לבחור סוג גישה וזמן"}
                data = f"ap:{r['id']}:{mode}:{minutes}"
            elif r["kind"] == "site":
                if choice == "session":
                    data = f"st:{r['id']}:s"
                else:
                    minutes = self._minutes(body.get("minutes"))
                    if minutes is None:
                        return {"ok": False, "error": "לא הבנתי את הזמן"}
                    data = f"st:{r['id']}:{minutes}"
            else:
                minutes = self._minutes(body.get("minutes"), allow_zero=False)
                if not minutes:
                    return {"ok": False, "error": "לא הבנתי את הזמן"}
                data = f"ex:{r['id']}:{minutes}"
            return {"ok": True, "message": hg.decide(data, self.WHO)}
        if a in ("site_add", "site_remove"):
            lst = str(body.get("list", ""))
            if lst not in ("allow", "block", "always"):
                return {"ok": False, "error": "רשימה לא מוכרת"}
            domains = [normalize_domain(w) for w in str(body.get("domain", "")).replace(",", " ").split()]
            domains = [d for d in domains if valid_domain(d) and not re.fullmatch(r"[\d.]+", d)]
            if not domains:
                return {"ok": False, "error": "כתובת אתר לא תקינה. למשל: wikipedia.org"}
            minutes = None
            if a == "site_add" and lst == "allow" and str(body.get("minutes", "")).strip() not in ("", "0"):
                minutes = self._minutes(body.get("minutes"), allow_zero=False)
                if not minutes:
                    return {"ok": False, "error": "לא הבנתי את הזמן. למשל: 30, 2 שעות, 18:30"}
            for d in domains:
                db.add_site(d, lst, minutes) if a == "site_add" else db.remove_site(d, lst)
            return {"ok": True, "message": ("נוסף: " if a == "site_add" else "הוסר: ") + ", ".join(domains)}
        if a == "app_rule":
            rule = str(body.get("rule", ""))
            if rule not in HomeGuard.APP_RULES:
                return {"ok": False, "error": "מצב לא מוכר"}
            return {"ok": True, "message": hg.set_app_rule(int(body.get("id", 0) or 0), rule)}
        if a == "kid_add":
            if not re.fullmatch(r"[a-z0-9_.-]{2,32}", user):
                return {"ok": False, "error": "שם משתמש באנגלית: אותיות, ספרות, נקודה או מקף (2 עד 32)"}
            if db.kid(user):
                return {"ok": False, "error": "כבר יש משתמש כזה"}
            pw = temp_password()
            role = "master" if body.get("master") else "kid"
            db.add_kid(user, pw, str(body.get("display", "")).strip()[:40] or user, role, must_set=True)
            return {"ok": True, "message": f"נוסף {user} עם סיסמה זמנית {pw}. בכניסה הראשונה תתבקש סיסמה אישית."}
        if a.startswith("kid_"):
            kid = db.kid(user)
            if not kid:
                return {"ok": False, "error": "אין משתמש כזה"}
            if a == "kid_setpw":
                pw = str(body.get("password", ""))
                if not 4 <= len(pw) <= 32:
                    return {"ok": False, "error": "סיסמה באורך 4 עד 32 תווים"}
                db.set_password(user, pw)
                return {"ok": True, "message": f"🔑 הסיסמה של {user} עודכנה"}
            if a == "kid_resetpw":
                pw = temp_password()
                db.set_password(user, pw, must_set=True)
                return {"ok": True, "message": f"🔑 סיסמה זמנית ל-{user}: {pw}"}
            if a == "kid_disable":
                db.x("UPDATE kids SET disabled=1 WHERE username=?", (user,))
                locked = hg.lock_kid(user)
                return {"ok": True, "message": f"⛔ {user} מושבת" + (f" (ננעל: {', '.join(locked)})" if locked else "")}
            if a == "kid_enable":
                db.x("UPDATE kids SET disabled=0 WHERE username=?", (user,))
                return {"ok": True, "message": f"✅ {user} פעיל שוב"}
            if a == "kid_lock":
                locked = hg.lock_kid(user)
                return {"ok": True, "message": "🔒 ננעל: " + ", ".join(locked) if locked else "הוא/היא לא מחובר/ת עכשיו"}
            if a == "kid_remove":
                hg.lock_kid(user)
                db.x("DELETE FROM kids WHERE username=?", (user,))
                return {"ok": True, "message": f"🗑 {user} הוסר"}
        if a == "setting":
            key = {"fullnet": "full_internet", "passwords": "require_password"}.get(str(body.get("key", "")))
            if not key:
                return {"ok": False, "error": "הגדרה לא מוכרת"}
            db.set_setting(key, "1" if body.get("value") else "0")
            return {"ok": True, "message": "נשמר"}
        if a == "update":
            hg.request_update()
            return {"ok": True, "message": "📲 ביקשתי מהמכשירים לבדוק עדכון עכשיו"}
        if a == "audit":
            checked, gone = hg.audit()
            return {"ok": True, "message": f"נבדקו {checked} הודעות" + (f", {len(gone)} נמחקו (נשלח דיווח בטלגרם)" if gone else ", כולן במקום")}
        if a == "token_new":
            label = " ".join(str(body.get("label", "")).split())[:60] or "טוקן גישה"
            token = self.new_token(f"טוקן · {label}", self.TOKEN_DAYS * 86400)
            hg.notify(f"🔑 נוצר טוקן גישה לממשק הניהול: {label}")
            return {"ok": True, "token": token, "message": "הטוקן מוצג פעם אחת בלבד. שמרו אותו."}
        if a == "token_revoke":
            db.x("DELETE FROM web_sessions WHERE id=?", (int(body.get("id", 0) or 0),))
            return {"ok": True, "message": "בוטל"}
        if a == "web_password":
            if not self.check_password(str(body.get("old", ""))):
                return {"ok": False, "error": "הסיסמה הנוכחית שגויה"}
            new = str(body.get("new", ""))
            if len(new) < 8:
                return {"ok": False, "error": "סיסמה של 8 תווים לפחות"}
            self.set_password(new)
            hg.notify("🔑 הסיסמה לממשק הניהול שונתה מהממשק. כל הכניסות נותקו.")
            return {"ok": True, "message": "הסיסמה שונתה. צריך להתחבר מחדש.", "relogin": True}
        return {"ok": False, "error": "פעולה לא מוכרת"}


HELP = """🛡️ HomeGuard – פקודות:
/status – מי מחובר ולכמה זמן
/lock <מחשב> – לנעול עכשיו (בלי שם = כל המחשבים)
/extend <מחשב> <דקות> – להוסיף זמן
✅ ברירת מחדל: כל האתרים חסומים, נכנסים רק לאתרים מאושרים
/allow site.com – לאשר אתר תמיד
/allow site.com 30 · 2 שעות · 18:30 – לאשר לזמן מוגבל או עד שעה (גובר גם על חסימה)
/fullnet on|off – להציע גם "אינטרנט מלא" בבקשות כניסה (ברירת מחדל: לא)
/unallow site.com – להסיר מהמאושרים
/block site.com – לחסום אתר תמיד
/unblock site.com – לבטל חסימה
/always site.com – אתר שפתוח בכל מצב, גם כשהאינטרנט חסום (🚫)
/unalways site.com – להסיר מהפתוחים תמיד
/sites – הרשימות

📱 אנדרואיד:
/apps [שם] – האפליקציות במכשירים: ⛔ חסומה (רק מאסטר) · 🟢 גם בלי אינטרנט (יש לה אינטרנט משלה) · 🌐 רק עם אינטרנט (ברירת מחדל). אפליקציה חדשה שמותקנת מגיעה לכאן עם כפתורים
/update – לעדכן עכשיו את האפליקציה במכשירים (בלי כבל; הם בודקים לבד גם כל 6 שעות)

🖥 ממשק אינטרנט:
/web – הקישור לממשק הניהול (כל מה שיש כאן, עם הסברים)
/webpass <סיסמה> – לקבוע סיסמה לממשק (8 תווים לפחות; מנתק את כל הכניסות הקודמות)

📚 לימודים (האפליקציה של הילדים):
/learn – סיכום הלמידה של היום: זמן פעיל בכל לשונית, איכות ויעדים
/learn code <קוד משפחה> – חיבור לאפליקציה (פעם אחת). אחר כך: הודעה כשילד משיג יעד, וסיכום כל ערב
/learn hour 20 – באיזו שעה לשלוח את הסיכום · /learn off – לכבות
את היעדים קובעים באפליקציה: אזור הורים ← פירוט ויעדים

📜 היסטוריה:
/history [מספר] – האירועים האחרונים, גם אם ההודעות נמחקו מהצ'אט
/audit – בדיקת התאמה עכשיו: האם נמחקו הודעות של הבוט (נבדק גם אוטומטית כל חצי שעה)

👧 חשבונות:
/passwords on|off – כניסה עם סיסמה או רק בחירת שם (ברירת מחדל: בלי סיסמה)
/owner – אני ההורה הראשי: רק אצלי כניסות מאסטר ואישורי אינטרנט מלא
/botonly on|off – ילדים נכנסים רק בבקשה בבוט, בלי סיסמה (ברירת מחדל: on)
⏱ בכל בקשה יש "זמן אחר": כותבים 45, 2 שעות או 18:30
/kids – כל החשבונות והסיסמאות
/addkid <משתמש> [שם] – ילד חדש עם סיסמה זמנית (בוחר/ת סיסמה אישית בכניסה הראשונה)
/addmaster <משתמש> [שם] – חשבון מאסטר: בלי אישור, בלי סינון, בלי הגבלת זמן
/setpw <משתמש> <סיסמה> – לקבוע סיסמה
/resetpw <משתמש> – סיסמה זמנית חדשה
/disable <משתמש> · /enable <משתמש> – להשבית / להחזיר חשבון
/rmkid <משתמש> – למחוק חשבון
/lock <משתמש> – לנעול את המחשב שבו הוא/היא מחובר/ת

בקשות כניסה מגיעות לכאן עם כפתורים: בוחרים סוג גישה ומשך זמן בלחיצה אחת (♾️ = בלי הגבלת זמן, עד שנועלים).
ילדים יכולים לבקש אתר מסוים מתוך הטיימר. אפשר לאשר אותו עד סוף הזמן שלהם, לזמן קצוב, עד שעה מסוימת או תמיד."""


# ------------------------------------------------------------------- HTTP API

def _load_admin_html() -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "admin.html")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return "<!doctype html><meta charset=utf-8><p>admin.html חסר ליד homeguard_server.py</p>"


ADMIN_HTML = _load_admin_html()


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

        # ---- parents' web page
        def _ip(self) -> str:
            fwd = self.headers.get("X-Forwarded-For", "")
            return (fwd.split(",")[0].strip() if fwd else self.client_address[0])[:64]

        def _admin_token(self) -> str:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return auth[7:].strip()
            for part in self.headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "hg_admin":
                    return v
            return ""

        def _admin_json(self, code: int, obj, cookie: str | None = None) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if cookie is not None:
                secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "") == "https" else ""
                # No Max-Age on a sign-in: a session cookie, gone when the browser closes (never "remembered").
                age = "" if cookie else "; Max-Age=0"
                self.send_header("Set-Cookie", f"hg_admin={cookie}; Path=/admin; HttpOnly; SameSite=Strict{age}{secure}")
            self.end_headers()
            self.wfile.write(body)

        def _admin_page(self) -> None:
            body = ADMIN_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                             "style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _admin(self, method: str) -> None:
            path = urlparse(self.path).path.rstrip("/")
            if method == "GET" and path == "/admin":
                self._admin_page()
                return
            if method == "POST":
                # A custom header can't be sent cross-site without CORS, which we never allow (CSRF guard).
                if self.headers.get("X-HG") != "1":
                    self._admin_json(403, {"error": "forbidden"})
                    return
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length > 65536:
                    self._admin_json(413, {"error": "too large"})
                    return
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                    if not isinstance(body, dict):
                        raise ValueError
                except ValueError:
                    self._admin_json(400, {"error": "bad json"})
                    return
                if path == "/admin/api/login":
                    res = hg.web.login(str(body.get("password", "")), self._ip(), self.headers.get("User-Agent", ""))
                    self._admin_json(200, res, cookie=res.get("token") if res.get("ok") else None)
                    return
            tok = self._admin_token()
            # The page marks requests made while the parent is using it; background refreshes aren't marked.
            sess = hg.web.session(tok, active=self.headers.get("X-HG-Active") == "1")
            if path == "/admin/api/whoami":
                self._admin_json(200, {"signed_in": bool(sess), "password_set": hg.web.password_set()})
                return
            if not sess:
                self._admin_json(401, {"error": "צריך להתחבר"})
                return
            qs = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
            if method == "GET" and path == "/admin/api/state":
                self._admin_json(200, hg.web.snapshot())
            elif method == "GET" and path == "/admin/api/history":
                count = int(qs["count"]) if qs.get("count", "").isdigit() else 50
                self._admin_json(200, {"events": hg.web.history(max(1, min(count, 500)))})
            elif method == "GET" and path == "/admin/api/tokens":
                self._admin_json(200, {"tokens": hg.web.tokens(sess["id"])})
            elif method == "POST" and path == "/admin/api/logout":
                hg.web.logout(tok)
                self._admin_json(200, {"ok": True}, cookie="")
            elif method == "POST" and path == "/admin/api/action":
                try:
                    res = hg.web.action(body, sess["id"])
                except (ValueError, TypeError) as e:
                    res = {"ok": False, "error": f"נתונים לא תקינים ({e})"}
                self._admin_json(200, res, cookie="" if res.get("relogin") else None)
            else:
                self._admin_json(404, {"error": "not found"})

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/admin"):
                if self.path == "/":
                    self.send_response(302)
                    self.send_header("Location", "/admin")
                    self.end_headers()
                    return
                self._admin("GET")
                return
            if not self._auth():
                return
            u = urlparse(self.path)
            qs = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/api/state":
                ver = qs.get("ver", "")
                self._send(200, hg.state(qs.get("pc", ""), qs.get("user", ""), int(ver) if ver.isdigit() else None))
            elif u.path == "/api/kids":
                self._send(200, hg.kids_for_lock_screen())
            elif u.path == "/api/request":
                self._send(200, hg.request_status(int(qs.get("id", "0"))))
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path.startswith("/admin"):
                self._admin("POST")
                return
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
                self._send(200, hg.login(pc, str(body.get("username", "")), str(body.get("password", "")),
                                         str(body.get("note", ""))))
            elif path == "/api/rerequest":
                self._send(200, hg.rerequest(pc, str(body.get("note", ""))))
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
            elif path == "/api/apps":
                apps = body.get("apps", [])
                self._send(200, hg.report_apps(pc, apps if isinstance(apps, list) else []))
            elif path == "/api/activity":
                self._send(200, hg.report_activity(pc, str(body.get("what", ""))))
            elif path == "/api/notice":
                hg.notify(str(body.get("text", ""))[:500] or f"הודעה מ-{pc}")
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
    hg.set_menus()

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

    def auditor():
        """Every half hour: are the bot's messages still in the parents' chats?"""
        while True:
            time.sleep(1800)
            try:
                hg.audit()
            except Exception:
                log.exception("audit failed")

    threading.Thread(target=auditor, daemon=True).start()

    def learner():
        """Every 15 minutes: learning goals met, and the evening summary."""
        while True:
            time.sleep(900)
            try:
                lg = hg.learning()
                if lg:
                    lg.tick()
            except Exception:
                log.exception("learning goals failed")

    threading.Thread(target=learner, daemon=True).start()

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
