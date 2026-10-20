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
                """
            )
            for table, col, decl in (("kids", "pw_plain", "TEXT"),
                                     ("kids", "role", "TEXT NOT NULL DEFAULT 'kid'"),
                                     ("kids", "must_set", "INTEGER NOT NULL DEFAULT 0"),
                                     ("kids", "disabled", "INTEGER NOT NULL DEFAULT 0"),
                                     ("sites", "expires", "REAL"),
                                     ("sites", "session_id", "INTEGER"),
                                     ("requests", "detail", "TEXT"),
                                     ("pcs", "version", "INTEGER")):
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


# ------------------------------------------------------------------------- Core

class HomeGuard:
    def __init__(self, cfg: dict, db: DB, tg: Telegram | None):
        self.cfg = cfg
        self.db = db
        self.tg = tg
        self.parents = [int(c) for c in cfg["parent_chat_ids"]]
        self.awaiting_time: dict[int, str] = {}

    # ---- messaging helpers
    def notify(self, text: str, keyboard=None) -> list[list[int]]:
        sent = []
        if not self.tg:
            log.info("NOTIFY: %s", text)
            return sent
        for chat in self.parents:
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
            self.notify(f"🔓 {kid['display']} נכנס/ה למחשב '{pc}' עם חשבון מאסטר ({hhmm(now)})")
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
        kb = []
        modes = self.login_modes()
        for mode in modes:
            options = list(self.cfg["durations"]) + ([0] if mode != "offline" else [])
            kb.append([{"text": f"{MODE_SHORT[mode]} {fmt_min(m) if m else '♾️'}",
                        "callback_data": f"ap:{rid}:{mode}:{m}"} for m in options])
        kb.append([{"text": f"⏱ זמן אחר {MODE_SHORT[mode]}", "callback_data": f"cu:{rid}:{mode}"}
                   for mode in modes])
        kb.append([{"text": "❌ לא עכשיו", "callback_data": f"dn:{rid}"}])
        text = (head + (f"\n💬 {note}" if note else "") + "\n" +
                " · ".join(f"{MODE_SHORT[m]} {MODE_NAMES[m]}" for m in modes) + " · ♾️ ללא הגבלת זמן")
        msgs = self.notify(text, kb)
        self.db.x("UPDATE requests SET messages=? WHERE id=?", (json.dumps(msgs), rid))
        return rid

    def full_internet_allowed(self) -> bool:
        return self.db.setting("full_internet", "0") == "1"

    def login_modes(self) -> tuple:
        """Default: only approved sites (or no internet). Full internet only after /fullnet on."""
        return ("allowlist", "full", "offline") if self.full_internet_allowed() else ("allowlist", "offline")

    def passwords_required(self) -> bool:
        return self.db.setting("require_password", "0") == "1"

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
                "apps_nonet": [r["pkg"] for r in self.db.q("SELECT pkg FROM apps WHERE rule='nonet'")],
                "update_seq": int(self.db.setting("update_seq", "0")),
                "server_time": now}

    # ---- apps on Android devices
    APP_RULES = {"ok": "✅ מותרת", "nonet": "📵 בלי אינטרנט", "blocked": "⛔ חסומה"}

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
                "✅ מותרת · 📵 בלי אינטרנט (חוסם לפי שמות אתרים) · ⛔ חסומה (לא נפתחת בכלל)" + more), kb

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
            self.send(chat, "⏱ כמה זמן? כתבו מספר דקות (45), שעות (2 שעות / 1.5ש) או עד איזו שעה (18:30)",
                      {"force_reply": True})
        return "כתבו את הזמן"

    def answer_custom_time(self, chat: int, text: str) -> None:
        minutes = parse_duration(text)
        if not minutes:
            self.reply(chat, "לא הבנתי 🙂 למשל: 45, 2 שעות, 1.5ש או 18:30")
            return
        data = self.awaiting_time.pop(chat)
        parts = data.split(":")
        if parts[0] == "cu":
            result = self.decide(f"ap:{parts[1]}:{parts[2]}:{minutes}", "הורה")
        elif parts[0] == "cs":
            result = self.decide(f"st:{parts[1]}:{minutes}", "הורה")
        else:
            result = self.decide(f"ex:{parts[1]}:{minutes}", "הורה")
        self.reply(chat, f"{result} ({fmt_min(minutes)})")

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
/apps [שם] – האפליקציות במכשירים: ✅ מותרת · 📵 בלי אינטרנט · ⛔ חסומה. אפליקציה חדשה שמותקנת מגיעה לכאן עם כפתורים
/update – לעדכן עכשיו את האפליקציה במכשירים (בלי כבל; הם בודקים לבד גם כל 6 שעות)

📜 היסטוריה:
/history [מספר] – האירועים האחרונים, גם אם ההודעות נמחקו מהצ'אט
/audit – בדיקת התאמה עכשיו: האם נמחקו הודעות של הבוט (נבדק גם אוטומטית כל חצי שעה)

👧 חשבונות:
/passwords on|off – כניסה עם סיסמה או רק בחירת שם (ברירת מחדל: בלי סיסמה)
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
                ver = qs.get("ver", "")
                self._send(200, hg.state(qs.get("pc", ""), qs.get("user", ""), int(ver) if ver.isdigit() else None))
            elif u.path == "/api/kids":
                self._send(200, hg.kids_for_lock_screen())
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
    tg.call("setMyCommands", commands=[
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
        {"command": "history", "description": "היסטוריית אירועים"},
        {"command": "audit", "description": "בדיקה אם נמחקו הודעות"},
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

    def auditor():
        """Every half hour: are the bot's messages still in the parents' chats?"""
        while True:
            time.sleep(1800)
            try:
                hg.audit()
            except Exception:
                log.exception("audit failed")

    threading.Thread(target=auditor, daemon=True).start()

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
