"""Learning goals from the family's "לימודים" app (oritre/english-app), reported by the bot.

The app syncs every learner's sessions (active time), answers and lessons to
Firestore under families/<code>. Parents set goals per learner in the app's
parents' area (profile.goals). Every few minutes this module reads that data
and sends the parents:
  * a message the moment a goal is met (once per goal per day / week),
  * an evening summary per learner: active minutes per tab, quality, goals,
  * on Sunday's summary, also last week's weekly goals.
Nothing is sent from Friday afternoon to Saturday night.

The rules mirror js/insights.js in the app; keep the two in step.
"""
from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta

log = logging.getLogger("homeguard.learning")

API_KEY = "AIzaSyA3dpj8qdE8UcQ8MooMoC2waaeOOrTzch4"  # the app's public web key (also in its firebaseConfig.js)
PROJECT = "projects/english-app-94b40/databases/(default)/documents"
BASE = f"https://firestore.googleapis.com/v1/{PROJECT}"

SUBJECTS = [("english", "🔤", "אנגלית"), ("think", "🧠", "חשיבה ומדעים"), ("know", "🌍", "ידע כללי")]
SUBJ = {s: (i, n) for s, i, n in SUBJECTS}
RIGHT = {"correct", "typo"}
CHOICE = {"choose", "pick", "mcq", "fill_blank", "match_pairs", "order", "buckets"}
TYPED = {"translate_he_en", "translate_en_he", "listen_type", "listen_translate", "spell", "speak"}
MIN_FOR_QUALITY = 8


# ---- Firestore REST

def _val(v):
    (k, x), = v.items()
    if k == "integerValue":
        return int(x)
    if k == "doubleValue":
        return float(x)
    if k == "nullValue":
        return None
    if k == "mapValue":
        return {a: _val(b) for a, b in x.get("fields", {}).items()}
    if k == "arrayValue":
        return [_val(b) for b in x.get("values", [])]
    return x


def _get(url: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"} if data else {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def _query(code: str, store: str, field: str, value: dict) -> list[dict]:
    """Records of one store where field >= value. Firestore counts one read per record
    returned (and one for an empty answer), so the bot only ever asks for what's new."""
    body = {"structuredQuery": {
        "from": [{"collectionId": store}],
        "where": {"fieldFilter": {"field": {"fieldPath": field}, "op": "GREATER_THAN_OR_EQUAL", "value": value}},
    }}
    rows = _get(f"{BASE}/families/{code}:runQuery?key={API_KEY}", body)
    return [{k: _val(v) for k, v in r["document"].get("fields", {}).items()} for r in rows if "document" in r]


# Devices stamp updated_at with their own clocks; an hour of overlap covers clocks that are a bit off.
OVERLAP_MS = 3600 * 1000
KEEP_DAYS = 21


class FamilyCache:
    """A copy of the family's learning data in the bot's database, refreshed incrementally:
    the first time, the last three weeks; after that, only records changed since the last look."""

    def __init__(self, db, code: str):
        self.db = db
        self.code = code
        db.x("CREATE TABLE IF NOT EXISTS learn_docs (store TEXT, id TEXT, date TEXT, doc TEXT, PRIMARY KEY (store, id))")

    def refresh(self, today: str) -> int:
        since = (date.fromisoformat(today) - timedelta(days=KEEP_DAYS)).isoformat()
        n = 0
        for store in ("profiles", "results", "attempts"):
            key = f"learn_seen:{self.code}:{store}"
            seen = int(self.db.setting(key, "0") or 0)
            if seen:
                docs = _query(self.code, store, "updated_at", {"integerValue": str(seen - OVERLAP_MS)})
            elif store == "profiles":
                docs = _query(self.code, store, "updated_at", {"integerValue": "0"})
            else:
                docs = _query(self.code, store, "date", {"stringValue": since})
            for d in docs:
                if store == "attempts" and d.get("type") == "talk":
                    continue  # transcripts aren't needed here
                if store == "attempts":
                    d["taps"] = [t for t in d.get("taps") or [] if t.get("k") == "choice"]  # all the guess check needs
                self.db.x("INSERT OR REPLACE INTO learn_docs (store, id, date, doc) VALUES (?,?,?,?)",
                          (store, str(d.get("id")), d.get("date", ""), json.dumps(d, ensure_ascii=False)))
                seen = max(seen, int(d.get("updated_at") or 0))
            if seen:
                self.db.set_setting(key, str(seen))
            n += len(docs)
        self.db.x("DELETE FROM learn_docs WHERE store='attempts' AND date < ?", (since,))
        return n

    def load(self, today: str) -> dict:
        self.refresh(today)
        rows = {s: [json.loads(r["doc"]) for r in self.db.q("SELECT doc FROM learn_docs WHERE store=?", (s,))]
                for s in ("profiles", "results", "attempts")}
        return {
            "profiles": rows["profiles"], "results": rows["results"],
            "sessions": [a for a in rows["attempts"] if a.get("type") == "session"],
            "attempts": [a for a in rows["attempts"] if a.get("type") not in ("session", "talk")],
        }


# ---- the same rules as js/insights.js

def subject_of(lesson_id) -> str:
    i = str(lesson_id or "")
    return "know" if i.startswith("k-") else "think" if i.startswith(("t-", "tp-")) else "english"


def week_start(today: str) -> str:
    d = date.fromisoformat(today)
    return (d - timedelta(days=(d.weekday() + 1) % 7)).isoformat()  # Sunday


def period_range(period: str, today: str) -> tuple[str, str]:
    if period == "day":
        return today, today
    start = date.fromisoformat(week_start(today))
    if period == "lastweek":
        start -= timedelta(days=7)
    return start.isoformat(), (start + timedelta(days=6)).isoformat()


def guess_ms(t: str) -> int:
    return 3000 if t == "read" else 1500 if t in CHOICE else 1200


def is_guess(a: dict) -> bool:
    if a.get("type") in TYPED or a.get("outcome") == "skipped":
        return False
    if a.get("outcome") == "wrong" and (a.get("ms") or 0) < guess_ms(a.get("type")):
        return True
    return sum(1 for t in a.get("taps") or [] if t.get("k") == "choice") >= 3


def quality_score(x: dict):
    if x["items"] < MIN_FOR_QUALITY:
        return None
    parts = [(x["first_try"], .45), (None if x["guess_share"] is None else 1 - x["guess_share"], .25),
             (x["focus"], .15), (1 if x["fix_rate"] is None else x["fix_rate"], .15)]
    parts = [(v, k) for v, k in parts if v is not None]
    w = sum(k for _, k in parts)
    return round(100 * sum(v * k for v, k in parts) / w)


def insights(data: dict, pid: str, rng: tuple[str, str], subject: str = "all") -> dict:
    lo, hi = rng

    def pick(rows):
        return [r for r in rows if r.get("profile_id") == pid and lo <= r.get("date", "") <= hi
                and (subject == "all" or subject_of(r.get("lesson_id")) == subject)]

    sessions = pick(data["sessions"])
    answers = [a for a in pick(data["attempts"]) if a.get("outcome") != "skipped"]
    results = pick(data["results"])
    active = sum(s.get("active_s") or 0 for s in sessions)
    opened = sum(s.get("open_s") or 0 for s in sessions)
    groups: dict = {}
    for a in sorted(answers, key=lambda a: a.get("at") or 0):
        groups.setdefault((a.get("sid") or a.get("date"), a.get("lesson_id"), a.get("exercise_id")), []).append(a.get("outcome"))
    items = list(groups.values())
    missed = [g for g in items if g[0] not in RIGHT]
    fixed = [g for g in missed if any(o in RIGHT or o == "retry" for o in g)]
    first_done: dict = {}
    for r in sorted((r for r in data["results"] if r.get("profile_id") == pid), key=lambda r: r.get("date", "")):
        first_done.setdefault(r.get("lesson_id"), r.get("id"))
    practice = [r for r in results if str(r.get("lesson_id")).startswith("tp-")]
    fresh = [r for r in results if not str(r.get("lesson_id")).startswith("tp-") and first_done.get(r.get("lesson_id")) == r.get("id")]
    x = {
        "active_min": active / 60, "open_min": opened / 60,
        "focus": active / opened if opened >= 60 else None,
        "items": len(items),
        "first_try": (len(items) - len(missed)) / len(items) if items else None,
        "fix_rate": len(fixed) / len(missed) if missed else None,
        "guess_share": sum(1 for a in answers if is_guess(a)) / len(answers) if answers else None,
        "new_lessons": len(fresh), "mastered": sum(1 for r in fresh if (r.get("accuracy") or 0) >= 80),
        "progress": len(fresh) + len(practice),
    }
    x["quality"] = quality_score(x)
    return x


KIND_VALUE = {
    "minutes": lambda x: round(x["active_min"]),
    "lessons": lambda x: x["progress"],
    "quality": lambda x: x["quality"],
}


def goal_label(g: dict) -> str:
    per = "ביום" if g.get("period") == "day" else "בשבוע"
    subj = f" ב{SUBJ[g['subject']][1]}" if g.get("subject") in SUBJ else ""
    if g["kind"] == "quality":
        return f"ציון איכות {g['target']} לפחות {per}{subj}"
    unit = "דק'" if g["kind"] == "minutes" else "שיעורים"
    return f"{g['target']} {unit} {per}{subj}"


def goal_status(g: dict, data: dict, pid: str, day: str) -> dict:
    rng = period_range(g.get("period", "day"), day)
    x = insights(data, pid, rng, g.get("subject") or "all")
    actual = KIND_VALUE[g["kind"]](x)
    return {"goal": g, "range": rng, "actual": actual, "met": actual is not None and actual >= g["target"]}


def fmt_pct(v) -> str:
    return "—" if v is None else f"{round(v * 100)}%"


def kid_summary(p: dict, data: dict, today: str, with_last_week: bool = False) -> str:
    pid = p["id"]
    day = insights(data, pid, (today, today))
    lines = [f"{p.get('avatar', '')} {p.get('name', '')}: {round(day['active_min'])} דק' פעילות היום"
             + (f", איכות {day['quality']}" if day["quality"] is not None else "")]
    per = [f"{icon} {round(insights(data, pid, (today, today), s)['active_min'])}" for s, icon, _ in SUBJECTS]
    lines.append("   " + " · ".join(per) + (f" · נכון בניסיון ראשון {fmt_pct(day['first_try'])}" if day["items"] else ""))
    if day["guess_share"] and day["guess_share"] >= .2 and day["items"] >= 10:
        lines.append(f"   ⚠️ {fmt_pct(day['guess_share'])} מהתשובות נראות כמו ניחוש")
    for g in p.get("goals") or []:
        st = goal_status(g, data, pid, today)
        mark = "✅" if st["met"] else ("⏳" if g.get("period") == "week" else "❌")
        lines.append(f"   {mark} {goal_label(g)}: {'—' if st['actual'] is None else st['actual']}")
    if with_last_week:
        prev = (date.fromisoformat(week_start(today)) - timedelta(days=1)).isoformat()
        weekly = [g for g in p.get("goals") or [] if g.get("period") == "week"]
        if weekly:
            lines.append("   בשבוע שעבר: " + ", ".join(
                f"{'✅' if goal_status(g, data, pid, prev)['met'] else '❌'} {goal_label(g)}" for g in weekly))
    return "\n".join(lines)


def is_shabbat(now: datetime) -> bool:
    """Friday from 15:00 until Saturday 21:00: the bot stays quiet."""
    wd = now.weekday()  # Mon=0 .. Fri=4, Sat=5
    return (wd == 4 and now.hour >= 15) or (wd == 5 and now.hour < 21)


class LearningGoals:
    """Owned by HomeGuard; `tick()` runs every few minutes from a thread."""

    def __init__(self, hg, code: str, report_hour: int = 20, loader=None):
        self.hg = hg
        self.code = code
        self.report_hour = report_hour
        self.loader = loader or (lambda code, today: FamilyCache(hg.db, code).load(today))

    def _once(self, key: str) -> bool:
        """True the first time a key is seen (kept in the bot's settings table)."""
        k = f"learn:{key}"
        if self.hg.db.setting(k):
            return False
        self.hg.db.set_setting(k, "1")
        return True

    def summary_text(self, today: str, data: dict | None = None) -> str:
        data = data or self.loader(self.code, today)
        sunday = date.fromisoformat(today).weekday() == 6
        kids = [p for p in data["profiles"] if p.get("goals") or any(s.get("profile_id") == p["id"] for s in data["sessions"])]
        if not kids:
            return "📚 עוד אין נתוני למידה מהאפליקציה."
        return "📚 סיכום למידה להיום\n\n" + "\n\n".join(kid_summary(p, data, today, sunday) for p in kids)

    def tick(self, now: datetime | None = None) -> None:
        now = now or datetime.now()
        # Quiet on Shabbat and at night (the kids don't learn then, and it saves cloud reads).
        if is_shabbat(now) or not 7 <= now.hour < 23:
            return
        today = now.date().isoformat()
        data = self.loader(self.code, today)
        for p in data["profiles"]:
            for g in p.get("goals") or []:
                st = goal_status(g, data, p["id"], today)
                if st["met"] and self._once(f"met:{p['id']}:{g.get('id')}:{st['range'][0]}"):
                    self.hg.notify(f"🎯 יעד הושג! {p.get('avatar', '')} {p.get('name', '')}: {goal_label(g)} ({st['actual']})")
        if now.hour >= self.report_hour and self._once(f"summary:{today}"):
            self.hg.notify(self.summary_text(today, data))
