"""Learning goals from the לימודים app: the rules (same as js/insights.js) and the bot messages.

    python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))

import homeguard_server as hs  # noqa: E402
import learning_goals as lg  # noqa: E402
from test_homeguard import FakeTelegram  # noqa: E402

T = "2026-10-27"  # a Tuesday
N = iter(range(10 ** 6))


def sess(lesson, active, opened, day=T, finished=True):
    return {"profile_id": "k1", "type": "session", "lesson_id": lesson, "date": day, "active_s": active, "open_s": opened, "finished": finished}


def ans(lesson, ex, outcome, ms=4000, **kw):
    return dict({"profile_id": "k1", "lesson_id": lesson, "exercise_id": ex, "type": "choose", "outcome": outcome,
                 "ms": ms, "date": T, "at": next(N), "sid": "s1"}, **kw)


DATA = {
    "profiles": [{"id": "k1", "name": "רעי", "avatar": "🐸", "goals": [
        {"id": "g1", "kind": "minutes", "subject": "all", "target": 15, "period": "day"},
        {"id": "g2", "kind": "lessons", "subject": "think", "target": 3, "period": "week"}]}],
    "sessions": [sess("u1-l1", 600, 900), sess("t-a-1", 300, 300), sess("k-x-1", 120, 600, finished=False)],
    "attempts": [ans("u1-l1", "e1", "correct"), ans("u1-l1", "e2", "wrong", 500), ans("u1-l1", "e2", "correct"),
                 ans("u1-l1", "e3", "wrong"), ans("t-a-1", "q1", "correct", 3000, type="mcq")],
    "results": [{"id": "r0", "profile_id": "k1", "lesson_id": "u1-l1", "date": "2026-10-01", "accuracy": 60},
                {"id": "r1", "profile_id": "k1", "lesson_id": "u1-l1", "date": T, "accuracy": 90},
                {"id": "r2", "profile_id": "k1", "lesson_id": "t-a-1", "date": T, "accuracy": 85},
                {"id": "r3", "profile_id": "k1", "lesson_id": "tp-a", "date": T, "accuracy": 70}],
}


class RulesTest(unittest.TestCase):
    def test_same_numbers_as_the_app(self):
        # Mirrors the "insights" test in english-app/tests/logic.test.mjs.
        x = lg.insights(DATA, "k1", (T, T))
        self.assertEqual(round(x["active_min"]), 17)
        self.assertEqual(x["items"], 4)
        self.assertEqual(x["first_try"], .5)
        self.assertEqual(x["fix_rate"], .5)
        self.assertEqual(x["guess_share"], 1 / 5)
        self.assertEqual(x["new_lessons"], 1)
        self.assertEqual(x["progress"], 2)
        self.assertIsNone(x["quality"])
        self.assertEqual(lg.insights(DATA, "k1", (T, T), "know")["active_min"], 2)

    def test_periods_and_subjects(self):
        self.assertEqual(lg.period_range("week", "2026-10-28"), ("2026-10-25", "2026-10-31"))
        self.assertEqual(lg.period_range("lastweek", "2026-10-28"), ("2026-10-18", "2026-10-24"))
        self.assertEqual(lg.week_start("2026-10-25"), "2026-10-25")
        self.assertEqual(lg.subject_of("tp-frac"), "think")
        self.assertEqual(lg.subject_of("coach-1"), "english")
        self.assertEqual(lg.quality_score({"items": 10, "first_try": 1, "guess_share": 0, "focus": 1, "fix_rate": None}), 100)

    def test_shabbat_is_quiet(self):
        self.assertTrue(lg.is_shabbat(datetime(2026, 10, 30, 16)))   # Friday afternoon
        self.assertTrue(lg.is_shabbat(datetime(2026, 10, 31, 12)))   # Saturday
        self.assertFalse(lg.is_shabbat(datetime(2026, 10, 31, 21)))  # Saturday night
        self.assertFalse(lg.is_shabbat(datetime(2026, 10, 27, 20)))


class BotTest(unittest.TestCase):
    def setUp(self):
        cfg = dict(hs.DEFAULT_CONFIG, parent_chat_ids=[1], db=os.path.join(tempfile.mkdtemp(), "db"))
        self.tg = FakeTelegram()
        self.hg = hs.HomeGuard(cfg, hs.DB(cfg["db"]), self.tg)

    def cmd(self, text):
        self.hg.handle_update({"message": {"chat": {"id": 1}, "from": {"first_name": "אורי"}, "text": text}})
        return self.tg.sent()[-1]["text"]

    def test_goal_met_once_and_evening_summary_once(self):
        self.assertIn("עוד לא מחובר", self.cmd("/learn"))
        self.assertIn("מחובר", self.cmd("/learn code ab3d-ef7h"))
        self.assertEqual(self.hg.db.setting("learn_code"), "AB3DEF7H")
        g = self.hg.learning()
        g.loader = lambda code, today: DATA
        before = len(self.tg.sent())
        g.tick(datetime(2026, 10, 27, 15))
        sent = [m["text"] for m in self.tg.sent()[before:]]
        self.assertEqual(len(sent), 1)
        self.assertIn("יעד הושג", sent[0])
        self.assertIn("15 דק' ביום", sent[0])
        g.tick(datetime(2026, 10, 27, 15, 5))  # nothing new
        g.tick(datetime(2026, 10, 27, 20))  # the evening summary
        g.tick(datetime(2026, 10, 27, 21))
        sent = [m["text"] for m in self.tg.sent()[before:]]
        self.assertEqual(len(sent), 2)
        self.assertIn("סיכום למידה", sent[1])
        self.assertIn("🔤 10 · 🧠 5 · 🌍 2", sent[1])
        self.assertIn("⏳ 3 שיעורים בשבוע בחשיבה ומדעים: 2", sent[1])  # a new lesson and a practice round


if __name__ == "__main__":
    unittest.main()


class CacheTest(unittest.TestCase):
    def test_first_three_weeks_then_only_changes(self):
        db = hs.DB(os.path.join(tempfile.mkdtemp(), "db"))
        calls = []
        remote = {"profiles": [{"id": "k1", "updated_at": 100}],
                  "results": [{"id": "r1", "date": T, "updated_at": 200}],
                  "attempts": [dict(sess("u1-l1", 60, 60), id="s1", updated_at=300), dict(ans("u1-l1", "e1", "correct"), id="a1", updated_at=310)]}

        def fake(code, store, field, value):
            calls.append((store, field, list(value.values())[0]))
            return remote[store] if len(calls) <= 3 else [r for r in remote[store] if r["updated_at"] >= int(list(value.values())[0])]

        orig, lg._query = lg._query, fake
        try:
            cache = lg.FamilyCache(db, "AB3DEF7H")
            data = cache.load(T)
            self.assertEqual(calls[:3], [("profiles", "updated_at", "0"), ("results", "date", "2026-10-06"), ("attempts", "date", "2026-10-06")])
            self.assertEqual((len(data["sessions"]), len(data["attempts"]), len(data["results"])), (1, 1, 1))
            remote["attempts"].append(dict(ans("u1-l1", "e2", "wrong"), id="a2", updated_at=5_000_000))
            data = cache.load(T)
            self.assertEqual(calls[5], ("attempts", "updated_at", str(310 - lg.OVERLAP_MS)))
            self.assertEqual(len(data["attempts"]), 2)
        finally:
            lg._query = orig
