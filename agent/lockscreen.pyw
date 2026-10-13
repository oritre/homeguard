"""HomeGuard lock screen: runs in the logged-in user's session (scheduled task at logon).

Covers every monitor until a parent approves the kid's request in Telegram, then
shrinks to a small timer with "more time" and "I'm done" buttons, and locks
again when the time is up. Talks only to the local agent on 127.0.0.1.
"""
from __future__ import annotations

import json
import sys
import tkinter as tk
import urllib.request

AGENT = "http://127.0.0.1:8765"
BG = "#1d2433"
FG = "#f2f4f8"
ACCENT = "#4f8cff"
FONT = "Segoe UI"


def call(method: str, path: str, body: dict | None = None) -> dict | None:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(AGENT + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except Exception:  # noqa: BLE001
        return None


def single_instance() -> bool:
    if sys.platform != "win32":
        return True
    import ctypes
    ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\HomeGuardLockScreen")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def virtual_screen(root: tk.Tk) -> tuple[int, int, int, int]:
    if sys.platform == "win32":
        import ctypes
        m = ctypes.windll.user32.GetSystemMetrics
        return m(76), m(77), m(78), m(79)  # x, y, width, height across all monitors
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()


def mmss(sec: int) -> str:
    sec = max(0, sec)
    h, rem = divmod(sec, 3600)
    return f"{h}:{rem // 60:02d}:{rem % 60:02d}" if h else f"{rem // 60}:{rem % 60:02d}"


class LockScreen:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HomeGuard")
        self.root.configure(bg=BG)
        self.root.overrideredirect(True)
        self.root.protocol("WM_DELETE_WINDOW", lambda: None)
        x, y, w, h = virtual_screen(self.root)
        self.full_geometry = f"{w}x{h}+{x}+{y}"
        self.root.geometry(self.full_geometry)
        self.root.attributes("-topmost", True)
        self.root.bind_all("<Alt-F4>", lambda e: "break")

        self.state = "locked"  # locked | waiting | unlocked
        self.request_id = None
        self.remaining = 0
        self.warned = set()

        self.frame = tk.Frame(self.root, bg=BG)
        self.frame.place(relx=0.5, rely=0.5, anchor="center")
        self.title = tk.Label(self.frame, text="🛡️ המחשב נעול", font=(FONT, 32, "bold"), fg=FG, bg=BG)
        self.title.pack(pady=(0, 6))
        self.subtitle = tk.Label(self.frame, text="הכניסו שם משתמש וסיסמה, ואבא או אמא יאשרו בטלגרם",
                                 font=(FONT, 14), fg="#aab3c5", bg=BG)
        self.subtitle.pack(pady=(0, 24))

        self.form = tk.Frame(self.frame, bg=BG)
        self.form.pack()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        for label, var, show in (("שם משתמש", self.user_var, ""), ("סיסמה", self.pass_var, "●")):
            tk.Label(self.form, text=label, font=(FONT, 13), fg=FG, bg=BG, anchor="e").pack(fill="x")
            e = tk.Entry(self.form, textvariable=var, show=show, font=(FONT, 16), width=22, justify="center",
                         relief="flat")
            e.pack(pady=(2, 12), ipady=6)
            e.bind("<Return>", lambda ev: self.login())
            if not show:
                self.user_entry = e
        self.login_btn = tk.Button(self.form, text="בקשו כניסה", font=(FONT, 15, "bold"), bg=ACCENT, fg="white",
                                   activebackground=ACCENT, relief="flat", width=18, command=self.login)
        self.login_btn.pack(pady=(8, 0), ipady=4)

        self.cancel_btn = tk.Button(self.frame, text="ביטול", font=(FONT, 13), bg="#39445a", fg=FG,
                                    relief="flat", width=12, command=self.cancel)
        self.message = tk.Label(self.frame, text="", font=(FONT, 13), fg="#ffb4a8", bg=BG)
        self.message.pack(pady=(16, 0))

        # Small timer window shown while unlocked.
        self.timer = tk.Toplevel(self.root)
        self.timer.overrideredirect(True)
        self.timer.attributes("-topmost", True)
        self.timer.configure(bg=BG)
        self.timer_label = tk.Label(self.timer, text="", font=(FONT, 14, "bold"), fg=FG, bg=BG, padx=10)
        self.timer_label.pack(side="right")
        tk.Button(self.timer, text="עוד זמן", font=(FONT, 10), relief="flat", bg="#39445a", fg=FG,
                  command=self.ask_more).pack(side="right", padx=2, pady=4)
        tk.Button(self.timer, text="סיימתי", font=(FONT, 10), relief="flat", bg="#39445a", fg=FG,
                  command=self.done).pack(side="right", padx=(6, 2), pady=4)
        self.timer.withdraw()
        self._drag = (0, 0)
        self.timer_label.bind("<Button-1>", lambda e: setattr(self, "_drag", (e.x, e.y)))
        self.timer_label.bind("<B1-Motion>", self._move_timer)

        self.root.after(200, self.keep_on_top)
        self.root.after(300, self.poll)

    # ---------------------------------------------------------------- display
    def keep_on_top(self):
        if self.state != "unlocked":
            self.root.deiconify()
            self.root.geometry(self.full_geometry)
            self.root.lift()
            self.root.attributes("-topmost", True)
            try:
                self.root.focus_force()
            except tk.TclError:
                pass
        else:
            self.timer.lift()
        self.root.after(400, self.keep_on_top)

    def _move_timer(self, e):
        x = self.timer.winfo_x() + e.x - self._drag[0]
        y = self.timer.winfo_y() + e.y - self._drag[1]
        self.timer.geometry(f"+{x}+{y}")

    def show_locked(self, note: str = ""):
        self.state = "locked"
        self.request_id = None
        self.timer.withdraw()
        self.title.config(text="🛡️ המחשב נעול")
        self.subtitle.config(text="הכניסו שם משתמש וסיסמה, ואבא או אמא יאשרו בטלגרם")
        self.cancel_btn.pack_forget()
        self.form.pack(before=self.message)
        self.login_btn.config(state="normal")
        self.pass_var.set("")
        self.message.config(text=note)
        self.root.deiconify()
        self.user_entry.focus_set()

    def show_waiting(self, display: str):
        self.state = "waiting"
        self.form.pack_forget()
        self.title.config(text=f"שלום {display} 👋")
        self.subtitle.config(text="שלחנו בקשה לאבא ואמא בטלגרם. מחכים לאישור...")
        self.message.config(text="")
        self.cancel_btn.pack(before=self.message, pady=(10, 0))

    def show_unlocked(self, session: dict):
        self.state = "unlocked"
        self.warned = set()
        self.root.withdraw()
        w = self.root.winfo_screenwidth()
        self.timer.deiconify()
        self.timer.update_idletasks()
        self.timer.geometry(f"+{w - self.timer.winfo_width() - 24}+12")

    # ---------------------------------------------------------------- actions
    def login(self):
        user, pw = self.user_var.get().strip(), self.pass_var.get()
        if not user or not pw:
            self.message.config(text="צריך שם משתמש וסיסמה")
            return
        self.login_btn.config(state="disabled")
        res = call("POST", "/login", {"username": user, "password": pw})
        self.login_btn.config(state="normal")
        if not res:
            self.message.config(text="אין חיבור לשומר המחשב. נסו שוב עוד רגע.")
        elif not res.get("ok"):
            self.message.config(text=res.get("error", "שגיאה"))
            self.pass_var.set("")
        else:
            self.request_id = res["request_id"]
            self.show_waiting(res.get("display", user))

    def cancel(self):
        if self.request_id:
            call("POST", "/cancel", {"request_id": self.request_id})
        self.show_locked()

    def ask_more(self):
        res = call("POST", "/extend", {})
        self.timer_label.config(text="ביקשנו עוד זמן ⏳" if res and res.get("ok") else "אין חיבור")

    def done(self):
        call("POST", "/end", {})
        self.show_locked("להתראות! 👋")

    # ------------------------------------------------------------------ poll
    def poll(self):
        st = call("GET", "/state")
        if st is None:
            # Agent not reachable: stay locked.
            if self.state == "unlocked":
                self.show_locked("אין חיבור לשומר המחשב")
        elif st.get("exempt"):
            self.root.destroy()  # a parent is logged in
            return
        else:
            session = st.get("session")
            if session and self.state != "unlocked":
                self.show_unlocked(session)
            elif not session and self.state == "unlocked":
                self.show_locked("⏰ הזמן נגמר")
            elif self.state == "waiting" and self.request_id:
                r = call("GET", f"/request?id={self.request_id}") or {}
                if r.get("status") == "denied":
                    self.show_locked("אבא/אמא אמרו לא עכשיו 🙁")
                elif r.get("status") == "cancelled":
                    self.show_locked()
            if session and self.state == "unlocked":
                self.update_timer(session, st.get("extend_pending"))
        self.root.after(2000, self.poll)

    def update_timer(self, session: dict, extend_pending: bool):
        rem = session["remaining"]
        text = f"⏱ {mmss(rem)}"
        if extend_pending:
            text += "  (ביקשנו עוד זמן)"
        color = BG
        if rem <= 60:
            color = "#b3261e"
        elif rem <= 300:
            color = "#b26a00"
        for warn_at in (300, 60):
            if rem <= warn_at and warn_at not in self.warned:
                self.warned.add(warn_at)
                self.timer.lift()
        self.timer.configure(bg=color)
        self.timer_label.config(text=text, bg=color)

    def run(self):
        self.show_locked()
        self.root.mainloop()


if __name__ == "__main__":
    if single_instance():
        LockScreen().run()
