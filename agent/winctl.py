"""Windows-specific controls: who is logged in, firewall, DNS settings, logoff.

Every function is a no-op (with a log line) off Windows so the agent's logic can
be tested on any machine.
"""
from __future__ import annotations

import logging
import subprocess
import sys

log = logging.getLogger("homeguard.win")
IS_WIN = sys.platform == "win32"
NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW

if IS_WIN:
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _wtsapi = ctypes.WinDLL("wtsapi32", use_last_error=True)
    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    _wtsapi.WTSQuerySessionInformationW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
        ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.DWORD)]
    _wtsapi.WTSLogoffSession.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL]
    _wtsapi.WTSQueryUserToken.argtypes = [wintypes.ULONG, ctypes.POINTER(wintypes.HANDLE)]
    _advapi.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
        wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p]
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _ntdll = ctypes.WinDLL("ntdll")
    _ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
    _ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    _wtsapi.WTSDisconnectSession.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL]


def run(cmd: list[str]) -> str:
    if not IS_WIN:
        log.info("[dry-run] %s", " ".join(cmd))
        return ""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, creationflags=NO_WINDOW, timeout=60)
        if p.returncode != 0:
            log.warning("%s -> %s %s", cmd[0], p.returncode, (p.stdout + p.stderr).strip()[:300])
        return p.stdout
    except Exception as e:  # noqa: BLE001
        log.warning("%s failed: %s", cmd, e)
        return ""


def powershell(script: str) -> str:
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])


# ------------------------------------------------------------ console session

def console_session() -> tuple[int | None, str]:
    """(session id, user name) of whoever sits at the physical screen; user '' if nobody."""
    if not IS_WIN:
        return None, ""
    sid = _kernel32.WTSGetActiveConsoleSessionId()
    if sid == 0xFFFFFFFF:
        return None, ""
    buf = wintypes.LPWSTR()
    size = wintypes.DWORD()
    if not _wtsapi.WTSQuerySessionInformationW(None, sid, 5, ctypes.byref(buf), ctypes.byref(size)):  # WTSUserName
        return sid, ""
    name = buf.value or ""
    _wtsapi.WTSFreeMemory(buf)
    return sid, name


def launch_in_session(session_id: int, cmdline: str, cwd: str) -> bool:
    """Start a program on a user's desktop (the agent runs as SYSTEM). Used to bring the lock screen up
    the moment a kid signs in, instead of waiting for the logon task, which can take several seconds."""
    if not IS_WIN or session_id is None:
        log.info("[dry-run] launch in session %s: %s", session_id, cmdline)
        return False

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
                    ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                    ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    token = wintypes.HANDLE()
    if not _wtsapi.WTSQueryUserToken(wintypes.ULONG(session_id), ctypes.byref(token)):
        log.warning("WTSQueryUserToken(%s) failed: %s", session_id, ctypes.get_last_error())
        return False
    env = ctypes.c_void_p()
    try:
        if not userenv.CreateEnvironmentBlock(ctypes.byref(env), token, False):
            env = ctypes.c_void_p()
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(si)
        si.lpDesktop = "winsta0\\default"
        pi = PROCESS_INFORMATION()
        flags = 0x00000400 | NO_WINDOW  # CREATE_UNICODE_ENVIRONMENT
        ok = _advapi.CreateProcessAsUserW(token, None, ctypes.create_unicode_buffer(cmdline), None, None, False,
                                          flags, env, cwd, ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            log.warning("CreateProcessAsUser failed: %s", ctypes.get_last_error())
            return False
        _kernel32.CloseHandle(pi.hThread)
        _kernel32.CloseHandle(pi.hProcess)
        return True
    finally:
        if env:
            userenv.DestroyEnvironmentBlock(env)
        _kernel32.CloseHandle(token)


def keep_wifi_connected() -> None:
    """With the internet blocked Windows may decide the Wi-Fi is useless and drop it (or hop to another
    saved network). Turn off that 'soft disconnect'."""
    if not IS_WIN:
        log.info("[dry-run] keep wifi connected")
        return
    import winreg
    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                              r"SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy") as k:
            winreg.SetValueEx(k, "fMinimizeConnections", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(k, "fSoftDisconnectConnections", 0, winreg.REG_DWORD, 0)
    except OSError as e:
        log.warning("wifi policy failed: %s", e)
    # The Wi-Fi also dropped by itself with the internet open: stop Windows powering the adapter down.
    out = powershell(
        "Get-NetAdapter -Physical | Where-Object { $_.NdisPhysicalMedium -eq 9 } | ForEach-Object { "
        "$pm = Get-NetAdapterPowerManagement -Name $_.Name; "
        "if ($pm.AllowComputerToTurnOffDevice -ne 'Disabled') { "
        "Set-NetAdapterPowerManagement -Name $_.Name -AllowComputerToTurnOffDevice Disabled -NoRestart; "
        "$_.InterfaceDescription + ': power saving turned off' } }").strip()
    if out:
        log.info("wifi %s", out.replace("\r", "").replace("\n", "; "))


def wifi_profiles() -> list[tuple[str, str]]:
    """Saved Wi-Fi networks as (name, 'auto'|'manual'), read from Windows' own profile files: `netsh wlan
    show ...` needs Location turned on, these files don't."""
    if not IS_WIN:
        return []
    import glob
    import os
    import xml.etree.ElementTree as ET
    out = []
    root = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Wlansvc", "Profiles",
                        "Interfaces", "*", "*.xml")
    for path in sorted(glob.glob(root), key=os.path.getmtime, reverse=True):
        try:
            tree = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            continue
        ns = {"w": tree.tag.split("}")[0].strip("{")} if tree.tag.startswith("{") else {}
        name = tree.findtext("w:name" if ns else "name", "", ns)
        mode = tree.findtext("w:connectionMode" if ns else "connectionMode", "", ns) or "manual"
        if name and all(name != n for n, _ in out):
            out.append((name, mode))
    return out


def wifi_set_auto(name: str) -> None:
    """Make Windows join this saved network by itself (it stops doing so after a manual disconnect)."""
    run(["netsh", "wlan", "set", "profileparameter", f"name={name}", "connectionmode=auto"])


def wifi_connect(name: str) -> str:
    if not IS_WIN:
        log.info("[dry-run] wifi connect %s", name)
        return ""
    try:
        p = subprocess.run(["netsh", "wlan", "connect", f"name={name}"], capture_output=True, text=True,
                           creationflags=NO_WINDOW, timeout=30)
        return f"{p.returncode} {(p.stdout + p.stderr).strip()[:200]}"
    except Exception as e:  # noqa: BLE001
        return f"failed: {e}"


def connected_networks() -> list[str]:
    """Names of the networks Windows is connected to right now (no Location needed)."""
    return [n.strip() for n in powershell("(Get-NetConnectionProfile).Name").splitlines() if n.strip()]


def logoff(session_id: int) -> None:
    log.warning("logging off session %s", session_id)
    if IS_WIN and session_id is not None:
        _wtsapi.WTSLogoffSession(None, session_id, False)


def disconnect(session_id: int) -> None:
    """Back to the Windows sign-in screen, leaving the user's session (and open programs) in place."""
    log.info("switching user: disconnecting session %s", session_id)
    if IS_WIN and session_id is not None:
        _wtsapi.WTSDisconnectSession(None, session_id, False)


def sessions() -> dict[int, str]:
    """Signed-in Windows sessions, {session id: user name}, connected or not."""
    if not IS_WIN:
        return {}

    class WTS_SESSION_INFOW(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("pWinStationName", wintypes.LPWSTR), ("State", ctypes.c_int)]

    buf = ctypes.POINTER(WTS_SESSION_INFOW)()
    count = wintypes.DWORD()
    if not _wtsapi.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(buf), ctypes.byref(count)):
        return {}
    ids = [buf[i].SessionId for i in range(count.value)]
    _wtsapi.WTSFreeMemory(buf)
    out = {}
    for sid in ids:
        name = wintypes.LPWSTR()
        size = wintypes.DWORD()
        if _wtsapi.WTSQuerySessionInformationW(None, sid, 5, ctypes.byref(name), ctypes.byref(size)):
            if name.value:
                out[sid] = name.value
            _wtsapi.WTSFreeMemory(name)
    return out


def session_processes(session_id: int, username: str) -> list[tuple[int, str]]:
    """(pid, program name) of everything `username` runs in that session."""
    want = user_sid(username)
    if not IS_WIN or not want:
        return []

    class WTS_PROCESS_INFOW(ctypes.Structure):
        _fields_ = [("SessionId", wintypes.DWORD), ("ProcessId", wintypes.DWORD),
                    ("pProcessName", wintypes.LPWSTR), ("pUserSid", ctypes.c_void_p)]

    buf = ctypes.POINTER(WTS_PROCESS_INFOW)()
    count = wintypes.DWORD()
    if not _wtsapi.WTSEnumerateProcessesW(None, 0, 1, ctypes.byref(buf), ctypes.byref(count)):
        return []
    out = []
    try:
        for i in range(count.value):
            p = buf[i]
            if p.SessionId != session_id or not p.pUserSid:
                continue
            s = wintypes.LPWSTR()
            if _advapi.ConvertSidToStringSidW(ctypes.c_void_p(p.pUserSid), ctypes.byref(s)):
                same = s.value == want
                _kernel32.LocalFree(s)
                if same:
                    out.append((p.ProcessId, p.pProcessName or ""))
    finally:
        _wtsapi.WTSFreeMemory(buf)
    return out


def suspend(pid: int, resume: bool = False) -> bool:
    """Freeze (or unfreeze) a whole program: it keeps its windows and work, but runs nothing, plays
    nothing and uses no network until it is unfrozen."""
    if not IS_WIN:
        return False
    h = _kernel32.OpenProcess(0x0800, False, pid)  # PROCESS_SUSPEND_RESUME
    if not h:
        return False
    try:
        fn = _ntdll.NtResumeProcess if resume else _ntdll.NtSuspendProcess
        return fn(h) == 0
    finally:
        _kernel32.CloseHandle(h)


def ensure_kid_account(username: str, display: str) -> bool:
    """A standard Windows account without a password for a kid (HomeGuard's approval is the lock).
    Returns True when it was created now."""
    if not IS_WIN or not username.isascii() or not username.replace("_", "").replace("-", "").isalnum():
        return False
    disp = display.replace("'", "''")
    out = powershell(
        f"if (-not (Get-LocalUser -Name '{username}' -ErrorAction SilentlyContinue)) {{ "
        f"New-LocalUser -Name '{username}' -FullName '{disp}' -NoPassword -UserMayNotChangePassword "
        f"-AccountNeverExpires | Out-Null; "
        f"Set-LocalUser -Name '{username}' -PasswordNeverExpires $true; "
        f"Add-LocalGroupMember -SID 'S-1-5-32-545' -Member '{username}' -ErrorAction SilentlyContinue; "
        f"'created' }}")
    return "created" in out


def is_admin(username: str) -> bool:
    """Member of the local Administrators group (a parent's account)."""
    if not IS_WIN or not username:
        return False
    # By the group's SID: its name depends on the Windows language. (Get-LocalGroupMember breaks on
    # leftover accounts, ADSI doesn't.)
    out = powershell(
        "$g = (New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate("
        "[System.Security.Principal.NTAccount]).Value.Split('\\')[-1]; "
        "([ADSI]('WinNT://./' + $g + ',group')).psbase.Invoke('Members') | ForEach-Object { "
        "$_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) }")
    return username.lower() in {n.strip().lower() for n in out.splitlines()}


def unharden_user(username: str) -> None:
    """Undo harden_user: a parent's account gets the normal desktop, Task Manager and Win-key shortcuts."""
    sid = user_sid(username)
    if not sid:
        return
    import winreg
    for path, names in ((r"\Software\Microsoft\Windows\CurrentVersion\Policies\System", ("DisableTaskMgr", "Shell")),
                        (r"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", ("NoWinKeys",))):
        try:
            with winreg.OpenKey(winreg.HKEY_USERS, sid + path, 0, winreg.KEY_SET_VALUE) as k:
                for name in names:
                    try:
                        winreg.DeleteValue(k, name)
                    except FileNotFoundError:
                        pass
        except OSError:
            pass


def user_sid(username: str) -> str | None:
    if not IS_WIN or not username:
        return None
    sid = ctypes.create_string_buffer(256)
    sid_size = wintypes.DWORD(256)
    dom = ctypes.create_unicode_buffer(256)
    dom_size = wintypes.DWORD(256)
    use = wintypes.DWORD()
    if not _advapi.LookupAccountNameW(None, username, sid, ctypes.byref(sid_size), dom,
                                      ctypes.byref(dom_size), ctypes.byref(use)):
        return None
    out = wintypes.LPWSTR()
    if not _advapi.ConvertSidToStringSidW(sid, ctypes.byref(out)):
        return None
    value = out.value
    _kernel32.LocalFree(out)
    return value


def harden_user(username: str, shell: str = "") -> None:
    """Disable Task Manager and Win-key shortcuts for a kid's Windows account. With `shell`, that program
    starts instead of the Windows desktop at sign-in (the lock screen, which opens the desktop once a
    parent approves), so the desktop never shows before the lock screen. Takes effect from the next sign-in."""
    sid = user_sid(username)
    if not sid:
        return
    import winreg
    try:
        for path, values in (
            (r"\Software\Microsoft\Windows\CurrentVersion\Policies\System", {"DisableTaskMgr": 1}),
            (r"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", {"NoWinKeys": 1}),
        ):
            with winreg.CreateKey(winreg.HKEY_USERS, sid + path) as k:
                for name, val in values.items():
                    winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, val)
        with winreg.CreateKey(winreg.HKEY_USERS, sid + SHELL_KEY) as k:
            if shell:
                winreg.SetValueEx(k, "Shell", 0, winreg.REG_SZ, shell)
            else:
                try:
                    winreg.DeleteValue(k, "Shell")
                except FileNotFoundError:
                    pass
    except OSError as e:
        log.warning("harden %s failed: %s", username, e)


SHELL_KEY = r"\Software\Microsoft\Windows\CurrentVersion\Policies\System"


def network_status(full: bool = False) -> dict:
    """What the network looks like right now, for the diagnostics log."""
    if not IS_WIN:
        return {}
    st = {}
    for line in run(["netsh", "advfirewall", "show", "currentprofile"]).splitlines():
        if line.lower().startswith("firewall policy"):
            st["firewall"] = line.split()[-1]
    if full:
        st["windows"] = powershell(
            "(Get-NetAdapter | Where-Object { $_.Status -ne 'Disabled' } | ForEach-Object { "
            "$_.Name + ' ' + $_.Status }) -join ', '; "
            "(Get-NetConnectionProfile | ForEach-Object { $_.Name + '=' + $_.IPv4Connectivity }) -join ', '; "
            "(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | "
            "ForEach-Object { $_.InterfaceAlias + ' dns ' + ($_.ServerAddresses -join '/') }) -join ', '"
        ).strip().replace("\r", "").replace("\n", " | ")
    return st


# ------------------------------------------------------------------- firewall

RULE_PREFIX = "HomeGuard"


def firewall_setup(server_ip: str, upstream_dns: str) -> None:
    """Allow rules that stay in place while outbound traffic is blocked."""
    for name in ("Server", "LAN", "DNS", "DHCP"):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}-{name}"])
    # Getting an address from the router (DHCP) must work while everything else is closed, or after a
    # restart the PC has no network at all until Windows' own rule lets it through.
    for local, remote in (("68", "67"), ("546", "547")):
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}-DHCP", "dir=out",
             "action=allow", "protocol=UDP", f"localport={local}", f"remoteport={remote}", "enable=yes"])
    run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}-Server", "dir=out",
         "action=allow", f"remoteip={server_ip}", "enable=yes"])
    run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}-LAN", "dir=out",
         "action=allow", "remoteip=LocalSubnet", "enable=yes"])
    # Auto-update: SYSTEM's PowerShell (the "HomeGuard Update" task) reaches GitHub with the internet off.
    powershell(
        f"Remove-NetFirewallRule -Name {RULE_PREFIX}-Update -ErrorAction SilentlyContinue; "
        f"New-NetFirewallRule -Name {RULE_PREFIX}-Update -DisplayName {RULE_PREFIX}-Update -Direction Outbound "
        "-Action Allow -Program \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
        "-LocalUser 'D:(A;;CC;;;SY)' | Out-Null")
    # Name lookups keep working with the internet off, so always-open sites can be found.
    for proto in ("UDP", "TCP"):
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}-DNS", "dir=out",
             "action=allow", f"remoteip={upstream_dns}", f"protocol={proto}", "remoteport=53", "enable=yes"])


def allow_ips(ips: list[str]) -> None:
    """Addresses of the always-open sites, reachable while the internet is off. [] removes the rule."""
    run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}-Always"])
    if ips:
        run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}-Always", "dir=out",
             "action=allow", "remoteip=" + ",".join(ips), "enable=yes"])


def internet(enabled: bool) -> None:
    log.info("internet %s", "ON" if enabled else "OFF")
    run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
    policy = "blockinbound,allowoutbound" if enabled else "blockinbound,blockoutbound"
    run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", policy])


def point_dns_to_local() -> None:
    powershell(
        "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { "
        "Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex -ServerAddresses ('127.0.0.1','::1') }; "
        "Clear-DnsClientCache")


def flush_dns() -> None:
    run(["ipconfig", "/flushdns"])


def restore_defaults() -> None:
    """Used by the uninstaller."""
    internet(True)
    for name in ("Server", "LAN", "DNS", "DHCP", "Always", "Update"):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}-{name}"])
    powershell("Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex "
               "-ResetServerAddresses }")
