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


def logoff(session_id: int) -> None:
    log.warning("logging off session %s", session_id)
    if IS_WIN and session_id is not None:
        _wtsapi.WTSLogoffSession(None, session_id, False)


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


def harden_user(username: str) -> None:
    """Disable Task Manager and Win-key shortcuts for a kid's Windows account."""
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
    except OSError as e:
        log.warning("harden %s failed: %s", username, e)


# ------------------------------------------------------------------- firewall

RULE_PREFIX = "HomeGuard"


def firewall_setup(server_ip: str, upstream_dns: str) -> None:
    """Allow rules that stay in place while outbound traffic is blocked."""
    for name in ("Server", "LAN", "DNS"):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}-{name}"])
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
    for name in ("Server", "LAN", "DNS", "Always", "Update"):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}-{name}"])
    powershell("Get-NetAdapter | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex "
               "-ResetServerAddresses }")
