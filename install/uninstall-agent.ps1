# HomeGuard - הסרת הסוכן (להריץ כמנהל)
$ErrorActionPreference = "Continue"
Stop-ScheduledTask -TaskName "HomeGuard Agent"
Unregister-ScheduledTask -TaskName "HomeGuard Agent" -Confirm:$false
Unregister-ScheduledTask -TaskName "HomeGuard Lock" -Confirm:$false
Get-Process pythonw -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$env:ProgramFiles\Python3*" } | Stop-Process -Force
$pythonw = Get-ChildItem "$env:ProgramFiles\Python3*\pythonw.exe" | Select-Object -First 1 -ExpandProperty FullName
& ($pythonw -replace "pythonw.exe$", "python.exe") "$env:ProgramFiles\HomeGuard\homeguard_agent.py" uninstall
# Kids' accounts start the lock screen instead of the desktop: give them the normal Windows desktop back
Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | ForEach-Object {
    $sid = $_.SID
    $loaded = Test-Path "Registry::HKEY_USERS\$sid"
    $root = if ($loaded) { "HKU\$sid" } else { "HKU\HG_$sid" }
    if (-not $loaded) { reg load $root "$($_.LocalPath)\NTUSER.DAT" 2>$null | Out-Null }
    $key = "$root\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    if ((reg query $key /v Shell 2>$null) -match "lockscreen.pyw") { reg delete $key /v Shell /f | Out-Null }
    if (-not $loaded) { [gc]::Collect(); reg unload $root 2>$null | Out-Null }
}
Remove-Item "$env:ProgramFiles\HomeGuard" -Recurse -Force
Remove-Item "$env:ProgramData\HomeGuard" -Recurse -Force
Write-Host "HomeGuard הוסר. האינטרנט וה-DNS הוחזרו לברירת המחדל."
