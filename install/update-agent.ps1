<#
  HomeGuard - עדכון הסוכן על מחשב של הילדים (בלי להתקין מחדש), ואופציונלית שליטה מרחוק (RustDesk).
  להריץ פעם אחת ב-PowerShell כמנהל (Run as Administrator) על מחשב הילדים:

    irm https://raw.githubusercontent.com/oritre/homeguard/main/install/update-agent.ps1 | iex

  מאז המחשב מתעדכן לבד: המשימה "HomeGuard Update" (SYSTEM) בודקת כל שעה ובעליית המחשב אם יש גרסה חדשה ב-GitHub.
  ההגדרות (שרת, טוקן, שם מחשב) נשארות כמו שהן ב-C:\ProgramData\HomeGuard\agent.json.
#>
$ErrorActionPreference = "Stop"

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$auto = $me.IsSystem  # run by the scheduled task: no questions, no output
if (-not $auto -and -not ([Security.Principal.WindowsPrincipal]$me).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "צריך להריץ כמנהל (Run as Administrator)"
}
$app = "$env:ProgramFiles\HomeGuard"
$data = "$env:ProgramData\HomeGuard"
if (-not (Test-Path "$app\homeguard_agent.py")) { throw "HomeGuard לא מותקן כאן. השתמשו ב-install-agent.ps1" }
$pending = "$data\pending"
$tmp = "$data\update-tmp"
function Say($text) { if (-not $auto) { Write-Host $text } }

if ($auto) {
    # A log for the parents: C:\ProgramData\HomeGuard\update.log (only the last run)
    Start-Transcript "$data\update.log" -Force | Out-Null
}

# 1. Download a new version into $pending. While the PC is locked the internet is closed, so open GitHub's
#    addresses (the DNS filter answers for them even then) just for this run. If it fails, the next hourly
#    run tries again.
$gitHubRule = "HomeGuard-UpdateNow"
try {
    $ips = @("api.github.com", "github.com", "codeload.github.com") | ForEach-Object {
        Resolve-DnsName $_ -Type A -ErrorAction SilentlyContinue | Where-Object IPAddress | ForEach-Object IPAddress
    } | Select-Object -Unique
    Remove-NetFirewallRule -Name $gitHubRule -ErrorAction SilentlyContinue
    if ($ips) {
        New-NetFirewallRule -Name $gitHubRule -DisplayName $gitHubRule -Direction Outbound -Action Allow `
            -RemoteAddress $ips -Protocol TCP -RemotePort 443 | Out-Null
    }
} catch { Write-Output "firewall: $_" }
try {
    $sha = $null
    try {
        $sha = (Invoke-RestMethod "https://api.github.com/repos/oritre/homeguard/commits/main" -UseBasicParsing).sha
    } catch {
        if (-not $auto) { throw "אין חיבור ל-GitHub: $_" }
    }
    $installed = Get-Content "$data\version.txt" -ErrorAction SilentlyContinue
    $staged = Get-Content "$pending\.sha" -ErrorAction SilentlyContinue
    if ($sha -and $sha -ne $installed -and $sha -ne $staged) {
        Say "מוריד את הגרסה האחרונה..."
        Remove-Item $tmp, $pending -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -ItemType Directory $tmp | Out-Null
        Invoke-WebRequest "https://github.com/oritre/homeguard/archive/$sha.zip" -OutFile "$tmp\hg.zip" -UseBasicParsing
        Expand-Archive "$tmp\hg.zip" $tmp
        $src = Get-ChildItem $tmp -Directory | Select-Object -First 1
        New-Item -ItemType Directory $pending | Out-Null
        Copy-Item "$($src.FullName)\agent\*" $pending -Recurse -Force
        Copy-Item "$($src.FullName)\install\update-agent.ps1" $pending -Force
        Set-Content "$pending\.sha" $sha
    }
} finally {
    Remove-NetFirewallRule -Name $gitHubRule -ErrorAction SilentlyContinue
}

# 2. Install it. Restarting the agent cuts a running session for a few seconds, so the task waits until
#    no kid is using approved time (locked, signed out or a parent), or the PC starts up.
#    Run by hand, it installs right away.
function Kid-Session {
    try {
        $st = Invoke-RestMethod "http://127.0.0.1:8765/state" -UseBasicParsing -TimeoutSec 5
        return [bool]($st.user -and -not $st.exempt -and $st.session)
    } catch { return $false }  # agent not running
}
if ((Test-Path "$pending\.sha") -and (-not $auto -or -not (Kid-Session))) {
    Stop-ScheduledTask -TaskName "HomeGuard Agent" -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
        Where-Object { $_.CommandLine -like "*homeguard_agent.py*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $new = Get-Content "$pending\.sha"
    Remove-Item "$pending\.sha"
    Copy-Item "$pending\*" $app -Recurse -Force
    # Windows PowerShell reads a script without a BOM in the ANSI code page, which breaks the Hebrew text
    $text = Get-Content "$pending\update-agent.ps1" -Raw -Encoding UTF8
    [IO.File]::WriteAllText("$app\update-agent.ps1", $text, [Text.UTF8Encoding]::new($true))
    Set-Content "$data\version.txt" $new
    Remove-Item $pending -Recurse -Force -ErrorAction SilentlyContinue
    # Restart the lock screen too, so the new version runs (the agent brings it back within seconds)
    Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
        Where-Object { $_.CommandLine -like "*lockscreen.pyw*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-ScheduledTask -TaskName "HomeGuard Agent"
    Say "הסוכן עודכן והופעל מחדש."
} else {
    Say "הסוכן כבר מעודכן."
}
if ($auto) { Stop-Transcript | Out-Null; return }

# Automatic updates from now on: at startup and every hour, as SYSTEM
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -StartWhenAvailable
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$app\update-agent.ps1`""
$hourly = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
$boot = New-ScheduledTaskTrigger -AtStartup
$boot.Delay = "PT1M"
Register-ScheduledTask -TaskName "HomeGuard Update" -Action $action -Trigger $hourly, $boot `
    -Principal (New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest) `
    -Settings $settings -Force | Out-Null
Say "עדכון אוטומטי מופעל: המחשב יבדוק כל שעה אם יש גרסה חדשה."

# 3. Remote control from the parents' PC over the home network (RustDesk, direct IP, no cloud account)
$rd = "$env:ProgramFiles\RustDesk\rustdesk.exe"
$answer = if (Test-Path $rd) { "n" } else { Read-Host "להתקין גם שליטה מרחוק (RustDesk)? (y/n)" }
if ($answer -match '^(y|Y|כ)') {
    if (-not (Test-Path $rd)) {
        Write-Host "מתקין RustDesk..."
        # The latest MSI from RustDesk's GitHub releases (winget doesn't always find the package)
        $rel = Invoke-RestMethod "https://api.github.com/repos/rustdesk/rustdesk/releases/latest" -UseBasicParsing
        $msi = $rel.assets | Where-Object { $_.name -like "*x86_64*.msi" } | Select-Object -First 1
        if ($msi) {
            Invoke-WebRequest $msi.browser_download_url -OutFile "$env:TEMP\rustdesk.msi" -UseBasicParsing
            Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\rustdesk.msi`" /qn" -Wait
        } else {
            winget install --id RustDesk.RustDesk --silent --accept-package-agreements --accept-source-agreements
        }
        Start-Sleep 10
    }
    if (-not (Test-Path $rd)) { throw "RustDesk לא הותקן. נסו שוב או התקינו מ-rustdesk.com" }
    $pw = Read-Host "סיסמה קבועה לשליטה מרחוק (לפחות 8 תווים)"
    # The settings go through the RustDesk service, which takes a moment to start after installing
    for ($i = 0; $i -lt 30; $i++) {
        if ((Get-Service RustDesk -ErrorAction SilentlyContinue).Status -eq "Running") { break }
        Start-Service RustDesk -ErrorAction SilentlyContinue
        Start-Sleep 2
    }
    for ($i = 0; $i -lt 10; $i++) {
        & $rd --password $pw | Out-Null
        & $rd --option direct-server Y | Out-Null
        if (((& $rd --option direct-server) | Out-String).Trim() -eq "Y") { break }
        Start-Sleep 3
    }
    # HomeGuard blocks incoming connections; let the home network reach RustDesk only.
    netsh advfirewall firewall delete rule name="HomeGuard-Remote" | Out-Null
    netsh advfirewall firewall add rule name="HomeGuard-Remote" dir=in action=allow protocol=TCP `
        localport=21118 remoteip=LocalSubnet enable=yes | Out-Null
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
            $_.PrefixOrigin -in 'Dhcp', 'Manual' -and $_.IPAddress -notlike '169.*' } |
        Select-Object -First 1).IPAddress
    Write-Host ""
    Write-Host "שליטה מרחוק מוכנה. במחשב של אבא: RustDesk -> להקליד $ip (או $env:COMPUTERNAME) -> הסיסמה שבחרת."
}
