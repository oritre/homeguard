<#
  HomeGuard - עדכון הסוכן על מחשב של הילדים (בלי להתקין מחדש), ואופציונלית שליטה מרחוק (RustDesk).
  להריץ ב-PowerShell כמנהל (Run as Administrator) על מחשב הילדים:

    irm https://raw.githubusercontent.com/oritre/homeguard/main/install/update-agent.ps1 | iex

  ההגדרות (שרת, טוקן, שם מחשב) נשארות כמו שהן ב-C:\ProgramData\HomeGuard\agent.json.
#>
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "צריך להריץ כמנהל (Run as Administrator)"
}
$app = "$env:ProgramFiles\HomeGuard"
if (-not (Test-Path "$app\homeguard_agent.py")) { throw "HomeGuard לא מותקן כאן. השתמשו ב-install-agent.ps1" }

# 1. The latest agent files from GitHub
$tmp = Join-Path $env:TEMP "homeguard-update"
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $tmp | Out-Null
Write-Host "מוריד את הגרסה האחרונה..."
Invoke-WebRequest "https://github.com/oritre/homeguard/archive/refs/heads/main.zip" -OutFile "$tmp\hg.zip" -UseBasicParsing
Expand-Archive "$tmp\hg.zip" $tmp
$src = Get-ChildItem $tmp -Directory | Select-Object -First 1

# 2. Replace the files and restart the agent (the lock screen restarts itself)
Stop-ScheduledTask -TaskName "HomeGuard Agent" -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
    Where-Object { $_.CommandLine -like "*homeguard_agent.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Copy-Item "$($src.FullName)\agent\*" $app -Recurse -Force
Start-ScheduledTask -TaskName "HomeGuard Agent"
Write-Host "הסוכן עודכן והופעל מחדש."

# 3. Remote control from the parents' PC over the home network (RustDesk, direct IP, no cloud account)
$answer = Read-Host "להתקין גם שליטה מרחוק (RustDesk)? (y/n)"
if ($answer -match '^(y|Y|כ)') {
    $rd = "$env:ProgramFiles\RustDesk\rustdesk.exe"
    if (-not (Test-Path $rd)) {
        Write-Host "מתקין RustDesk..."
        winget install --id RustDesk.RustDesk --scope machine --silent --accept-package-agreements --accept-source-agreements
        Start-Sleep 10
    }
    if (-not (Test-Path $rd)) { throw "RustDesk לא הותקן. נסו שוב או התקינו מ-rustdesk.com" }
    $pw = Read-Host "סיסמה קבועה לשליטה מרחוק (לפחות 8 תווים)"
    & $rd --password $pw | Out-Null
    & $rd --option direct-server Y | Out-Null
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
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
