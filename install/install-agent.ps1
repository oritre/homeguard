<#
  HomeGuard - התקנת הסוכן על מחשב של הילדים.
  להריץ ב-PowerShell כמנהל (Run as Administrator):

    powershell -ExecutionPolicy Bypass -File install-agent.ps1 `
        -ServerUrl http://192.168.33.53:8800 -AgentToken <token> `
        -PcName "סלון" -ExemptUsers "ori","wife"
#>
param(
    [string]$ServerUrl = "http://192.168.33.53:8800",  # HomeGuard add-on on the Home Assistant Pi
    [Parameter(Mandatory = $true)] [string]$AgentToken,
    [string]$PcName = $env:COMPUTERNAME,
    [string[]]$ExemptUsers = @(),
    [string]$UpstreamDns = "1.1.1.3"
)
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "צריך להריץ כמנהל (Run as Administrator)"
}

# 1. Python for all users (Program Files, so kids can't modify it)
function Find-Python {
    Get-ChildItem "$env:ProgramFiles\Python3*\pythonw.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
}
$pythonw = Find-Python
if (-not $pythonw) {
    Write-Host "מתקין Python..."
    winget install --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements
    $pythonw = Find-Python
    if (-not $pythonw) { throw "Python לא הותקן. התקינו Python 3.12 'for all users' ונסו שוב." }
}
$python = $pythonw -replace "pythonw.exe$", "python.exe"
Write-Host "Python: $pythonw"

# 2. Program files
$app = "$env:ProgramFiles\HomeGuard"
New-Item -ItemType Directory -Force $app | Out-Null
Copy-Item "$PSScriptRoot\..\agent\*" $app -Recurse -Force

# 3. Config, readable only by SYSTEM and Administrators
$data = "$env:ProgramData\HomeGuard"
New-Item -ItemType Directory -Force $data | Out-Null
$cfg = [ordered]@{
    server_url   = $ServerUrl
    agent_token  = $AgentToken
    pc_name      = $PcName
    exempt_users = @($ExemptUsers)
    upstream_dns = $UpstreamDns
}
[IO.File]::WriteAllText("$data\agent.json", ($cfg | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
icacls $data /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

# 4. Browsers: no DNS-over-HTTPS, so site filtering can't be bypassed
$pol = @{
    "HKLM:\SOFTWARE\Policies\Google\Chrome"  = @{ DnsOverHttpsMode = "off" }
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge" = @{ DnsOverHttpsMode = "off" }
    "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" = @{ DnsOverHttpsMode = "off" }
}
foreach ($k in $pol.Keys) {
    New-Item -Path $k -Force | Out-Null
    foreach ($n in $pol[$k].Keys) { Set-ItemProperty -Path $k -Name $n -Value $pol[$k][$n] }
}
$ff = "HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
New-Item -Path $ff -Force | Out-Null
Set-ItemProperty $ff -Name Enabled -Value 0 -Type DWord
Set-ItemProperty $ff -Name Locked -Value 1 -Type DWord

# 5. Scheduled tasks
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

# Agent: at startup, as SYSTEM
$agentAction = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$app\homeguard_agent.py`"" -WorkingDirectory $app
$agentTrigger = New-ScheduledTaskTrigger -AtStartup
$system = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "HomeGuard Agent" -Action $agentAction -Trigger $agentTrigger `
    -Principal $system -Settings $settings -Force | Out-Null

# Lock screen: at every logon, as the user, re-launched every minute if closed
$lockAction = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$app\lockscreen.pyw`"" -WorkingDirectory $app
$lockTrigger = New-ScheduledTaskTrigger -AtLogOn
$lockTrigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 1)).Repetition
$users = New-ScheduledTaskPrincipal -GroupId "S-1-5-32-545" -RunLevel Limited
Register-ScheduledTask -TaskName "HomeGuard Lock" -Action $lockAction -Trigger $lockTrigger `
    -Principal $users -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName "HomeGuard Agent"
Write-Host ""
Write-Host "HomeGuard הותקן על '$PcName'. משתמשים פטורים: $($ExemptUsers -join ', ')"
Write-Host "חשוב: חשבון ה-Windows של הילדים חייב להיות 'Standard user' (לא מנהל)."
Write-Host "לוג: $data\agent.log"
