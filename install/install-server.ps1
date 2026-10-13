<#
  HomeGuard - התקנת השרת + בוט הטלגרם על מחשב שתמיד דלוק (למשל המחשב של ההורים).
  להריץ כמנהל:
    powershell -ExecutionPolicy Bypass -File install-server.ps1 -TelegramToken <token-from-BotFather>
  אחרי ההתקנה: שלחו /start לבוט מהטלפון שלכם ושל אשתך, והוסיפו את מזהי הצ'אט:
    install-server.ps1 -TelegramToken <token> -ParentChatIds 11111,22222
#>
param(
    [Parameter(Mandatory = $true)] [string]$TelegramToken,
    [long[]]$ParentChatIds = @(),
    [int]$Port = 8800
)
$ErrorActionPreference = "Stop"
$pythonw = Get-ChildItem "$env:ProgramFiles\Python3*\pythonw.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $pythonw) {
    winget install --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements
    $pythonw = Get-ChildItem "$env:ProgramFiles\Python3*\pythonw.exe" | Select-Object -First 1 -ExpandProperty FullName
}
$python = $pythonw -replace "pythonw.exe$", "python.exe"

$app = "$env:ProgramFiles\HomeGuardServer"
$data = "$env:ProgramData\HomeGuardServer"
New-Item -ItemType Directory -Force $app, $data | Out-Null
Copy-Item "$PSScriptRoot\..\server\*" $app -Recurse -Force

$cfgPath = "$data\config.json"
if (Test-Path $cfgPath) {
    $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
} else {
    $cfg = [pscustomobject]@{ agent_token = (& $python "$app\homeguard_server.py" gen-token).Trim() }
}
$cfg | Add-Member -Force telegram_token $TelegramToken
$cfg | Add-Member -Force port $Port
$cfg | Add-Member -Force db "$data\homeguard.db"
if ($ParentChatIds.Count -gt 0) { $cfg | Add-Member -Force parent_chat_ids @($ParentChatIds) }
elseif (-not $cfg.parent_chat_ids) { $cfg | Add-Member -Force parent_chat_ids @() }
[IO.File]::WriteAllText($cfgPath, ($cfg | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
icacls $data /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null

New-NetFirewallRule -DisplayName "HomeGuard Server" -Direction Inbound -Protocol TCP -LocalPort $Port `
    -RemoteAddress LocalSubnet -Action Allow -ErrorAction SilentlyContinue | Out-Null

$action = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$app\homeguard_server.py`" run --config `"$cfgPath`"" -WorkingDirectory $data
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "HomeGuard Server" -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Force | Out-Null
Stop-ScheduledTask -TaskName "HomeGuard Server" -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "HomeGuard Server"

$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -in "Dhcp","Manual" -and $_.IPAddress -notlike "169.*" } |
    Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "השרת רץ. כתובת לסוכנים:  http://${ip}:$Port"
Write-Host "Agent token (צריך אותו בהתקנת כל מחשב):  $($cfg.agent_token)"
Write-Host "הוספת ילד:  & `"$python`" `"$app\homeguard_server.py`" kid add noam 1234 נועם --config `"$cfgPath`""
Write-Host "טיפ: קבעו לשרת כתובת IP קבועה בראוטר (DHCP reservation)."
