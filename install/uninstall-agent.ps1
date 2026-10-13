# HomeGuard - הסרת הסוכן (להריץ כמנהל)
$ErrorActionPreference = "Continue"
Stop-ScheduledTask -TaskName "HomeGuard Agent"
Unregister-ScheduledTask -TaskName "HomeGuard Agent" -Confirm:$false
Unregister-ScheduledTask -TaskName "HomeGuard Lock" -Confirm:$false
Get-Process pythonw -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$env:ProgramFiles\Python3*" } | Stop-Process -Force
$pythonw = Get-ChildItem "$env:ProgramFiles\Python3*\pythonw.exe" | Select-Object -First 1 -ExpandProperty FullName
& ($pythonw -replace "pythonw.exe$", "python.exe") "$env:ProgramFiles\HomeGuard\homeguard_agent.py" uninstall
Remove-Item "$env:ProgramFiles\HomeGuard" -Recurse -Force
Remove-Item "$env:ProgramData\HomeGuard" -Recurse -Force
Write-Host "HomeGuard הוסר. האינטרנט וה-DNS הוחזרו לברירת המחדל."
