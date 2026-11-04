# Makes a kid's Windows account look and work like the template account (the shared account the
# parents set up): wallpaper, theme, taskbar, keyboard languages, Explorer options, default apps and
# Brave's bookmarks. Run by the HomeGuard agent as SYSTEM. Prints one line per step for the log:
#   OK <what> / SKIP <what> <why> / FAIL <what> <error>
param(
    [Parameter(Mandatory = $true)][string]$Template,
    [Parameter(Mandatory = $true)][string]$Kid
)
# Not 'Stop': in Windows PowerShell that turns any line reg.exe writes to stderr into an exception.
$ErrorActionPreference = 'Continue'

function Get-Sid([string]$name) {
    try { (New-Object System.Security.Principal.NTAccount($name)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
    catch { $null }
}
function Get-ProfilePath([string]$sid) {
    $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (-not (Test-Path $k)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty $k).ProfileImagePath)
    if (Test-Path $p) { $p } else { $null }
}

$tSid = Get-Sid $Template; $kSid = Get-Sid $Kid
$tDir = if ($tSid) { Get-ProfilePath $tSid }; $kDir = if ($kSid) { Get-ProfilePath $kSid }
if (-not $tDir) { 'SKIP all template profile not found'; exit 0 }
if (-not $kDir) { 'SKIP all kid has not signed in yet'; exit 0 }

# Each user's registry: already loaded while they are signed in, otherwise loaded here for a moment.
$loaded = @()
function Open-Hive([string]$sid, [string]$dir, [string]$tag) {
    if (Test-Path "Registry::HKEY_USERS\$sid") { return "HKEY_USERS\$sid" }
    $name = "HG_$tag"
    & reg.exe load "HKEY_USERS\$name" (Join-Path $dir 'NTUSER.DAT') 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "cannot load the registry of $tag" }
    $script:loaded += "HKEY_USERS\$name"
    return "HKEY_USERS\$name"
}

try {
    $tHive = Open-Hive $tSid $tDir 'template'
    $kHive = Open-Hive $kSid $kDir 'kid'

    # ---- look: theme, taskbar and Explorer options, keyboard languages, taskbar pins
    foreach ($key in @(
            'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize',
            'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
            'Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband',
            'Software\Microsoft\Windows\CurrentVersion\Search',
            'Software\Microsoft\Windows\DWM',
            'Control Panel\International\User Profile',
            'Keyboard Layout\Preload',
            'Keyboard Layout\Substitutes',
            'Keyboard Layout\Toggle')) {
        if (-not (Test-Path "Registry::$tHive\$key")) { continue }
        & reg.exe copy "$tHive\$key" "$kHive\$key" /s /f 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { "OK $key" } else { "FAIL $key reg copy $LASTEXITCODE" }
    }
    $pins = 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned'
    if (Test-Path (Join-Path $tDir $pins)) {
        $sh = New-Object -ComObject WScript.Shell
        Get-ChildItem (Join-Path $tDir $pins) -Recurse -File -Filter *.lnk | ForEach-Object {
            $target = $sh.CreateShortcut($_.FullName).TargetPath
            if ($target -and $target.StartsWith($tDir, 'OrdinalIgnoreCase')) { "SKIP pin $($_.BaseName) installed only for $Template"; return }
            $dest = Join-Path (Join-Path $kDir $pins) $_.FullName.Substring((Join-Path $tDir $pins).Length)
            New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
        }
        'OK taskbar pins'
    }

    # ---- wallpaper: a copy in Public, since the kid can't read the template's own folders
    $desk = Get-ItemProperty "Registry::$tHive\Control Panel\Desktop" -ErrorAction SilentlyContinue
    $wall = if ($desk) { $desk.WallPaper } else { '' }
    if (-not $wall -or -not (Test-Path -LiteralPath $wall)) {
        $wall = Join-Path $tDir 'AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper'
    }
    if (Test-Path -LiteralPath $wall) {
        $ext = [IO.Path]::GetExtension($wall); if (-not $ext) { $ext = '.jpg' }
        $pub = Join-Path $env:PUBLIC "Pictures\HomeGuard-wallpaper$ext"
        if ($wall.StartsWith($tDir, 'OrdinalIgnoreCase')) { Copy-Item -LiteralPath $wall -Destination $pub -Force; $wall = $pub }
        $kd = "Registry::$kHive\Control Panel\Desktop"
        Set-ItemProperty $kd -Name WallPaper -Value $wall
        foreach ($v in 'WallpaperStyle', 'TileWallpaper') {
            if ($desk -and $null -ne $desk.$v) { Set-ItemProperty $kd -Name $v -Value $desk.$v }
        }
        'OK wallpaper'
    }

    # ---- default apps: the template's choices, applied by Windows at every sign-in (a policy file)
    $assoc = @()
    $fe = "Registry::$tHive\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
    if (Test-Path $fe) {
        Get-ChildItem $fe | ForEach-Object {
            $uc = Join-Path $_.PSPath 'UserChoice'
            if (Test-Path $uc) { $p = (Get-ItemProperty $uc).ProgId; if ($p) { $assoc += , @($_.PSChildName, $p) } }
        }
    }
    $ua = "Registry::$tHive\Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
    if (Test-Path $ua) {
        Get-ChildItem $ua | ForEach-Object {
            $uc = Join-Path $_.PSPath 'UserChoice'
            if (Test-Path $uc) { $p = (Get-ItemProperty $uc).ProgId; if ($p) { $assoc += , @($_.PSChildName, $p) } }
        }
    }
    if ($assoc.Count) {
        $xml = New-Object System.Text.StringBuilder
        [void]$xml.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
        [void]$xml.AppendLine('<DefaultAssociations>')
        foreach ($a in $assoc) {
            $id = [Security.SecurityElement]::Escape($a[0]); $pg = [Security.SecurityElement]::Escape($a[1])
            [void]$xml.AppendLine("  <Association Identifier=`"$id`" ProgId=`"$pg`" ApplicationName=`"$pg`" />")
        }
        [void]$xml.AppendLine('</DefaultAssociations>')
        $dir = Join-Path $env:SystemRoot 'HomeGuard'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $file = Join-Path $dir 'default-apps.xml'
        [IO.File]::WriteAllText($file, $xml.ToString(), (New-Object System.Text.UTF8Encoding($false)))
        $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        New-Item -Path $pol -Force | Out-Null
        Set-ItemProperty $pol -Name DefaultAssociationsConfiguration -Value $file
        "OK default apps $($assoc.Count)"
    }

    # ---- Brave: bookmarks and the bookmarks bar
    $rel = 'AppData\Local\BraveSoftware\Brave-Browser\User Data'
    $tB = Join-Path (Join-Path $tDir $rel) 'Default'
    if (-not (Test-Path (Join-Path $tB 'Bookmarks'))) { 'SKIP brave template has no Brave bookmarks' }
    else {
        $machine = @("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe",
            "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe") | Where-Object { Test-Path $_ }
        $kidOwn = Test-Path (Join-Path $kDir 'AppData\Local\BraveSoftware\Brave-Browser\Application\brave.exe')
        $running = Get-Process brave -IncludeUserName -ErrorAction SilentlyContinue |
            Where-Object { $_.UserName -and $_.UserName.Split('\')[-1] -ieq $Kid }
        if (-not $machine -and -not $kidOwn) { "SKIP brave installed only for $Template, not for all users" }
        elseif ($running) { 'SKIP brave open in the kid account, next time' }
        else {
            $kB = Join-Path (Join-Path $kDir $rel) 'Default'
            New-Item -ItemType Directory -Force -Path $kB | Out-Null
            Copy-Item -LiteralPath (Join-Path $tB 'Bookmarks') -Destination (Join-Path $kB 'Bookmarks') -Force -ErrorAction Stop
            Remove-Item -LiteralPath (Join-Path $kB 'Bookmarks.bak') -ErrorAction SilentlyContinue
            $show = $true
            try { $show = [bool]((Get-Content -Raw -Encoding UTF8 (Join-Path $tB 'Preferences') | ConvertFrom-Json).bookmark_bar.show_on_all_tabs) } catch { }
            $kp = Join-Path $kB 'Preferences'
            try {
                $prefs = if (Test-Path $kp) { Get-Content -Raw -Encoding UTF8 $kp | ConvertFrom-Json -ErrorAction Stop } else { New-Object PSObject }
                if ($prefs.bookmark_bar -and $prefs.bookmark_bar.show_on_all_tabs -eq $show) { "OK brave bookmarks, bar shown=$show"; return }
                if (-not $prefs.bookmark_bar) { $prefs | Add-Member -NotePropertyName bookmark_bar -NotePropertyValue (New-Object PSObject) -Force }
                $prefs.bookmark_bar | Add-Member -NotePropertyName show_on_all_tabs -NotePropertyValue $show -Force
                [IO.File]::WriteAllText($kp, ($prefs | ConvertTo-Json -Depth 100 -Compress), (New-Object System.Text.UTF8Encoding($false)))
                "OK brave bookmarks, bar shown=$show"
            } catch { "FAIL brave preferences $($_.Exception.Message)" }
        }
    }
} catch {
    "FAIL all $($_.Exception.Message)"
} finally {
    [GC]::Collect(); [GC]::WaitForPendingFinalizers()
    foreach ($h in $loaded) { & reg.exe unload $h 2>&1 | Out-Null }
}
