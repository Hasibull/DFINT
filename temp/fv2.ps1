<#
.SYNOPSIS
    DFINT - Digital Forensic Investigation Tool
    Matrix-style terminal forensic report.
#>

# ==================== TERMINAL THEME ====================
$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Green'
Clear-Host

# ==================== SELF-ELEVATION ====================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`n[!] Administrator privileges required. Triggering UAC prompt..." -ForegroundColor Green
    Start-Sleep -Seconds 1
    $cmd = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell.exe -ArgumentList $cmd -Verb RunAs
    exit
}

# ==================== LAYOUT HELPERS ====================
function PR($t, $n) { $l = $t.Length; if ($l -ge $n) { return $t.Substring(0, $n) }; return $t + (" " * ($n - $l)) }
function Sep { Write-Host ("-" * 70) -ForegroundColor DarkGreen }

# ==================== BANNER ====================
function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "          ____   ____  _  _   _  _______             " -ForegroundColor Green
    Write-Host "         |  _ \ |  __|| || \ | ||__| |__|            " -ForegroundColor Green
    Write-Host "         | | | || |_  | ||  \| |   | |               " -ForegroundColor Green
    Write-Host "         | |_| ||  _| | || |\  |   | |               " -ForegroundColor Green
    Write-Host "         |____/ |_|   |_||_| \_|   |_|               " -ForegroundColor Green
    Write-Host "                                                     " -ForegroundColor Green
    Write-Host ""
    Write-Host "       Digital Forensic Investigation Tool" -ForegroundColor Green
    Write-Host "             Host: $env:COMPUTERNAME" -ForegroundColor Green
    Write-Host "                 User: $env:USERNAME" -ForegroundColor Green
    Write-Host "--------------------------------------------------" -ForegroundColor DarkGreen
    Write-Host ""
}

# ==================== INPUT ====================
function Get-DaysInput {
    while ($true) {
        Write-Host "  For how many days (back from today): " -ForegroundColor Green -NoNewline
        $d = Read-Host
        if ($d -match '^\d+$' -and [int]$d -gt 0) { return [int]$d }
        Write-Host "  Invalid input. Enter a positive number." -ForegroundColor Red
    }
}

function PressEnter {
    Write-Host ""; Write-Host "Press Enter to return to menu..." -ForegroundColor DarkGreen; [void][System.Console]::ReadLine()
}

# ==================== DATA COLLECTORS ====================
function Get-SoftwareData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $installed = New-Object System.Collections.Generic.List[object]
    $uninstalled = New-Object System.Collections.Generic.List[object]

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName = 'Application'; ID = 1033, 11707, 1034, 11724; StartTime = $start } -ErrorAction Stop | Sort-Object TimeCreated
        foreach ($evt in $events) {
            $product = "Unknown Product"
            if ($evt.Message -match "Product Name:\s*(.+?)\.") { $product = $Matches[1].Trim() }
            elseif ($evt.Message -match "Product:\s*([^\r\n]+)") { $product = $Matches[1].Trim() }
            $user = "SYSTEM"
            if ($evt.Properties.Count -gt 1 -and $evt.Properties[1].Value) { $user = $evt.Properties[1].Value }
            $location = "N/A"
            if ($evt.Message -match "Installation folder:\s*([^\r\n]+)") { $location = $Matches[1].Trim() }
            $row = New-Object PSObject -Property @{Name = $product; Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location = $location; User = $user }
            if ($evt.Id -in 1033, 11707) { $installed.Add($row) } else { $uninstalled.Add($row) }
        }
    }
    catch {}

    try {
        $setupEvents = Get-WinEvent -FilterHashtable @{LogName = 'Setup'; StartTime = $start } -ErrorAction Stop | Where-Object { $_.Message -match "install|uninstall|update" }
        foreach ($evt in $setupEvents) {
            $name = "Setup Event"; if ($evt.Message -match "([^\r\n]+)") { $name = $Matches[1].Trim() }
            $row = New-Object PSObject -Property @{Name = $name; Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location = "Windows Setup Log"; User = "SYSTEM" }
            $installed.Add($row)
        }
    }
    catch {}

    return @{Installed = $installed.ToArray(); Uninstalled = $uninstalled.ToArray() }
}

function Get-FileData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $files = New-Object System.Collections.Generic.List[object]
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4663, 4660, 4656; StartTime = $start } -ErrorAction Stop | Sort-Object TimeCreated
        foreach ($evt in $events) {
            $msg = $evt.Message; $user = "N/A"
            if ($msg -match "Account Name:\s+([^\r\n]+)") { $user = $Matches[1].Trim() }
            $objectName = "N/A"
            if ($msg -match "Object Name:\s+([^\r\n]+)") { $objectName = $Matches[1].Trim() }
            $action = "Accessed"
            if ($msg -match "WriteData \(or AddFile\)" -or $msg -match "0x2") { $action = "Created" }
            if ($msg -match "Delete" -or $evt.Id -eq 4660) { $action = "Deleted" }
            $leafName = $objectName
            if ($objectName -ne "N/A" -and $objectName -match "\\") { $leafName = Split-Path $objectName -Leaf }
            $row = New-Object PSObject -Property @{Action = $action; Name = $leafName; Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location = $objectName; User = $user }
            $files.Add($row)
        }
    }
    catch {}
    return $files.ToArray()
}

function Get-LoginData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $raw = New-Object System.Collections.Generic.List[object]

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 4624, 4625, 4634; StartTime = $start } -ErrorAction Stop | Sort-Object TimeCreated

        foreach ($evt in $events) {
            $targetUser = "N/A"; $targetDomain = "N/A"; $logonType = "N/A"; $workstation = "N/A"; $ipAddress = "-"

            if ($evt.Id -eq 4634) {
                if ($evt.Properties[1] -and $evt.Properties[1].Value) { $targetUser = $evt.Properties[1].Value }
                if ($evt.Properties[2] -and $evt.Properties[2].Value) { $targetDomain = $evt.Properties[2].Value }
                $logonType = "Logoff"
            }
            else {
                if ($evt.Properties[5] -and $evt.Properties[5].Value) { $targetUser = $evt.Properties[5].Value }
                if ($evt.Properties[6] -and $evt.Properties[6].Value) { $targetDomain = $evt.Properties[6].Value }
                if ($evt.Properties[8] -and $evt.Properties[8].Value) { $logonType = $evt.Properties[8].Value }
                if ($evt.Properties[11] -and $evt.Properties[11].Value) { $workstation = $evt.Properties[11].Value }
                if ($evt.Properties[18] -and $evt.Properties[18].Value) { $ipAddress = $evt.Properties[18].Value }
            }

            # Skip garbage accounts
            if ([string]::IsNullOrWhiteSpace($targetUser)) { continue }
            if ($targetUser -eq "N/A") { continue }
            if ($targetUser -in "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON") { continue }
            if ($targetUser -match '^(UMFD|DWM|IUSR|DefaultAccount|Font Driver|Window Manager)-?\d*$') { continue }
            if ($targetUser -match '^[0-9a-fA-F]{8}-') { continue }  # Skip GUID-like names
            if ($targetUser -match '^S-1-5-') { continue }           # Skip SIDs

            $typeDesc = "Type $logonType"
            if ($logonType -eq 2) { $typeDesc = "Interactive" }
            elseif ($logonType -eq 3) { $typeDesc = "Network" }
            elseif ($logonType -eq 7) { $typeDesc = "Unlock" }
            elseif ($logonType -eq 10) { $typeDesc = "RemoteDesktop" }
            elseif ($evt.Id -eq 4634) { $typeDesc = "Logoff" }

            $status = "Success"
            if ($evt.Id -eq 4625) { $status = "Failed" }
            if ($evt.Id -eq 4634) { $status = "Logoff" }

            $ws = $workstation
            if ($ipAddress -ne "-" -and $ipAddress -ne $workstation) { $ws = "$workstation ($ipAddress)" }

            $raw.Add((New-Object PSObject -Property @{
                User        = $targetUser
                Time        = $evt.TimeCreated
                TimeStr     = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm")
                Type        = $typeDesc
                Workstation = $ws
                Status      = $status
            }))
        }
    }
    catch {}

    # Deduplicate: one per user per type per minute
    $deduped = $raw | Group-Object -Property { $_.User + "|" + $_.Type + "|" + $_.Time.ToString("yyyyMMddHHmm") } | ForEach-Object { $_.Group | Select-Object -First 1 } | Sort-Object Time
    return $deduped
}

# ==================== RENDERERS ====================
function Render-Stats($Software, $Files, $Logins) {
    Write-Host ""
    Write-Host "    STATISTICS" -ForegroundColor Green
    Sep
    $fmt = "    {0,-14} {1,6} {2}"
    Write-Host ($fmt -f "Installed", $Software.Installed.Count, "software packages") -ForegroundColor Green
    Write-Host ($fmt -f "Uninstalled", $Software.Uninstalled.Count, "software packages") -ForegroundColor Green
    Write-Host ($fmt -f "File Events", $Files.Count, "created / modified / deleted") -ForegroundColor Green
    Write-Host ($fmt -f "User Logins", $Logins.Count, "session events") -ForegroundColor Green
    Write-Host ""
    Sep
}

function SectionHeader($icon, $title, $count) {
    Write-Host ""
    Write-Host "  $icon  $title  ($count found)" -ForegroundColor Green
    Sep
}

function Render-Software($Software, $Days) {
    SectionHeader "[+]" "INSTALLED SOFTWARE" $Software.Installed.Count
    if ($Software.Installed.Count -eq 0) {
        Write-Host "      [-] No installation events found." -ForegroundColor DarkGreen
    }
    else {
        Write-Host "  $(PR "NAME" 22) $(PR "TIME" 21) $(PR "LOCATION" 15) $(PR "USER" 10)" -ForegroundColor DarkGreen
        foreach ($sw in $Software.Installed) {
            $loc = $sw.Location; if ($loc.Length -gt 15) { $loc = $loc.Substring(0, 12) + "..." }
            Write-Host "  $(PR $sw.Name 22) $(PR $sw.Time 21) $(PR $loc 15) $(PR $sw.User 10)" -ForegroundColor Green
        }
    }
    Write-Host ""

    SectionHeader "[x]" "UNINSTALLED SOFTWARE" $Software.Uninstalled.Count
    if ($Software.Uninstalled.Count -eq 0) {
        Write-Host "      [-] No uninstallation events found." -ForegroundColor DarkGreen
    }
    else {
        Write-Host "  $(PR "NAME" 22) $(PR "TIME" 21) $(PR "LOCATION" 15) $(PR "USER" 10)" -ForegroundColor DarkGreen
        foreach ($sw in $Software.Uninstalled) {
            $loc = $sw.Location; if ($loc.Length -gt 15) { $loc = $loc.Substring(0, 12) + "..." }
            Write-Host "  $(PR $sw.Name 22) $(PR $sw.Time 21) $(PR $loc 15) $(PR $sw.User 10)" -ForegroundColor Yellow
        }
    }
}

function Render-Files($Files, $Days) {
    SectionHeader "[~]" "FILE ACTIVITY" $Files.Count
    if ($Files.Count -eq 0) {
        Write-Host "      [-] No file events found. Auditing may not be enabled." -ForegroundColor DarkGreen
    }
    else {
        Write-Host "  $(PR "ACTION" 12) $(PR "FILE NAME" 26) $(PR "TIME" 18) $(PR "USER" 10)" -ForegroundColor DarkGreen
        foreach ($f in ($Files | Select-Object -First 50)) {
            $badge = switch ($f.Action) {
                "Created" { "+ CREATED" }
                "Deleted" { "x DELETED" }
                "Modified" { "~ MODIFIED" }
                default { "  ACCESSED" }
            }
            $bc = switch ($f.Action) { "Created" { "Green" } "Deleted" { "Red" } "Modified" { "Yellow" } default { "DarkGreen" } }
            $name = $f.Name; if ($name.Length -gt 26) { $name = $name.Substring(0, 23) + "..." }
            $uc = if ($f.User -eq "administrator") { "Green" } else { "Green" }
            Write-Host "  " -NoNewline
            Write-Host $(PR $badge 12) -ForegroundColor $bc -NoNewline
            Write-Host " $(PR $name 26) $(PR $f.Time 18) " -NoNewline -ForegroundColor Green
            Write-Host $(PR $f.User 10) -ForegroundColor $uc
        }
        if ($Files.Count -gt 50) {
            Write-Host "      ... and $($Files.Count - 50) more events" -ForegroundColor DarkGreen
        }
    }
}

function Render-Logins($Logins, $Days) {
    SectionHeader "[@]" "USER LOGIN HISTORY" $Logins.Count
    if ($Logins.Count -eq 0) {
        Write-Host "      [-] No login events found." -ForegroundColor DarkGreen
    }
    else {
        Write-Host "  $(PR "USER" 16) $(PR "TIME" 21) $(PR "TYPE" 12) $(PR "WORKSTATION" 16)" -ForegroundColor DarkGreen
        foreach ($l in ($Logins | Select-Object -First 50)) {
            $badge = switch ($l.Type) {
                "Interactive" { "[DESKTOP]" }
                "RemoteDesktop" { "[RDP]" }
                "Network" { "[NETWORK]" }
                "Unlock" { "[UNLOCK]" }
                "Logoff" { "[LOGOFF]" }
                "Failed" { "[FAILED]" }
                default { "[OTHER]" }
            }
            $bc = switch ($l.Type) { "Interactive" { "Green" } "RemoteDesktop" { "Yellow" } "Network" { "Green" } "Unlock" { "Green" } "Logoff" { "DarkGreen" } "Failed" { "Red" } default { "DarkGreen" } }
            $uc = if ($l.Status -eq "Failed") { "Red" } else { "Green" }
            $tc = if ($l.Status -eq "Failed") { "Red" } else { "Green" }
            $ws = $l.Workstation; if ($ws.Length -gt 16) { $ws = $ws.Substring(0, 13) + "..." }
            Write-Host "  " -NoNewline
            Write-Host $(PR $l.User 16) -ForegroundColor $uc -NoNewline
            Write-Host " $(PR $l.TimeStr 21) " -NoNewline -ForegroundColor $tc
            Write-Host $(PR $badge 12) -ForegroundColor $bc -NoNewline
            Write-Host " $(PR $ws 16)" -ForegroundColor Green
        }
        if ($Logins.Count -gt 50) {
            Write-Host "      ... and $($Logins.Count - 50) more events" -ForegroundColor DarkGreen
        }
    }
}

function Render-FullReport($Software, $Files, $Logins, $Days) {
    Show-Banner
    Render-Stats $Software $Files $Logins
    Render-Software $Software $Days
    Render-Files $Files $Days
    Render-Logins $Logins $Days
    PressEnter
}

# ==================== MAIN MENU ====================
while ($true) {
    Show-Banner
    Write-Host "  What to look for?" -ForegroundColor Green
    Write-Host ""
    Write-Host "  [1]  Installed/Uninstalled software" -ForegroundColor Green
    Write-Host "  [2]  Created/Deleted files" -ForegroundColor Green
    Write-Host "  [3]  User Login history" -ForegroundColor Green
    Write-Host "  [4]  All (Full forensic report)" -ForegroundColor Green
    Write-Host "  [5]  Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "  dfin > " -ForegroundColor Green -NoNewline
    $choice = Read-Host

    switch ($choice) {
        "1" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host "  [+] Scanning Application log..." -ForegroundColor Green
            Write-Host ""
            $sw = Get-SoftwareData -Days $days
            Render-Software $sw $days
            PressEnter
        }
        "2" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host "  [~] Scanning Security log for file events..." -ForegroundColor Green
            Write-Host ""
            $files = Get-FileData -Days $days
            Render-Files $files $days
            PressEnter
        }
        "3" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host "  [@] Scanning Security log for login events..." -ForegroundColor Green
            Write-Host ""
            $logins = Get-LoginData -Days $days
            Render-Logins $logins $days
            PressEnter
        }
        "4" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host "  [*] Collecting forensic data..." -ForegroundColor Green
            $sw = Get-SoftwareData -Days $days
            $files = Get-FileData -Days $days
            $logins = Get-LoginData -Days $days
            Render-FullReport $sw $files $logins $days
        }
        "5" {
            Write-Host ""; Write-Host "  [*] Exiting DFIN. Stay safe." -ForegroundColor Green
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host ""; Write-Host "  [!] Invalid choice. Press Enter to continue..." -ForegroundColor Red
            [void][System.Console]::ReadLine()
        }
    }
}