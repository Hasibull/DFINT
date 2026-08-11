<#
.SYNOPSIS
    DFIN - Digital Forensic Investigation Tool
    ASCII-art terminal forensic report.
#>

# ==================== SELF-ELEVATION ====================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`n[!] Administrator privileges required. Triggering UAC prompt..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    $cmd = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell.exe -ArgumentList $cmd -Verb RunAs
    exit
}

# ==================== ANSI COLOR ENGINE ====================
$e = [char]27
function Res { "$e[0m" }
function Fg($c) {
    switch($c) {
        "k"{30} "r"{31} "g"{32} "y"{33} "b"{34} "m"{35} "c"{36} "w"{37}
        "K"{90} "R"{91} "G"{92} "Y"{93} "B"{94} "M"{95} "C"{96} "W"{97}
        default{37}
    }
}
function X($t,$c) { "$e[$(Fg $c)m$t$(Res)" }
function Bg($t,$c) {
    $bg = switch($c) { "r"{101} "g"{102} "y"{103} "b"{104} "m"{105} "c"{106} "k"{100} default{100} }
    "$e[${bg}m$e[30m$t$(Res)"
}

# ==================== LAYOUT HELPERS ====================
function PR($t,$n) { $l=$t.Length; if($l-ge$n){return $t.Substring(0,$n)} return $t+(" "*($n-$l)) }
function PL($t,$n) { $l=$t.Length; if($l-ge$n){return $t.Substring(0,$n)} return (" "*($n-$l))+$t }
function PC($t,$n) { $l=$t.Length; if($l-ge$n){return $t.Substring(0,$n)} $left=[math]::Floor(($n-$l)/2); $right=$n-$l-$left; return (" "*$left)+$t+(" "*$right) }
function RP($ch,$n) { ([string]$ch)*$n }

# ==================== BADGES ====================
function Badge($text,$color) {
    $map = @{ "c"=@("k","c"); "g"=@("k","g"); "r"=@("W","r"); "y"=@("k","y"); "m"=@("W","m"); "b"=@("W","b"); "x"=@("W","k") }
    $m = $map[$color]; if(-not $m){$m=@("W","k")}
    Bg " $text " $m[1]
}
function ActBadge($a) {
    switch($a) { "Created"{Badge " + CREATED  " "g"} "Deleted"{Badge " x DELETED  " "r"} "Modified"{Badge " ~ MODIFIED " "y"} default{Badge "   ACCESSED " "x"} }
}
function TypeBadge($t) {
    switch($t) { "Interactive"{Badge " DESKTOP  " "g"} "RemoteDesktop"{Badge " RDP      " "y"} "Network"{Badge " NETWORK  " "b"} "Unlock"{Badge " UNLOCK   " "c"} "Logoff"{Badge " LOGOFF   " "x"} "Failed"{Badge " FAILED   " "r"} default{Badge " OTHER    " "x"} }
}

# ==================== ASCII ART BANNER ====================
function Show-Banner {
    Clear-Host
    $banner = @(
        "",
        "         ____  _____ ____  _   _     _      _         ",
        "        |  _ \|  ___/ ___|| \ | |   (_) ___| |_ _   _ ",
        "        | | | | |_  \___ \|  \| |   | |/ _ \ __| | | |",
        "        | |_| |  _|  ___) | |\  |   | |  __/ |_| |_| |",
        "        |____/|_|   |____/|_| \_|  _/ |\___|\__|\__, |",
        "                                  |__/           |___/ ",
        "",
        "              Digital Forensic Investigation Tool",
        ""
    )
    foreach($line in $banner) { Write-Host (X $line "c") }
    Write-Host (X "       +================================================+" "K")
    Write-Host (X "       |  Host: " "K") -NoNewline; Write-Host (X $env:COMPUTERNAME "W") -NoNewline
    Write-Host (X "  |  Version: 1.0  |" "K")
    Write-Host (X "       +================================================+" "K")
    Write-Host ""
}

# ==================== INPUT ====================
function Get-DaysInput {
    while($true) {
        Write-Host (X "[?] Enter lookback period in days: " "Y") -NoNewline
        $d = Read-Host
        if($d -match '^\d+$' -and [int]$d -gt 0){ return [int]$d }
        Write-Host (X "[!] Invalid input. Enter a positive number." "R")
    }
}
function PressEnter {
    Write-Host ""; Write-Host (X "[*] Press Enter to return to menu..." "K"); [void][System.Console]::ReadLine()
}

# ==================== SPINNER / PROGRESS ====================
function Show-Spinner($msg, $seconds) {
    $spins = @("|","/","-","\")
    $end = (Get-Date).AddSeconds($seconds)
    $i = 0
    while((Get-Date) -lt $end) {
        Write-Host "`r$(X "[$($spins[$i % 4])]" "C") $(X $msg "W")" -NoNewline
        Start-Sleep -Milliseconds 100
        $i++
    }
    Write-Host "`r$(X "[+]" "G") $(X $msg "W")" -NoNewline; Write-Host ""
}

# ==================== DATA COLLECTORS ====================
function Get-SoftwareData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $installed = New-Object System.Collections.Generic.List[object]
    $uninstalled = New-Object System.Collections.Generic.List[object]
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1033,11707,1034,11724; StartTime=$start} -ErrorAction Stop | Sort-Object TimeCreated
        foreach($evt in $events) {
            $product = "Unknown Product"
            if($evt.Message -match "Product Name:\s*(.+?)\."){ $product = $Matches[1].Trim() }
            elseif($evt.Message -match "Product:\s*([^\r\n]+)"){ $product = $Matches[1].Trim() }
            $user = "SYSTEM"
            if($evt.Properties.Count -gt 1 -and $evt.Properties[1].Value){ $user = $evt.Properties[1].Value }
            $location = "N/A"
            if($evt.Message -match "Installation folder:\s*([^\r\n]+)"){ $location = $Matches[1].Trim() }
            $row = New-Object PSObject -Property @{Name=$product; Time=$evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location=$location; User=$user}
            if($evt.Id -in 1033,11707){ $installed.Add($row) } else { $uninstalled.Add($row) }
        }
    } catch {}
    try {
        $setupEvents = Get-WinEvent -FilterHashtable @{LogName='Setup'; StartTime=$start} -ErrorAction Stop | Where-Object { $_.Message -match "install|uninstall|update" }
        foreach($evt in $setupEvents) {
            $name = "Setup Event"; if($evt.Message -match "([^\r\n]+)"){ $name = $Matches[1].Trim() }
            $row = New-Object PSObject -Property @{Name=$name; Time=$evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location="Windows Setup Log"; User="SYSTEM"}
            $installed.Add($row)
        }
    } catch {}
    return @{Installed=$installed.ToArray(); Uninstalled=$uninstalled.ToArray()}
}

function Get-FileData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $files = New-Object System.Collections.Generic.List[object]
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663,4660,4656; StartTime=$start} -ErrorAction Stop | Sort-Object TimeCreated
        foreach($evt in $events) {
            $msg = $evt.Message; $user = "N/A"
            if($msg -match "Account Name:\s+([^\r\n]+)"){ $user = $Matches[1].Trim() }
            $objectName = "N/A"
            if($msg -match "Object Name:\s+([^\r\n]+)"){ $objectName = $Matches[1].Trim() }
            $action = "Accessed"
            if($msg -match "WriteData \(or AddFile\)" -or $msg -match "0x2"){ $action = "Created" }
            if($msg -match "Delete" -or $evt.Id -eq 4660){ $action = "Deleted" }
            $leafName = $objectName
            if($objectName -ne "N/A" -and $objectName -match "\\"){ $leafName = Split-Path $objectName -Leaf }
            $row = New-Object PSObject -Property @{Action=$action; Name=$leafName; Time=$evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location=$objectName; User=$user}
            $files.Add($row)
        }
    } catch {}
    return $files.ToArray()
}

function Get-LoginData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $raw = New-Object System.Collections.Generic.List[object]
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4634; StartTime=$start} -ErrorAction Stop | Sort-Object TimeCreated
        foreach($evt in $events) {
            $targetUser = "N/A"; $targetDomain = "N/A"; $logonType = "N/A"; $workstation = "N/A"; $ipAddress = "-"
            if ($evt.Id -eq 4634) {
                if ($evt.Properties[1] -and $evt.Properties[1].Value) { $targetUser = $evt.Properties[1].Value }
                if ($evt.Properties[2] -and $evt.Properties[2].Value) { $targetDomain = $evt.Properties[2].Value }
                $logonType = "Logoff"
            } else {
                if ($evt.Properties[5] -and $evt.Properties[5].Value) { $targetUser = $evt.Properties[5].Value }
                if ($evt.Properties[6] -and $evt.Properties[6].Value) { $targetDomain = $evt.Properties[6].Value }
                if ($evt.Properties[8] -and $evt.Properties[8].Value) { $logonType = $evt.Properties[8].Value }
                if ($evt.Properties[11] -and $evt.Properties[11].Value) { $workstation = $evt.Properties[11].Value }
                if ($evt.Properties[18] -and $evt.Properties[18].Value) { $ipAddress = $evt.Properties[18].Value }
            }
            if ([string]::IsNullOrWhiteSpace($targetUser)) { continue }
            if ($targetUser -in "SYSTEM","LOCAL SERVICE","NETWORK SERVICE","ANONYMOUS LOGON") { continue }
            if ($targetUser -match '^(UMFD|DWM|IUSR|DefaultAccount)-?\d*$') { continue }
            $typeDesc = "Type $logonType"
            if ($logonType -eq 2)      { $typeDesc = "Interactive" }
            elseif ($logonType -eq 3)  { $typeDesc = "Network" }
            elseif ($logonType -eq 4)  { $typeDesc = "Batch" }
            elseif ($logonType -eq 5)  { $typeDesc = "Service" }
            elseif ($logonType -eq 7)  { $typeDesc = "Unlock" }
            elseif ($logonType -eq 8)  { $typeDesc = "NetworkCleartext" }
            elseif ($logonType -eq 10) { $typeDesc = "RemoteDesktop" }
            elseif ($evt.Id -eq 4634)  { $typeDesc = "Logoff" }
            $status = "Success"; if ($evt.Id -eq 4625) { $status = "Failed" }; if ($evt.Id -eq 4634) { $status = "Logoff" }
            $ws = $workstation; if ($ipAddress -ne "-" -and $ipAddress -ne $workstation) { $ws = "$workstation ($ipAddress)" }
            $raw.Add((New-Object PSObject -Property @{User=$targetUser; Domain=$targetDomain; Time=$evt.TimeCreated; TimeStr=$evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Type=$typeDesc; Workstation=$ws; Status=$status; Id=$evt.Id}))
        }
    } catch {}
    $deduped = $raw | Group-Object -Property { $_.User + "|" + $_.Type + "|" + $_.Time.ToString("yyyyMMddHHmm") + "|" + $_.Status } | ForEach-Object { $_.Group | Select-Object -First 1 } | Sort-Object Time
    return $deduped
}

# ==================== RENDERERS ====================
function Sep($color) { Write-Host (X (RP "=" 70) $color) }

function Render-Stats($Software,$Files,$Logins) {
    Write-Host ""
    Write-Host (X "    STATISTICS" "W") -NoNewline; Write-Host (X " =========================================================" "K")
    Write-Host ""
    $fmt = "    {0}  {1,-14} {2,6} {3}"
    Write-Host ($fmt -f (X "[+]" "G"), "Installed", $Software.Installed.Count, (X "software packages" "K"))
    Write-Host ($fmt -f (X "[x]" "R"), "Uninstalled", $Software.Uninstalled.Count, (X "software packages" "K"))
    Write-Host ($fmt -f (X "[~]" "C"), "File Events", $Files.Count, (X "created / modified / deleted" "K"))
    Write-Host ($fmt -f (X "[@]" "M"), "User Logins", $Logins.Count, (X "session events" "K"))
    Write-Host ""
    Sep "K"
}

function Render-SectionHeader($title, $count, $iconColor, $icon) {
    Write-Host ""
    Write-Host "  $(X $icon $iconColor) $(X $title "W") $(X "($count found)" "Y")"
    Sep $iconColor
}

function Render-Software($Software, $Days) {
    Render-SectionHeader "INSTALLED SOFTWARE" $Software.Installed.Count "c" "[+]"
    if($Software.Installed.Count -eq 0) {
        Write-Host (X "      [-] No installation events found in the last $Days days." "K")
    } else {
        Write-Host (X "      NAME                     TIME                  LOCATION        USER" "K")
        Write-Host (X "      ----                     ----                  --------        ----" "K")
        foreach($sw in $Software.Installed) {
            $loc = $sw.Location; if($loc.Length -gt 15){ $loc = $loc.Substring(0,12) + "..." }
            $line = "      {0,-24} {1,-21} {2,-15} {3}"
            Write-Host ($line -f (X $sw.Name "W"), (X $sw.Time "C"), (X $loc "K"), (X $sw.User "B"))
        }
    }
    Write-Host ""

    Render-SectionHeader "UNINSTALLED SOFTWARE" $Software.Uninstalled.Count "r" "[x]"
    if($Software.Uninstalled.Count -eq 0) {
        Write-Host (X "      [-] No uninstallation events found in the last $Days days." "K")
    } else {
        Write-Host (X "      NAME                     TIME                  LOCATION        USER" "K")
        Write-Host (X "      ----                     ----                  --------        ----" "K")
        foreach($sw in $Software.Uninstalled) {
            $loc = $sw.Location; if($loc.Length -gt 15){ $loc = $loc.Substring(0,12) + "..." }
            $line = "      {0,-24} {1,-21} {2,-15} {3}"
            Write-Host ($line -f (X $sw.Name "W"), (X $sw.Time "R"), (X $loc "K"), (X $sw.User "R"))
        }
    }
}

function Render-Files($Files, $Days) {
    Render-SectionHeader "FILE ACTIVITY" $Files.Count "g" "[~]"
    if($Files.Count -eq 0) {
        Write-Host (X "      [-] No file events found. Auditing may not be enabled." "K")
    } else {
        Write-Host (X "      ACTION       FILE NAME                TIME              USER" "K")
        Write-Host (X "      ------       ---------                ----              ----" "K")
        foreach($f in ($Files | Select-Object -First 50)) {
            $badge = ActBadge $f.Action
            $name = $f.Name; if($name.Length -gt 24){ $name = $name.Substring(0,21) + "..." }
            $uc = if($f.User -eq "administrator"){ "M" } else { "B" }
            $nc = if($f.Action -eq "Deleted"){ "K" } else { "W" }
            $left = "      "
            Write-Host "$left$badge  $(X (PR $name 24) $nc)  $(X (PR $f.Time 17) "C")  $(X (PR $f.User 12) $uc)"
        }
        if($Files.Count -gt 50) {
            Write-Host (X "      ... and $($Files.Count - 50) more events" "K")
        }
    }
}

function Render-Logins($Logins, $Days) {
    Render-SectionHeader "USER LOGIN HISTORY" $Logins.Count "m" "[@]"
    if($Logins.Count -eq 0) {
        Write-Host (X "      [-] No login events found in the last $Days days." "K")
    } else {
        Write-Host (X "      USER            TIME                  TYPE         WORKSTATION" "K")
        Write-Host (X "      ----            ----                  ----         -----------" "K")
        foreach($l in ($Logins | Select-Object -First 50)) {
            $badge = TypeBadge $l.Type
            $ws = $l.Workstation; if($ws.Length -gt 13){ $ws = $ws.Substring(0,10) + "..." }
            $uc = if($l.Status -eq "Failed"){ "R" } else { "W" }
            $tc = if($l.Status -eq "Failed"){ "R" } else { "C" }
            $left = "      "
            Write-Host "$left$(X (PR $l.User 15) $uc)  $(X (PR $l.Time 21) $tc)  $badge  $(X (PR $ws 13) "K")"
        }
        if($Logins.Count -gt 50) {
            Write-Host (X "      ... and $($Logins.Count - 50) more events" "K")
        }
    }
}

function Render-FullReport($Software,$Files,$Logins,$Days) {
    Show-Banner
    Render-Stats $Software $Files $Logins
    Render-Software $Software $Days
    Render-Files $Files $Days
    Render-Logins $Logins $Days
    PressEnter
}

# ==================== MAIN MENU ====================
while($true) {
    Show-Banner
    Write-Host (X "  MODULES" "W")
    Write-Host ""
    Write-Host "  $(X "[1]" "C")  Installed/Uninstalled software"
    Write-Host "  $(X "[2]" "G")  Created/Deleted files"
    Write-Host "  $(X "[3]" "M")  User Login history"
    Write-Host "  $(X "[4]" "Y")  All (Full forensic report)"
    Write-Host "  $(X "[5]" "R")  Exit"
    Write-Host ""
    Write-Host (X "  dfin > " "Y") -NoNewline
    $choice = Read-Host

    switch($choice) {
        "1" {
            $days = Get-DaysInput
            Show-Banner
            Show-Spinner "Scanning Application log..." 1
            $sw = Get-SoftwareData -Days $days
            Render-Software $sw $days
            PressEnter
        }
        "2" {
            $days = Get-DaysInput
            Show-Banner
            Show-Spinner "Scanning Security log for file events..." 1
            $files = Get-FileData -Days $days
            Render-Files $files $days
            PressEnter
        }
        "3" {
            $days = Get-DaysInput
            Show-Banner
            Show-Spinner "Scanning Security log for login events..." 1
            $logins = Get-LoginData -Days $days
            Render-Logins $logins $days
            PressEnter
        }
        "4" {
            $days = Get-DaysInput
            Show-Banner
            Show-Spinner "Collecting software events..." 1
            $sw = Get-SoftwareData -Days $days
            Show-Spinner "Collecting file activity..." 1
            $files = Get-FileData -Days $days
            Show-Spinner "Collecting login history..." 1
            $logins = Get-LoginData -Days $days
            Render-FullReport $sw $files $logins $days
        }
        "5" {
            Write-Host ""
            Write-Host (X "  [*] Exiting DFIN. Stay safe." "C")
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host ""
            Write-Host (X "  [!] Invalid choice. Press Enter to continue..." "R")
            [void][System.Console]::ReadLine()
        }
    }
}

