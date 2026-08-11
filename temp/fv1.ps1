<#
.SYNOPSIS
    DFIN - Digital Forensic Investigation Tool
    Beautiful terminal-based forensic report. ASCII-safe source.
#>

# ==================== SELF-ELEVATION ====================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`n[!] Administrator privileges required. Triggering UAC prompt..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    $cmd = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell.exe -ArgumentList $cmd -Verb RunAs
    exit
}

# ==================== UNICODE BORDER CHARS (runtime) ====================
$UC = @{
    tl = [char]0x250C
    tr = [char]0x2510
    bl = [char]0x2514
    br = [char]0x2518
    hz = [char]0x2500
    vt = [char]0x2502
    tj = [char]0x252C
    bj = [char]0x2534
    lj = [char]0x251C
    rj = [char]0x2524
}

# ==================== ANSI COLOR ENGINE ====================
$esc = [char]27

function AnsiReset { "$esc[0m" }

function AnsiFg($code) {
    switch($code) {
        "k" { "30" } "r" { "31" } "g" { "32" } "y" { "33" }
        "b" { "34" } "m" { "35" } "c" { "36" } "w" { "37" }
        "K" { "90" } "R" { "91" } "G" { "92" } "Y" { "93" }
        "B" { "94" } "M" { "95" } "C" { "96" } "W" { "97" }
        default { "37" }
    }
}

function ColorText($text, $code) {
    "$esc[$(AnsiFg $code)m$text$(AnsiReset)"
}

function ColorBg($text, $bgCode) {
    $bg = switch($bgCode) {
        "r" { "101" } "g" { "102" } "y" { "103" }
        "b" { "104" } "m" { "105" } "c" { "106" }
        "k" { "100" }
        default { "100" }
    }
    "$esc[${bg}m$esc[30m$text$(AnsiReset)"
}

# ==================== LAYOUT HELPERS ====================
function RepeatChar($ch, $n) {
    ([string]$ch) * $n
}

function PadRight($text, $n) {
    $len = $text.Length
    if($len -ge $n) { return $text.Substring(0, $n) }
    return $text + (" " * ($n - $len))
}

function PadLeft($text, $n) {
    $len = $text.Length
    if($len -ge $n) { return $text.Substring(0, $n) }
    return (" " * ($n - $len)) + $text
}

function PadCenter($text, $n) {
    $len = $text.Length
    if($len -ge $n) { return $text.Substring(0, $n) }
    $left = [math]::Floor(($n - $len) / 2)
    $right = $n - $len - $left
    return (" " * $left) + $text + (" " * $right)
}

function HLine($width, $colorCode) {
    ColorText (RepeatChar $UC.hz ($width - 2)) $colorCode
}

function TopLine($width, $colorCode) {
    $a = ColorText $UC.tl $colorCode
    $b = HLine $width $colorCode
    $c = ColorText $UC.tr $colorCode
    Write-Host "$a$b$c"
}

function BotLine($width, $colorCode) {
    $a = ColorText $UC.bl $colorCode
    $b = HLine $width $colorCode
    $c = ColorText $UC.br $colorCode
    Write-Host "$a$b$c"
}

function MidLine($width, $colorCode) {
    $a = ColorText $UC.lj $colorCode
    $b = HLine $width $colorCode
    $c = ColorText $UC.rj $colorCode
    Write-Host "$a$b$c"
}

function BoxRow($text, $width, $borderColor, $textColor) {
    $inner = $width - 4
    $txt = PadRight $text $inner
    $left = ColorText "$($UC.vt) " $borderColor
    $mid = ColorText $txt $textColor
    $right = ColorText " $($UC.vt)" $borderColor
    Write-Host "$left$mid$right"
}

function MakeBadge($text, $color) {
    $map = @{
        "c" = @("k", "c")
        "g" = @("k", "g")
        "r" = @("W", "r")
        "y" = @("k", "y")
        "m" = @("W", "m")
        "b" = @("W", "b")
        "x" = @("W", "k")
    }
    $m = $map[$color]
    if(-not $m) { $m = @("W", "k") }
    ColorBg " $text " $m[1]
}

function ActionBadge($action) {
    switch($action) {
        "Created"  { MakeBadge " + CREATED  " "g" }
        "Deleted"  { MakeBadge " x DELETED  " "r" }
        "Modified" { MakeBadge " ~ MODIFIED " "y" }
        default    { MakeBadge "   ACCESSED " "x" }
    }
}

function TypeBadge($type) {
    switch($type) {
        "Interactive"   { MakeBadge " DESKTOP  " "g" }
        "RemoteDesktop" { MakeBadge " RDP      " "y" }
        "Network"       { MakeBadge " NETWORK  " "b" }
        "Unlock"        { MakeBadge " UNLOCK   " "c" }
        "Failed"        { MakeBadge " FAILED   " "r" }
        default         { MakeBadge " OTHER    " "x" }
    }
}

# ==================== BANNER ====================
function Show-Banner {
    Clear-Host
    $w = 70
    TopLine $w "c"
    BoxRow (PadCenter "D F I N" 66) $w "c" "C"
    BoxRow (PadCenter "Digital Forensic Investigation Tool" 66) $w "c" "c"
    BotLine $w "c"
    Write-Host ""
}

# ==================== INPUT ====================
function Get-DaysInput {
    while($true) {
        Write-Host (ColorText "For how many days (back from today): " "Y") -NoNewline
        $d = Read-Host
        if($d -match '^\d+$' -and [int]$d -gt 0) { return [int]$d }
        Write-Host (ColorText "  Invalid input. Enter a positive number." "R")
    }
}

function PressEnter {
    Write-Host ""
    Write-Host (ColorText "Press Enter to return to menu..." "K")
    [void][System.Console]::ReadLine()
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
            if($evt.Message -match "Product Name:\s*(.+?)\.") { $product = $Matches[1].Trim() }
            elseif($evt.Message -match "Product:\s*([^\r\n]+)") { $product = $Matches[1].Trim() }
            $user = "SYSTEM"
            if($evt.Properties.Count -gt 1 -and $evt.Properties[1].Value) { $user = $evt.Properties[1].Value }
            $location = "N/A"
            if($evt.Message -match "Installation folder:\s*([^\r\n]+)") { $location = $Matches[1].Trim() }
            $row = New-Object PSObject -Property @{Name=$product; Time=$evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location=$location; User=$user}
            if($evt.Id -in 1033,11707) { $installed.Add($row) } else { $uninstalled.Add($row) }
        }
    } catch {}

    try {
        $setupEvents = Get-WinEvent -FilterHashtable @{LogName='Setup'; StartTime=$start} -ErrorAction Stop | Where-Object { $_.Message -match "install|uninstall|update" }
        foreach($evt in $setupEvents) {
            $name = "Setup Event"
            if($evt.Message -match "([^\r\n]+)") { $name = $Matches[1].Trim() }
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
            $msg = $evt.Message
            $user = "N/A"
            if($msg -match "Account Name:\s+([^\r\n]+)") { $user = $Matches[1].Trim() }
            $objectName = "N/A"
            if($msg -match "Object Name:\s+([^\r\n]+)") { $objectName = $Matches[1].Trim() }
            $action = "Accessed"
            if($msg -match "WriteData \(or AddFile\)" -or $msg -match "0x2") { $action = "Created" }
            if($msg -match "Delete" -or $evt.Id -eq 4660) { $action = "Deleted" }
            $leafName = $objectName
            if($objectName -ne "N/A" -and $objectName -match "\\") { $leafName = Split-Path $objectName -Leaf }
            $row = New-Object PSObject -Property @{Action=$action; Name=$leafName; Time=$evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Location=$objectName; User=$user}
            $files.Add($row)
        }
    } catch {}
    return $files.ToArray()
}

function Get-LoginData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $logins = New-Object System.Collections.Generic.List[object]
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4634; StartTime=$start} -ErrorAction Stop | Sort-Object TimeCreated
        foreach($evt in $events) {
            $targetUser = if($evt.Properties[5]) { $evt.Properties[5].Value } else { "N/A" }
            if($targetUser -in "SYSTEM","LOCAL SERVICE","NETWORK SERVICE","ANONYMOUS LOGON","DWM-1","UMFD-1") { continue }
            $logonType = if($evt.Properties[8]) { $evt.Properties[8].Value } else { "N/A" }
            $workstation = if($evt.Properties[11]) { $evt.Properties[11].Value } else { "N/A" }
            $ipAddress = if($evt.Properties[18]) { $evt.Properties[18].Value } else { "-" }
            $typeDesc = "Type $logonType"
            if($logonType -eq 2) { $typeDesc = "Interactive" }
            elseif($logonType -eq 3) { $typeDesc = "Network" }
            elseif($logonType -eq 7) { $typeDesc = "Unlock" }
            elseif($logonType -eq 10) { $typeDesc = "RemoteDesktop" }
            $status = "Success"
            if($evt.Id -eq 4625) { $status = "Failed" }
            $ws = $workstation
            if($ipAddress -ne "-") { $ws = "$workstation ($ipAddress)" }
            $row = New-Object PSObject -Property @{User=$targetUser; Time=$evt.TimeCreated.ToString("dd MMM yyyy, HH:mm"); Type=$typeDesc; Workstation=$ws; Status=$status}
            $logins.Add($row)
        }
    } catch {}
    return $logins.ToArray()
}

# ==================== RENDERERS ====================
function Render-Stats($Software,$Files,$Logins) {
    $w = 16
    $cards = @(
        @{label="INSTALLED"; val=$Software.Installed.Count; color="c"; title="packages"}
        @{label="UNINSTALLED"; val=$Software.Uninstalled.Count; color="r"; title="packages"}
        @{label="FILE EVENTS"; val=$Files.Count; color="g"; title="events"}
        @{label="USER LOGINS"; val=$Logins.Count; color="m"; title="sessions"}
    )
    for($row=0; $row -lt 5; $row++) {
        $line = ""
        foreach($card in $cards) {
            $c = $card.color
            switch($row) {
                0 {
                    $line += (ColorText $UC.tl $c) + (ColorText (RepeatChar $UC.hz ($w-2)) $c) + (ColorText $UC.tr $c) + "  "
                }
                1 {
                    $line += (ColorText "$($UC.vt) " $c) + (ColorText (PadCenter $card.label ($w-4)) "K") + (ColorText " $($UC.vt)" $c) + "  "
                }
                2 {
                    $line += (ColorText "$($UC.vt) " $c) + (ColorText (PadCenter $card.val.ToString() ($w-4)) $c.ToUpper()) + (ColorText " $($UC.vt)" $c) + "  "
                }
                3 {
                    $line += (ColorText "$($UC.vt) " $c) + (ColorText (PadCenter $card.title ($w-4)) "K") + (ColorText " $($UC.vt)" $c) + "  "
                }
                4 {
                    $line += (ColorText $UC.bl $c) + (ColorText (RepeatChar $UC.hz ($w-2)) $c) + (ColorText $UC.br $c) + "  "
                }
            }
        }
        Write-Host $line
    }
    Write-Host ""
}

function Render-SectionHeader($title,$count,$color,$icon) {
    $total = 70
    $titleText = " $icon  $title "
    $countText = " $count found "
    $fill = $total - $titleText.Length - $countText.Length - 4
    if($fill -lt 0) { $fill = 1 }
    $hz = ColorText $UC.hz $color
    $out = (ColorText $UC.tl $color) + $hz + $hz + (ColorText $titleText "W") + ($hz * $fill) + (ColorText $countText "Y") + $hz + $hz + (ColorText $UC.tr $color)
    Write-Host $out
}

function Render-SectionFooter($color) {
    $out = (ColorText $UC.bl $color) + (ColorText (RepeatChar $UC.hz 68) $color) + (ColorText $UC.br $color)
    Write-Host $out
    Write-Host ""
}

function Render-TableHeader($cols,$widths,$color) {
    $line = ColorText "$($UC.vt) " $color
    for($i=0; $i -lt $cols.Count; $i++) {
        $line += (ColorText (PadRight $cols[$i] $widths[$i]) "K") + "  "
    }
    $line += ColorText $UC.vt $color
    Write-Host $line
    $sep = (ColorText $UC.lj $color) + (ColorText (RepeatChar $UC.hz 68) $color) + (ColorText $UC.rj $color)
    Write-Host $sep
}

function Render-TableRow($vals,$widths,$color,$colors) {
    $line = ColorText "$($UC.vt) " $color
    for($i=0; $i -lt $vals.Count; $i++) {
        $tc = if($colors[$i]) { $colors[$i] } else { "W" }
        $line += (ColorText (PadRight $vals[$i] $widths[$i]) $tc) + "  "
    }
    $line += ColorText $UC.vt $color
    Write-Host $line
}

function Render-EmptyRow($msg,$color) {
    $out = (ColorText "$($UC.vt) " $color) + (ColorText (PadRight $msg 66) "K") + (ColorText " $($UC.vt)" $color)
    Write-Host $out
}

function Render-Software($Software,$Days) {
    Render-SectionHeader "INSTALLED SOFTWARE" "$($Software.Installed.Count)" "c" "[+]"
    if($Software.Installed.Count -eq 0) {
        Render-EmptyRow "No installation events found in the last $Days days." "c"
    } else {
        Render-TableHeader @("NAME","TIME","LOCATION","USER") @(22,20,16,6) "c"
        foreach($sw in $Software.Installed) {
            $loc = $sw.Location
            if($loc.Length -gt 16) { $loc = $loc.Substring(0,13) + "..." }
            Render-TableRow @($sw.Name,$sw.Time,$loc,$sw.User) @(22,20,16,6) "c" @("W","C","K","B")
        }
    }
    Render-SectionFooter "c"

    Render-SectionHeader "UNINSTALLED SOFTWARE" "$($Software.Uninstalled.Count)" "r" "[x]"
    if($Software.Uninstalled.Count -eq 0) {
        Render-EmptyRow "No uninstallation events found in the last $Days days." "r"
    } else {
        Render-TableHeader @("NAME","TIME","LOCATION","USER") @(22,20,16,6) "r"
        foreach($sw in $Software.Uninstalled) {
            $loc = $sw.Location
            if($loc.Length -gt 16) { $loc = $loc.Substring(0,13) + "..." }
            Render-TableRow @($sw.Name,$sw.Time,$loc,$sw.User) @(22,20,16,6) "r" @("W","R","K","R")
        }
    }
    Render-SectionFooter "r"
}

function Render-Files($Files,$Days) {
    Render-SectionHeader "FILE ACTIVITY" "$($Files.Count)" "g" "[~]"
    if($Files.Count -eq 0) {
        Render-EmptyRow "No file events found. Auditing may not be enabled." "g"
    } else {
        Render-TableHeader @("ACTION","FILE NAME","TIME","USER") @(14,24,18,8) "g"
        foreach($f in ($Files | Select-Object -First 50)) {
            $badge = ActionBadge $f.Action
            $name = $f.Name
            if($name.Length -gt 24) { $name = $name.Substring(0,21) + "..." }
            $uc = if($f.User -eq "administrator") { "M" } else { "B" }
            $nc = if($f.Action -eq "Deleted") { "K" } else { "W" }
            $left = ColorText "$($UC.vt) " "g"
            $mid1 = ColorText (PadRight $name 24) $nc
            $mid2 = ColorText (PadRight $f.Time 18) "C"
            $mid3 = ColorText (PadRight $f.User 8) $uc
            $right = ColorText " $($UC.vt)" "g"
            Write-Host "$left$badge  $mid1  $mid2  $mid3$right"
        }
        if($Files.Count -gt 50) {
            Render-EmptyRow "... and $($Files.Count - 50) more events" "g"
        }
    }
    Render-SectionFooter "g"
}

function Render-Logins($Logins,$Days) {
    Render-SectionHeader "USER LOGIN HISTORY" "$($Logins.Count)" "m" "[@]"
    if($Logins.Count -eq 0) {
        Render-EmptyRow "No login events found in the last $Days days." "m"
    } else {
        Render-TableHeader @("USER","TIME","TYPE","WORKSTATION") @(16,20,14,14) "m"
        foreach($l in ($Logins | Select-Object -First 50)) {
            $badge = TypeBadge $l.Type
            $ws = $l.Workstation
            if($ws.Length -gt 14) { $ws = $ws.Substring(0,11) + "..." }
            $uc = if($l.Status -eq "Failed") { "R" } else { "W" }
            $tc = if($l.Status -eq "Failed") { "R" } else { "C" }
            $left = ColorText "$($UC.vt) " "m"
            $mid1 = ColorText (PadRight $l.User 16) $uc
            $mid2 = ColorText (PadRight $l.Time 20) $tc
            $mid3 = ColorText (PadRight $ws 14) "K"
            $right = ColorText " $($UC.vt)" "m"
            Write-Host "$left$mid1  $mid2  $badge  $mid3$right"
        }
        if($Logins.Count -gt 50) {
            Render-EmptyRow "... and $($Logins.Count - 50) more events" "m"
        }
    }
    Render-SectionFooter "m"
}

function Render-FullReport($Software,$Files,$Logins,$Days) {
    Show-Banner
    Write-Host (ColorText "  Host: " "K") -NoNewline
    Write-Host (ColorText $env:COMPUTERNAME "W") -NoNewline
    Write-Host (ColorText "  |  Period: " "K") -NoNewline
    Write-Host (ColorText "Last $Days days" "Y") -NoNewline
    Write-Host (ColorText "  |  Generated: " "K") -NoNewline
    Write-Host (ColorText (Get-Date -Format "dd MMM yyyy HH:mm") "C")
    Write-Host ""
    Render-Stats $Software $Files $Logins
    Render-Software $Software $Days
    Render-Files $Files $Days
    Render-Logins $Logins $Days
    PressEnter
}

# ==================== MAIN MENU ====================
while($true) {
    Show-Banner
    Write-Host (ColorText "  What to look for?" "W")
    Write-Host ""
    Write-Host "  $(ColorText "[1]" "C")  Installed/Uninstalled software"
    Write-Host "  $(ColorText "[2]" "G")  Created/Deleted files"
    Write-Host "  $(ColorText "[3]" "M")  User Login history"
    Write-Host "  $(ColorText "[4]" "Y")  All (Full forensic report)"
    Write-Host "  $(ColorText "[5]" "R")  Exit"
    Write-Host ""
    Write-Host (ColorText "  Choose your option: " "Y") -NoNewline
    $choice = Read-Host

    switch($choice) {
        "1" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host (ColorText "  Scanning Application log... please wait." "C")
            Write-Host ""
            $sw = Get-SoftwareData -Days $days
            Render-Software $sw $days
            PressEnter
        }
        "2" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host (ColorText "  Scanning Security log for file events... please wait." "G")
            Write-Host ""
            $files = Get-FileData -Days $days
            Render-Files $files $days
            PressEnter
        }
        "3" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host (ColorText "  Scanning Security log for login events... please wait." "M")
            Write-Host ""
            $logins = Get-LoginData -Days $days
            Render-Logins $logins $days
            PressEnter
        }
        "4" {
            $days = Get-DaysInput
            Show-Banner
            Write-Host (ColorText "  Collecting forensic data... please wait." "Y")
            $sw = Get-SoftwareData -Days $days
            $files = Get-FileData -Days $days
            $logins = Get-LoginData -Days $days
            Render-FullReport $sw $files $logins $days
        }
        "5" {
            Write-Host ""
            Write-Host (ColorText "  Exiting DFIN. Stay safe." "C")
            Start-Sleep -Seconds 1
            exit
        }
        default {
            Write-Host ""
            Write-Host (ColorText "  Invalid choice. Press Enter to continue..." "R")
            [void][System.Console]::ReadLine()
        }
    }
}