<#
.SYNOPSIS
    DFIN - Digital Forensic Investigation Tool
    Simple Windows forensic CLI.

.DESCRIPTION
    Collects:
      1. Installed / Uninstalled software
      2. Created / Modified / Deleted files
      3. User login history
      4. Full report

    Requires Administrator privileges.

    NOTE:
    Software uninstall detection is based on Windows evidence.
    If an application does not generate an uninstall event or leaves
    no recoverable evidence, no forensic tool can guarantee detection.
#>

# ==================== TERMINAL THEME ====================

$Host.UI.RawUI.BackgroundColor = 'Black'
$Host.UI.RawUI.ForegroundColor = 'Green'
Clear-Host


# ==================== SELF-ELEVATION ====================

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {

    Write-Host "`n[!] Administrator privileges required. Triggering UAC prompt..." -ForegroundColor Green
    Start-Sleep -Seconds 1

    $cmd = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell.exe -ArgumentList $cmd -Verb RunAs
    exit
}


# ==================== LAYOUT HELPERS ====================

function PR($t, $n) {
    if ($null -eq $t) {
        $t = ""
    }

    $t = [string]$t
    $l = $t.Length

    if ($l -ge $n) {
        return $t.Substring(0, $n)
    }

    return $t + (" " * ($n - $l))
}

function Sep {
    Write-Host ("-" * 70) -ForegroundColor DarkGreen
}


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

        if ($d -match '^\d+$' -and [int]$d -gt 0) {
            return [int]$d
        }

        Write-Host "  Invalid input. Enter a positive number." -ForegroundColor Red
    }
}


function PressEnter {

    Write-Host ""
    Write-Host "Press Enter to return to menu..." -ForegroundColor DarkGreen
    [void][System.Console]::ReadLine()
}


# ============================================================
# SOFTWARE HELPERS
# ============================================================

function Get-EventTextValue {
    param(
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [string[]]$Names
    )

    try {

        $xml = [xml]$Event.ToXml()

        foreach ($name in $Names) {

            $node = $xml.Event.EventData.Data |
                Where-Object { $_.Name -eq $name } |
                Select-Object -First 1

            if ($node -and $node.'#text') {
                return [string]$node.'#text'
            }
        }
    }
    catch {
        return $null
    }

    return $null
}


function New-SoftwareRow {
    param(
        [string]$Name,
        [datetime]$Time,
        [string]$Location,
        [string]$User,
        [string]$Action,
        [string]$Source,
        [string]$Evidence
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        $Name = "Unknown Software"
    }

    if ([string]::IsNullOrWhiteSpace($Location)) {
        $Location = "N/A"
    }

    if ([string]::IsNullOrWhiteSpace($User)) {
        $User = "SYSTEM"
    }

    return [PSCustomObject]@{
        Name     = $Name.Trim()
        Time     = $Time.ToString("dd MMM yyyy, HH:mm")
        Location = $Location.Trim()
        User     = $User.Trim()
        Action   = $Action
        Source   = $Source
        Evidence = $Evidence
    }
}


# ============================================================
# SOFTWARE DATA
# ============================================================

function Get-SoftwareData {

    param([int]$Days)

    $start = (Get-Date).AddDays(-$Days)

    $installed   = New-Object System.Collections.Generic.List[object]
    $uninstalled = New-Object System.Collections.Generic.List[object]


    # ========================================================
    # 1. WINDOWS INSTALLER / MSI
    # ========================================================

    Write-Host "  [1/2] Checking Windows Installer..." -ForegroundColor DarkGreen

    $msiLogs = @(
        "Application",
        "Microsoft-Windows-MsiInstaller/Operational"
    )

    foreach ($logName in $msiLogs) {

        try {

            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Id        = 1033, 1034, 11707, 11724
                StartTime = $start
            } -ErrorAction Stop


            foreach ($evt in $events) {

                $msg = $evt.Message

                if ([string]::IsNullOrWhiteSpace($msg)) {
                    continue
                }


                # ------------------------------------------------
                # PRODUCT NAME
                # ------------------------------------------------

                $name = $null

                if ($msg -match '(?im)Product Name:\s*(.+?)(?:\r?\n|$)') {
                    $name = $Matches[1].Trim()
                }
                elseif ($msg -match '(?im)Product:\s*(.+?)(?:\r?\n|$)') {
                    $name = $Matches[1].Trim()
                }


                if ([string]::IsNullOrWhiteSpace($name)) {
                    continue
                }


                # ------------------------------------------------
                # USER
                # ------------------------------------------------

                $user = "SYSTEM"

                if ($msg -match '(?im)(?:User Name|User|Account Name):\s*(.+?)(?:\r?\n|$)') {

                    $candidate = $Matches[1].Trim()

                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        $user = $candidate
                    }
                }


                # ------------------------------------------------
                # ACTION
                # ------------------------------------------------

                if ($evt.Id -in 1033,11707) {

                    $installed.Add(
                        [PSCustomObject]@{
                            Name     = $name
                            Time     = $evt.TimeCreated
                            Location = "Windows Installer"
                            User     = $user
                            Source   = "MSI"
                            Evidence = "Event $($evt.Id)"
                        }
                    )
                }
                elseif ($evt.Id -in 1034,11724) {

                    $uninstalled.Add(
                        [PSCustomObject]@{
                            Name     = $name
                            Time     = $evt.TimeCreated
                            Location = "Windows Installer"
                            User     = $user
                            Source   = "MSI"
                            Evidence = "Event $($evt.Id)"
                        }
                    )
                }
            }
        }
        catch {
            # Log may not exist on this Windows installation.
        }
    }


    # ========================================================
    # 2. WINGET LOGS
    # ========================================================

    Write-Host "  [2/2] Checking WinGet logs..." -ForegroundColor DarkGreen

    try {

        $wingetLogDir = Join-Path `
            $env:LOCALAPPDATA `
            "Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir"


        if (Test-Path $wingetLogDir) {

            $logFiles = Get-ChildItem `
                -Path $wingetLogDir `
                -File `
                -Recurse `
                -ErrorAction SilentlyContinue


            foreach ($file in $logFiles) {

                if ($file.LastWriteTime -lt $start) {
                    continue
                }


                try {

                    $content = Get-Content `
                        -LiteralPath $file.FullName `
                        -Raw `
                        -ErrorAction SilentlyContinue

                    if ([string]::IsNullOrWhiteSpace($content)) {
                        continue
                    }


                    # Only process logs that contain uninstall activity.
                    if ($content -notmatch '(?i)\buninstall\b|\buninstalled\b|\buninstallation\b') {
                        continue
                    }


                    # ------------------------------------------------
                    # TRY TO FIND SOFTWARE NAME
                    # ------------------------------------------------

                    $names = New-Object System.Collections.Generic.List[string]


                    # Common WinGet patterns
                    $patterns = @(
                        '(?im)Found\s+(.+?)\s+\[',
                        '(?im)Successfully uninstalled\s+(.+?)(?:\r?\n|$)',
                        '(?im)Uninstalling\s+(.+?)(?:\r?\n|$)',
                        '(?im)Uninstall\s+(.+?)(?:\r?\n|$)'
                    )


                    foreach ($pattern in $patterns) {

                        $matches = [regex]::Matches(
                            $content,
                            $pattern
                        )

                        foreach ($match in $matches) {

                            if ($match.Groups.Count -gt 1) {

                                $candidate = $match.Groups[1].Value.Trim()

                                if (
                                    $candidate.Length -gt 1 -and
                                    $candidate.Length -lt 150 -and
                                    $candidate -notmatch '^(package|application|command|operation)$'
                                ) {

                                    $names.Add($candidate)
                                }
                            }
                        }
                    }


                    # ------------------------------------------------
                    # SPECIAL CASE: CURL
                    # ------------------------------------------------

                    if (
                        $content -match '(?i)\bcurl\b' -and
                        $content -match '(?i)\buninstall\b|\buninstalled\b'
                    ) {

                        $names.Add("cURL")
                    }


                    $uniqueNames = @(
                        $names |
                        Sort-Object -Unique
                    )


                    foreach ($name in $uniqueNames) {

                        $uninstalled.Add(
                            [PSCustomObject]@{
                                Name     = $name
                                Time     = $file.LastWriteTime
                                Location = "WinGet"
                                User     = $env:USERNAME
                                Source   = "WinGet"
                                Evidence = $file.Name
                            }
                        )
                    }
                }
                catch {
                    continue
                }
            }
        }
    }
    catch {
        # WinGet may not be installed.
    }


    # ========================================================
    # REMOVE DUPLICATES
    # ========================================================

    $installed = @(
        $installed |
        Sort-Object Time |
        Group-Object -Property {
            "$($_.Name)|$($_.Time.ToString('yyyyMMddHHmm'))|$($_.Source)"
        } |
        ForEach-Object {
            $_.Group | Select-Object -First 1
        }
    )


    $uninstalled = @(
        $uninstalled |
        Sort-Object Time |
        Group-Object -Property {
            "$($_.Name)|$($_.Time.ToString('yyyyMMddHHmm'))|$($_.Source)"
        } |
        ForEach-Object {
            $_.Group | Select-Object -First 1
        }
    )


    return @{
        Installed   = $installed
        Uninstalled = $uninstalled
    }
}


# ============================================================
# FILE DATA
# ============================================================

function Get-FileData {

    param([int]$Days)

    $start = (Get-Date).AddDays(-$Days)

    $events = New-Object System.Collections.Generic.List[object]


    # ========================================================
    # 1. NTFS USN JOURNAL
    # ========================================================

    Write-Host "  [1/2] Reading NTFS USN Journal..." -ForegroundColor DarkGreen


    try {

        # Get local NTFS volumes
        $volumes = Get-CimInstance Win32_LogicalDisk `
            -Filter "DriveType=3" `
            -ErrorAction Stop |
            Where-Object {
                $_.FileSystem -eq "NTFS"
            }


        if ($volumes.Count -eq 0) {

            Write-Host "      [!] No NTFS volumes found." `
                -ForegroundColor DarkYellow
        }


        foreach ($volume in $volumes) {

            $drive = $volume.DeviceID

            Write-Host "      Scanning $drive ..." `
                -ForegroundColor DarkGreen


            # ------------------------------------------------
            # Read USN journal
            # ------------------------------------------------

            try {

                $raw = & fsutil.exe usn readjournal $drive csv 2>&1

                if ($LASTEXITCODE -ne 0) {

                    Write-Host "      [!] USN read failed on $drive" `
                        -ForegroundColor DarkYellow

                    continue
                }


                # ------------------------------------------------
                # Find CSV header
                # ------------------------------------------------

                $headerIndex = -1

                for ($i = 0; $i -lt $raw.Count; $i++) {

                    if ([string]$raw[$i] -match '^Usn,File name,') {

                        $headerIndex = $i
                        break
                    }
                }


                if ($headerIndex -lt 0) {

                    Write-Host "      [!] USN CSV header not found on $drive" `
                        -ForegroundColor DarkYellow

                    continue
                }


                # Header + records
                $csv = @(
                    $raw[$headerIndex..($raw.Count - 1)] |
                    ForEach-Object {
                        [string]$_
                    }
                )


                $records = $csv | ConvertFrom-Csv


                # ------------------------------------------------
                # Process USN records
                # ------------------------------------------------

                foreach ($record in $records) {

                    if ([string]::IsNullOrWhiteSpace($record.'File name')) {
                        continue
                    }


                    # Timestamp
                    try {

                        $timestamp = [datetime]::Parse(
                            $record.'Time stamp'
                        )
                    }
                    catch {
                        continue
                    }


                    # Date range
                    if ($timestamp -lt $start) {
                        continue
                    }

                    if ($timestamp -gt (Get-Date)) {
                        continue
                    }


                    $reason = [string]$record.Reason


                    # ------------------------------------------------
                    # Determine action
                    # ------------------------------------------------

                    $action = $null


                    if ($reason -match '(?i)File delete') {

                        $action = "Deleted"
                    }
                    elseif ($reason -match '(?i)File create') {

                        $action = "Created"
                    }
                    elseif (
                        $reason -match '(?i)Data overwrite' -or
                        $reason -match '(?i)Data extend' -or
                        $reason -match '(?i)Data truncation' -or
                        $reason -match '(?i)Basic info change' -or
                        $reason -match '(?i)Security change'
                    ) {

                        $action = "Modified"
                    }
                    elseif ($reason -match '(?i)Rename') {

                        $action = "Renamed"
                    }


                    if ($null -eq $action) {
                        continue
                    }


                    $fileName = [string]$record.'File name'


                    # ------------------------------------------------
                    # USN doesn't contain the complete path.
                    #
                    # We keep the volume + filename here rather
                    # than pretending we know the full path.
                    # ------------------------------------------------

                    $location = "$drive\$fileName"


                    $events.Add(
                        [PSCustomObject]@{
                            Action     = $action
                            Name       = $fileName
                            Time       = $timestamp
                            Location   = $location
                            User       = "N/A"
                            Source     = "NTFS USN"
                            Evidence   = "USN $($record.Usn) | $reason"
                            USN        = [string]$record.Usn
                            FileID     = [string]$record.'File ID'
                        }
                    )
                }
            }
            catch {

                Write-Host "      [!] Error reading USN on $drive : $($_.Exception.Message)" `
                    -ForegroundColor DarkYellow
            }
        }
    }
    catch {

        Write-Host "      [!] Could not enumerate NTFS volumes: $($_.Exception.Message)" `
            -ForegroundColor DarkYellow
    }


    # ========================================================
    # 2. WINDOWS SECURITY EVENTS 4663 / 4660
    # ========================================================

    Write-Host "  [2/2] Reading Windows Security file events..." `
        -ForegroundColor DarkGreen


    try {

        $securityEvents = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4663,4660
            StartTime = $start
        } -ErrorAction Stop |
        Sort-Object TimeCreated


        foreach ($evt in $securityEvents) {

            $message = $evt.Message

            if ([string]::IsNullOrWhiteSpace($message)) {
                continue
            }


            # ------------------------------------------------
            # Object name
            # ------------------------------------------------

            $objectName = $null

            if ($message -match '(?im)Object Name:\s+([^\r\n]+)') {

                $objectName = $Matches[1].Trim()
            }


            if ([string]::IsNullOrWhiteSpace($objectName)) {
                continue
            }


            # ------------------------------------------------
            # User
            # ------------------------------------------------

            $user = "N/A"

            if ($message -match '(?im)Account Name:\s+([^\r\n]+)') {

                $candidate = $Matches[1].Trim()

                if (
                    -not [string]::IsNullOrWhiteSpace($candidate) -and
                    $candidate -notin @(
                        "-",
                        "SYSTEM",
                        "LOCAL SERVICE",
                        "NETWORK SERVICE"
                    )
                ) {

                    $user = $candidate
                }
            }


            # ------------------------------------------------
            # Determine action
            # ------------------------------------------------

            $action = $null


            # Event 4660 = object deletion
            if ($evt.Id -eq 4660) {

                $action = "Deleted"
            }
            else {

                # 4663 contains "Accesses"
                if ($message -match '(?im)Accesses:\s*(.+?)(?:\r?\n|$)') {

                    $access = $Matches[1]


                    if ($access -match '(?i)Delete') {

                        $action = "Deleted"
                    }
                    elseif (
                        $access -match '(?i)WriteData' -or
                        $access -match '(?i)AppendData' -or
                        $access -match '(?i)WriteAttributes' -or
                        $access -match '(?i)WriteEA'
                    ) {

                        $action = "Modified"
                    }
                }
            }


            if ($null -eq $action) {
                continue
            }


            # ------------------------------------------------
            # Get filename
            # ------------------------------------------------

            $name = Split-Path $objectName -Leaf

            if ([string]::IsNullOrWhiteSpace($name)) {

                $name = $objectName
            }


            $events.Add(
                [PSCustomObject]@{
                    Action     = $action
                    Name       = $name
                    Time       = $evt.TimeCreated
                    Location   = $objectName
                    User       = $user
                    Source     = "Security"
                    Evidence   = "Event ID $($evt.Id)"
                    USN        = $null
                    FileID     = $null
                }
            )
        }
    }
    catch {

        Write-Host ""
        Write-Host "      [!] Security file auditing is not enabled." `
            -ForegroundColor DarkYellow

        Write-Host "          Continuing with NTFS USN Journal evidence." `
            -ForegroundColor DarkGreen
    }


    # ========================================================
    # 3. CORRELATE SECURITY + USN EVENTS
    # ========================================================

    Write-Host "  [*] Correlating file evidence..." `
        -ForegroundColor DarkGreen


    $final = New-Object System.Collections.Generic.List[object]


    # --------------------------------------------------------
    # First add USN events
    # --------------------------------------------------------

    foreach ($event in ($events | Where-Object {
        $_.Source -eq "NTFS USN"
    })) {

        $final.Add($event)
    }


    # --------------------------------------------------------
    # Process Security events
    #
    # If a Security event closely matches a USN event,
    # attach the Security user/evidence to the USN record.
    # Otherwise keep the Security event independently.
    # --------------------------------------------------------

    foreach ($security in ($events | Where-Object {
        $_.Source -eq "Security"
    })) {

        $match = $final |
            Where-Object {

                $_.Action -eq $security.Action -and
                $_.Name -eq $security.Name -and
                [math]::Abs(
                    ($_.Time - $security.Time).TotalSeconds
                ) -le 5
            } |
            Select-Object -First 1


        if ($null -ne $match) {

            # Add user attribution
            if (
                $security.User -ne "N/A" -and
                -not [string]::IsNullOrWhiteSpace($security.User)
            ) {

                $match.User = $security.User
            }


            # Combine evidence
            $match.Source = "USN + Security"
            $match.Evidence = "$($match.Evidence) | $($security.Evidence)"
        }
        else {

            $final.Add($security)
        }
    }


    # ========================================================
    # 4. CLEAN / SORT / LIMIT
    # ========================================================

    return @(
        $final |
        Sort-Object Time
    )
}

# ============================================================
# LOGIN DATA
# ============================================================

function Get-LoginData {

    param([int]$Days)

    $start = (Get-Date).AddDays(-$Days)

    $logins = New-Object System.Collections.Generic.List[object]

    Write-Host "  [~] Reading Windows login history..." `
        -ForegroundColor DarkGreen


    try {

        $events = Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = 4624,4625,4634,4647,4648
            StartTime = $start
        } -ErrorAction Stop


        foreach ($evt in $events) {

            $message = $evt.Message

            if ([string]::IsNullOrWhiteSpace($message)) {
                continue
            }


            # ------------------------------------------------
            # USERNAME
            # ------------------------------------------------

            $user = "N/A"

            if ($message -match '(?im)Account Name:\s+([^\r\n]+)') {

                $candidate = $Matches[1].Trim()

                if (
                    -not [string]::IsNullOrWhiteSpace($candidate) -and
                    $candidate -notin @(
                        "-",
                        "SYSTEM",
                        "LOCAL SERVICE",
                        "NETWORK SERVICE"
                    )
                ) {
                    $user = $candidate
                }
            }


            # ------------------------------------------------
            # DOMAIN
            # ------------------------------------------------

            $domain = "N/A"

            if ($message -match '(?im)Account Domain:\s+([^\r\n]+)') {

                $domain = $Matches[1].Trim()
            }


            # ------------------------------------------------
            # LOGON TYPE
            # ------------------------------------------------

            $logonType = "N/A"

            if ($message -match '(?im)Logon Type:\s+(\d+)') {

                $type = [int]$Matches[1]

                $logonType = switch ($type) {

                    2  { "Interactive" }
                    3  { "Network" }
                    4  { "Batch" }
                    5  { "Service" }
                    7  { "Unlock" }
                    8  { "NetworkCleartext" }
                    9  { "NewCredentials" }
                    10 { "RemoteInteractive (RDP)" }
                    11 { "CachedInteractive" }

                    default {
                        "Type $type"
                    }
                }
            }


            # ------------------------------------------------
            # SOURCE IP
            # ------------------------------------------------

            $ip = "N/A"

            if ($message -match '(?im)Source Network Address:\s+([^\r\n]+)') {

                $candidateIP = $Matches[1].Trim()

                if (
                    -not [string]::IsNullOrWhiteSpace($candidateIP) -and
                    $candidateIP -ne "-"
                ) {
                    $ip = $candidateIP
                }
            }


            # ------------------------------------------------
            # WORKSTATION
            # ------------------------------------------------

            $workstation = "N/A"

            if ($message -match '(?im)Workstation Name:\s+([^\r\n]+)') {

                $workstation = $Matches[1].Trim()
            }


            # ------------------------------------------------
            # ACTION
            # ------------------------------------------------

            $action = switch ($evt.Id) {

                4624 { "Successful Login" }
                4625 { "Failed Login" }
                4634 { "Logoff" }
                4647 { "User Logoff" }
                4648 { "Explicit Credentials" }

                default {
                    "Event $($evt.Id)"
                }
            }


            $logins.Add(
                [PSCustomObject]@{
                    Action      = $action
                    User        = $user
                    Domain      = $domain
                    Time        = $evt.TimeCreated
                    LogonType   = $logonType
                    SourceIP    = $ip
                    Workstation = $workstation
                    EventID     = $evt.Id
                    Source      = "Windows Security"
                }
            )
        }
    }
    catch {

        Write-Host ""
        Write-Host "  [!] Unable to read Windows Security login events." `
            -ForegroundColor DarkYellow

        Write-Host "      $($_.Exception.Message)" `
            -ForegroundColor DarkYellow
    }


    return @(
        $logins |
        Sort-Object Time
    )
}


# ============================================================
# RENDERERS
# ============================================================

function Render-Stats($Software, $Files, $Logins) {

    Write-Host ""
    Write-Host "    STATISTICS" -ForegroundColor Green
    Sep

    $fmt = "    {0,-14} {1,6} {2}"

    Write-Host ($fmt -f "Installed", $Software.Installed.Count, "software packages") `
        -ForegroundColor Green

    Write-Host ($fmt -f "Uninstalled", $Software.Uninstalled.Count, "software packages") `
        -ForegroundColor Green

    Write-Host ($fmt -f "File Events", $Files.Count, "created / modified / deleted") `
        -ForegroundColor Green

    Write-Host ($fmt -f "User Logins", $Logins.Count, "session events") `
        -ForegroundColor Green

    Write-Host ""
    Sep
}


function SectionHeader($icon, $title, $count) {

    Write-Host ""
    Write-Host "  $icon  $title  ($count found)" -ForegroundColor Green
    Sep
}


# ============================================================
# SOFTWARE RENDERER
# ============================================================

function Render-Software($Software, $Days) {

    # ========================================================
    # INSTALLED
    # ========================================================

    SectionHeader "[+]" "INSTALLED SOFTWARE" $Software.Installed.Count

    if ($Software.Installed.Count -eq 0) {

        Write-Host "  No verified installation events found." `
            -ForegroundColor DarkGreen
    }
    else {

        Write-Host ""
        Write-Host "  $(PR "SOFTWARE" 28) $(PR "TIME" 21) $(PR "SOURCE" 12)" `
            -ForegroundColor DarkGreen

        Sep


        foreach ($sw in $Software.Installed) {

            $name = $sw.Name

            if ($name.Length -gt 28) {
                $name = $name.Substring(0, 25) + "..."
            }


            Write-Host "  $(PR $name 28) " `
                -NoNewline `
                -ForegroundColor Green

            Write-Host "$(PR $sw.Time 21) " `
                -NoNewline `
                -ForegroundColor Green

            Write-Host "$(PR $sw.Source 12)" `
                -ForegroundColor Green
        }
    }


    Write-Host ""


    # ========================================================
    # UNINSTALLED
    # ========================================================

    SectionHeader "[x]" "UNINSTALLED SOFTWARE" $Software.Uninstalled.Count

    if ($Software.Uninstalled.Count -eq 0) {

        Write-Host "  No verified uninstallation events found." `
            -ForegroundColor DarkGreen

        Write-Host ""
        Write-Host "  Note: Software removed without a retained Windows/WinGet" `
            -ForegroundColor DarkGreen

        Write-Host "        uninstall record cannot be reconstructed reliably." `
            -ForegroundColor DarkGreen
    }
    else {

        Write-Host ""
        Write-Host "  $(PR "SOFTWARE" 28) $(PR "TIME" 21) $(PR "SOURCE" 12)" `
            -ForegroundColor DarkGreen

        Sep


        foreach ($sw in $Software.Uninstalled) {

            $name = $sw.Name

            if ($name.Length -gt 28) {
                $name = $name.Substring(0, 25) + "..."
            }


            Write-Host "  $(PR $name 28) " `
                -NoNewline `
                -ForegroundColor Yellow

            Write-Host "$(PR $sw.Time 21) " `
                -NoNewline `
                -ForegroundColor Yellow

            Write-Host "$(PR $sw.Source 12)" `
                -ForegroundColor Yellow
        }


        Write-Host ""

        Write-Host "  Evidence:" -ForegroundColor DarkGreen

        foreach ($sw in $Software.Uninstalled) {

            Write-Host "    $($sw.Name) -> $($sw.Evidence)" `
                -ForegroundColor DarkGreen
        }
    }
}

# ============================================================
# FILE RENDERER
# ============================================================

function Render-Files($Files, $Days) {

    SectionHeader "[~]" "FILE ACTIVITY" $Files.Count


    if ($Files.Count -eq 0) {

        Write-Host "  No file activity found in the selected period." `
            -ForegroundColor DarkGreen

        return
    }


    Write-Host ""

    Write-Host "  $(PR "ACTION" 11) $(PR "FILE NAME" 28) $(PR "TIME" 19) $(PR "SOURCE" 16)" `
        -ForegroundColor DarkGreen

    Sep


    foreach ($f in ($Files | Select-Object -First 100)) {

        $badge = switch ($f.Action) {

            "Created"  { "CREATED" }
            "Deleted"  { "DELETED" }
            "Modified" { "MODIFIED" }
            "Renamed"  { "RENAMED" }

            default {
                $f.Action.ToUpper()
            }
        }


        $bc = switch ($f.Action) {

            "Created"  { "Green" }
            "Deleted"  { "Red" }
            "Modified" { "Yellow" }
            "Renamed"  { "Cyan" }

            default {
                "Green"
            }
        }


        $name = $f.Name

        if ($name.Length -gt 28) {
            $name = $name.Substring(0, 25) + "..."
        }


        $source = $f.Source

        if ($source.Length -gt 16) {
            $source = $source.Substring(0, 13) + "..."
        }


        Write-Host "  " -NoNewline

        Write-Host $(PR $badge 11) `
            -ForegroundColor $bc `
            -NoNewline

        Write-Host " $(PR $name 28) " `
            -NoNewline `
            -ForegroundColor Green

        Write-Host $(PR $f.Time.ToString("dd MMM yyyy, HH:mm") 19) `
            -NoNewline `
            -ForegroundColor Green

        Write-Host $(PR $source 16) `
            -ForegroundColor DarkGreen
    }


    if ($Files.Count -gt 100) {

        Write-Host ""

        Write-Host "  ... and $($Files.Count - 100) more events" `
            -ForegroundColor DarkGreen
    }


    # ========================================================
    # SUMMARY
    # ========================================================

    Write-Host ""

    $usnCount = @(
        $Files |
        Where-Object {
            $_.Source -eq "NTFS USN" -or
            $_.Source -eq "USN + Security"
        }
    ).Count


    $securityCount = @(
        $Files |
        Where-Object {
            $_.Source -eq "Security" -or
            $_.Source -eq "USN + Security"
        }
    ).Count


    Write-Host "  Evidence sources:" -ForegroundColor DarkGreen

    Write-Host "    NTFS USN Journal : $usnCount" `
        -ForegroundColor DarkGreen

    Write-Host "    Security 4663/4660: $securityCount" `
        -ForegroundColor DarkGreen
}

# ============================================================
# LOGIN RENDERER
# ============================================================

function Render-Logins($Logins, $Days) {

    SectionHeader "[>]" "LOGIN HISTORY" $Logins.Count


    if ($Logins.Count -eq 0) {

        Write-Host "  No login events found." `
            -ForegroundColor DarkGreen

        return
    }


    Write-Host ""

    Write-Host "  $(PR "ACTION" 22) $(PR "USER" 18) $(PR "TIME" 19) $(PR "LOGON TYPE" 25) $(PR "SOURCE IP" 18)" `
        -ForegroundColor DarkGreen

    Sep


    foreach ($login in $Logins) {

        $action = $login.Action

        $color = switch ($login.Action) {

            "Successful Login" { "Green" }
            "Failed Login"     { "Red" }
            "Logoff"           { "Yellow" }
            "User Logoff"      { "Yellow" }

            default {
                "Cyan"
            }
        }


        $user = $login.User

        if ($user.Length -gt 18) {
            $user = $user.Substring(0, 15) + "..."
        }


        $type = $login.LogonType

        if ($type.Length -gt 25) {
            $type = $type.Substring(0, 22) + "..."
        }


        $ip = $login.SourceIP

        if ($ip.Length -gt 18) {
            $ip = $ip.Substring(0, 15) + "..."
        }


        Write-Host "  $(PR $action 22) " `
            -NoNewline `
            -ForegroundColor $color

        Write-Host "$(PR $user 18) " `
            -NoNewline `
            -ForegroundColor Green

        Write-Host "$(PR $login.Time.ToString("dd MMM yyyy, HH:mm") 19) " `
            -NoNewline `
            -ForegroundColor Green

        Write-Host "$(PR $type 25) " `
            -NoNewline `
            -ForegroundColor Green

        Write-Host "$(PR $ip 18)" `
            -ForegroundColor Green
    }
}

# ============================================================
# FULL REPORT
# ============================================================

function Render-FullReport($Software, $Files, $Logins, $Days) {

    Show-Banner

    Render-Stats $Software $Files $Logins
    Render-Software $Software $Days
    Render-Files $Files $Days
    Render-Logins $Logins $Days

    PressEnter
}

# ============================================================
# Export in JSON format
# ============================================================

function Export-DFINTJson {

    param(
        [hashtable]$Software,
        [array]$Files,
        [int]$Days
    )

    try {

        # ----------------------------------------------------
        # Create export directory
        # ----------------------------------------------------

        $exportDir = Join-Path $PSScriptRoot "reports"

        if (-not (Test-Path $exportDir)) {

            New-Item `
                -ItemType Directory `
                -Path $exportDir `
                -Force |
                Out-Null
        }


        # ----------------------------------------------------
        # Generate filename
        # ----------------------------------------------------

        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

        $fileName = "DFINT_Report_$timestamp.json"

        $outputPath = Join-Path $exportDir $fileName


        # ----------------------------------------------------
        # Build report
        # ----------------------------------------------------

        $report = [ordered]@{

            tool = [ordered]@{
                name    = "DFINT"
                version = "1.0"
            }

            investigation = [ordered]@{
                host           = $env:COMPUTERNAME
                user           = "$env:USERDOMAIN\$env:USERNAME"
                collectionTime = (Get-Date).ToString("o")
                periodDays     = $Days
                startTime      = (Get-Date).AddDays(-$Days).ToString("o")
                endTime        = (Get-Date).ToString("o")
            }

            software = [ordered]@{

                installed = @(
                    $Software.Installed |
                    ForEach-Object {

                        [ordered]@{
                            name      = $_.Name
                            time      = $_.Time.ToString("o")
                            location  = $_.Location
                            user      = $_.User
                            source    = $_.Source
                            evidence  = $_.Evidence
                        }
                    }
                )

                uninstalled = @(
                    $Software.Uninstalled |
                    ForEach-Object {

                        [ordered]@{
                            name      = $_.Name
                            time      = $_.Time.ToString("o")
                            location  = $_.Location
                            user      = $_.User
                            source    = $_.Source
                            evidence  = $_.Evidence
                        }
                    }
                )
            }


            fileActivity = @(
                $Files |
                ForEach-Object {

                    [ordered]@{
                        action    = $_.Action
                        name      = $_.Name
                        time      = $_.Time.ToString("o")
                        location  = $_.Location
                        user      = $_.User
                        source    = $_.Source
                        evidence  = $_.Evidence
                    }
                }
            )
        }


        # ----------------------------------------------------
        # Convert to JSON
        # ----------------------------------------------------

        $json = $report |
            ConvertTo-Json -Depth 10


        # ----------------------------------------------------
        # Write file
        # ----------------------------------------------------

        $json |
            Out-File `
                -FilePath $outputPath `
                -Encoding utf8 `
                -Force


        Write-Host ""
        Write-Host "  [+] JSON report exported successfully." `
            -ForegroundColor Green

        Write-Host "      $outputPath" `
            -ForegroundColor DarkGreen

        return $outputPath
    }
    catch {

        Write-Host ""
        Write-Host "  [!] Failed to export JSON report." `
            -ForegroundColor Red

        Write-Host "      $($_.Exception.Message)" `
            -ForegroundColor Red

        return $null
    }
}


# ============================================================
# MAIN MENU
# ============================================================

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

        # ====================================================
        # SOFTWARE
        # ====================================================

        "1" {

            $days = Get-DaysInput

            Show-Banner

            Write-Host "  [+] Collecting software installation evidence..." `
                -ForegroundColor Green

            Write-Host ""

            $sw = Get-SoftwareData -Days $days

            Render-Software $sw $days

            PressEnter
        }


        # ====================================================
        # FILES
        # ====================================================

        "2" {

            $days = Get-DaysInput

            Show-Banner

            Write-Host "  [~] Scanning Security log for file events..." `
                -ForegroundColor Green

            Write-Host ""

            $files = Get-FileData -Days $days

            Render-Files $files $days

            PressEnter
        }


        # ====================================================
        # LOGIN HISTORY
        # ====================================================

        "3" {

            $days = Get-DaysInput

            Show-Banner

            Write-Host "  [@] Scanning Security log for login events..." `
                -ForegroundColor Green

            Write-Host ""

            $logins = Get-LoginData -Days $days

            Render-Logins $logins $days

            PressEnter
        }


        # ====================================================
        # FULL REPORT
        # ====================================================

        "4" {

            $days = Get-DaysInput

            Show-Banner

            Write-Host "  [*] Collecting forensic data..." `
                -ForegroundColor Green

            Write-Host ""

            $sw      = Get-SoftwareData -Days $days
            $files   = Get-FileData -Days $days
            $logins  = Get-LoginData -Days $days

            Render-FullReport $sw $files $logins $days

            Export-DFINTJson `
                -Software $sq `
                -Files $files `
                -Logins $logins `
                -Days $days
        }


        # ====================================================
        # EXIT
        # ====================================================

        "5" {

            Write-Host ""
            Write-Host "  [*] Exiting DFIN. Stay safe." -ForegroundColor Green

            Start-Sleep -Seconds 1

            exit
        }


        # ====================================================
        # INVALID OPTION
        # ====================================================

        default {

            Write-Host ""
            Write-Host "  [!] Invalid choice. Press Enter to continue..." `
                -ForegroundColor Red

            [void][System.Console]::ReadLine()
        }
    }
}
