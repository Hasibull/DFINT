<#
.SYNOPSIS
    DFIN - Digital Forensic Investigation Tool
    Gathers software, file, and login activity from Windows Event Logs.
#>

# ==================== SELF-ELEVATION ====================
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "`n[!] Administrator privileges required. Triggering UAC prompt..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    $cmd = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell.exe -ArgumentList $cmd -Verb RunAs
    exit
}

# ==================== HELPERS ====================
function Show-Header {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "           D F I N   T O O L            " -ForegroundColor Cyan
    Write-Host "    Digital Forensic Investigation      " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-DaysInput {
    param([string]$Context)
    while ($true) {
        $d = Read-Host "For how many days (back from today)"
        if ($d -match '^\d+$' -and [int]$d -gt 0) { return [int]$d }
        Write-Host "Invalid input. Enter a positive number." -ForegroundColor Red
    }
}

function Pause-Menu {
    Write-Host "`nPress Enter to return to menu..." -ForegroundColor DarkGray
    [void][System.Console]::ReadLine()
}

# ==================== MODULE 1: SOFTWARE ====================
function Get-SoftwareHistory {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $installIds = 1033, 11707
    $uninstallIds = 1034, 11724

    Show-Header
    Write-Host "Scanning Application log for software changes (last $Days days)..." -ForegroundColor Yellow
    Write-Host ""

    $installed = @()
    $uninstalled = @()

    # --- Application Log (MSI) ---
    $appEvents = @()
    try {
        $appEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ID = $installIds + $uninstallIds
            StartTime = $start
        } -ErrorAction Stop | Sort-Object TimeCreated
    } catch [System.Exception] {
        if ($_.Exception.Message -like "*No events were found*") {
            Write-Host "[i] No MSI installer events found in Application log for this period." -ForegroundColor DarkYellow
        } else {
            Write-Host "[!] Error reading Application log: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    foreach ($evt in $appEvents) {
        $product = "Unknown Product"
        if ($evt.Message -match "Product Name:\s*(.+?)\.") { $product = $Matches[1].Trim() }
        elseif ($evt.Message -match "Product:\s*([^\r\n]+)") { $product = $Matches[1].Trim() }
        
        $user = "SYSTEM"
        if ($evt.Properties.Count -gt 1 -and $evt.Properties[1].Value) { $user = $evt.Properties[1].Value }
        
        $location = "N/A"
        if ($evt.Message -match "Installation folder:\s*([^\r\n]+)") { $location = $Matches[1].Trim() }

        $row = [PSCustomObject]@{
            Name = $product
            Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm")
            Location = $location
            User = $user
        }

        if ($evt.Id -in $installIds) { $installed += $row } else { $uninstalled += $row }
    }

    # --- Setup Log (Windows Updates / Modern installers) ---
    $setupEvents = @()
    try {
        $setupEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Setup'
            StartTime = $start
        } -ErrorAction Stop | Where-Object { $_.Message -match "install|uninstall|update" } | Sort-Object TimeCreated
    } catch {
        # Setup log might not exist or be empty; silently ignore
    }

    foreach ($evt in $setupEvents) {
        $installed += [PSCustomObject]@{
            Name = if ($evt.Message -match "([^\r\n]+)") { $Matches[1].Trim() } else { "Setup Event" }
            Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm")
            Location = "Windows Setup Log"
            User = "SYSTEM"
        }
    }

    # --- Output ---
    Write-Host "INSTALLED SOFTWARE" -ForegroundColor Green
    Write-Host "------------------" -ForegroundColor Green
    if ($installed.Count -eq 0) {
        Write-Host "No installation events found." -ForegroundColor DarkGray
    } else {
        $installed | Format-Table -AutoSize
    }

    Write-Host "`nUNINSTALLED SOFTWARE" -ForegroundColor Red
    Write-Host "--------------------" -ForegroundColor Red
    if ($uninstalled.Count -eq 0) {
        Write-Host "No uninstallation events found." -ForegroundColor DarkGray
    } else {
        $uninstalled | Format-Table -AutoSize
    }

    Write-Host "`nNote: Only MSI-based installers and Windows Updates are logged here." -ForegroundColor DarkYellow
    Pause-Menu
}

# ==================== MODULE 2: FILE ACTIVITY ====================
function Get-FileActivity {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)

    Show-Header
    Write-Host "Scanning Security log for file activity (last $Days days)..." -ForegroundColor Yellow
    Write-Host ""

    # First check if file auditing is even enabled
    $auditPolicy = auditpol /get /subcategory:"File System" 2>$null
    $isAuditing = $auditPolicy -match "Success|Failure"

    if (-not $isAuditing) {
        Write-Host "[!] WARNING: File System auditing does not appear to be enabled." -ForegroundColor Red
        Write-Host "    No file creation/deletion events will exist unless auditing was" -ForegroundColor Red
        Write-Host "    previously turned on and SACLs were configured on target folders." -ForegroundColor Red
        Write-Host "`n    To enable going forward (won't help retroactively):" -ForegroundColor DarkYellow
        Write-Host "    auditpol /set /subcategory:'File System' /success:enable /failure:enable" -ForegroundColor DarkYellow
        Write-Host ""
    }

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4663, 4660, 4656
            StartTime = $start
        } -ErrorAction Stop | Sort-Object TimeCreated

        $created = @()
        $deleted = @()
        $accessed = @()

        foreach ($evt in $events) {
            $msg = $evt.Message
            $time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm:ss")

            # Extract Subject (User)
            $user = "N/A"
            if ($msg -match "Account Name:\s+([^\r\n]+)") { $user = $Matches[1].Trim() }

            # Extract Object Name (File/Folder path)
            $objectName = "N/A"
            if ($msg -match "Object Name:\s+([^\r\n]+)") { $objectName = $Matches[1].Trim() }

            # Determine action from Access Mask or keywords
            $action = "Accessed"
            if ($msg -match "WriteData \(or AddFile\)" -or $msg -match "0x2") { $action = "Created/Modified" }
            if ($msg -match "Delete" -or $evt.Id -eq 4660) { $action = "Deleted" }

            $row = [PSCustomObject]@{
                Name = Split-Path $objectName -Leaf
                Time = $time
                Location = $objectName
                User = $user
            }

            switch -Regex ($action) {
                "Created" { $created += $row }
                "Deleted" { $deleted += $row }
                default   { $accessed += $row }
            }
        }

        # Created
        Write-Host "CREATED / MODIFIED FILES" -ForegroundColor Green
        Write-Host "------------------------" -ForegroundColor Green
        if ($created.Count -eq 0) {
            Write-Host "No file creation events found." -ForegroundColor DarkGray
        } else {
            $created | Select-Object -First 50 | Format-Table -AutoSize
            if ($created.Count -gt 50) { Write-Host "... and $($created.Count - 50) more events" -ForegroundColor DarkGray }
        }

        # Deleted
        Write-Host "`nDELETED FILES" -ForegroundColor Red
        Write-Host "-------------" -ForegroundColor Red
        if ($deleted.Count -eq 0) {
            Write-Host "No file deletion events found." -ForegroundColor DarkGray
        } else {
            $deleted | Select-Object -First 50 | Format-Table -AutoSize
            if ($deleted.Count -gt 50) { Write-Host "... and $($deleted.Count - 50) more events" -ForegroundColor DarkGray }
        }

        Write-Host "`nNote: File auditing must be enabled BEFORE events occur." -ForegroundColor DarkYellow
        Write-Host "      Results depend on SACL configuration on target folders." -ForegroundColor DarkYellow

    } catch [System.Exception] {
        if ($_.Exception.Message -like "*Access is denied*") {
            Write-Host "Access denied to Security log. Ensure you ran as Administrator." -ForegroundColor Red
        } else {
            Write-Host "Error reading Security log: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Pause-Menu
}

# ==================== MODULE 3: LOGIN HISTORY ====================
function Get-LoginHistory {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)

    Show-Header
    Write-Host "Scanning Security log for login activity (last $Days days)..." -ForegroundColor Yellow
    Write-Host ""

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624, 4625, 4634, 4648
            StartTime = $start
        } -ErrorAction Stop | Sort-Object TimeCreated

        $logins = @()
        $failed = @()
        $logoffs = @()

        foreach ($evt in $events) {
            $time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm:ss")
            
            # Extract from Properties array (faster than regex on huge messages)
            $targetUser = if ($evt.Properties[5]) { $evt.Properties[5].Value } else { "N/A" }
            $logonType = if ($evt.Properties[8]) { $evt.Properties[8].Value } else { "N/A" }
            $workstation = if ($evt.Properties[11]) { $evt.Properties[11].Value } else { "N/A" }
            $ipAddress = if ($evt.Properties[18]) { $evt.Properties[18].Value } else { "N/A" }

            # Filter out common noise accounts
            if ($targetUser -in "SYSTEM","LOCAL SERVICE","NETWORK SERVICE","ANONYMOUS LOGON","DWM-1","UMFD-1") { continue }

            # Map logon type
            $typeDesc = switch ($logonType) {
                2  { "Interactive (Local)" }
                3  { "Network (Share)" }
                4  { "Batch" }
                5  { "Service" }
                7  { "Unlock" }
                8  { "NetworkCleartext" }
                9  { "NewCredentials" }
                10 { "RemoteDesktop (RDP)" }
                11 { "CachedInteractive" }
                default { "Type $logonType" }
            }

            $location = if ($ipAddress -ne "-") { "$workstation ($ipAddress)" } else { $workstation }

            $row = [PSCustomObject]@{
                Name = $targetUser
                Time = $time
                Location = $location
                User = $typeDesc
            }

            switch ($evt.Id) {
                4624 { $logins += $row }
                4625 { $failed += $row }
                4634 { $logoffs += $row }
                4648 { $logins += $row }  # Explicit credential logon
            }
        }

        # Successful Logins
        Write-Host "SUCCESSFUL LOGINS" -ForegroundColor Green
        Write-Host "-----------------" -ForegroundColor Green
        if ($logins.Count -eq 0) {
            Write-Host "No login events found." -ForegroundColor DarkGray
        } else {
            $logins | Sort-Object Time -Descending | Select-Object -First 50 | Format-Table -AutoSize
            if ($logins.Count -gt 50) { Write-Host "... and $($logins.Count - 50) more events" -ForegroundColor DarkGray }
        }

        # Failed Logins
        Write-Host "`nFAILED LOGINS" -ForegroundColor Red
        Write-Host "-------------" -ForegroundColor Red
        if ($failed.Count -eq 0) {
            Write-Host "No failed login events found." -ForegroundColor DarkGray
        } else {
            $failed | Sort-Object Time -Descending | Select-Object -First 50 | Format-Table -AutoSize
            if ($failed.Count -gt 50) { Write-Host "... and $($failed.Count - 50) more events" -ForegroundColor DarkGray }
        }

        # Logoffs
        Write-Host "`nLOGOFFS" -ForegroundColor DarkCyan
        Write-Host "-------" -ForegroundColor DarkCyan
        if ($logoffs.Count -eq 0) {
            Write-Host "No logoff events found." -ForegroundColor DarkGray
        } else {
            $logoffs | Sort-Object Time -Descending | Select-Object -First 30 | Format-Table -AutoSize
        }

    } catch [System.Exception] {
        if ($_.Exception.Message -like "*Access is denied*") {
            Write-Host "Access denied to Security log. Ensure you ran as Administrator." -ForegroundColor Red
        } else {
            Write-Host "Error reading Security log: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Pause-Menu
}

# ==================== MODULE 4: ALL ====================
function Get-AllForensics {
    param([int]$Days)
    Get-SoftwareHistory -Days $Days
    Get-FileActivity -Days $Days
    Get-LoginHistory -Days $Days
}

# ==================== MAIN MENU ====================
while ($true) {
    Show-Header
    Write-Host "What to look for?" -ForegroundColor White
    Write-Host "  1. Installed/Uninstalled software"
    Write-Host "  2. Created/Deleted files"
    Write-Host "  3. User Login history"
    Write-Host "  4. All"
    Write-Host "  5. Exit"
    Write-Host ""
    
    $choice = Read-Host "Choose your option"
    
    switch ($choice) {
        "1" { 
            $days = Get-DaysInput
            Get-SoftwareHistory -Days $days 
        }
        "2" { 
            $days = Get-DaysInput
            Get-FileActivity -Days $days 
        }
        "3" { 
            $days = Get-DaysInput
            Get-LoginHistory -Days $days 
        }
        "4" { 
            $days = Get-DaysInput
            Get-AllForensics -Days $days 
        }
        "5" { 
            Write-Host "`nExiting DFIN. Stay safe." -ForegroundColor Cyan
            Start-Sleep -Seconds 1
            exit 
        }
        default { 
            Write-Host "Invalid choice. Press Enter to continue..." -ForegroundColor Red
            [void][System.Console]::ReadLine()
        }
    }
}