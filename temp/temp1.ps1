<#
.SYNOPSIS
    DFIN - Digital Forensic Investigation Tool
    Exports a beautiful HTML report from Windows Event Logs.
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
    while ($true) {
        $d = Read-Host "For how many days (back from today)"
        if ($d -match '^\d+$' -and [int]$d -gt 0) { return [int]$d }
        Write-Host "Invalid input. Enter a positive number." -ForegroundColor Red
    }
}

# ==================== DATA COLLECTORS ====================
function Get-SoftwareData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $installed = New-Object System.Collections.Generic.List[object]
    $uninstalled = New-Object System.Collections.Generic.List[object]

    # Application Log (MSI)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            ID = 1033, 11707, 1034, 11724
            StartTime = $start
        } -ErrorAction Stop | Sort-Object TimeCreated

        foreach ($evt in $events) {
            $product = "Unknown Product"
            if ($evt.Message -match "Product Name:\s*(.+?)\.") { $product = $Matches[1].Trim() }
            elseif ($evt.Message -match "Product:\s*([^\r\n]+)") { $product = $Matches[1].Trim() }

            $user = "SYSTEM"
            if ($evt.Properties.Count -gt 1 -and $evt.Properties[1].Value) { $user = $evt.Properties[1].Value }

            $location = "N/A"
            if ($evt.Message -match "Installation folder:\s*([^\r\n]+)") { $location = $Matches[1].Trim() }

            $row = New-Object PSObject -Property @{
                Name = $product
                Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm")
                Location = $location
                User = $user
            }

            if ($evt.Id -in 1033, 11707) { $installed.Add($row) } else { $uninstalled.Add($row) }
        }
    } catch { }

    # Setup Log (Windows Updates / Modern installers)
    try {
        $setupEvents = Get-WinEvent -FilterHashtable @{LogName = 'Setup'; StartTime = $start} -ErrorAction Stop |
            Where-Object { $_.Message -match "install|uninstall|update" }
        foreach ($evt in $setupEvents) {
            $name = "Setup Event"
            if ($evt.Message -match "([^\r\n]+)") { $name = $Matches[1].Trim() }
            $row = New-Object PSObject -Property @{
                Name = $name
                Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm")
                Location = "Windows Setup Log"
                User = "SYSTEM"
            }
            $installed.Add($row)
        }
    } catch { }

    return @{ Installed = $installed.ToArray(); Uninstalled = $uninstalled.ToArray() }
}

function Get-FileData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $files = New-Object System.Collections.Generic.List[object]

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4663, 4660, 4656
            StartTime = $start
        } -ErrorAction Stop | Sort-Object TimeCreated

        foreach ($evt in $events) {
            $msg = $evt.Message
            $user = "N/A"
            if ($msg -match "Account Name:\s+([^\r\n]+)") { $user = $Matches[1].Trim() }

            $objectName = "N/A"
            if ($msg -match "Object Name:\s+([^\r\n]+)") { $objectName = $Matches[1].Trim() }

            $action = "Accessed"
            $actionClass = "modified"
            $actionIcon = "&#9998;"
            if ($msg -match "WriteData \(or AddFile\)" -or $msg -match "0x2") {
                $action = "Created"
                $actionClass = "created"
                $actionIcon = "&#10133;"
            }
            if ($msg -match "Delete" -or $evt.Id -eq 4660) {
                $action = "Deleted"
                $actionClass = "deleted"
                $actionIcon = "&#10005;"
            }

            $leafName = $objectName
            if ($objectName -ne "N/A" -and $objectName -match "\\") {
                $leafName = Split-Path $objectName -Leaf
            }

            $row = New-Object PSObject -Property @{
                Action = $action
                ActionClass = $actionClass
                ActionIcon = $actionIcon
                Name = $leafName
                Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm")
                Location = $objectName
                User = $user
            }
            $files.Add($row)
        }
    } catch { }

    return $files.ToArray()
}

function Get-LoginData {
    param([int]$Days)
    $start = (Get-Date).AddDays(-$Days)
    $logins = New-Object System.Collections.Generic.List[object]

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            ID = 4624, 4625, 4634
            StartTime = $start
        } -ErrorAction Stop | Sort-Object TimeCreated

        foreach ($evt in $events) {
            $targetUser = if ($evt.Properties[5]) { $evt.Properties[5].Value } else { "N/A" }
            if ($targetUser -in "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "DWM-1", "UMFD-1") { continue }

            $logonType = if ($evt.Properties[8]) { $evt.Properties[8].Value } else { "N/A" }
            $workstation = if ($evt.Properties[11]) { $evt.Properties[11].Value } else { "N/A" }
            $ipAddress = if ($evt.Properties[18]) { $evt.Properties[18].Value } else { "-" }

            $typeDesc = "Type $logonType"
            $typeClass = "other"
            $typeIcon = "&#10067;"
            if ($logonType -eq 2) {
                $typeDesc = "Interactive"
                $typeClass = "interactive"
                $typeIcon = "&#128187;"
            } elseif ($logonType -eq 3) {
                $typeDesc = "Network"
                $typeClass = "network"
                $typeIcon = "&#127760;"
            } elseif ($logonType -eq 7) {
                $typeDesc = "Unlock"
                $typeClass = "unlock"
                $typeIcon = "&#128275;"
            } elseif ($logonType -eq 10) {
                $typeDesc = "RemoteDesktop"
                $typeClass = "rdp"
                $typeIcon = "&#127760;"
            }

            $status = "Success"
            $statusClass = "success"
            if ($evt.Id -eq 4625) {
                $status = "Failed"
                $statusClass = "failed"
            }

            $initial = "?"
            if ($targetUser -and $targetUser -ne "N/A" -and $targetUser.Length -gt 0) {
                $initial = $targetUser.Substring(0, 1).ToUpper()
            }

            $ws = $workstation
            if ($ipAddress -ne "-") {
                $ws = "$workstation ($ipAddress)"
            }

            $row = New-Object PSObject -Property @{
                User = $targetUser
                Initial = $initial
                Time = $evt.TimeCreated.ToString("dd MMM yyyy, HH:mm")
                Logoff = "-"
                Type = $typeDesc
                TypeClass = $typeClass
                TypeIcon = $typeIcon
                Workstation = $ws
                Status = $status
                StatusClass = $statusClass
            }
            $logins.Add($row)
        }
    } catch { }

    return $logins.ToArray()
}

# ==================== HTML REPORT GENERATOR ====================
function Export-DFINReport {
    param(
        [hashtable]$Software,
        [array]$Files,
        [array]$Logins,
        [int]$Days
    )

    $reportDate = (Get-Date).ToString("dd MMM yyyy 'at' HH:mm")
    $hostname = $env:COMPUTERNAME

    # Build Installed rows
    $instRows = New-Object System.Collections.Generic.List[string]
    if ($Software.Installed.Count -eq 0) {
        $instRows.Add('<tr><td colspan="4" class="empty">No installation events found in the specified period.</td></tr>')
    } else {
        $icons = @("A", "B", "C", "D", "E", "F", "G", "H")
        $iconCls = @("app-cyan", "app-green", "app-amber", "app-red")
        for ($i = 0; $i -lt $Software.Installed.Count; $i++) {
            $sw = $Software.Installed[$i]
            $ic = $icons[$i % $icons.Length]
            $cl = $iconCls[$i % $iconCls.Length]
            $instRows.Add("<tr><td><div style='display:flex;align-items:center;gap:10px'><div class='app-icon $cl'>$ic</div>$($sw.Name)</div></td><td><span class='timestamp'><span class='dot dot-cyan'></span>$($sw.Time)</span></td><td class='mono' style='color:#94a3b8'>$($sw.Location)</td><td><span class='tag tag-blue'>$($sw.User)</span></td></tr>")
        }
    }

    # Build Uninstalled rows
    $uninstRows = New-Object System.Collections.Generic.List[string]
    if ($Software.Uninstalled.Count -eq 0) {
        $uninstRows.Add('<tr><td colspan="4" class="empty">No uninstallation events found in the specified period.</td></tr>')
    } else {
        foreach ($sw in $Software.Uninstalled) {
            $uninstRows.Add("<tr><td><div style='display:flex;align-items:center;gap:10px'><div class='app-icon app-red'>X</div>$($sw.Name)</div></td><td><span class='timestamp'><span class='dot dot-red'></span>$($sw.Time)</span></td><td class='mono strikethrough' style='color:#94a3b8'>$($sw.Location)</td><td><span class='tag tag-red'>$($sw.User)</span></td></tr>")
        }
    }

    # Build File rows
    $fileRows = New-Object System.Collections.Generic.List[string]
    if ($Files.Count -eq 0) {
        $fileRows.Add('<tr><td colspan="5" class="empty">No file events found. File auditing may not be enabled on this system.</td></tr>')
    } else {
        $displayFiles = $Files | Select-Object -First 50
        foreach ($f in $displayFiles) {
            $delStyle = ""
            if ($f.ActionClass -eq 'deleted') { $delStyle = "text-decoration:line-through;opacity:0.7" }
            $userTag = "tag-blue"
            if ($f.User -eq 'administrator') { $userTag = "tag-purple" }
            $fileRows.Add("<tr><td><span class='action-tag action-$($f.ActionClass)'><span>$($f.ActionIcon)</span> $($f.Action)</span></td><td class='mono' style='color:#e2e8f0;$delStyle'>$($f.Name)</td><td style='color:#94a3b8;font-size:12px'>$($f.Time)</td><td class='mono' style='color:#64748b;font-size:11px'>$($f.Location)</td><td><span class='tag $userTag'>$($f.User)</span></td></tr>")
        }
        if ($Files.Count -gt 50) {
            $fileRows.Add("<tr><td colspan='5' style='text-align:center;color:#64748b;padding:12px'>... and $($Files.Count - 50) more events</td></tr>")
        }
    }

    # Build Login rows
    $loginRows = New-Object System.Collections.Generic.List[string]
    if ($Logins.Count -eq 0) {
        $loginRows.Add('<tr><td colspan="5" class="empty">No login events found in the specified period.</td></tr>')
    } else {
        $avatarColors = @("avatar-blue", "avatar-purple", "avatar-red")
        $displayLogins = $Logins | Select-Object -First 50
        for ($i = 0; $i -lt $displayLogins.Count; $i++) {
            $l = $displayLogins[$i]
            $avatar = $avatarColors[$i % 3]
            $dot = "dot-cyan"
            if ($l.StatusClass -eq 'failed') { $dot = "dot-red" }
            $loginRows.Add("<tr><td><div style='display:flex;align-items:center;gap:10px'><div class='user-avatar $avatar'>$($l.Initial)</div>$($l.User)</div></td><td><span class='timestamp'><span class='dot $dot'></span>$($l.Time)</span></td><td style='color:#94a3b8'>$($l.Logoff)</td><td><span class='type-tag type-$($l.TypeClass)'>$($l.TypeIcon) $($l.Type)</span></td><td class='mono' style='color:#94a3b8'>$($l.Workstation)</td></tr>")
        }
        if ($Logins.Count -gt 50) {
            $loginRows.Add("<tr><td colspan='5' style='text-align:center;color:#64748b;padding:12px'>... and $($Logins.Count - 50) more events</td></tr>")
        }
    }

    # Assemble HTML
    $htmlParts = New-Object System.Collections.Generic.List[string]
    
    $htmlParts.Add('<!DOCTYPE html>')
    $htmlParts.Add('<html lang="en"><head><meta charset="UTF-8">')
    $htmlParts.Add("<title>DFIN Forensic Report - $hostname</title>")
    $htmlParts.Add('<style>')
    $htmlParts.Add('*{margin:0;padding:0;box-sizing:border-box}')
    $htmlParts.Add("body{font-family:'Segoe UI',system-ui,sans-serif;background:linear-gradient(135deg,#0f172a 0%,#1e293b 100%);min-height:100vh;padding:24px;color:#e2e8f0}")
    $htmlParts.Add('.container{max-width:1200px;margin:0 auto}')
    $htmlParts.Add('.header{text-align:center;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid #334155}')
    $htmlParts.Add('.brand{display:inline-flex;align-items:center;gap:12px;margin-bottom:8px}')
    $htmlParts.Add('.logo{width:48px;height:48px;background:linear-gradient(135deg,#06b6d4,#3b82f6);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;box-shadow:0 4px 15px rgba(6,182,212,0.3)}')
    $htmlParts.Add('h1{margin:0;font-size:32px;font-weight:700;background:linear-gradient(90deg,#06b6d4,#60a5fa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-0.5px}')
    $htmlParts.Add('.subtitle{margin:0;color:#94a3b8;font-size:14px;letter-spacing:2px;text-transform:uppercase}')
    $htmlParts.Add('.badge{margin-top:12px;display:inline-flex;align-items:center;gap:8px;background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);padding:6px 16px;border-radius:20px;font-size:12px;color:#22d3ee}')
    $htmlParts.Add('.pulse{width:8px;height:8px;background:#22d3ee;border-radius:50%;animation:pulse 2s infinite}')
    $htmlParts.Add('@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}')
    $htmlParts.Add('.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-bottom:28px}')
    $htmlParts.Add('.stat-card{padding:20px;border-radius:16px;backdrop-filter:blur(10px)}')
    $htmlParts.Add('.stat-cyan{background:linear-gradient(135deg,rgba(6,182,212,0.15),rgba(59,130,246,0.1));border:1px solid rgba(6,182,212,0.2)}')
    $htmlParts.Add('.stat-red{background:linear-gradient(135deg,rgba(239,68,68,0.15),rgba(249,115,22,0.1));border:1px solid rgba(239,68,68,0.2)}')
    $htmlParts.Add('.stat-green{background:linear-gradient(135deg,rgba(16,185,129,0.15),rgba(34,197,94,0.1));border:1px solid rgba(16,185,129,0.2)}')
    $htmlParts.Add('.stat-purple{background:linear-gradient(135deg,rgba(168,85,247,0.15),rgba(139,92,246,0.1));border:1px solid rgba(168,85,247,0.2)}')
    $htmlParts.Add('.stat-label{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}')
    $htmlParts.Add('.stat-value{font-size:32px;font-weight:700}')
    $htmlParts.Add('.stat-cyan .stat-value{color:#22d3ee}')
    $htmlParts.Add('.stat-red .stat-value{color:#f87171}')
    $htmlParts.Add('.stat-green .stat-value{color:#34d399}')
    $htmlParts.Add('.stat-purple .stat-value{color:#c084fc}')
    $htmlParts.Add('.stat-note{font-size:12px;color:#64748b;margin-top:4px}')
    $htmlParts.Add('.panel{background:rgba(30,41,59,0.6);border:1px solid #334155;border-radius:16px;margin-bottom:20px;overflow:hidden;backdrop-filter:blur(10px)}')
    $htmlParts.Add('.panel-header{padding:16px 20px;border-bottom:1px solid #334155;display:flex;align-items:center;gap:10px}')
    $htmlParts.Add('.panel-cyan{background:linear-gradient(90deg,rgba(6,182,212,0.2),transparent)}')
    $htmlParts.Add('.panel-red{background:linear-gradient(90deg,rgba(239,68,68,0.2),transparent)}')
    $htmlParts.Add('.panel-green{background:linear-gradient(90deg,rgba(16,185,129,0.2),transparent)}')
    $htmlParts.Add('.panel-purple{background:linear-gradient(90deg,rgba(168,85,247,0.2),transparent)}')
    $htmlParts.Add('.panel-title{font-weight:600;font-size:15px}')
    $htmlParts.Add('.panel-cyan .panel-title{color:#22d3ee}')
    $htmlParts.Add('.panel-red .panel-title{color:#f87171}')
    $htmlParts.Add('.panel-green .panel-title{color:#34d399}')
    $htmlParts.Add('.panel-purple .panel-title{color:#c084fc}')
    $htmlParts.Add('.badge-count{margin-left:auto;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600}')
    $htmlParts.Add('.panel-cyan .badge-count{background:rgba(6,182,212,0.2);color:#22d3ee}')
    $htmlParts.Add('.panel-red .badge-count{background:rgba(239,68,68,0.2);color:#f87171}')
    $htmlParts.Add('.panel-green .badge-count{background:rgba(16,185,129,0.2);color:#34d399}')
    $htmlParts.Add('.panel-purple .badge-count{background:rgba(168,85,247,0.2);color:#c084fc}')
    $htmlParts.Add('table{width:100%;border-collapse:collapse;font-size:13px}')
    $htmlParts.Add('th{padding:14px 20px;text-align:left;color:#94a3b8;font-weight:500;text-transform:uppercase;font-size:11px;letter-spacing:0.5px;border-bottom:1px solid #334155;background:rgba(15,23,42,0.5)}')
    $htmlParts.Add('td{padding:14px 20px}')
    $htmlParts.Add('tr{border-bottom:1px solid rgba(51,65,85,0.5)}')
    $htmlParts.Add('tr:last-child{border-bottom:none}')
    $htmlParts.Add('.app-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff}')
    $htmlParts.Add('.app-cyan{background:rgba(6,182,212,0.3)}')
    $htmlParts.Add('.app-green{background:rgba(16,185,129,0.3)}')
    $htmlParts.Add('.app-amber{background:rgba(245,158,11,0.3)}')
    $htmlParts.Add('.app-red{background:rgba(239,68,68,0.3)}')
    $htmlParts.Add('.user-avatar{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:white}')
    $htmlParts.Add('.avatar-blue{background:linear-gradient(135deg,#3b82f6,#06b6d4)}')
    $htmlParts.Add('.avatar-purple{background:linear-gradient(135deg,#8b5cf6,#ec4899)}')
    $htmlParts.Add('.avatar-red{background:linear-gradient(135deg,#ef4444,#f97316)}')
    $htmlParts.Add('.tag{padding:3px 10px;border-radius:6px;font-size:11px;font-weight:500}')
    $htmlParts.Add('.tag-blue{background:rgba(59,130,246,0.15);color:#60a5fa}')
    $htmlParts.Add('.tag-red{background:rgba(239,68,68,0.15);color:#f87171}')
    $htmlParts.Add('.tag-purple{background:rgba(168,85,247,0.15);color:#c084fc}')
    $htmlParts.Add('.action-tag{padding:3px 10px;border-radius:6px;font-size:11px;font-weight:600;display:inline-flex;align-items:center;gap:4px}')
    $htmlParts.Add('.action-created{background:rgba(16,185,129,0.2);color:#34d399}')
    $htmlParts.Add('.action-modified{background:rgba(245,158,11,0.2);color:#fbbf24}')
    $htmlParts.Add('.action-deleted{background:rgba(239,68,68,0.2);color:#f87171}')
    $htmlParts.Add('.type-tag{padding:3px 10px;border-radius:6px;font-size:11px;font-weight:500}')
    $htmlParts.Add('.type-interactive{background:rgba(16,185,129,0.2);color:#34d399}')
    $htmlParts.Add('.type-rdp{background:rgba(245,158,11,0.2);color:#fbbf24}')
    $htmlParts.Add('.type-failed{background:rgba(239,68,68,0.2);color:#f87171}')
    $htmlParts.Add('.type-other{background:rgba(100,116,139,0.2);color:#94a3b8}')
    $htmlParts.Add('.strikethrough{text-decoration:line-through;opacity:0.7}')
    $htmlParts.Add('.mono{font-family:monospace;font-size:12px}')
    $htmlParts.Add('.timestamp{color:#cbd5e1;display:inline-flex;align-items:center;gap:6px}')
    $htmlParts.Add('.dot{width:6px;height:6px;border-radius:50%;display:inline-block}')
    $htmlParts.Add('.dot-cyan{background:#22d3ee}')
    $htmlParts.Add('.dot-red{background:#f87171}')
    $htmlParts.Add('.empty{padding:20px;color:#64748b;text-align:center}')
    $htmlParts.Add('.footer{text-align:center;padding:20px;color:#64748b;font-size:12px;border-top:1px solid #334155;margin-top:10px}')
    $htmlParts.Add('</style></head><body>')
    $htmlParts.Add('<div class="container">')
    $htmlParts.Add('<div class="header"><div class="brand"><div class="logo">&#128269;</div><h1>DFIN</h1></div><p class="subtitle">Digital Forensic Investigation Tool</p><div class="badge"><span class="pulse"></span>Scanning last ' + $Days + ' days &bull; ' + $hostname + '</div></div>')
    $htmlParts.Add('<div class="stats">')
    $htmlParts.Add('<div class="stat-card stat-cyan"><div class="stat-label">Installed</div><div class="stat-value">' + $Software.Installed.Count + '</div><div class="stat-note">Software packages</div></div>')
    $htmlParts.Add('<div class="stat-card stat-red"><div class="stat-label">Uninstalled</div><div class="stat-value">' + $Software.Uninstalled.Count + '</div><div class="stat-note">Software packages</div></div>')
    $htmlParts.Add('<div class="stat-card stat-green"><div class="stat-label">File Events</div><div class="stat-value">' + $Files.Count + '</div><div class="stat-note">Created / Modified / Deleted</div></div>')
    $htmlParts.Add('<div class="stat-card stat-purple"><div class="stat-label">User Logins</div><div class="stat-value">' + $Logins.Count + '</div><div class="stat-note">Session events</div></div>')
    $htmlParts.Add('</div>')

    $htmlParts.Add('<div class="panel"><div class="panel-header panel-cyan"><span style="font-size:18px">&#128230;</span><span class="panel-title">Installed Software</span><span class="badge-count">' + $Software.Installed.Count + ' found</span></div><table><thead><tr><th>Name</th><th>Installation Time</th><th>Location</th><th>User</th></tr></thead><tbody>')
    foreach ($r in $instRows) { $htmlParts.Add($r) }
    $htmlParts.Add('</tbody></table></div>')

    $htmlParts.Add('<div class="panel"><div class="panel-header panel-red"><span style="font-size:18px">&#128465;</span><span class="panel-title">Uninstalled Software</span><span class="badge-count">' + $Software.Uninstalled.Count + ' found</span></div><table><thead><tr><th>Name</th><th>Uninstallation Time</th><th>Location</th><th>User</th></tr></thead><tbody>')
    foreach ($r in $uninstRows) { $htmlParts.Add($r) }
    $htmlParts.Add('</tbody></table></div>')

    $htmlParts.Add('<div class="panel"><div class="panel-header panel-green"><span style="font-size:18px">&#128193;</span><span class="panel-title">File Activity</span><span class="badge-count">' + $Files.Count + ' events</span></div><table><thead><tr><th>Action</th><th>File Name</th><th>Timestamp</th><th>Location</th><th>User</th></tr></thead><tbody>')
    foreach ($r in $fileRows) { $htmlParts.Add($r) }
    $htmlParts.Add('</tbody></table></div>')

    $htmlParts.Add('<div class="panel"><div class="panel-header panel-purple"><span style="font-size:18px">&#128100;</span><span class="panel-title">User Login History</span><span class="badge-count">' + $Logins.Count + ' sessions</span></div><table><thead><tr><th>User</th><th>Login Time</th><th>Logoff Time</th><th>Type</th><th>Workstation / IP</th></tr></thead><tbody>')
    foreach ($r in $loginRows) { $htmlParts.Add($r) }
    $htmlParts.Add('</tbody></table></div>')

    $htmlParts.Add('<div class="footer"><p>DFIN Forensic Report &bull; Generated on ' + $reportDate + '</p><p style="margin-top:4px;opacity:0.7">Data sourced from Windows Event Logs (Application, Security, Setup)</p></div>')
    $htmlParts.Add('</div></body></html>')

    $html = $htmlParts -join "`n"
    $outPath = "$env:TEMP\DFIN_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $html | Out-File -FilePath $outPath -Encoding UTF8
    return $outPath
}

# ==================== MAIN MENU ====================
while ($true) {
    Show-Header
    Write-Host "What to look for?" -ForegroundColor White
    Write-Host "  1. Installed/Uninstalled software"
    Write-Host "  2. Created/Deleted files"
    Write-Host "  3. User Login history"
    Write-Host "  4. All (Generate full HTML report)"
    Write-Host "  5. Exit"
    Write-Host ""

    $choice = Read-Host "Choose your option"

    switch ($choice) {
        "1" {
            $days = Get-DaysInput
            $sw = Get-SoftwareData -Days $days
            $path = Export-DFINReport -Software $sw -Files @() -Logins @() -Days $days
            Start-Process $path
            Write-Host "`n[i] Report opened in browser: $path" -ForegroundColor Green
            Start-Sleep -Seconds 2
        }
        "2" {
            $days = Get-DaysInput
            $files = Get-FileData -Days $days
            $path = Export-DFINReport -Software @{Installed = @(); Uninstalled = @() } -Files $files -Logins @() -Days $days
            Start-Process $path
            Write-Host "`n[i] Report opened in browser: $path" -ForegroundColor Green
            Start-Sleep -Seconds 2
        }
        "3" {
            $days = Get-DaysInput
            $logins = Get-LoginData -Days $days
            $path = Export-DFINReport -Software @{Installed = @(); Uninstalled = @() } -Files @() -Logins $logins -Days $days
            Start-Process $path
            Write-Host "`n[i] Report opened in browser: $path" -ForegroundColor Green
            Start-Sleep -Seconds 2
        }
        "4" {
            $days = Get-DaysInput
            Write-Host "`n[*] Collecting forensic data... Please wait." -ForegroundColor Cyan
            $sw = Get-SoftwareData -Days $days
            Write-Host "    [OK] Software log scanned" -ForegroundColor Green
            $files = Get-FileData -Days $days
            Write-Host "    [OK] File activity log scanned" -ForegroundColor Green
            $logins = Get-LoginData -Days $days
            Write-Host "    [OK] Security log scanned" -ForegroundColor Green
            $path = Export-DFINReport -Software $sw -Files $files -Logins $logins -Days $days
            Start-Process $path
            Write-Host "`n[OK] Full forensic report generated and opened!" -ForegroundColor Green
            Write-Host "    Location: $path" -ForegroundColor DarkGray
            Start-Sleep -Seconds 3
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