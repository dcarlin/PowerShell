# Windows Incident Response Analysis Script
# Author: Derek Carlin
# Purpose: Initial analysis of potentially compromised Windows system
# This script analyzes the host windows system, creates the C:\Logs folder and generates multiple analysis artifacts and a summarized report for review.
#Instructions: To improve this script, update the variables with safe paths, suspicious paths, and suspicious ports.
# To run this script. '.\Live-Response-Triage.ps1'

# Create log directory if it doesn't exist
$logPath = "C:\Logs\IR_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $logPath

# Function to write colored output and log
function Write-IRLog {
    param($Message, $LogFile)
    Write-Host $Message -ForegroundColor Green
    Add-Content -Path "$logPath\$LogFile" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
}

# Function to export objects to CSV
function Export-ToCSV {
    param($Data, $FileName)
    $Data | Export-Csv -Path "$logPath\$FileName" -NoTypeInformation
    Write-IRLog "Exported data to $FileName" "main.log"
}

# Enhanced suspicious path detection function
function Test-SuspiciousPath {
    param(
        [string]$Path,
        [string]$Type  # 'Service', 'Process', or 'Connection'
    )
    
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    
    # Normalize path for consistent comparison
    $normalizedPath = $Path.ToLower().Replace('"', '').Trim()
    
    # Define safe paths that should be excluded from flagging
    $safePaths = @(
        'c:\windows\system32',
        'c:\windows\syswow64',
        'c:\program files',
        'c:\program files (x86)'
    )
    
    # Define explicitly suspicious locations to check
    # Note: These paths are now more specific to avoid false positives
    $suspiciousLocations = @(
        '\appdata\local\temp\',      # Specific temp directory
        '\windows\temp\',            # Windows temp
        '\users\public\',            # Public user directory
        '\recycler\',                # Recycler directory
        '\programdata\temp\',        # ProgramData temp
        'c:\temp\',                  # Root temp directory
        '\windows\system32\tasks\'   # Tasks directory when not from a safe path
    )
    
    # Check if path is in safe location
    $isSafePath = $false
    foreach ($safe in $safePaths) {
        if ($normalizedPath.StartsWith($safe)) {
            $isSafePath = $true
            break
        }
    }
    
    # Check for suspicious locations - using exact path matching
    $inSuspiciousLocation = $false
    foreach ($loc in $suspiciousLocations) {
        # Use more precise matching to avoid false positives
        if ($normalizedPath.Contains($loc)) {
            $inSuspiciousLocation = $true
            break
        }
    }
    
    # Type-specific additional checks
    $hasTypeSpecificIssue = switch ($Type) {
        'Service' {
            # For services, check for unquoted paths with spaces
            $Path.Contains(' ') -and -not $Path.StartsWith('"')
        }
        'Process' {
            # For processes, check for suspicious extensions and temp patterns
            $normalizedPath -match '\.(tmp|dat)$' -or
            $normalizedPath -match '\\temp\d+\.' -or
            $normalizedPath -match '\\temporary internet files\\'
        }
        'Connection' {
            # For connections, no additional path checks needed
            $false
        }
        default { $false }
    }
    
    # Return true if any of our conditions are met
    return (-not $isSafePath) -and ($inSuspiciousLocation -or $hasTypeSpecificIssue)
}

# 1. System Information Baseline
Write-IRLog "Starting system baseline collection..." "main.log"
Get-ComputerInfo | Export-Csv "$logPath\system_info.csv" -NoTypeInformation

# 2. Process Analysis
Write-IRLog "Analyzing running processes..." "main.log"

# Get detailed process information including command line and owner
$processes = Get-Process | Select-Object Name, Id, Path, Company, StartTime, 
    @{N='CommandLine';E={(Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine}},
    @{N='Owner';E={(Get-Process -Id $_.Id -IncludeUserName).UserName}},
    @{N='DigitalSignature';E={
        try {
            $sig = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
            if($sig) { $sig.Status } else { "Unknown" }
        } catch { "Unable to verify" }
    }}

# Hunt for suspicious processes
$suspiciousProcesses = $processes | Where-Object {
    $proc = $_
    
    # Initialize array to store reasons for flagging
    $reasons = @()
    
    # Check process path
    if ($proc.Path -and (Test-SuspiciousPath -Path $proc.Path -Type 'Process')) {
        $reasons += "Suspicious path: $($proc.Path)"
    }
    
    # Check digital signature
    if ($proc.DigitalSignature -ne "Valid") {
        $reasons += "Invalid/missing digital signature"
    }
    
    # Check if no company information
    if (-not $proc.Company) {
        $reasons += "No company information"
    }
    
    if ($reasons.Count -gt 0) {
        $proc | Add-Member -NotePropertyName 'SuspiciousReasons' -NotePropertyValue ($reasons -join '; ') -Force
        return $true
    }
    return $false
}

# 3. Service Analysis
Write-IRLog "Analyzing services..." "main.log"
$services = Get-WmiObject Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName

# Hunt for suspicious services
$suspiciousServices = $services | Where-Object {
    $svc = $_
    $reasons = @()
    
    if (Test-SuspiciousPath -Path $svc.PathName -Type 'Service') {
        $reasons += "Suspicious path: $($svc.PathName)"
    }
    
    # Check for unquoted service paths with spaces
    if ($svc.PathName -and $svc.PathName.Contains(' ') -and -not $svc.PathName.StartsWith('"')) {
        $reasons += "Unquoted service path with spaces"
    }
    
    if ($reasons.Count -gt 0) {
        $svc | Add-Member -NotePropertyName 'SuspiciousReasons' -NotePropertyValue ($reasons -join '; ') -Force
        return $true
    }
    return $false
}

# 4. Network Connection Analysis
Write-IRLog "Analyzing network connections..." "main.log"

# Known suspicious ports
# Update this list accordingly
$suspiciousPorts = @(4444, 31337, 1080, 6666, 666, 12345, 27374, 5000)

# Get network connections with process details
$netConnections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
    @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess).Name}},
    @{N='ProcessPath';E={(Get-Process -Id $_.OwningProcess).Path}}

# Hunt for suspicious connections
$suspiciousConnections = $netConnections | Where-Object {
    $conn = $_
    $reasons = @()
    
    # Check for known suspicious ports
    if ($suspiciousPorts -contains $conn.LocalPort -or $suspiciousPorts -contains $conn.RemotePort) {
        $reasons += "Suspicious port detected"
    }
    
    # Check process path if available
    if ($conn.ProcessPath -and (Test-SuspiciousPath -Path $conn.ProcessPath -Type 'Connection')) {
        $reasons += "Suspicious process path: $($conn.ProcessPath)"
    }
    
    if ($reasons.Count -gt 0) {
        $conn | Add-Member -NotePropertyName 'SuspiciousReasons' -NotePropertyValue ($reasons -join '; ') -Force
        return $true
    }
    return $false
}

# 5. User Account Analysis
Write-IRLog "Analyzing user accounts and groups..." "main.log"
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired
$groups = Get-LocalGroup | ForEach-Object {
    $group = $_
    Get-LocalGroupMember -Group $group.Name | Select-Object @{N='Group';E={$group.Name}}, Name, PrincipalSource
}

# 6. Scheduled Tasks Analysis
Write-IRLog "Analyzing scheduled tasks..." "main.log"
$tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, 
    @{N='Actions';E={$_.Actions.Execute}},
    @{N='Arguments';E={$_.Actions.Arguments}}

# 7. Network Shares
Write-IRLog "Analyzing network shares..." "main.log"
$shares = Get-SmbShare | Select-Object Name, Path, Description

# 8. Autostart Locations (Registry)
Write-IRLog "Analyzing autostart registry keys..." "main.log"
$asepPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$asepEntries = foreach ($path in $asepPaths) {
    if (Test-Path $path) {
        Get-ItemProperty $path | 
            Get-Member -MemberType NoteProperty | 
            Where-Object { $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider') } |
            ForEach-Object {
                [PSCustomObject]@{
                    Path = $path
                    Name = $_.Name
                    Value = (Get-ItemProperty $path).$($_.Name)
                }
            }
    }
}

# 9. Recent Files
Write-IRLog "Analyzing recently created files in writable locations..." "main.log"
$writablePaths = @(
    "C:\Windows\Temp",
    "C:\Temp",
    $env:TEMP,
    $env:TMP
)

$recentFiles = foreach ($path in $writablePaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Recurse -File |
            Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-2) } |
            Select-Object FullName, CreationTime, LastWriteTime, Length
    }
}

# Export all results
Export-ToCSV $processes "all_processes.csv"
Export-ToCSV $suspiciousProcesses "suspicious_processes.csv"
Export-ToCSV $services "all_services.csv"
Export-ToCSV $suspiciousServices "suspicious_services.csv"
Export-ToCSV $netConnections "network_connections.csv"
Export-ToCSV $suspiciousConnections "suspicious_connections.csv"
Export-ToCSV $users "local_users.csv"
Export-ToCSV $groups "group_memberships.csv"
Export-ToCSV $tasks "scheduled_tasks.csv"
Export-ToCSV $shares "network_shares.csv"
Export-ToCSV $asepEntries "autostart_entries.csv"
Export-ToCSV $recentFiles "recent_files.csv"

# Create summary report
Write-IRLog "Creating summary report..." "main.log"
$summary = @"
Incident Response Analysis Summary
================================
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
System: $env:COMPUTERNAME

Findings:
- Suspicious Processes: $($suspiciousProcesses.Count)
- Suspicious Services: $($suspiciousServices.Count)
- Suspicious Network Connections: $($suspiciousConnections.Count)
- Local Users: $($users.Count)
- Scheduled Tasks: $($tasks.Count)
- Network Shares: $($shares.Count)
- Auto-Start Entries: $($asepEntries.Count)
- Recent Files in Writable Locations: $($recentFiles.Count)

All detailed logs can be found in: $logPath
"@

$summary | Out-File "$logPath\summary.txt"
Write-IRLog "Analysis complete. Summary report generated at $logPath\summary.txt" "main.log"