<#
.SYNOPSIS
    Checks multiple remote computers to verify if a specific agent is installed.
.DESCRIPTION
    This script accepts a list of IP addresses or computer names and remotely checks if 'AGENTNAME' 
    is installed on each system. It can check installed software, running services, or processes.
.PARAMETER ComputerList
    Path to a text file containing IP addresses or computer names, one per line.
.PARAMETER AgentName
    The name of the agent to check for (default is 'AGENTNAME').
.PARAMETER CheckType
    The type of check to perform: 'Software', 'Service', or 'Process' (default is 'Software').
.EXAMPLE
    .\Check-AgentInstallation.ps1 -ComputerList "C:\computers.txt" -AgentName "MyAgent" -CheckType "Service"
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentName = "AGENTNAME",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Software", "Service", "Process")]
    [string]$CheckType = "Software"
)

# Function to check if agent is installed via installed software
function Check-InstalledSoftware {
    param (
        [string]$Computer,
        [string]$AgentName
    )
    
    try {
        $installedSoftware = Invoke-Command -ComputerName $Computer -ScriptBlock {
            Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Select-Object DisplayName, DisplayVersion, Publisher
        } -ErrorAction Stop
        
        $result = $installedSoftware | Where-Object { $_.DisplayName -like "*$AgentName*" }
        
        if ($result) {
            return $true, "Installed: $($result.DisplayName) v$($result.DisplayVersion) by $($result.Publisher)"
        } else {
            return $false, "Not installed"
        }
    }
    catch {
        return $false, "Error: $_"
    }
}

# Function to check if agent is running as a service
function Check-RunningService {
    param (
        [string]$Computer,
        [string]$AgentName
    )
    
    try {
        $service = Invoke-Command -ComputerName $Computer -ScriptBlock {
            param($name)
            Get-Service -Name "*$name*" -ErrorAction SilentlyContinue
        } -ArgumentList $AgentName -ErrorAction Stop
        
        if ($service) {
            return $true, "Service: $($service.Name) - Status: $($service.Status)"
        } else {
            return $false, "Service not found"
        }
    }
    catch {
        return $false, "Error: $_"
    }
}

# Function to check if agent is running as a process
function Check-RunningProcess {
    param (
        [string]$Computer,
        [string]$AgentName
    )
    
    try {
        $process = Invoke-Command -ComputerName $Computer -ScriptBlock {
            param($name)
            Get-Process -Name "*$name*" -ErrorAction SilentlyContinue
        } -ArgumentList $AgentName -ErrorAction Stop
        
        if ($process) {
            return $true, "Process: $($process.Name) - PID: $($process.Id)"
        } else {
            return $false, "Process not found"
        }
    }
    catch {
        return $false, "Error: $_"
    }
}

# Main function to check computers
function Check-Agent {
    param (
        [string]$ComputerFile,
        [string]$AgentName,
        [string]$CheckType
    )
    
    # Check if the file exists
    if (-not (Test-Path $ComputerFile)) {
        Write-Error "Computer list file not found: $ComputerFile"
        return
    }
    
    # Read the list of computers
    $computers = Get-Content $ComputerFile
    
    # Create results array
    $results = @()
    
    # Process each computer
    foreach ($computer in $computers) {
        Write-Host "Checking $computer for $AgentName..." -ForegroundColor Cyan
        
        # Verify connectivity first
        if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
            $results += [PSCustomObject]@{
                Computer = $computer
                Status = "Offline"
                Details = "Unable to connect"
                AgentInstalled = $false
            }
            continue
        }
        
        # Perform the appropriate check
        switch ($CheckType) {
            "Software" {
                $checkResult = Check-InstalledSoftware -Computer $computer -AgentName $AgentName
            }
            "Service" {
                $checkResult = Check-RunningService -Computer $computer -AgentName $AgentName
            }
            "Process" {
                $checkResult = Check-RunningProcess -Computer $computer -AgentName $AgentName
            }
        }
        
        # Add to results
        $results += [PSCustomObject]@{
            Computer = $computer
            Status = if ($checkResult[0]) { "Installed" } else { "Not Installed" }
            Details = $checkResult[1]
            AgentInstalled = $checkResult[0]
        }
    }
    
    return $results
}

# Execute the main function
$checkResults = Check-Agent -ComputerFile $ComputerList -AgentName $AgentName -CheckType $CheckType

# Display results
$checkResults | Format-Table -AutoSize

# Export results to CSV
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputFile = "AgentCheck_$timestamp.csv"
$checkResults | Export-Csv -Path $outputFile -NoTypeInformation

Write-Host "Results exported to $outputFile" -ForegroundColor Green

# Summary statistics
$total = $checkResults.Count
$installed = ($checkResults | Where-Object { $_.AgentInstalled -eq $true }).Count
$notInstalled = ($checkResults | Where-Object { $_.AgentInstalled -eq $false -and $_.Status -ne "Offline" }).Count
$offline = ($checkResults | Where-Object { $_.Status -eq "Offline" }).Count

Write-Host "Summary:" -ForegroundColor Yellow
Write-Host "Total computers: $total" -ForegroundColor Yellow
Write-Host "Agent installed: $installed" -ForegroundColor Green
Write-Host "Agent not installed: $notInstalled" -ForegroundColor Red
Write-Host "Computers offline: $offline" -ForegroundColor Gray