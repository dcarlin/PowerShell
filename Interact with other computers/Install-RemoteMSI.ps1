# This script takes an input file of ip addresses and installs an MSI file
# This script includes several important features for remote MSI installation
# IPListPath: Path to the file containing IP addresses
# MSIPath: Path to the MSI package to install
# Optional LogPath: Where to save the installation log
# Optional Credential: For authentication if needed

# Written by Derek Carlin

# Basic usage
# .\Install-RemoteMSI.ps1 -IPListPath ".\ip_list.txt" -MSIPath ".\package.msi"

# With credentials
# $cred = Get-Credential
# .\Install-RemoteMSI.ps1 -IPListPath ".\ip_list.txt" -MSIPath ".\package.msi" -Credential $cred

# Parameters for the script
param(
    [Parameter(Mandatory=$true)]
    [string]$IPListPath,
    
    [Parameter(Mandatory=$true)]
    [string]$MSIPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\installation_log.txt",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

# Function to write to log file
function Write-Log {
    param($Message)
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    Add-Content -Path $LogPath -Value $logMessage
    Write-Host $logMessage
}

# Function to test connection
function Test-RemoteConnection {
    param($IP)
    Test-Connection -ComputerName $IP -Count 1 -Quiet
}

# Verify MSI file exists
if (-not (Test-Path $MSIPath)) {
    Write-Log "ERROR: MSI file not found at path: $MSIPath"
    exit 1
}

# Read IP addresses from file
try {
    $ipAddresses = Get-Content -Path $IPListPath -ErrorAction Stop
    Write-Log "Successfully loaded IP addresses from: $IPListPath"
}
catch {
    Write-Log "ERROR: Unable to read IP list file: $_"
    exit 1
}

# Process each IP address
foreach ($ip in $ipAddresses) {
    # Skip empty lines
    if ([string]::IsNullOrWhiteSpace($ip)) {
        continue
    }
    
    Write-Log "Processing IP: $ip"
    
    # Test connection
    if (-not (Test-RemoteConnection $ip)) {
        Write-Log "ERROR: Cannot connect to $ip - skipping"
        continue
    }
    
    try {
        # Create Admin share path for MSI file
        $remotePath = "\\$ip\C$\Windows\Temp\$(Split-Path $MSIPath -Leaf)"
        
        # Copy MSI to remote machine
        Write-Log "Copying MSI to $ip..."
        Copy-Item -Path $MSIPath -Destination $remotePath -Force
        
        # Prepare installation command
        $installCommand = "msiexec.exe /i `"$remotePath`" /qn /log `"C:\Windows\Temp\msi_install.log`""
        
        # Execute installation
        Write-Log "Starting installation on $ip..."
        $result = if ($Credential) {
            Invoke-Command -ComputerName $ip -Credential $Credential -ScriptBlock {
                param($cmd)
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -NoNewWindow
            } -ArgumentList $installCommand
        } else {
            Invoke-Command -ComputerName $ip -ScriptBlock {
                param($cmd)
                Start-Process -FilePath "cmd.exe" -ArgumentList "/c $cmd" -Wait -NoNewWindow
            } -ArgumentList $installCommand
        }
        
        # Clean up remote MSI file
        Remove-Item -Path $remotePath -Force
        Write-Log "Installation completed on $ip"
        
        # Copy back installation log
        $remoteLogPath = "\\$ip\C$\Windows\Temp\msi_install.log"
        if (Test-Path $remoteLogPath) {
            Copy-Item -Path $remoteLogPath -Destination ".\$ip-install.log" -Force
            Remove-Item -Path $remoteLogPath -Force
        }
    }
    catch {
        Write-Log "ERROR on $ip : $_"
    }
}

Write-Log "Processing complete!"