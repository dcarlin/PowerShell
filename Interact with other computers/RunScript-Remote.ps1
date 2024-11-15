# Written by Derek Carlin

# Read IP addresses from file (one IP per line)
# Put the ip_addresses.txt file and the script.ps1 (script you want to run) files in the same directory
$ipAddresses = Get-Content -Path ".\ip_addresses.txt"

# Loop through each IP address
foreach ($ip in $ipAddresses) {
    # Skip empty lines
    if ([string]::IsNullOrWhiteSpace($ip)) {
        continue
    }

    Write-Host "Processing IP: $ip"
    
    try {
        # Execute script.ps1 for current IP
        # Assuming script.ps1 accepts IP as parameter
        & ".\script.ps1" -IPAddress $ip
    }
    catch {
        Write-Warning "Error processing IP $ip : $_"
    }
}

Write-Host "Processing complete!"