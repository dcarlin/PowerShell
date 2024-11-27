# .\Add-CVESuppressions.ps1 -InputFile path\to\cve-arn-list.txt
# AWS Inspector Finding Suppression Script for Windows
param(
    [Parameter(Mandatory=$true)]
    [string]$InputFile
)

# Function to check if a command exists
function Test-CommandExists {
    param ($command)
    
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'stop'
    
    try {
        if (Get-Command $command) { return $true }
    }
    catch { return $false }
    finally { $ErrorActionPreference = $oldPreference }
}

# Function to validate ARN format
function Test-ARNFormat {
    param ([string]$arn)
    
    return $arn -match '^arn:aws:inspector2:[a-z0-9-]+:\d+:finding/[a-f0-9]+$'
}

# Validate AWS CLI is installed
if (-not (Test-CommandExists "aws")) {
    Write-Host "AWS CLI is not installed. Please install it first."
    exit 1
}

# Check if file exists
if (-not (Test-Path $InputFile)) {
    Write-Host "Input file not found: $InputFile"
    exit 1
}

# Get AWS account ID
try {
    $AccountId = aws sts get-caller-identity --query Account --output text
    if (-not $AccountId) {
        Write-Host "Failed to get AWS account ID. Please check your AWS credentials."
        exit 1
    }
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Host "Error getting AWS account ID: $errorMessage"
    exit 1
}

# Get current region
try {
    $Region = aws configure get region
    if (-not $Region) {
        Write-Host "AWS region not set. Please configure your AWS CLI."
        exit 1
    }
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Host "Error getting AWS region: $errorMessage"
    exit 1
}

# Read finding ARNs and create suppression rules
Get-Content $InputFile | ForEach-Object {
    $findingArn = $_.Trim()
    
    # Skip empty lines and comments
    if ($findingArn -and -not $findingArn.StartsWith("#")) {
        Write-Host "Processing finding ARN: $findingArn"
        
        # Validate ARN format
        if (-not (Test-ARNFormat $findingArn)) {
            Write-Host "Invalid finding ARN format: $findingArn. Skipping..."
            return
        }
        
        # Extract finding ID from ARN for use in title
        $findingId = $findingArn.Split('/')[-1]
        
        # Create a unique title for each suppression rule
        $Title = "Finding_Suppression_${findingId}_$(Get-Date -Format 'yyyyMMdd')"
        
        # Create the filter criteria with correct structure
        $filterCriteria = @{
            "findingArn" = @(
                @{
                    "comparison" = "EQUALS"
                    "value" = $findingArn
                }
            )
        }

        # Create temporary file for JSON criteria
        $tempFile = [System.IO.Path]::GetTempFileName()
        $filterCriteria | ConvertTo-Json -Depth 10 | Set-Content $tempFile
        
        try {
            Write-Host "Creating suppression rule with criteria:"
            Get-Content $tempFile | Write-Host
            
            # Create the suppression rule using file-based input
            aws inspector2 create-filter `
                --action "SUPPRESS" `
                --filter-criteria "file://$tempFile" `
                --name "$Title" `
                --description "False Positive detection $findingId" `
                --region "$Region"
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully created suppression rule for finding $findingId"
            }
            else {
                Write-Host "Failed to create suppression rule for finding $findingId"
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Host ("Error creating suppression rule for finding {0}: {1}" -f $findingId, $errorMessage)
        }
        finally {
            # Clean up temporary file
            if (Test-Path $tempFile) {
                Remove-Item $tempFile
            }
        }
        
        # Add small delay to avoid API throttling
        Start-Sleep -Seconds 1
    }
}

Write-Host "Finished processing all findings"