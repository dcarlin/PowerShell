# Replace the TARGETMACHINE text with the hostname or IP of the target machine
# Replace the MACHINEWHEREMSIRESIDES with the machine name that has the MSI
(Get-WMIObject -ComputerName TARGETMACHINE -List | Where-Object -FilterScript {$_.Name -eq "Win32_Product"}).Install(\\MACHINEWHEREMSIRESIDES\path\package.msi)