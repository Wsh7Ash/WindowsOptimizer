# Windows Activation Watermark Remover
# Run this script as Administrator

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    Exit
}

# Create a restore point
Write-Host "Creating System Restore Point..." -ForegroundColor Green
Enable-ComputerRestore -Drive "$env:SystemDrive"
Checkpoint-Computer -Description "Before Watermark Removal" -RestorePointType "MODIFY_SETTINGS"

function Remove-WindowsWatermark {
    Write-Host "`nRemoving Windows Activation Watermark..." -ForegroundColor Cyan

    # Registry paths for watermark removal
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    )

    # Create registry paths if they don't exist
    foreach ($path in $registryPaths) {
        if (!(Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
    }

    # Remove watermark through registry modifications
    Write-Host "Modifying Registry Settings..." -NoNewline
    try {
        # Disable watermark
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "SkipRearm" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "SkipRearm" -Value 1 -Type DWord
        
        # Disable activation notifications
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWindowsUpdate" -Value 1 -Type DWord
        
        # Additional watermark removal settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "Activation" -Value 1 -Type DWord
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" -Name "LastActivation" -Value 1 -Type DWord
        
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
    }

    # Modify system files
    Write-Host "Modifying System Files..." -NoNewline
    try {
        # Create a backup of the original file
        $system32Path = "$env:SystemRoot\System32"
        $dllPath = "$system32Path\spp.dll"
        $dllBackup = "$system32Path\spp.dll.backup"

        if (Test-Path $dllPath) {
            Copy-Item -Path $dllPath -Destination $dllBackup -Force
            Write-Host "Backup created at: $dllBackup" -ForegroundColor Green
        }

        # Additional system file modifications
        $additionalFiles = @(
            "$system32Path\sppobjs.dll",
            "$system32Path\sppcomapi.dll"
        )

        foreach ($file in $additionalFiles) {
            if (Test-Path $file) {
                $backupFile = "$file.backup"
                Copy-Item -Path $file -Destination $backupFile -Force
                Write-Host "Backup created at: $backupFile" -ForegroundColor Green
            }
        }

        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
    }

    # Restart Windows Explorer
    Write-Host "Restarting Windows Explorer..." -NoNewline
    try {
        Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-Process "explorer"
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
    }

    Write-Host "`nWatermark removal completed!" -ForegroundColor Green
    Write-Host "Please restart your computer for all changes to take effect." -ForegroundColor Yellow
}

# Main execution
Write-Host "Windows Activation Watermark Remover" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "WARNING: This script will modify system files and registry settings." -ForegroundColor Yellow
Write-Host "A system restore point has been created before making changes." -ForegroundColor Yellow
$confirmation = Read-Host "Do you want to continue? (Y/N)"

if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
    Remove-WindowsWatermark
} else {
    Write-Host "Operation cancelled." -ForegroundColor Red
} 