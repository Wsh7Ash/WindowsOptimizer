# extremlydeleteedge.ps1
# PowerShell script to remove Microsoft Edge
# WARNING: This will completely remove Microsoft Edge from your system
# Run as Administrator

param(
    [switch]$Force,
    [switch]$WhatIf
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

Write-Host "Microsoft Edge Removal Script" -ForegroundColor Yellow
Write-Host "==============================" -ForegroundColor Yellow

if (-not $Force) {
    $confirmation = Read-Host "Are you sure you want to completely remove Microsoft Edge? This action cannot be easily undone. (y/N)"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        Write-Host "Operation cancelled." -ForegroundColor Green
        exit 0
    }
}

# Function to kill Edge processes
function Stop-EdgeProcesses {
    Write-Host "Stopping Microsoft Edge processes..." -ForegroundColor Cyan
    
    $edgeProcesses = @("msedge", "msedgewebview2", "MicrosoftEdgeUpdate")
    
    foreach ($process in $edgeProcesses) {
        try {
            Get-Process -Name $process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Host "  Stopped $process" -ForegroundColor Green
        }
        catch {
            Write-Host "  Could not stop $process (may not be running)" -ForegroundColor Yellow
        }
    }
}

# Function to remove Edge installation directories
function Remove-EdgeDirectories {
    Write-Host "Removing Microsoft Edge directories..." -ForegroundColor Cyan
    
    $edgePaths = @(
        "$env:ProgramFiles\Microsoft\Edge",
        "$env:ProgramFiles(x86)\Microsoft\Edge",
        "$env:LOCALAPPDATA\Microsoft\Edge",
        "$env:ProgramData\Microsoft\Edge",
        "$env:ProgramFiles\Microsoft\EdgeWebView",
        "$env:ProgramFiles(x86)\Microsoft\EdgeWebView"
    )
    
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            try {
                if ($WhatIf) {
                    Write-Host "  Would remove: $path" -ForegroundColor Yellow
                } else {
                    Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  Removed: $path" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  Failed to remove: $path" -ForegroundColor Red
            }
        }
    }
}

# Function to uninstall Edge via setup
function Uninstall-EdgeSetup {
    Write-Host "Attempting to uninstall Edge via setup..." -ForegroundColor Cyan
    
    $edgeInstaller = Get-ChildItem -Path "$env:ProgramFiles(x86)\Microsoft\Edge\Application" -Name "msedge.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    
    if ($edgeInstaller) {
        $installerPath = "$env:ProgramFiles(x86)\Microsoft\Edge\Application\$($edgeInstaller.Directory.Name)\Installer\setup.exe"
        
        if (Test-Path $installerPath) {
            if ($WhatIf) {
                Write-Host "  Would run: $installerPath --uninstall --force-uninstall --system-level" -ForegroundColor Yellow
            } else {
                try {
                    Start-Process -FilePath $installerPath -ArgumentList "--uninstall", "--force-uninstall", "--system-level" -Wait -NoNewWindow
                    Write-Host "  Edge uninstall completed" -ForegroundColor Green
                }
                catch {
                    Write-Host "  Setup uninstall failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
}

# Function to remove Edge from registry
function Remove-EdgeRegistry {
    Write-Host "Cleaning Edge registry entries..." -ForegroundColor Cyan
    
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Edge",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate",
        "HKCU:\SOFTWARE\Microsoft\Edge"
    )
    
    foreach ($regPath in $registryPaths) {
        if (Test-Path $regPath) {
            try {
                if ($WhatIf) {
                    Write-Host "  Would remove registry: $regPath" -ForegroundColor Yellow
                } else {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  Removed registry: $regPath" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  Failed to remove registry: $regPath" -ForegroundColor Red
            }
        }
    }
}

# Function to remove Edge from Windows Apps
function Remove-EdgeAppx {
    Write-Host "Removing Edge from Windows Apps..." -ForegroundColor Cyan
    
    try {
        $edgePackages = Get-AppxPackage -Name "*MicrosoftEdge*" -AllUsers -ErrorAction SilentlyContinue
        
        foreach ($package in $edgePackages) {
            if ($WhatIf) {
                Write-Host "  Would remove package: $($package.Name)" -ForegroundColor Yellow
            } else {
                try {
                    Remove-AppxPackage -Package $package.PackageFullName -ErrorAction SilentlyContinue
                    Write-Host "  Removed package: $($package.Name)" -ForegroundColor Green
                }
                catch {
                    Write-Host "  Failed to remove package: $($package.Name)" -ForegroundColor Red
                }
            }
        }
    }
    catch {
        Write-Host "  Could not enumerate Edge packages" -ForegroundColor Yellow
    }
}

# Function to remove Edge shortcuts
function Remove-EdgeShortcuts {
    Write-Host "Removing Edge shortcuts..." -ForegroundColor Cyan
    
    $shortcutPaths = @(
        "$env:PUBLIC\Desktop\Microsoft Edge.lnk",
        "$env:USERPROFILE\Desktop\Microsoft Edge.lnk",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
    )
    
    foreach ($shortcut in $shortcutPaths) {
        if (Test-Path $shortcut) {
            try {
                if ($WhatIf) {
                    Write-Host "  Would remove shortcut: $shortcut" -ForegroundColor Yellow
                } else {
                    Remove-Item -Path $shortcut -Force -ErrorAction SilentlyContinue
                    Write-Host "  Removed shortcut: $shortcut" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  Failed to remove shortcut: $shortcut" -ForegroundColor Red
            }
        }
    }
}

# Main execution
try {
    Write-Host ""
    
    if ($WhatIf) {
        Write-Host "WHAT-IF MODE: No changes will be made" -ForegroundColor Magenta
        Write-Host ""
    }
    
    Stop-EdgeProcesses
    Write-Host ""
    
    Uninstall-EdgeSetup
    Write-Host ""
    
    Remove-EdgeAppx
    Write-Host ""
    
    Remove-EdgeDirectories
    Write-Host ""
    
    Remove-EdgeRegistry
    Write-Host ""
    
    Remove-EdgeShortcuts
    Write-Host ""
    
    if ($WhatIf) {
        Write-Host "What-if analysis complete. No changes were made." -ForegroundColor Magenta
    } else {
        Write-Host "Microsoft Edge removal process completed!" -ForegroundColor Green
        Write-Host "You may need to restart your computer for all changes to take effect." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Note: Some Edge components may be restored by Windows Updates." -ForegroundColor Yellow
    }
}
catch {
    Write-Host "An error occurred during the removal process: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Script execution finished." -ForegroundColor Cyan