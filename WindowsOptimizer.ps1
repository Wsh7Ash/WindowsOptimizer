# Windows System Optimizer
# Run this script as Administrator

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    Exit
}

# Function to safely stop and disable a service
function Optimize-Service {
    param (
        [string]$ServiceName,
        [string]$DisplayName
    )
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Host "Optimized service: $DisplayName" -ForegroundColor Green
        }
    } catch {
        Write-Host "Could not optimize service: $DisplayName" -ForegroundColor Yellow
    }
}

# 1. Memory Optimization
function Optimize-Memory {
    Write-Host "`nOptimizing Memory..." -ForegroundColor Cyan
    
    # Clear PageFile on shutdown
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1
    
    # Optimize memory usage
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1
    
    # Disable Memory Compression
    Disable-MMAgent -mc
    
    # Disable Superfetch/Prefetch
    Optimize-Service -ServiceName "SysMain" -DisplayName "Superfetch"
    
    # Optimize Virtual Memory
    $computersystem = Get-WmiObject Win32_ComputerSystem
    $physicalmemory = [Math]::Round(($computersystem.TotalPhysicalMemory / 1GB), 2)
    $recommendedmin = [Math]::Round($physicalmemory * 0.5, 0) * 1024
    $recommendedmax = [Math]::Round($physicalmemory * 1.5, 0) * 1024
    
    $computersystem = Get-WmiObject Win32_ComputerSystem
    $automaticManagedPagefile = $computersystem.AutomaticManagedPagefile
    
    if ($automaticManagedPagefile) {
        $computersystem.AutomaticManagedPagefile = $false
        $computersystem.Put()
    }
    
    $pagefile = Get-WmiObject Win32_PageFileSetting
    $pagefile.InitialSize = $recommendedmin
    $pagefile.MaximumSize = $recommendedmax
    $pagefile.Put()
    
    Write-Host "Memory optimization completed!" -ForegroundColor Green
}

# 2. CPU and Process Optimization
function Optimize-CPU {
    Write-Host "`nOptimizing CPU and Processes..." -ForegroundColor Cyan
    
    # Set CPU Priority Scheme to Programs
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38
    
    # Disable CPU Core Parking
    powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
    powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
    
    # Optimize processor performance
    powercfg -setacvalueindex scheme_current sub_processor PERFINCPOL 2
    powercfg -setacvalueindex scheme_current sub_processor PERFDECPOL 1
    powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2
    
    # Disable power throttling
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord
    
    # Optimize process scheduling
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value 2000
    
    # Apply High Performance Power Plan
    powercfg -setactive scheme_current
    
    Write-Host "CPU optimization completed!" -ForegroundColor Green
}

# 3. GPU Optimization
function Optimize-GPU {
    Write-Host "`nOptimizing GPU..." -ForegroundColor Cyan
    
    # Disable Full Screen Optimizations globally
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2
    
    # Disable Game DVR and Game Bar
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0
    
    # Optimize GPU for Performance
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High"
    
    # Disable Hardware Accelerated GPU Scheduling (can improve performance in some cases)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 1
    
    Write-Host "GPU optimization completed!" -ForegroundColor Green
}

# 4. Service Optimization
function Optimize-Services {
    Write-Host "`nOptimizing Services..." -ForegroundColor Cyan
    
    $servicesToDisable = @(
        @{Name = "DiagTrack"; Display = "Connected User Experiences and Telemetry"},
        @{Name = "dmwappushservice"; Display = "WAP Push Message Routing Service"},
        @{Name = "MapsBroker"; Display = "Downloaded Maps Manager"},
        @{Name = "lfsvc"; Display = "Geolocation Service"},
        @{Name = "SharedAccess"; Display = "Internet Connection Sharing"},
        @{Name = "lmhosts"; Display = "TCP/IP NetBIOS Helper"},
        @{Name = "WSearch"; Display = "Windows Search"},
        @{Name = "XboxGipSvc"; Display = "Xbox Accessory Management Service"},
        @{Name = "XblAuthManager"; Display = "Xbox Live Auth Manager"},
        @{Name = "XblGameSave"; Display = "Xbox Live Game Save"},
        @{Name = "XboxNetApiSvc"; Display = "Xbox Live Networking Service"},
        @{Name = "wisvc"; Display = "Windows Insider Service"},
        @{Name = "WerSvc"; Display = "Windows Error Reporting Service"},
        @{Name = "RetailDemo"; Display = "Retail Demo Service"},
        @{Name = "PcaSvc"; Display = "Program Compatibility Assistant Service"},
        @{Name = "diagnosticshub.standardcollector.service"; Display = "Microsoft (R) Diagnostics Hub Standard Collector Service"}
    )
    
    foreach ($service in $servicesToDisable) {
        Optimize-Service -ServiceName $service.Name -DisplayName $service.Display
    }
    
    Write-Host "Services optimization completed!" -ForegroundColor Green
}

# 5. Network Optimization
function Optimize-Network {
    Write-Host "`nOptimizing Network..." -ForegroundColor Cyan
    
    # Enable Network Optimizations
    netsh int tcp set global autotuninglevel=normal
    netsh int tcp set global chimney=enabled
    netsh int tcp set global dca=enabled
    netsh int tcp set global ecncapability=enabled
    netsh int tcp set global timestamps=disabled
    
    # Optimize TCP/IP settings
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Value 64
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "Tcp1323Opts" -Value 1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpMaxDupAcks" -Value 2
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Value 30
    
    # Set DNS to Google's DNS
    Set-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).InterfaceIndex -ServerAddresses "8.8.8.8","8.8.4.4"
    
    # Disable IPv6 (optional, can improve IPv4 performance)
    Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
    
    # Optimize Network Adapter Settings
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Energy-Efficient Ethernet" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Flow Control" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
    
    Write-Host "Network optimization completed!" -ForegroundColor Green
}

# 6. Storage Optimization
function Optimize-Storage {
    Write-Host "`nOptimizing Storage..." -ForegroundColor Cyan
    
    # Disable Hibernation to save space
    powercfg -h off
    
    # Clean up Windows components
    cleanmgr /sagerun:1
    
    # Disable Storage Sense
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 0
    
    # Optimize NTFS
    fsutil behavior set disablelastaccess 1
    fsutil behavior set disable8dot3 1
    
    # Disable Prefetch and Superfetch
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0
    
    # Disable Windows Search Indexing
    Set-Service "WSearch" -StartupType Disabled
    Stop-Service "WSearch" -Force
    
    Write-Host "Storage optimization completed!" -ForegroundColor Green
}

# 7. Privacy and Telemetry Optimization
function Optimize-Privacy {
    Write-Host "`nOptimizing Privacy Settings..." -ForegroundColor Cyan
    
    # Disable Telemetry
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0
    
    # Disable Advertising ID
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0
    
    # Disable Windows Tips
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1
    
    # Disable Consumer Features
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1
    
    # Disable Activity History
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Value 0
    
    Write-Host "Privacy optimization completed!" -ForegroundColor Green
}

# 8. Windows Debloater
function Remove-WindowsBloat {
    Write-Host "`nDebloating Windows..." -ForegroundColor Cyan

    # List of apps to remove
    $appsToRemove = @(
        "Microsoft.3DBuilder"
        "Microsoft.BingFinance"
        "Microsoft.BingNews"
        "Microsoft.BingSports"
        "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MixedReality.Portal"
        "Microsoft.Office.OneNote"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        "Microsoft.StorePurchaseApp"
        "Microsoft.WindowsAlarms"
        "Microsoft.WindowsCamera"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"
    )

    # Remove Windows Apps
    foreach ($app in $appsToRemove) {
        Write-Host "Removing $app..." -NoNewline
        try {
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            Write-Host "Done!" -ForegroundColor Green
        } catch {
            Write-Host "Failed!" -ForegroundColor Red
        }
    }

    # Disable Windows Features
    $featuresToDisable = @(
        "WindowsMediaPlayer"
        "Internet-Explorer-Optional-*"
        "WorkFolders-Client"
        "FaxServicesClientPackage"
    )

    foreach ($feature in $featuresToDisable) {
        Write-Host "Disabling Windows Feature: $feature..." -NoNewline
        try {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Done!" -ForegroundColor Green
        } catch {
            Write-Host "Failed!" -ForegroundColor Red
        }
    }

    # Disable Scheduled Tasks
    $tasksToDisable = @(
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
        "\Microsoft\Windows\Application Experience\StartupAppTask"
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        "\Microsoft\Windows\Feedback\Siuf\DmClient"
        "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    )

    foreach ($task in $tasksToDisable) {
        Write-Host "Disabling Scheduled Task: $task..." -NoNewline
        try {
            Disable-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Done!" -ForegroundColor Green
        } catch {
            Write-Host "Failed!" -ForegroundColor Red
        }
    }

    # Disable Telemetry and Data Collection
    Write-Host "Disabling Telemetry and Data Collection..." -NoNewline
    try {
        # Disable Telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
        
        # Disable Customer Experience Improvement Program
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Value 0 -Type DWord
        
        # Disable Application Telemetry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value 0 -Type DWord
        
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Disable OneDrive
    Write-Host "Disabling OneDrive..." -NoNewline
    try {
        if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive") {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1
        }
        Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
        Start-Sleep -s 2
        $oneDrivePath = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        if (Test-Path $oneDrivePath) {
            & $oneDrivePath /uninstall
        }
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Remove Temporary Files
    Write-Host "Cleaning Temporary Files..." -NoNewline
    try {
        Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    Write-Host "Windows Debloating completed!" -ForegroundColor Green
}

# 9. Gaming Optimization
function Optimize-Gaming {
    Write-Host "`nOptimizing for Gaming Performance..." -ForegroundColor Cyan

    # Optimize Network Settings for Gaming
    Write-Host "Optimizing Network Settings..." -NoNewline
    try {
        # Set Network Throttling Index
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff
        
        # Set Gaming Priorities
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High"
        
        # Optimize Network Adapter
        $networkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.MediaType -eq "802.3"}
        if ($networkAdapter) {
            Set-NetAdapterAdvancedProperty -Name $networkAdapter.Name -DisplayName "Flow Control" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name $networkAdapter.Name -DisplayName "Interrupt Moderation" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name $networkAdapter.Name -DisplayName "Power Saving Mode" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
        }
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Optimize Visual Effects for Performance
    Write-Host "Optimizing Visual Effects..." -NoNewline
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Disable Full-Screen Optimizations for Games
    Write-Host "Optimizing Full-Screen Settings..." -NoNewline
    try {
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Value 1
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Value 2
        Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Value 2
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    Write-Host "Gaming optimization completed!" -ForegroundColor Green
}

# 10. Security Optimization
function Optimize-Security {
    Write-Host "`nOptimizing System Security..." -ForegroundColor Cyan

    # Enable Windows Defender Features
    Write-Host "Enhancing Windows Defender..." -NoNewline
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableBlockAtFirstSeen $false
        Set-MpPreference -DisableEmailScanning $false
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Configure Windows Firewall
    Write-Host "Configuring Firewall..." -NoNewline
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast True
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Enable Controlled Folder Access
    Write-Host "Enabling Controlled Folder Access..." -NoNewline
    try {
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Enable Network Protection
    Write-Host "Enabling Network Protection..." -NoNewline
    try {
        Set-MpPreference -EnableNetworkProtection Enabled
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    Write-Host "Security optimization completed!" -ForegroundColor Green
}

# 11. Advanced System Optimization
function Optimize-AdvancedSystem {
    Write-Host "`nPerforming Advanced System Optimization..." -ForegroundColor Cyan

    # Optimize Boot Configuration
    Write-Host "Optimizing Boot Configuration..." -NoNewline
    try {
        bcdedit /set useplatformclock false
        bcdedit /set disabledynamictick yes
        bcdedit /set useplatformtick yes
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Optimize System Response
    Write-Host "Optimizing System Response..." -NoNewline
    try {
        # Disable HPET (High Precision Event Timer)
        bcdedit /deletevalue useplatformclock
        
        # Optimize Win32Priority
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38
        
        # Optimize NTFS
        fsutil behavior set disablelastaccess 1
        fsutil behavior set disable8dot3 1
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Optimize Power Settings
    Write-Host "Optimizing Power Settings..." -NoNewline
    try {
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
        powercfg /setactive e9a42b02-d5df-448d-aa00-03f14749eb61
        
        # Disable USB Selective Suspend
        powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
        powercfg -setdcvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    # Optimize Registry for Performance
    Write-Host "Optimizing Registry..." -NoNewline
    try {
        # Increase System Responsiveness
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0
        
        # Optimize Desktop Window Manager
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 0
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value 0
        
        # Optimize Explorer
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0
        Write-Host "Done!" -ForegroundColor Green
    } catch {
        Write-Host "Failed!" -ForegroundColor Red
    }

    Write-Host "Advanced system optimization completed!" -ForegroundColor Green
}

# Main Menu Function
function Show-Menu {
    Clear-Host
    Write-Host "================ Windows System Optimizer ================" -ForegroundColor Cyan
    Write-Host "1: Memory Optimization"
    Write-Host "2: CPU Optimization"
    Write-Host "3: GPU Optimization"
    Write-Host "4: Service Optimization"
    Write-Host "5: Network Optimization"
    Write-Host "6: Storage Optimization"
    Write-Host "7: Privacy Optimization"
    Write-Host "8: Windows Debloater"
    Write-Host "9: Gaming Optimization"
    Write-Host "10: Security Optimization"
    Write-Host "11: Advanced System Optimization"
    Write-Host "12: Run All Optimizations"
    Write-Host "Q: Quit"
    Write-Host "====================================================" -ForegroundColor Cyan
}

# Create restore point
function Create-RestorePoint {
    Write-Host "Creating System Restore Point..." -ForegroundColor Green
    Enable-ComputerRestore -Drive "$env:SystemDrive"
    Checkpoint-Computer -Description "Before System Optimization" -RestorePointType "MODIFY_SETTINGS"
}

# Main Program Loop
do {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    
    if ($selection -ne 'Q') {
        Create-RestorePoint
    }
    
    switch ($selection) {
        '1' {
            Optimize-Memory
            pause
        }
        '2' {
            Optimize-CPU
            pause
        }
        '3' {
            Optimize-GPU
            pause
        }
        '4' {
            Optimize-Services
            pause
        }
        '5' {
            Optimize-Network
            pause
        }
        '6' {
            Optimize-Storage
            pause
        }
        '7' {
            Optimize-Privacy
            pause
        }
        '8' {
            Remove-WindowsBloat
            pause
        }
        '9' {
            Optimize-Gaming
            pause
        }
        '10' {
            Optimize-Security
            pause
        }
        '11' {
            Optimize-AdvancedSystem
            pause
        }
        '12' {
            Optimize-Memory
            Optimize-CPU
            Optimize-GPU
            Optimize-Services
            Optimize-Network
            Optimize-Storage
            Optimize-Privacy
            Remove-WindowsBloat
            Optimize-Gaming
            Optimize-Security
            Optimize-AdvancedSystem
            Write-Host "`nAll optimizations completed! Please restart your computer for changes to take effect." -ForegroundColor Green
            pause
        }
        'Q' {
            Write-Host "Exiting..."
            return
        }
    }
} while ($selection -ne 'Q') 