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
    Write-Host "8: Run All Optimizations"
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
            Optimize-Memory
            Optimize-CPU
            Optimize-GPU
            Optimize-Services
            Optimize-Network
            Optimize-Storage
            Optimize-Privacy
            Write-Host "`nAll optimizations completed! Please restart your computer for changes to take effect." -ForegroundColor Green
            pause
        }
        'Q' {
            Write-Host "Exiting..."
            return
        }
    }
} while ($selection -ne 'Q') 