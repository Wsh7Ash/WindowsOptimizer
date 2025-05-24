# Windows Optimizer

A comprehensive PowerShell script for optimizing Windows performance, privacy, and system resources.

## 🚀 Features

### 1. Memory Optimization
- Smart virtual memory management
- Memory compression control
- PageFile optimization
- Superfetch/Prefetch management

### 2. CPU Optimization
- Process priority optimization
- CPU core parking management
- Power plan optimization
- Process scheduling enhancement

### 3. GPU Optimization
- Gaming performance improvements
- Hardware acceleration management
- Graphics priority optimization
- Full-screen optimization control

### 4. Service Optimization
- Unnecessary service removal
- Background process optimization
- System service management
- Xbox and telemetry service control

### 5. Network Optimization
- TCP/IP parameter tuning
- DNS optimization
- Network adapter enhancement
- IPv6 control options

### 6. Storage Optimization
- NTFS optimization
- Disk cleanup automation
- File system enhancement
- Storage sense management

### 7. Privacy Optimization
- Telemetry control
- Advertising ID management
- Windows Tips control
- Activity history management

### 8. Windows Debloater
- Removes unnecessary Windows apps
- Disables unwanted Windows features
- Removes telemetry and data collection
- Disables unnecessary scheduled tasks
- Removes OneDrive integration
- Cleans temporary files
- Optimizes system performance

### 9. Gaming Optimization
- Network throttling optimization
- Gaming mode enhancements
- Visual effects optimization
- Full-screen optimizations
- Network adapter tuning
- Input lag reduction
- System responsiveness improvement

### 10. Security Optimization
- Windows Defender enhancement
- Firewall optimization
- Controlled folder access
- Network protection
- Real-time monitoring
- Email scanning protection
- Behavior monitoring

### 11. Advanced System Optimization
- Boot configuration optimization
- System response enhancement
- HPET optimization
- Power settings tuning
- Registry optimization
- Desktop manager enhancement
- Explorer performance tuning

## 📋 Requirements

- Windows 10/11
- PowerShell 5.1 or later
- Administrator privileges

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/Wsh7Ash/WindowsOptimizer.git
```

2. Navigate to the project directory:
```bash
cd WindowsOptimizer
```

## 💻 Usage

### Main Optimizer
1. Right-click on `WindowsOptimizer.ps1` and select "Run with PowerShell as Administrator"
   
   OR

2. Open PowerShell as Administrator and run:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\WindowsOptimizer.ps1
```

### Watermark Removal
To remove the Windows activation watermark:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\RemoveWatermark.ps1
```

⚠️ **Important**: The watermark removal script:
- Creates a system restore point before making changes
- Backs up modified system files
- Requires a system restart to take effect
- May need to be run again after major Windows updates

3. Select optimization options from the menu:
```
================ Windows System Optimizer ================
1: Memory Optimization
2: CPU Optimization
3: GPU Optimization
4: Service Optimization
5: Network Optimization
6: Storage Optimization
7: Privacy Optimization
8: Windows Debloater
9: Gaming Optimization
10: Security Optimization
11: Advanced System Optimization
12: Run All Optimizations
Q: Quit
====================================================
```

## ⚠️ Important Notes

- Always create a system restore point before running optimizations (automatically done by the script)
- Some optimizations may require a system restart
- Not all optimizations may be suitable for every system
- Review the changes before applying them
- The Windows Debloater will remove pre-installed apps and features
- Some security features may need to be adjusted based on your needs
- Gaming optimizations may affect non-gaming applications

## 🛡️ Safety Features

- Automatic system restore point creation
- Error handling for each optimization
- Confirmation prompts for major changes
- Easy-to-use menu interface
- Safe removal of Windows components
- Reversible optimizations
- Detailed status reporting

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Windows PowerShell community
- System optimization experts
- Open-source contributors
- Gaming community feedback
- Security researchers

## ⚡ Performance Impact

The optimizations can potentially improve:
- System responsiveness
- Gaming performance
- Boot time
- Memory management
- Network speed
- Storage efficiency
- Overall system performance
- Reduced system bloat
- Input lag
- Application loading times
- Security posture
- System stability

## 🔍 Troubleshooting

If you encounter issues:
1. Ensure you're running as Administrator
2. Check the Windows Event Viewer for errors
3. Restore from the created restore point if needed
4. Open an issue on GitHub for support
5. Check the detailed error messages in the console
6. Verify system compatibility before optimization

## 🔄 Updates

Check the repository regularly for updates and new optimizations. 