# AppBlocker - Advanced Application Blocker 🛡️

A powerful Windows application blocker with advanced security features that allows you to block specific applications from running on your system.

## 📋 Table of Contents
- [Features](#features)
- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Security Features](#security-features)
- [Security Bypass Reporting](#security-bypass-reporting)
- [FAQ](#faq)
- [Legal Disclaimer](#legal-disclaimer)

## <h2 id="features">✨ Features</h2>

### 🔒 Security
- **Password Protection** - All critical operations require administrator password
- **Star-based Password Input** - Secure password entry with visual feedback
- **Hash-based Authentication** - PBKDF2-HMAC-SHA256 with salt
- **Multiple Verification Methods** - Process names, window titles, company names
- **Auto-start Service** - Runs as Windows scheduled task
- **Self-healing** - Automatic restart on crashes

### 🎯 Application Blocking
- **Multiple Detection Methods**:
  - Process name matching
  - Window title detection
  - Company name verification
  - File hash checking
- **Pre-configured Database** - Popular applications (Steam, Discord, Chrome, Firefox, Spotify, etc.)
- **Manual Application Addition** - Add any application by process name or PID
- **Real-time Monitoring** - Continuous background monitoring
- **Force Termination** - Aggressive process killing when needed

### ⚙️ Service Management
- **Windows Service Integration** - Runs as scheduled task
- **Startup Automation** - Automatically starts with Windows
- **Detailed Logging** - Comprehensive activity logs
- **Service Status Monitoring** - Real-time status checks
- **Easy Installation/Removal** - Simple service management

## <h2 id="system-requirements"> 🖥️ System Requirements</h2>

- **OS**: Windows 10/11 (64-bit)
- **Architecture**: x64
- **Privileges**: Administrator rights required
- **Python**: 3.8+ (if running from source)
- **Dependencies**: psutil, pywin32
- **Storage**: 10MB free space
- **Memory**: 50MB RAM (minimal footprint)

## <h2 id="installation">📥 Installation</h2>

### Method 1: Pre-compiled Executable (Recommended)
1. Download `AppBlocker.exe` from the latest release. You can find this file in the dist folder.
2. Right-click the executable and select "Run as administrator"
3. Done!

### Method 2: From Source Code
```bash
# Clone the repository
git clone https://github.com/yourusername/appblocker.git
cd appblocker

# Install required dependencies
pip install psutil pywin32

# Run the application (as administrator)
python appblocker.py
```

### Method 3: Using PyInstaller (Build Yourself)
```bash
# Build standalone executable
pyinstaller --onefile --console --name "AppBlocker" --icon=shield.ico --add-data "*.json;." --hidden-import win32timezone appblocker.py

# The executable will be in the 'dist' folder

```


## Usage Guide

1.  **🔐 Configure Security**
    * Set or change administrator password
    * Required for all privileged operations
    * Password shown as stars (`***`) during input for security
    * Strong password recommendations enforced

2.  **🎯 Manage Applications (Requires Password)**
    * **Show Blocked Applications** - View currently blocked apps with details
    * **Add Application to Blocklist** - Three methods:
        * Popular Applications - Select from pre-configured list (e.g., Steam, Discord)
        * Process Name - Enter exact process name (e.g., `chrome.exe`, `spotify.exe`)
        * PID - Select from running processes list
    * **Remove Application** - Remove apps from the blocklist

3.  **🚀 Manage Service (Requires Password)**
    * **Install as Service** - Enable automatic startup monitoring
    * **Uninstall Service** - Remove automatic monitoring
    * **Check Service Status** - View service status, last run time, and logs
    * **Run Monitoring Manually** - Temporary manual monitoring (`Ctrl+C` to stop)

4.  **🔍 View Processes**
    * See all running processes with memory usage
    * Identify which processes are currently blocked
    * Find PIDs for manual blocking
    * Real-time process monitoring

5.  **📊 Check Service Logs**
    * View recent monitoring activity
    * See blocked application attempts with timestamps
    * Monitor service health and errors
    * Track all security-related events

6.  **⚠️ Reset Security (Requires Password)**
    * Complete security system reset
    * Removes all passwords and configurations
    * Use with **extreme caution!**
    * Requires current password verification


## Security Bypass Reporting

### If you bypass the security email me at


##  <h2 id="faq">❓ FAQ</h2>

### Q: Does it work with all Windows applications?
A: Most Windows applications are supported. Some system processes, anti-virus software, and specially protected applications might require additional configuration or may not be blockable due to system protections.

### Q: Can I block websites or browser extensions?
A: No, AppBlocker works at the application process level, not web content level. It blocks executable processes, not web traffic or browser extensions.

### Q: Is there a noticeable performance impact?
A: Minimal impact - the service uses efficient process monitoring with small memory footprint (typically < 50MB RAM). CPU usage is negligible during normal operation.

### Q: How do I completely uninstall AppBlocker?
A:

* Use "Uninstall Service" option (requires password)

* Delete the application executable

* Remove C:\ProgramData\AppBlocker directory

* Verify removal from Task Scheduler

### Q: Can the password be recovered if forgotten?
A: No, for security reasons there is no password recovery. You must use the "Reset Security" option which requires the current password. If completely forgotten, you'll need to reinstall the application.

### Q: Does it work on Windows Server editions?
A: While primarily designed for Windows 10/11, it should work on Windows Server 2016+ with appropriate permissions and dependencies.

### Q: Can multiple applications be blocked simultaneously?
A: Yes, there's no limit to the number of applications you can add to the blocklist. The service monitors and blocks all specified applications.

### Q: How often does the service check for blocked applications?
A: The monitoring service checks running processes every 3 seconds, providing near real-time blocking of unauthorized applications.

### Q: Can I use wildcards or partial names for blocking?
A: Currently, exact process names are required for reliable blocking. The system matches against complete process names for security reasons.


## <h2 id="legal-disclamer">⚖️ Legal Disclaimer </h2>

### Purposes
This software is intended for legitimate purposes including:

* Parental controls and child protection

* Workplace productivity and focus management

* Educational institution computer management

* Personal self-control and habit building

* Organizational security policy enforcement

### No Liability
The developers and contributors are not responsible for:

* Misuse or illegal use of this software

* Legal violations committed by users

* System instability or damages caused by improper use

* Any direct, indirect, or consequential damages

* Loss of data, privacy breaches, or security incidents

* Violations of terms of service or licensing agreements


### 📄 License

This project is licensed under the MIT License.

## Contact
You can contact me via e-mail: pagafryba@gmail.com
