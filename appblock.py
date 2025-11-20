import os
import sys
import ctypes
import subprocess
import psutil
import time
import json
import hashlib
import win32process
import win32gui
import win32con
import win32api
import base64
from datetime import datetime, timedelta

try:
    import win32cred
    CREDENTIAL_MANAGER_AVAILABLE = True
except ImportError:
    CREDENTIAL_MANAGER_AVAILABLE = False

# Cross-platform password input with stars
def input_with_stars(prompt="Enter password: "):
    """
    Password input that shows stars (*) instead of characters
    Works on both Windows and other platforms
    """
    import sys
    import msvcrt  # Windows specific
    
    print(prompt, end='', flush=True)
    password = []
    
    while True:
        char = msvcrt.getch()
        
        # Enter key (carriage return or line feed)
        if char in [b'\r', b'\n']:
            print()  # New line after Enter
            break
        # Backspace key
        elif char == b'\x08':
            if password:
                password.pop()
                # Move cursor back, print space, move cursor back again
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        # Escape key or Ctrl+C
        elif char == b'\x1b' or char == b'\x03':
            raise KeyboardInterrupt("Password input cancelled")
        # Regular character
        else:
            try:
                char_decoded = char.decode('utf-8')
                if char_decoded.isprintable():
                    password.append(char_decoded)
                    sys.stdout.write('*')
                    sys.stdout.flush()
            except UnicodeDecodeError:
                pass  # Ignore non-printable characters
    
    return ''.join(password)

class SecureAppBlocker:
    def __init__(self):
        # Configuration paths
        if self.is_service_context():
            self.config_dir = os.path.join(os.getenv('ProgramData'), 'AppBlocker')
        else:
            self.config_dir = os.path.dirname(os.path.abspath(__file__))
            
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
            
        self.config_file = os.path.join(self.config_dir, "secure_app_blocker_config.json")
        self.log_file = os.path.join(self.config_dir, "appblocker_log.txt")
        self.auth_file = os.path.join(self.config_dir, ".auth")
        
        self.blocked_apps = []
        self.block_schedule = {}
        self.load_config()
        
        # Application database
        self.app_database = {
            "steam": {
                "process_names": ["steam.exe", "steamservice.exe", "steamwebhelper.exe"],
                "window_titles": ["steam"],
                "company_names": ["valve corporation"]
            },
            "discord": {
                "process_names": ["discord.exe", "discordptb.exe", "discordcanary.exe"],
                "window_titles": ["discord"],
                "company_names": ["discord inc."]
            },
            "spotify": {
                "process_names": ["spotify.exe", "spotifylauncher.exe"],
                "window_titles": ["spotify"],
                "company_names": ["spotify ltd"]
            },
            "chrome": {
                "process_names": ["chrome.exe"],
                "window_titles": ["google chrome"],
                "company_names": ["google llc"]
            },
            "firefox": {
                "process_names": ["firefox.exe"],
                "window_titles": ["mozilla firefox"],
                "company_names": ["mozilla corporation"]
            }
        }

    # SECURITY METHODS
    def create_password_hash(self, password, salt=None):
        """Creates password hash with salt"""
        if salt is None:
            salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt + key).decode()

    def verify_password(self, password, stored_hash):
        """Verifies password against stored hash"""
        try:
            decoded = base64.b64decode(stored_hash.encode())
            salt = decoded[:32]
            stored_key = decoded[32:]
            key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            return key == stored_key
        except:
            return False

    def safe_input_password(self, prompt="🔒 Enter password: "):
        """Secure password input with stars for visibility"""
        try:
            return input_with_stars(prompt)
        except KeyboardInterrupt:
            print("\n❌ Password input cancelled")
            return ""
        except Exception as e:
            # Fallback to regular input if star input fails
            print(f"⚠️  Using basic input: {e}")
            return input(prompt)

    def setup_authentication(self):
        """Configures authentication system"""
        if self.is_authentication_configured():
            print("🔐 Authentication system is already configured")
            change = input("Do you want to change the password? (Y/N): ").strip().upper()
            if change != 'Y':
                return True

        print("\n" + "=" * 50)
        print("🔐 SECURITY CONFIGURATION")
        print("=" * 50)
        print("Set administrator password for AppBlocker")
        print("Password will be required for:")
        print("  - Installing/uninstalling service")
        print("  - Modifying blocked applications list")
        print("  - Accessing advanced functions")
        print("\n💡 Password will be shown as stars (***) while typing")
        print("   Press Backspace to correct mistakes")
        print("   Press Enter when done")
        
        while True:
            print("\n" + "=" * 30)
            password = self.safe_input_password("🔒 Enter new password: ")
            
            if not password:
                print("❌ Password cannot be empty")
                continue
            
            # Show password strength
                
            confirm_password = self.safe_input_password("🔒 Confirm password: ")
            
            if not confirm_password:
                print("❌ Confirmation password cannot be empty")
                continue
                
            if password != confirm_password:
                print("❌ Passwords do not match")
                continue
                
            break

        # Save password hash
        password_hash = self.create_password_hash(password)
        try:
            with open(self.auth_file, 'w', encoding='utf-8') as f:
                f.write(password_hash)
        except Exception as e:
            print(f"❌ Error saving password: {e}")
            return False

        print("\n✅ Security configuration completed")
        print("💡 Remember the password - it will be required for important operations")
        return True

    
    def is_authentication_configured(self):
        """Checks if authentication is configured"""
        return os.path.exists(self.auth_file)

    def authenticate_admin(self, operation_name="this operation"):
        """Verifies administrator password"""
        if not self.is_authentication_configured():
            print("❌ Security system is not configured")
            print("Run 'Configure security' in main menu")
            return False

        print(f"\n🔐 AUTHENTICATION REQUIRED")
        print(f"Operation: {operation_name}")
        print("-" * 40)
        print("Enter administrator password to continue")
        print("💡 Password will be shown as stars (***)")
        
        # Give user 3 attempts
        for attempt in range(3):
            password = self.safe_input_password("🔒 Password: ")
            
            if not password:
                print("❌ No password entered")
                continue
            
            # Check hash from file
            try:
                with open(self.auth_file, 'r', encoding='utf-8') as f:
                    stored_hash = f.read().strip()
            except:
                print("❌ Error reading authentication file")
                return False

            if self.verify_password(password, stored_hash):
                print("✅ Authentication successful")
                return True
            else:
                remaining_attempts = 2 - attempt
                if remaining_attempts > 0:
                    print(f"❌ Incorrect password. Remaining attempts: {remaining_attempts}")
                else:
                    print("❌ Too many failed attempts. Access blocked.")
                    return False
        
        return False

    def reset_authentication(self):
        """Resets authentication system (requires verification)"""
        print("\n⚠️  SECURITY SYSTEM RESET")
        print("This operation will remove all security measures!")
        
        if not self.authenticate_admin("security system reset"):
            return False

        confirm = input("Are you sure you want to reset the security system? (YES/NO): ")
        if confirm.upper() != 'YES':
            print("❌ Reset cancelled")
            return False

        # Delete hash file
        try:
            if os.path.exists(self.auth_file):
                os.remove(self.auth_file)
                print("✅ Authentication file removed")
        except Exception as e:
            print(f"❌ Error deleting file: {e}")

        print("✅ Security system has been reset")
        return True

    # LOGGING AND CONFIGURATION METHODS
    def is_service_context(self):
        """Checks if program is running as service"""
        try:
            return os.getenv('SESSIONNAME') == 'Console' or not os.getenv('USERNAME')
        except:
            return False

    def is_admin(self):
        """Checks if program is running as administrator"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def log_message(self, message):
        """Logs message to file"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}"
        
        if not self.is_service_context():
            print(log_entry)
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + '\n')
        except Exception as e:
            print(f"Log write error: {e}")

    def load_config(self):
        """Loads configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.blocked_apps = data.get('blocked_apps', [])
                    self.block_schedule = data.get('schedule', {})
                self.log_message(f"✅ Configuration loaded: {len(self.blocked_apps)} applications")
            else:
                self.save_config()
                self.log_message("📝 New configuration created")
        except Exception as e:
            self.log_message(f"❌ Configuration loading error: {e}")

    def save_config(self):
        """Saves configuration to file"""
        try:
            data = {
                'blocked_apps': self.blocked_apps,
                'schedule': self.block_schedule,
                'last_updated': datetime.now().isoformat()
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.log_message("💾 Configuration saved")
        except Exception as e:
            self.log_message(f"❌ Configuration save error: {e}")

    # APPLICATION MANAGEMENT METHODS (now protected)
    def show_blocked_apps(self):
        """Shows list of blocked applications"""
        print("\n🚫 BLOCKED APPLICATIONS:")
        print("-" * 50)
        
        if not self.blocked_apps:
            print("No blocked applications")
            return
        
        for i, app in enumerate(self.blocked_apps, 1):
            print(f"{i}. {app['app_name']}")
            if 'process_names' in app:
                print(f"   Processes: {', '.join(app['process_names'])}")
            print()

    def add_application(self):
        """Adds application to blocked list (requires authentication)"""
        if not self.authenticate_admin("adding applications to blocklist"):
            return

        print("\n📋 ADD APPLICATION TO BLOCKLIST")
        print("1 - From popular applications list")
        print("2 - By process name (e.g., chrome.exe)")
        print("3 - By PID (process identifier)")
        print("4 - Cancel")
        
        choice = input("\nChoose method (1-4): ").strip()
        
        if choice == "1":
            self.add_from_popular_list()
        elif choice == "2":
            self.add_by_process_name()
        elif choice == "3":
            self.add_by_pid()
        elif choice == "4":
            print("❌ Operation cancelled")
        else:
            print("❌ Invalid choice")

    def add_from_popular_list(self):
        """Adds from popular applications list"""
        print("\n🎯 POPULAR APPLICATIONS:")
        apps = list(self.app_database.keys())
        for i, app in enumerate(apps, 1):
            status = "🚫 BLOCKED" if any(a['app_name'] == app for a in self.blocked_apps) else "✅ AVAILABLE TO BLOCK"
            print(f"{i}. {app:15} - {status}")
        
        try:
            choice = input("\nChoose application number: ").strip()
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(apps):
                    app_name = apps[index]
                    if not any(a['app_name'] == app_name for a in self.blocked_apps):
                        app_data = self.app_database[app_name].copy()
                        app_data['app_name'] = app_name
                        self.blocked_apps.append(app_data)
                        self.save_config()
                        print(f"✅ Added {app_name} to blocklist")
                    else:
                        print(f"ℹ️  {app_name} is already blocked")
                else:
                    print("❌ Invalid number")
        except Exception as e:
            print(f"❌ Error: {e}")

    def add_by_process_name(self):
        """Adds by process name"""
        print("\n📝 ADD BY PROCESS NAME")
        print("Examples: chrome.exe, discord.exe, spotify.exe")
        
        process_name = input("Enter process name: ").strip().lower()
        if not process_name.endswith('.exe'):
            process_name += '.exe'
        
        if process_name:
            app_name = process_name.replace('.exe', '')
            app_data = {
                'app_name': app_name,
                'process_names': [process_name],
                'detected_at': datetime.now().isoformat()
            }
            
            if not any(a['app_name'] == app_name for a in self.blocked_apps):
                self.blocked_apps.append(app_data)
                self.save_config()
                print(f"✅ Added {process_name} to blocklist")
            else:
                print(f"ℹ️  {app_name} is already blocked")
        else:
            print("❌ No process name provided")

    def add_by_pid(self):
        """Adds by process PID"""
        print("\n🔢 ADD BY PID")
        self.show_running_processes()
        
        pid_input = input("\nEnter process PID: ").strip()
        if pid_input.isdigit():
            pid = int(pid_input)
            try:
                process_info = self.get_process_info(pid)
                if process_info:
                    app_name = self.detect_application_type(process_info)
                    
                    blocked_app = {
                        'app_name': app_name,
                        'process_names': [process_info['name']],
                        'company_names': [process_info['company_name']] if process_info['company_name'] else [],
                        'detected_at': datetime.now().isoformat()
                    }
                    
                    if not any(a['app_name'] == app_name for a in self.blocked_apps):
                        self.blocked_apps.append(blocked_app)
                        self.save_config()
                        print(f"✅ Added {app_name} to blocklist")
                    else:
                        print(f"ℹ️  {app_name} is already blocked")
                else:
                    print("❌ Process with given PID not found")
            except Exception as e:
                print(f"❌ Error: {e}")
        else:
            print("❌ Invalid PID")

    def remove_application(self):
        """Removes application from blocked list (requires authentication)"""
        if not self.authenticate_admin("removing applications from blocklist"):
            return

        self.show_blocked_apps()
        
        if not self.blocked_apps:
            return
            
        try:
            choice = input("\nEnter application number to remove: ").strip()
            if choice.isdigit():
                index = int(choice) - 1
                if 0 <= index < len(self.blocked_apps):
                    app_name = self.blocked_apps[index]['app_name']
                    self.blocked_apps.pop(index)
                    self.save_config()
                    print(f"✅ Removed {app_name} from blocklist")
                else:
                    print("❌ Invalid number")
        except Exception as e:
            print(f"❌ Error: {e}")

    # SERVICE METHODS (password protected)
    def install_as_service(self):
        """Installs application as scheduled task (requires authentication)"""
        if not self.authenticate_admin("service installation"):
            return False

        if not self.is_admin():
            print("❌ Administrator privileges required")
            return False

        try:
            script_path = os.path.abspath(__file__)
            pythonw_path = sys.executable.replace("python.exe", "pythonw.exe")
            if not os.path.exists(pythonw_path):
                pythonw_path = sys.executable

            ps_script = f"""
$Action = New-ScheduledTaskAction -Execute "{pythonw_path}" -Argument "{script_path} --monitor"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "AppBlocker" -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel Highest -Description "App blocking service"
Start-ScheduledTask -TaskName "AppBlocker"
Write-Output "AppBlocker task has been created and started"
"""

            ps_script_file = "install_appblocker.ps1"
            with open(ps_script_file, 'w', encoding='utf-8') as f:
                f.write(ps_script)

            result = subprocess.run([
                'powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', ps_script_file
            ], capture_output=True, text=True, timeout=30)

            if os.path.exists(ps_script_file):
                os.remove(ps_script_file)

            if result.returncode == 0:
                print("✅ Successfully installed AppBlocker as service")
                self.log_message("🔧 Service installed by administrator")
                return True
            else:
                print(f"❌ Installation error: {result.stderr}")
                return False

        except Exception as e:
            print(f"❌ Error during installation: {e}")
            return False

    def uninstall_service(self):
        """Uninstalls scheduled task (requires authentication)"""
        if not self.authenticate_admin("service uninstallation"):
            return False

        if not self.is_admin():
            print("❌ Administrator privileges required")
            return False

        try:
            ps_script = """
Stop-ScheduledTask -TaskName "AppBlocker" -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "AppBlocker" -Confirm:$false
Write-Output "AppBlocker task has been removed"
"""

            ps_script_file = "uninstall_appblocker.ps1"
            with open(ps_script_file, 'w', encoding='utf-8') as f:
                f.write(ps_script)

            result = subprocess.run([
                'powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', ps_script_file
            ], capture_output=True, text=True, timeout=30)

            if os.path.exists(ps_script_file):
                os.remove(ps_script_file)

            if result.returncode == 0:
                print("✅ Successfully uninstalled AppBlocker service")
                self.log_message("🔧 Service uninstalled by administrator")
                return True
            else:
                print(f"❌ Uninstallation error: {result.stderr}")
                return False

        except Exception as e:
            print(f"❌ Error during uninstallation: {e}")
            return False

    # Remaining methods (unchanged)
    def show_running_processes(self):
        """Shows currently running processes"""
        print("\n🔍 CURRENTLY RUNNING PROCESSES:")
        print("-" * 60)
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        processes.sort(key=lambda x: x['memory_percent'], reverse=True)
        
        for i, proc in enumerate(processes[:20]):
            is_blocked = any(proc['name'].lower() in [p.lower() for p in app.get('process_names', [])] 
                           for app in self.blocked_apps)
            status = "🚫 BLOCKED" if is_blocked else "✅ ALLOWED"
            print(f"{i+1:2}. {proc['name']:25} (PID: {proc['pid']:6}) - {status}")

    def check_service_status(self):
        """Checks scheduled task status"""
        try:
            ps_script = """
$task = Get-ScheduledTask -TaskName "AppBlocker" -ErrorAction SilentlyContinue
if ($task) {
    $state = $task.State
    $lastRun = $task.LastRunTime
    $nextRun = $task.NextRunTime
    Write-Output "Status: $state"
    Write-Output "Last run: $lastRun"
    Write-Output "Next run: $nextRun"
} else {
    Write-Output "Task does not exist"
}
"""

            result = subprocess.run([
                'powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', ps_script
            ], capture_output=True, text=True, timeout=10)

            print("\n📊 APPBLOKER SERVICE STATUS:")
            print("-" * 40)
            if result.returncode == 0:
                print(result.stdout)
                
                log_path = os.path.join(os.getenv('ProgramData'), 'AppBlocker', 'appblocker_log.txt')
                if os.path.exists(log_path):
                    print(f"\n📝 Recent log entries:")
                    with open(log_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()[-10:]
                        for line in lines:
                            print(f"   {line.strip()}")
            else:
                print("❌ Cannot check status")

        except Exception as e:
            print(f"❌ Status check error: {e}")

    def run_monitoring_service(self):
        """Runs monitoring as service"""
        self.log_message("=" * 50)
        self.log_message("🛡️  APPBLOKER SERVICE STARTED")
        self.log_message("=" * 50)
        self.log_message(f"📁 Configuration directory: {self.config_dir}")
        self.log_message(f"🔍 Number of blocked applications: {len(self.blocked_apps)}")
        
        if self.blocked_apps:
            app_list = ", ".join([app['app_name'] for app in self.blocked_apps])
            self.log_message(f"🚫 Blocked applications: {app_list}")
        else:
            self.log_message("⚠️  NO APPLICATIONS TO BLOCK!")

        monitor_count = 0
        try:
            while True:
                killed_count = self.kill_blocked_applications()
                if killed_count > 0:
                    self.log_message(f"🚫 Blocked {killed_count} applications")
                
                monitor_count += 1
                if monitor_count % 60 == 0:
                    self.log_message(f"🔍 Monitoring active - cycle {monitor_count}")
                    self.load_config()
                
                time.sleep(3)

        except KeyboardInterrupt:
            self.log_message("⏹️  Service stopped by user")
        except Exception as e:
            self.log_message(f"❌ SERVICE ERROR: {e}")
            self.log_message("♻️  Restarting in 10 seconds...")
            time.sleep(10)
            self.run_monitoring_service()

    def kill_blocked_applications(self):
        """Terminates blocked applications"""
        killed_count = 0
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                process_info = self.get_process_info(proc.info['pid'])
                if process_info and self.is_process_blocked(process_info):
                    app_name = self.detect_application_type(process_info)
                    
                    try:
                        process = psutil.Process(proc.info['pid'])
                        process.terminate()
                        process.wait(timeout=2)
                        self.log_message(f"✅ Terminated {app_name} (PID: {proc.info['pid']})")
                        killed_count += 1
                        
                    except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                        try:
                            subprocess.run(
                                ["taskkill", "/F", "/PID", str(proc.info['pid'])], 
                                capture_output=True, 
                                timeout=5,
                                check=True
                            )
                            self.log_message(f"💥 Force terminated {app_name} (PID: {proc.info['pid']})")
                            killed_count += 1
                        except subprocess.CalledProcessError:
                            self.log_message(f"⚠️  Failed to terminate {app_name} (PID: {proc.info['pid']})")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return killed_count

    def is_process_blocked(self, process_info):
        """Checks if process should be blocked"""
        if not process_info:
            return False
            
        for blocked_app in self.blocked_apps:
            if 'process_names' in blocked_app:
                for proc_name in blocked_app['process_names']:
                    if proc_name.lower() == process_info['name'].lower():
                        return True
        return False

    def detect_application_type(self, process_info):
        """Detects application type"""
        if not process_info:
            return "unknown"
            
        for app_name, app_data in self.app_database.items():
            if 'process_names' in app_data:
                for proc_name in app_data['process_names']:
                    if proc_name.lower() == process_info['name'].lower():
                        return app_name
                        
        return process_info['name'].replace('.exe', '')

    def get_process_info(self, pid):
        """Gets process information"""
        try:
            process = psutil.Process(pid)
            info = {
                'pid': pid,
                'name': process.name(),
                'exe': process.exe(),
                'company_name': self.get_file_company(process.exe()) if process.exe() else ""
            }
            return info
        except:
            return None

    def get_file_company(self, file_path):
        """Gets company name from EXE file"""
        try:
            info = win32api.GetFileVersionInfo(file_path, '\\')
            company = info.get('CompanyName', '')
            return company.lower() if company else ""
        except:
            return ""

def main():
    blocker = SecureAppBlocker()
    
    # Service mode
    if len(sys.argv) > 1 and sys.argv[1] == "--monitor":
        blocker.run_monitoring_service()
        return

    if not blocker.is_admin():
        print("⚠️  Run as administrator for full functionality")
    
    # Check dependencies
    try:
        import psutil
        import win32gui
        import win32process
        import win32api
    except ImportError:
        print("📦 Installing required libraries...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil", "pywin32"])
        import psutil
        import win32gui
        import win32process
        import win32api

    while True:
        print("\n" + "=" * 60)
        print("🛡️  APPBLOKER - SECURE VERSION")
        print("=" * 60)
        print("1 - 🔐 Configure security")
        print("2 - 🎯 Manage applications (requires password)")
        print("3 - 🚀 Manage service (requires password)")
        print("4 - 🔍 View processes")
        print("5 - 📊 Check service logs")
        print("6 - ⚠️  Reset security (requires password)")
        print("7 - ❌ Exit")
        
        choice = input("\nChoose option (1-7): ").strip()
        
        if choice == "1":
            blocker.setup_authentication()
                    
        elif choice == "2":
            if not blocker.is_authentication_configured():
                print("❌ First configure security system (option 1)")
                continue
                
            while True:
                print("\n" + "=" * 40)
                print("🎯 APPLICATION MANAGEMENT")
                print("=" * 40)
                print("1 - Show blocked applications")
                print("2 - Add application to blocklist")
                print("3 - Remove application from blocklist")
                print("4 - Return to main menu")
                
                sub_choice = input("\nChoose option (1-4): ").strip()
                
                if sub_choice == "1":
                    blocker.show_blocked_apps()
                elif sub_choice == "2":
                    blocker.add_application()
                elif sub_choice == "3":
                    blocker.remove_application()
                elif sub_choice == "4":
                    break
                else:
                    print("❌ Invalid choice")
                    
        elif choice == "3":
            if not blocker.is_authentication_configured():
                print("❌ First configure security system (option 1)")
                continue
                
            while True:
                print("\n" + "=" * 40)
                print("🚀 SERVICE MANAGEMENT")
                print("=" * 40)
                print("1 - Install as service")
                print("2 - Uninstall service")
                print("3 - Check service status")
                print("4 - Run monitoring manually")
                print("5 - Return to main menu")
                
                sub_choice = input("\nChoose option (1-5): ").strip()
                
                if sub_choice == "1":
                    blocker.install_as_service()
                elif sub_choice == "2":
                    blocker.uninstall_service()
                elif sub_choice == "3":
                    blocker.check_service_status()
                elif sub_choice == "4":
                    print("\n🔍 Starting manual monitoring...")
                    print("Press Ctrl+C to stop")
                    try:
                        blocker.run_monitoring_service()
                    except KeyboardInterrupt:
                        print("\n⏹️  Monitoring stopped")
                elif sub_choice == "5":
                    break
                else:
                    print("❌ Invalid choice")
                    
        elif choice == "4":
            blocker.show_running_processes()
            
        elif choice == "5":
            print("\n📊 SERVICE LOGS:")
            print("-" * 40)
            if os.path.exists(blocker.log_file):
                with open(blocker.log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()[-20:]
                    for line in lines:
                        print(line.strip())
            else:
                print("No log file found")
                
        elif choice == "6":
            blocker.reset_authentication()
                
        elif choice == "7":
            print("Goodbye!")
            break
            
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    main()