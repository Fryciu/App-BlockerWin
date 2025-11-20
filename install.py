# install_appblocker.py - Prosty instalator
import sys
import os

def create_shortcut():
    """Tworzy skrót do aplikacji"""
    try:
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        script_path = os.path.abspath(__file__).replace("install_appblocker.py", "appblocker.py")
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(os.path.join(desktop, "AppBlocker.lnk"))
        shortcut.Targetpath = sys.executable
        shortcut.Arguments = f'"{script_path}"'
        shortcut.WorkingDirectory = os.path.dirname(script_path)
        shortcut.IconLocation = script_path
        shortcut.save()
        
        print("✅ Utworzono skrót na pulpicie")
    except:
        print("⚠️  Nie udało się utworzyć skrótu")

if __name__ == "__main__":
    print("🔧 Instalator AppBlocker")
    print("=" * 40)
    
    # Sprawdź uprawnienia
    if ctypes.windll.shell32.IsUserAnAdmin():
        from appblocker import AdvancedAppBlocker
        blocker = AdvancedAppBlocker()
        
        print("1. Zainstaluj jako usługę")
        print("2. Utwórz skrót na pulpicie")
        print("3. Oba powyższe")
        
        choice = input("\nWybierz opcję (1-3): ").strip()
        
        if choice in ["1", "3"]:
            blocker.install_as_service()
        
        if choice in ["2", "3"]:
            create_shortcut()
            
    else:
        print("❌ Uruchom jako administrator aby zainstalować")
        input("Naciśnij Enter aby zakończyć...")