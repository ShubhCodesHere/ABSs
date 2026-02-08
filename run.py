import os
import sys
import subprocess
import time

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("=" * 60)
    print("   🛡️  SECURE AGENT BROWSER SECURITY SUITE  🛡️")
    print("=" * 60)
    print("      Hackathon Submission - Easy Launcher")
    print("=" * 60)

def install_dependencies():
    print("\n📦 Installing dependencies from requirements.txt...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("\n✅ Dependencies installed successfully!")
        time.sleep(2)
    except subprocess.CalledProcessError:
        print("\n❌ Error installing dependencies.")
        input("Press Enter to continue...")

def start_attack_server():
    print("\n🚀 Starting Attack Server (Port 5001)...")
    print("   (This runs in a new window/process)")
    try:
        if os.name == 'nt':
            # Use specific quoting to handle paths with spaces
            cmd = f'"{sys.executable}" attack_server.py'
            subprocess.Popen(f'start cmd /k "{cmd}"', shell=True)
        else:
            subprocess.Popen([sys.executable, "attack_server.py"]) 
            print("   Running in background...")
    except Exception as e:
        print(f"❌ Failed to start server: {e}")

def start_dashboard():
    print("\n📊 Starting Security Dashboard...")
    print("   (Opening Streamlit app)")
    try:
        cmd = f'"{sys.executable}" -m streamlit run security/dashboard_app.py'
        if os.name == 'nt':
             # Use specific quoting to handle paths with spaces
            subprocess.Popen(f'start cmd /k "{cmd}"', shell=True)
        else:
            subprocess.Popen([sys.executable, "-m", "streamlit", "run", "security/dashboard_app.py"])
    except Exception as e:
        print(f"❌ Failed to start dashboard: {e}")

def run_secure_agent_default():
    print("\n🕵️  Running Secure Agent (Default Task)...")
    try:
        subprocess.run([sys.executable, "main_secure.py"])
    except Exception as e:
        print(f"❌ Error running agent: {e}")
    input("\nPress Enter to return to menu...")

def run_secure_agent_custom():
    print("\n🕵️  Running Secure Agent (Custom Task)...")
    task = input("   👉 Enter your custom prompt/task: ")
    if not task.strip():
        print("   ⚠️ No task entered. Returning...")
        return
    
    try:
        subprocess.run([sys.executable, "main_secure.py", task])
    except Exception as e:
        print(f"❌ Error running agent: {e}")
    input("\nPress Enter to return to menu...")

def main_menu():
    while True:
        clear_screen()
        print_header()
        print("\n   [1] 📦 Install/Update Dependencies")
        print("   [2] ☠️  Start Attack Server (Simulation Env)")
        print("   [3] 📊 Start Security Dashboard (Visualization)")
        print("   [4] 🤖 Run Secure Agent (Default Validation)")
        print("   [5] 🧠 Run Secure Agent (Custom Prompt)")
        print("\n   [0] 🚪 Exit")
        print("-" * 60)
        
        choice = input("   Select an option: ")
        
        if choice == '1':
            install_dependencies()
        elif choice == '2':
            start_attack_server()
        elif choice == '3':
            start_dashboard()
        elif choice == '4':
            run_secure_agent_default()
        elif choice == '5':
            run_secure_agent_custom()
        elif choice == '0':
            print("\n👋 Exiting. Goodbye!")
            sys.exit(0)
        else:
            input("   ❌ Invalid choice. Press Enter...")

if __name__ == "__main__":
    main_menu()