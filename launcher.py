# -*- coding: utf-8 -*-
# launcher.py - GUI Launcher for RDDS

import sys
import os
import ctypes
import subprocess
from tkinter import messagebox
import tkinter as tk

def is_admin():
    """Check if script is running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def restart_as_admin():
    """Restart the script with admin privileges"""
    try:
        script = os.path.abspath(__file__)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", "python", script, "", 1)
        sys.exit(0)
    except:
        messagebox.showerror("Error", "Failed to restart with administrator privileges!")
        sys.exit(1)

def main():
    """Main launcher function"""
    
    # Check admin privileges
    if not is_admin():
        root = tk.Tk()
        root.withdraw()  # Hide main window
        
        result = messagebox.askyesno(
            "Administrator Privileges Required",
            "🛡️ Rogue Detection System requires Administrator privileges to:\n\n"
            "• Capture network packets\n"
            "• Perform ARP scanning\n"
            "• Monitor network interfaces\n"
            "• Access raw socket operations\n\n"
            "Would you like to restart as Administrator?",
            icon='warning'
        )
        
        root.destroy()
        
        if result:
            restart_as_admin()
        else:
            messagebox.showinfo("Limited Functionality", 
                             "The application will run with limited functionality without admin privileges.")
    
    # Launch the GUI
    try:
        from gui_main import ModernRDDS_GUI
        app = ModernRDDS_GUI()
        app.run()
    except ImportError as e:
        messagebox.showerror("Import Error", f"Failed to import GUI module: {e}\n\nPlease ensure all required modules are installed.")
    except Exception as e:
        messagebox.showerror("Application Error", f"Failed to start application: {e}")

if __name__ == "__main__":
    main()
