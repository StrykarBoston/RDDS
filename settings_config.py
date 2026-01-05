# -*- coding: utf-8 -*-
# settings_config.py - Settings and Configuration Management

import json
import os
from tkinter import ttk, messagebox
import tkinter as tk

class SettingsManager:
    def __init__(self, settings_file='settings.json'):
        self.settings_file = settings_file
        self.settings = self.load_settings()
        
    def load_settings(self):
        """Load settings from file"""
        default_settings = {
            'network': {
                'interface': 'auto',
                'scan_timeout': 2,
                'max_threads': 10
            },
            'detection': {
                'risk_threshold': 70,
                'enable_mac_spoof_detection': True,
                'enable_vendor_check': True,
                'suspicious_vendors': ['Unknown', 'Raspberry Pi']
            },
            'monitoring': {
                'default_duration': 60,
                'alert_sound': True,
                'auto_save_reports': True
            },
            'gui': {
                'theme': 'light',
                'auto_refresh': True,
                'refresh_interval': 5
            },
            'logging': {
                'level': 'INFO',
                'max_file_size': 10485760,  # 10MB
                'backup_count': 5
            }
        }
        
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                    # Merge with defaults
                    for section in default_settings:
                        if section not in loaded_settings:
                            loaded_settings[section] = default_settings[section]
                        else:
                            for key, value in default_settings[section].items():
                                if key not in loaded_settings[section]:
                                    loaded_settings[section][key] = value
                    return loaded_settings
            except:
                pass
                
        return default_settings
    
    def save_settings(self):
        """Save settings to file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
            return True
        except:
            return False
    
    def get(self, section, key, default=None):
        """Get setting value"""
        return self.settings.get(section, {}).get(key, default)
    
    def set(self, section, key, value):
        """Set setting value"""
        if section not in self.settings:
            self.settings[section] = {}
        self.settings[section][key] = value

class SettingsDialog:
    def __init__(self, parent, settings_manager):
        self.parent = parent
        self.settings_manager = settings_manager
        self.dialog = None
        self.widgets = {}
        
    def show(self):
        """Show settings dialog"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("⚙️ Settings & Configuration")
        self.dialog.geometry("600x500")
        self.dialog.resizable(True, True)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Create notebook for settings categories
        notebook = ttk.Notebook(self.dialog)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create settings tabs
        self.create_network_settings(notebook)
        self.create_detection_settings(notebook)
        self.create_monitoring_settings(notebook)
        self.create_gui_settings(notebook)
        self.create_logging_settings(notebook)
        
        # Buttons
        button_frame = tk.Frame(self.dialog)
        button_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Button(button_frame, text="Save", command=self.save_settings).pack(side='right', padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side='right')
        ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_defaults).pack(side='left')
        
        # Center dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
    def create_network_settings(self, notebook):
        """Create network settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🌐 Network")
        
        # Network Interface
        tk.Label(frame, text="Network Interface:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(20, 5))
        self.widgets['network_interface'] = ttk.Combobox(frame, state='readonly')
        self.widgets['network_interface']['values'] = ['Auto'] + self.get_available_interfaces()
        self.widgets['network_interface'].pack(fill='x', padx=20, pady=(0, 15))
        self.widgets['network_interface'].set(self.settings_manager.get('network', 'interface', 'auto').title())
        
        # Scan Timeout
        tk.Label(frame, text="Scan Timeout (seconds):", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        self.widgets['scan_timeout'] = tk.Scale(frame, from_=1, to=10, orient='horizontal')
        self.widgets['scan_timeout'].set(self.settings_manager.get('network', 'scan_timeout', 2))
        self.widgets['scan_timeout'].pack(fill='x', padx=20, pady=(0, 15))
        
        # Max Threads
        tk.Label(frame, text="Maximum Scan Threads:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        self.widgets['max_threads'] = tk.Scale(frame, from_=1, to=20, orient='horizontal')
        self.widgets['max_threads'].set(self.settings_manager.get('network', 'max_threads', 10))
        self.widgets['max_threads'].pack(fill='x', padx=20, pady=(0, 15))
        
    def create_detection_settings(self, notebook):
        """Create detection settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🔍 Detection")
        
        # Risk Threshold
        tk.Label(frame, text="Risk Threshold:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(20, 5))
        self.widgets['risk_threshold'] = tk.Scale(frame, from_=0, to=100, orient='horizontal')
        self.widgets['risk_threshold'].set(self.settings_manager.get('detection', 'risk_threshold', 70))
        self.widgets['risk_threshold'].pack(fill='x', padx=20, pady=(0, 15))
        
        # Detection Options
        tk.Label(frame, text="Detection Options:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        
        self.widgets['mac_spoof_detection'] = tk.BooleanVar()
        self.widgets['mac_spoof_detection'].set(self.settings_manager.get('detection', 'enable_mac_spoof_detection', True))
        tk.Checkbutton(frame, text="Enable MAC Spoofing Detection", 
                       variable=self.widgets['mac_spoof_detection']).pack(anchor='w', padx=20, pady=2)
        
        self.widgets['vendor_check'] = tk.BooleanVar()
        self.widgets['vendor_check'].set(self.settings_manager.get('detection', 'enable_vendor_check', True))
        tk.Checkbutton(frame, text="Enable Vendor Check", 
                       variable=self.widgets['vendor_check']).pack(anchor='w', padx=20, pady=2)
        
        # Suspicious Vendors
        tk.Label(frame, text="Suspicious Vendors:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        self.widgets['suspicious_vendors'] = tk.Text(frame, height=5, width=50)
        vendors = self.settings_manager.get('detection', 'suspicious_vendors', ['Unknown', 'Raspberry Pi'])
        self.widgets['suspicious_vendors'].insert('1.0', '\n'.join(vendors))
        self.widgets['suspicious_vendors'].pack(fill='x', padx=20, pady=(0, 15))
        
    def create_monitoring_settings(self, notebook):
        """Create monitoring settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🎯 Monitoring")
        
        # Default Duration
        tk.Label(frame, text="Default Monitoring Duration (seconds):", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(20, 5))
        self.widgets['default_duration'] = tk.Scale(frame, from_=10, to=300, orient='horizontal')
        self.widgets['default_duration'].set(self.settings_manager.get('monitoring', 'default_duration', 60))
        self.widgets['default_duration'].pack(fill='x', padx=20, pady=(0, 15))
        
        # Monitoring Options
        tk.Label(frame, text="Monitoring Options:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        
        self.widgets['alert_sound'] = tk.BooleanVar()
        self.widgets['alert_sound'].set(self.settings_manager.get('monitoring', 'alert_sound', True))
        tk.Checkbutton(frame, text="Enable Alert Sound", 
                       variable=self.widgets['alert_sound']).pack(anchor='w', padx=20, pady=2)
        
        self.widgets['auto_save_reports'] = tk.BooleanVar()
        self.widgets['auto_save_reports'].set(self.settings_manager.get('monitoring', 'auto_save_reports', True))
        tk.Checkbutton(frame, text="Auto-save Reports", 
                       variable=self.widgets['auto_save_reports']).pack(anchor='w', padx=20, pady=2)
        
    def create_gui_settings(self, notebook):
        """Create GUI settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🎨 GUI")
        
        # Theme
        tk.Label(frame, text="Theme:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(20, 5))
        self.widgets['theme'] = ttk.Combobox(frame, state='readonly')
        self.widgets['theme']['values'] = ['Light', 'Dark']
        self.widgets['theme'].set(self.settings_manager.get('gui', 'theme', 'light').title())
        self.widgets['theme'].pack(fill='x', padx=20, pady=(0, 15))
        
        # GUI Options
        tk.Label(frame, text="Display Options:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        
        self.widgets['auto_refresh'] = tk.BooleanVar()
        self.widgets['auto_refresh'].set(self.settings_manager.get('gui', 'auto_refresh', True))
        tk.Checkbutton(frame, text="Auto-refresh Dashboard", 
                       variable=self.widgets['auto_refresh']).pack(anchor='w', padx=20, pady=2)
        
        # Refresh Interval
        tk.Label(frame, text="Refresh Interval (seconds):", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        self.widgets['refresh_interval'] = tk.Scale(frame, from_=1, to=60, orient='horizontal')
        self.widgets['refresh_interval'].set(self.settings_manager.get('gui', 'refresh_interval', 5))
        self.widgets['refresh_interval'].pack(fill='x', padx=20, pady=(0, 15))
        
    def create_logging_settings(self, notebook):
        """Create logging settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="📝 Logging")
        
        # Log Level
        tk.Label(frame, text="Log Level:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(20, 5))
        self.widgets['log_level'] = ttk.Combobox(frame, state='readonly')
        self.widgets['log_level']['values'] = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        self.widgets['log_level'].set(self.settings_manager.get('logging', 'level', 'INFO'))
        self.widgets['log_level'].pack(fill='x', padx=20, pady=(0, 15))
        
        # File Size
        tk.Label(frame, text="Max File Size (MB):", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        self.widgets['max_file_size'] = tk.Scale(frame, from_=1, to=100, orient='horizontal')
        size_mb = self.settings_manager.get('logging', 'max_file_size', 10485760) // 1048576
        self.widgets['max_file_size'].set(size_mb)
        self.widgets['max_file_size'].pack(fill='x', padx=20, pady=(0, 15))
        
        # Backup Count
        tk.Label(frame, text="Backup Count:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=20, pady=(10, 5))
        self.widgets['backup_count'] = tk.Scale(frame, from_=1, to=20, orient='horizontal')
        self.widgets['backup_count'].set(self.settings_manager.get('logging', 'backup_count', 5))
        self.widgets['backup_count'].pack(fill='x', padx=20, pady=(0, 15))
        
    def get_available_interfaces(self):
        """Get available network interfaces"""
        try:
            import psutil
            interfaces = list(psutil.net_if_addrs().keys())
            return interfaces
        except:
            return ['eth0', 'wlan0', 'lo']
        
    def save_settings(self):
        """Save all settings"""
        try:
            # Network settings
            self.settings_manager.set('network', 'interface', self.widgets['network_interface'].get().lower())
            self.settings_manager.set('network', 'scan_timeout', int(self.widgets['scan_timeout'].get()))
            self.settings_manager.set('network', 'max_threads', int(self.widgets['max_threads'].get()))
            
            # Detection settings
            self.settings_manager.set('detection', 'risk_threshold', int(self.widgets['risk_threshold'].get()))
            self.settings_manager.set('detection', 'enable_mac_spoof_detection', self.widgets['mac_spoof_detection'].get())
            self.settings_manager.set('detection', 'enable_vendor_check', self.widgets['vendor_check'].get())
            
            vendors_text = self.widgets['suspicious_vendors'].get('1.0', 'end').strip()
            vendors = [v.strip() for v in vendors_text.split('\n') if v.strip()]
            self.settings_manager.set('detection', 'suspicious_vendors', vendors)
            
            # Monitoring settings
            self.settings_manager.set('monitoring', 'default_duration', int(self.widgets['default_duration'].get()))
            self.settings_manager.set('monitoring', 'alert_sound', self.widgets['alert_sound'].get())
            self.settings_manager.set('monitoring', 'auto_save_reports', self.widgets['auto_save_reports'].get())
            
            # GUI settings
            self.settings_manager.set('gui', 'theme', self.widgets['theme'].get().lower())
            self.settings_manager.set('gui', 'auto_refresh', self.widgets['auto_refresh'].get())
            self.settings_manager.set('gui', 'refresh_interval', int(self.widgets['refresh_interval'].get()))
            
            # Logging settings
            self.settings_manager.set('logging', 'level', self.widgets['log_level'].get())
            self.settings_manager.set('logging', 'max_file_size', int(self.widgets['max_file_size'].get()) * 1048576)
            self.settings_manager.set('logging', 'backup_count', int(self.widgets['backup_count'].get()))
            
            # Save to file
            if self.settings_manager.save_settings():
                messagebox.showinfo("Success", "Settings saved successfully!")
                self.dialog.destroy()
            else:
                messagebox.showerror("Error", "Failed to save settings!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
            
    def reset_defaults(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Reset Settings", "Are you sure you want to reset all settings to defaults?"):
            # Reset settings manager
            self.settings_manager.settings = self.settings_manager.load_settings()
            
            # Update widgets
            self.widgets['network_interface'].set(self.settings_manager.get('network', 'interface', 'auto').title())
            self.widgets['scan_timeout'].set(self.settings_manager.get('network', 'scan_timeout', 2))
            self.widgets['max_threads'].set(self.settings_manager.get('network', 'max_threads', 10))
            
            self.widgets['risk_threshold'].set(self.settings_manager.get('detection', 'risk_threshold', 70))
            self.widgets['mac_spoof_detection'].set(self.settings_manager.get('detection', 'enable_mac_spoof_detection', True))
            self.widgets['vendor_check'].set(self.settings_manager.get('detection', 'enable_vendor_check', True))
            
            vendors = self.settings_manager.get('detection', 'suspicious_vendors', ['Unknown', 'Raspberry Pi'])
            self.widgets['suspicious_vendors'].delete('1.0', 'end')
            self.widgets['suspicious_vendors'].insert('1.0', '\n'.join(vendors))
            
            self.widgets['default_duration'].set(self.settings_manager.get('monitoring', 'default_duration', 60))
            self.widgets['alert_sound'].set(self.settings_manager.get('monitoring', 'alert_sound', True))
            self.widgets['auto_save_reports'].set(self.settings_manager.get('monitoring', 'auto_save_reports', True))
            
            self.widgets['theme'].set(self.settings_manager.get('gui', 'theme', 'light').title())
            self.widgets['auto_refresh'].set(self.settings_manager.get('gui', 'auto_refresh', True))
            self.widgets['refresh_interval'].set(self.settings_manager.get('gui', 'refresh_interval', 5))
            
            self.widgets['log_level'].set(self.settings_manager.get('logging', 'level', 'INFO'))
            size_mb = self.settings_manager.get('logging', 'max_file_size', 10485760) // 1048576
            self.widgets['max_file_size'].set(size_mb)
            self.widgets['backup_count'].set(self.settings_manager.get('logging', 'backup_count', 5))
            
            messagebox.showinfo("Success", "Settings reset to defaults!")
