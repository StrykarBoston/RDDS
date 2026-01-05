# -*- coding: utf-8 -*-
# gui_main.py - Modern GUI for Rogue Detection System

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import json
from datetime import datetime
import ctypes
from network_discovery import NetworkScanner
from rogue_detector import RogueDetector
from attack_detector import AttackDetector
from rogue_ap_detector import RogueAPDetector
from logger import SecurityLogger
from settings_config import SettingsManager, SettingsDialog
from npcapy_check import check_npcap_installation, install_npcap_instructions

class ModernRDDS_GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ Rogue Detection & Defense System")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Configure modern style
        self.setup_styles()
        
        # Initialize components
        self.scanner = NetworkScanner()
        self.detector = RogueDetector()
        self.attack_detector = AttackDetector()
        self.ap_detector = RogueAPDetector()
        self.logger = SecurityLogger()
        self.settings_manager = SettingsManager()
        
        # Threading components
        self.scan_queue = queue.Queue()
        self.monitoring = False
        self.current_scan_thread = None
        
        # Setup GUI
        self.setup_gui()
        
        # Check admin privileges and Npcap
        self.check_admin_privileges()
        self.check_npcap()
        
    def setup_styles(self):
        """Setup modern ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        self.colors = {
            'primary': '#2E86AB',
            'secondary': '#A23B72',
            'success': '#4CAF50',
            'warning': '#FF9800',
            'danger': '#F44336',
            'dark': '#212121',
            'light': '#F5F5F5',
            'text': '#333333'
        }
        
        # Configure button styles
        style.configure('Primary.TButton', 
                       background=self.colors['primary'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'))
        
        style.configure('Success.TButton',
                       background=self.colors['success'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'))
        
        style.configure('Danger.TButton',
                       background=self.colors['danger'],
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'))
        
        # Configure frame styles
        style.configure('Card.TFrame',
                       background='white',
                       relief='flat',
                       borderwidth=1)
        
        # Configure root window
        self.root.configure(bg=self.colors['light'])
        
    def check_npcap(self):
        """Check Npcap installation"""
        try:
            installed, message = check_npcap_installation()
            if not installed:
                messagebox.showerror(
                    "Npcap Required",
                    f"Npcap is required for network operations:\n\n{message}\n\n{install_npcap_instructions()}"
                )
                self.root.quit()
                return
            else:
                print(f"[*] Npcap check: {message}")
        except Exception as e:
            print(f"[!] Warning: Could not verify Npcap installation: {e}")
            
    def check_admin_privileges(self):
        """Check if running with admin privileges"""
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                messagebox.showwarning(
                    "Administrator Privileges Required",
                    "This application requires Administrator privileges to:\n"
                    "• Capture network packets\n"
                    "• Perform ARP scanning\n"
                    "• Monitor network interfaces\n\n"
                    "Please restart as Administrator."
                )
                self.root.quit()
                return
        except:
            pass
            
    def setup_gui(self):
        """Setup main GUI layout"""
        # Create main container
        main_container = tk.Frame(self.root, bg=self.colors['light'])
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Header
        self.create_header(main_container)
        
        # Content area with notebook
        self.create_notebook(main_container)
        
        # Status bar
        self.create_status_bar(main_container)
        
    def create_header(self, parent):
        """Create application header"""
        header_frame = tk.Frame(parent, bg=self.colors['primary'], height=80)
        header_frame.pack(fill='x', pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # Title
        title_label = tk.Label(
            header_frame,
            text="🛡️ Rogue Detection & Defense System",
            font=('Segoe UI', 20, 'bold'),
            bg=self.colors['primary'],
            fg='white'
        )
        title_label.pack(side='left', padx=20, pady=20)
        
        # Status indicator
        self.status_indicator = tk.Label(
            header_frame,
            text="● Ready",
            font=('Segoe UI', 12),
            bg=self.colors['primary'],
            fg=self.colors['success']
        )
        self.status_indicator.pack(side='right', padx=20, pady=20)
        
        # Update button
        update_button = tk.Button(
            header_frame,
            text="🔄",
            font=('Segoe UI', 16),
            bg=self.colors['primary'],
            fg='white',
            bd=0,
            relief='flat',
            command=self.check_for_updates,
            cursor='hand2'
        )
        update_button.pack(side='right', padx=(0, 10), pady=20)
        
        # Settings button
        settings_button = tk.Button(
            header_frame,
            text="⚙️",
            font=('Segoe UI', 16),
            bg=self.colors['primary'],
            fg='white',
            bd=0,
            relief='flat',
            command=self.open_settings,
            cursor='hand2'
        )
        settings_button.pack(side='right', padx=(0, 20), pady=20)
        
    def create_notebook(self, parent):
        """Create main notebook with tabs"""
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill='both', expand=True)
        
        # Dashboard tab
        self.create_dashboard_tab()
        
        # Network Scan tab
        self.create_scan_tab()
        
        # Device Management tab
        self.create_device_tab()
        
        # Real-time Monitoring tab
        self.create_monitoring_tab()
        
        # Reports tab
        self.create_reports_tab()
        
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # Main dashboard container
        main_frame = tk.Frame(dashboard_frame, bg=self.colors['light'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Stats cards
        self.create_stats_cards(main_frame)
        
        # Recent activity
        self.create_activity_panel(main_frame)
        
    def create_stats_cards(self, parent):
        """Create statistics cards"""
        cards_frame = tk.Frame(parent, bg=self.colors['light'])
        cards_frame.pack(fill='x', pady=(0, 20))
        
        # Card definitions
        cards = [
            ("🔍 Total Devices", "0", self.colors['primary']),
            ("🚨 Rogue Devices", "0", self.colors['danger']),
            ("⚠️ Suspicious", "0", self.colors['warning']),
            ("✅ Trusted", "0", self.colors['success'])
        ]
        
        self.stats_labels = {}
        
        for i, (title, value, color) in enumerate(cards):
            card = tk.Frame(cards_frame, bg='white', relief='raised', bd=1)
            card.pack(side='left', fill='both', expand=True, padx=(0, 10))
            
            # Title
            title_label = tk.Label(
                card, text=title,
                font=('Segoe UI', 12),
                bg='white', fg=self.colors['text']
            )
            title_label.pack(pady=(10, 5))
            
            # Value
            value_label = tk.Label(
                card, text=value,
                font=('Segoe UI', 24, 'bold'),
                bg='white', fg=color
            )
            value_label.pack(pady=(0, 10))
            
            # Store reference for updates
            self.stats_labels[title] = value_label
            
    def create_activity_panel(self, parent):
        """Create recent activity panel"""
        activity_frame = tk.Frame(parent, bg='white', relief='raised', bd=1)
        activity_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = tk.Label(
            activity_frame,
            text="📋 Recent Activity",
            font=('Segoe UI', 14, 'bold'),
            bg='white', fg=self.colors['text']
        )
        title_label.pack(pady=10, padx=10, anchor='w')
        
        # Activity text
        self.activity_text = scrolledtext.ScrolledText(
            activity_frame,
            height=15,
            font=('Consolas', 9),
            bg='#f8f9fa',
            fg=self.colors['text'],
            wrap='word'
        )
        self.activity_text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        self.activity_text.config(state='disabled')
        
    def create_scan_tab(self):
        """Create network scan tab"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="🔍 Network Scan")
        
        main_frame = tk.Frame(scan_frame, bg=self.colors['light'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = tk.Frame(main_frame, bg='white', relief='raised', bd=1)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # Scan button
        self.scan_button = ttk.Button(
            control_frame,
            text="🚀 Start Full Scan",
            command=self.start_full_scan,
            style='Primary.TButton'
        )
        self.scan_button.pack(pady=10)
        
        # Progress bar
        self.scan_progress = ttk.Progressbar(
            control_frame,
            mode='determinate',
            maximum=100
        )
        self.scan_progress.pack(fill='x', padx=10, pady=(0, 10))
        
        # Results area
        results_frame = tk.Frame(main_frame, bg='white', relief='raised', bd=1)
        results_frame.pack(fill='both', expand=True)
        
        # Results title
        title_label = tk.Label(
            results_frame,
            text="🔍 Scan Results",
            font=('Segoe UI', 14, 'bold'),
            bg='white', fg=self.colors['text']
        )
        title_label.pack(pady=10, padx=10, anchor='w')
        
        # Results treeview
        columns = ('IP', 'MAC', 'Vendor', 'Status', 'Risk Score')
        self.scan_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.scan_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=(0, 10))
        scrollbar.pack(side='right', fill='y', padx=(0, 10), pady=(0, 10))
        
    def create_device_tab(self):
        """Create device management tab"""
        device_frame = ttk.Frame(self.notebook)
        self.notebook.add(device_frame, text="📱 Device Management")
        
        main_frame = tk.Frame(device_frame, bg=self.colors['light'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Whitelist section
        whitelist_frame = tk.Frame(main_frame, bg='white', relief='raised', bd=1)
        whitelist_frame.pack(fill='both', expand=True)
        
        # Title and add button
        title_frame = tk.Frame(whitelist_frame, bg='white')
        title_frame.pack(fill='x', pady=10, padx=10)
        
        title_label = tk.Label(
            title_frame,
            text="🔐 Trusted Devices (Whitelist)",
            font=('Segoe UI', 14, 'bold'),
            bg='white', fg=self.colors['text']
        )
        title_label.pack(side='left')
        
        # Button frame
        button_frame = tk.Frame(title_frame, bg='white')
        button_frame.pack(side='right')
        
        # Edit button
        edit_button = ttk.Button(
            button_frame,
            text="✏️ Edit",
            command=self.edit_device_dialog,
            style='Primary.TButton'
        )
        edit_button.pack(side='right', padx=2)
        
        # Remove button
        remove_button = ttk.Button(
            button_frame,
            text="🗑️ Remove",
            command=self.remove_device_from_whitelist,
            style='Danger.TButton'
        )
        remove_button.pack(side='right', padx=2)
        
        # Add button
        add_button = ttk.Button(
            button_frame,
            text="➕ Add Device",
            command=self.add_device_dialog,
            style='Success.TButton'
        )
        add_button.pack(side='right', padx=2)
        
        # Whitelist treeview
        columns = ('MAC', 'IP', 'Name', 'Added Date')
        self.whitelist_tree = ttk.Treeview(whitelist_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.whitelist_tree.heading(col, text=col)
            self.whitelist_tree.column(col, width=150)
        
        # Scrollbar
        whitelist_scrollbar = ttk.Scrollbar(whitelist_frame, orient='vertical', command=self.whitelist_tree.yview)
        self.whitelist_tree.configure(yscrollcommand=whitelist_scrollbar.set)
        
        self.whitelist_tree.pack(side='left', fill='both', expand=True, padx=(10, 0), pady=(0, 10))
        whitelist_scrollbar.pack(side='right', fill='y', padx=(0, 10), pady=(0, 10))
        
        # Load whitelist
        self.load_whitelist_display()
        
    def create_monitoring_tab(self):
        """Create real-time monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="🎯 Real-time Monitoring")
        
        main_frame = tk.Frame(monitor_frame, bg=self.colors['light'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = tk.Frame(main_frame, bg='white', relief='raised', bd=1)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # Monitor controls
        controls_inner = tk.Frame(control_frame, bg='white')
        controls_inner.pack(pady=10)
        
        self.monitor_button = ttk.Button(
            controls_inner,
            text="▶️ Start Monitoring",
            command=self.toggle_monitoring,
            style='Primary.TButton'
        )
        self.monitor_button.pack(side='left', padx=5)
        
        # Duration entry
        tk.Label(controls_inner, text="Duration (s):", bg='white', fg=self.colors['text']).pack(side='left', padx=(20, 5))
        self.duration_var = tk.StringVar(value="60")
        duration_entry = tk.Entry(controls_inner, textvariable=self.duration_var, width=10, font=('Segoe UI', 10))
        duration_entry.pack(side='left', padx=5)
        
        # Monitor status
        self.monitor_status = tk.Label(
            control_frame,
            text="⏸️ Monitoring Stopped",
            font=('Segoe UI', 12),
            bg='white', fg=self.colors['text']
        )
        self.monitor_status.pack(pady=(0, 10))
        
        # Alerts area
        alerts_frame = tk.Frame(main_frame, bg='white', relief='raised', bd=1)
        alerts_frame.pack(fill='both', expand=True)
        
        # Alerts title
        title_label = tk.Label(
            alerts_frame,
            text="🚨 Live Attack Alerts",
            font=('Segoe UI', 14, 'bold'),
            bg='white', fg=self.colors['text']
        )
        title_label.pack(pady=10, padx=10, anchor='w')
        
        # Alerts text
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_frame,
            height=20,
            font=('Consolas', 9),
            bg='#f8f9fa',
            fg=self.colors['text'],
            wrap='word'
        )
        self.alerts_text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
    def create_reports_tab(self):
        """Create reports tab"""
        reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(reports_frame, text="📄 Reports")
        
        main_frame = tk.Frame(reports_frame, bg=self.colors['light'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Control panel
        control_frame = tk.Frame(main_frame, bg='white', relief='raised', bd=1)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # Generate report button
        generate_button = ttk.Button(
            control_frame,
            text="📊 Generate Report",
            command=self.generate_report,
            style='Primary.TButton'
        )
        generate_button.pack(pady=10)
        
        # Report display
        report_frame = tk.Frame(main_frame, bg='white', relief='raised', bd=1)
        report_frame.pack(fill='both', expand=True)
        
        # Report title
        title_label = tk.Label(
            report_frame,
            text="📄 Security Report",
            font=('Segoe UI', 14, 'bold'),
            bg='white', fg=self.colors['text']
        )
        title_label.pack(pady=10, padx=10, anchor='w')
        
        # Report text
        self.report_text = scrolledtext.ScrolledText(
            report_frame,
            height=20,
            font=('Consolas', 9),
            bg='#f8f9fa',
            fg=self.colors['text'],
            wrap='word'
        )
        self.report_text.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
    def create_status_bar(self, parent):
        """Create status bar"""
        status_frame = tk.Frame(parent, bg=self.colors['dark'], height=30)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        # Status label
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            font=('Segoe UI', 9),
            bg=self.colors['dark'],
            fg='white'
        )
        self.status_label.pack(side='left', padx=10, pady=5)
        
        # Time label
        self.time_label = tk.Label(
            status_frame,
            text="",
            font=('Segoe UI', 9),
            bg=self.colors['dark'],
            fg='white'
        )
        self.time_label.pack(side='right', padx=10, pady=5)
        
        # Update time
        self.update_time()
        
    def update_time(self):
        """Update time display"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
        
    def start_full_scan(self):
        """Start full network scan in background"""
        if self.current_scan_thread and self.current_scan_thread.is_alive():
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
            
        # Clear previous results
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
            
        # Update UI
        self.scan_button.config(text="⏸️ Scanning...", state='disabled')
        self.scan_progress['value'] = 0
        self.status_indicator.config(text="● Scanning...", fg=self.colors['warning'])
        self.update_status("Starting network scan...")
        
        # Start scan in background
        self.current_scan_thread = threading.Thread(target=self._perform_scan, daemon=True)
        self.current_scan_thread.start()
        
        # Check for results
        self.root.after(100, self.check_scan_results)
        
    def _perform_scan(self):
        """Perform the actual scan with progress updates"""
        try:
            # Step 1: Network discovery
            self.scan_queue.put(("progress", 10))
            self.scan_queue.put(("status", "Discovering network devices..."))
            network_range = self.scanner.get_network_range()
            
            self.scan_queue.put(("progress", 30))
            devices = self.scanner.arp_scan(network_range)
            self.scan_queue.put(("status", f"Found {len(devices)} devices"))
            
            # Step 2: Rogue detection
            self.scan_queue.put(("progress", 50))
            self.scan_queue.put(("status", "Analyzing for rogue devices..."))
            analyzed_devices, alerts = self.detector.analyze_network(devices)
            
            # Step 3: Wireless scan
            self.scan_queue.put(("progress", 70))
            self.scan_queue.put(("status", "Scanning wireless networks..."))
            try:
                wireless_networks = self.ap_detector.scan_wireless_networks_windows()
                ap_alerts = self.ap_detector.detect_evil_twin(wireless_networks)
                alerts.extend(ap_alerts)
            except Exception as wireless_error:
                print(f"[!] Wireless scan failed: {wireless_error}")
                self.scan_queue.put(("status", "Wireless scan failed - continuing..."))
            
            # Step 4: Final analysis
            self.scan_queue.put(("progress", 90))
            self.scan_queue.put(("status", "Finalizing analysis..."))
            
            # Send results
            self.scan_queue.put(("progress", 100))
            self.scan_queue.put(("results", analyzed_devices, alerts))
            
        except Exception as e:
            error_msg = str(e)
            if "Permission denied" in error_msg:
                error_msg = "Insufficient privileges. Please run as Administrator."
            elif "No such device" in error_msg:
                error_msg = "Network interface not available. Check your connection."
            self.scan_queue.put(("error", error_msg))
            
    def check_scan_results(self):
        """Check for scan results with progress updates"""
        try:
            while not self.scan_queue.empty():
                result = self.scan_queue.get_nowait()
                
                if result[0] == "progress":
                    # Update progress bar if it's determinate
                    if hasattr(self, 'scan_progress') and result[1] <= 100:
                        self.scan_progress['value'] = result[1]
                        
                elif result[0] == "status":
                    self.update_status(result[1])
                    self.add_activity(f"🔍 {result[1]}")
                    
                elif result[0] == "results":
                    analyzed_devices, alerts = result[1], result[2]
                    self.display_scan_results(analyzed_devices, alerts)
                    self.update_dashboard_stats(analyzed_devices)
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 100
                    self.scan_button.config(text="🚀 Start Full Scan", state='normal')
                    self.status_indicator.config(text="● Ready", fg=self.colors['success'])
                    self.update_status("Scan completed")
                    self.add_activity("✅ Full scan completed successfully")
                    
                elif result[0] == "error":
                    messagebox.showerror("Scan Error", f"Scan failed: {result[1]}")
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 0
                    self.scan_button.config(text="🚀 Start Full Scan", state='normal')
                    self.status_indicator.config(text="● Error", fg=self.colors['danger'])
                    self.update_status("Scan failed")
                    self.add_activity(f"❌ Scan failed: {result[1]}")
                    
        except queue.Empty:
            pass
            
        # Check again if scan is still running
        if self.current_scan_thread and self.current_scan_thread.is_alive():
            self.root.after(100, self.check_scan_results)
        else:
            # Ensure UI is reset if thread ended unexpectedly
            if self.scan_button['state'] == 'disabled':
                self.scan_progress.stop()
                self.scan_progress['value'] = 0
                self.scan_button.config(text="🚀 Start Full Scan", state='normal')
                self.status_indicator.config(text="● Ready", fg=self.colors['success'])
            
    def display_scan_results(self, devices, alerts):
        """Display scan results in treeview"""
        # Clear existing items
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
            
        # Add devices
        for device in devices:
            # Determine tag based on status
            tag = ''
            if device['status'] == 'ROGUE':
                tag = 'rogue'
            elif device['status'] == 'SUSPICIOUS':
                tag = 'suspicious'
            else:
                tag = 'trusted'
                
            self.scan_tree.insert('', 'end', values=(
                device['ip'],
                device['mac'],
                device.get('vendor', 'Unknown'),
                device['status'],
                f"{device['risk_score']}/100"
            ), tags=(tag,))
            
        # Configure tags
        self.scan_tree.tag_configure('rogue', background='#ffebee')
        self.scan_tree.tag_configure('suspicious', background='#fff3e0')
        self.scan_tree.tag_configure('trusted', background='#e8f5e8')
        
        # Store for later report generation
        self._last_devices = devices
        self._last_alerts = alerts
        
        # Log alerts
        for alert in alerts:
            self.add_activity(f"🚨 [{alert['severity']}] {alert['type']}: {alert['message']}")
            
    def update_dashboard_stats(self, devices):
        """Update dashboard statistics"""
        stats = {
            "🔍 Total Devices": str(len(devices)),
            "🚨 Rogue Devices": str(len([d for d in devices if d['status'] == 'ROGUE'])),
            "⚠️ Suspicious": str(len([d for d in devices if d['status'] == 'SUSPICIOUS'])),
            "✅ Trusted": str(len([d for d in devices if d['status'] == 'TRUSTED']))
        }
        
        for title, value in stats.items():
            if title in self.stats_labels:
                self.stats_labels[title].config(text=value)
                
    def add_activity(self, message):
        """Add message to activity log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_text.config(state='normal')
        self.activity_text.insert('end', f"[{timestamp}] {message}\n")
        self.activity_text.see('end')
        self.activity_text.config(state='disabled')
        
    def update_status(self, message):
        """Update status bar"""
        self.status_label.config(text=message)
        
    def load_whitelist_display(self):
        """Load whitelist into treeview"""
        # Clear existing items
        for item in self.whitelist_tree.get_children():
            self.whitelist_tree.delete(item)
            
        # Add whitelist devices
        for device in self.detector.whitelist:
            self.whitelist_tree.insert('', 'end', values=(
                device['mac'],
                device.get('ip', 'N/A'),
                device.get('name', 'Unknown'),
                device.get('added_date', 'Unknown')
            ))
            
    def add_device_dialog(self):
        """Show add device dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Device to Whitelist")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Form
        main_frame = tk.Frame(dialog, bg=self.colors['light'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # MAC Address
        tk.Label(main_frame, text="MAC Address:", bg=self.colors['light'], fg=self.colors['text']).pack(anchor='w', pady=(0, 5))
        mac_entry = tk.Entry(main_frame, width=40, font=('Segoe UI', 10))
        mac_entry.pack(fill='x', pady=(0, 15))
        
        # IP Address
        tk.Label(main_frame, text="IP Address:", bg=self.colors['light'], fg=self.colors['text']).pack(anchor='w', pady=(0, 5))
        ip_entry = tk.Entry(main_frame, width=40, font=('Segoe UI', 10))
        ip_entry.pack(fill='x', pady=(0, 15))
        
        # Device Name
        tk.Label(main_frame, text="Device Name:", bg=self.colors['light'], fg=self.colors['text']).pack(anchor='w', pady=(0, 5))
        name_entry = tk.Entry(main_frame, width=40, font=('Segoe UI', 10))
        name_entry.pack(fill='x', pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['light'])
        button_frame.pack(fill='x')
        
        def add_device():
            mac = mac_entry.get().strip()
            ip = ip_entry.get().strip()
            name = name_entry.get().strip()
            
            if not mac:
                messagebox.showerror("Error", "MAC address is required!")
                return
                
            device = {'mac': mac, 'ip': ip, 'name': name}
            if self.detector.add_to_whitelist(device):
                self.load_whitelist_display()
                self.add_activity(f"✅ Added device to whitelist: {mac}")
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Device already exists in whitelist!")
                
        ttk.Button(button_frame, text="Add Device", command=add_device, style='Success.TButton').pack(side='right', padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side='right')
        
    def edit_device_dialog(self):
        """Show edit device dialog"""
        selected = self.whitelist_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to edit!")
            return
            
        # Get selected device data
        item = self.whitelist_tree.item(selected[0])
        values = item['values']
        mac = values[0]
        ip = values[1]
        name = values[2]
        
        # Find device in whitelist
        device_to_edit = None
        for device in self.detector.whitelist:
            if device['mac'] == mac:
                device_to_edit = device
                break
                
        if not device_to_edit:
            messagebox.showerror("Error", "Device not found in whitelist!")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Device in Whitelist")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Form
        main_frame = tk.Frame(dialog, bg=self.colors['light'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # MAC Address (read-only)
        tk.Label(main_frame, text="MAC Address:", bg=self.colors['light'], fg=self.colors['text']).pack(anchor='w', pady=(0, 5))
        mac_entry = tk.Entry(main_frame, width=40, font=('Segoe UI', 10), state='readonly')
        mac_entry.insert(0, mac)
        mac_entry.pack(fill='x', pady=(0, 15))
        
        # IP Address
        tk.Label(main_frame, text="IP Address:", bg=self.colors['light'], fg=self.colors['text']).pack(anchor='w', pady=(0, 5))
        ip_entry = tk.Entry(main_frame, width=40, font=('Segoe UI', 10))
        ip_entry.insert(0, ip)
        ip_entry.pack(fill='x', pady=(0, 15))
        
        # Device Name
        tk.Label(main_frame, text="Device Name:", bg=self.colors['light'], fg=self.colors['text']).pack(anchor='w', pady=(0, 5))
        name_entry = tk.Entry(main_frame, width=40, font=('Segoe UI', 10))
        name_entry.insert(0, name)
        name_entry.pack(fill='x', pady=(0, 20))
        
        # Buttons
        button_frame = tk.Frame(main_frame, bg=self.colors['light'])
        button_frame.pack(fill='x')
        
        def update_device():
            new_ip = ip_entry.get().strip()
            new_name = name_entry.get().strip()
            
            # Update device in whitelist
            device_to_edit['ip'] = new_ip
            device_to_edit['name'] = new_name
            
            # Save whitelist
            self.detector.save_whitelist()
            
            # Refresh display
            self.load_whitelist_display()
            self.add_activity(f"✏️ Updated device in whitelist: {mac}")
            dialog.destroy()
                
        ttk.Button(button_frame, text="Update Device", command=update_device, style='Primary.TButton').pack(side='right', padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side='right')
        
    def remove_device_from_whitelist(self):
        """Remove selected device from whitelist"""
        selected = self.whitelist_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to remove!")
            return
            
        # Get selected device data
        item = self.whitelist_tree.item(selected[0])
        values = item['values']
        mac = values[0]
        name = values[2] if len(values) > 2 else 'Unknown'
        
        # Confirm deletion
        result = messagebox.askyesno(
            "Confirm Removal",
            f"Are you sure you want to remove {name} ({mac}) from the whitelist?\n\n"
            "This device will be treated as potentially rogue in future scans."
        )
        
        if result:
            # Remove from whitelist
            self.detector.whitelist = [d for d in self.detector.whitelist if d['mac'] != mac]
            self.detector.save_whitelist()
            
            # Refresh display
            self.load_whitelist_display()
            self.add_activity(f"🗑️ Removed device from whitelist: {mac}")
            messagebox.showinfo("Success", f"Device {mac} removed from whitelist!")
        
    def toggle_monitoring(self):
        """Toggle real-time monitoring"""
        if not self.monitoring:
            try:
                duration = int(self.duration_var.get())
                if duration <= 0:
                    messagebox.showerror("Error", "Duration must be greater than 0!")
                    return
                    
                self.monitoring = True
                self.monitor_button.config(text="⏹️ Stop Monitoring", style='Danger.TButton')
                self.monitor_status.config(text="🔴 Monitoring Active", fg=self.colors['danger'])
                self.status_indicator.config(text="● Monitoring", fg=self.colors['danger'])
                self.add_activity(f"🎯 Started real-time monitoring for {duration}s")
                
                # Start monitoring in background
                monitor_thread = threading.Thread(
                    target=self._perform_monitoring,
                    args=(duration,),
                    daemon=True
                )
                monitor_thread.start()
                
            except ValueError:
                messagebox.showerror("Error", "Invalid duration value!")
        else:
            self.monitoring = False
            self.monitor_button.config(text="▶️ Start Monitoring", style='Primary.TButton')
            self.monitor_status.config(text="⏸️ Monitoring Stopped", fg=self.colors['text'])
            self.status_indicator.config(text="● Ready", fg=self.colors['success'])
            self.add_activity("⏹️ Stopped monitoring")
            
    def _perform_monitoring(self, duration):
        """Perform real-time monitoring"""
        try:
            interface = self.scanner.interface
            attack_alerts = self.attack_detector.start_monitoring(interface, duration)
            
            for alert in attack_alerts:
                self.root.after(0, self._add_attack_alert, alert)
                
            # Auto-stop when done
            self.root.after(0, self.toggle_monitoring)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Monitoring Error", str(e)))
            self.root.after(0, self.toggle_monitoring)
            
    def _add_attack_alert(self, alert):
        """Add attack alert to display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert_text = f"[{timestamp}] 🚨 [{alert['severity']}] {alert['type']}: {alert['message']}\n"
        
        self.alerts_text.config(state='normal')
        self.alerts_text.insert('end', alert_text)
        self.alerts_text.see('end')
        self.alerts_text.config(state='disabled')
        
        self.add_activity(f"🚨 Attack detected: {alert['type']}")
        
    def generate_report(self):
        """Generate security report"""
        try:
            # Get current scan results if available
            devices = []
            alerts = []
            
            # Try to get devices from scan tree
            for child in self.scan_tree.get_children():
                values = self.scan_tree.item(child)['values']
                if len(values) >= 4:
                    device = {
                        'ip': values[0],
                        'mac': values[1],
                        'vendor': values[2],
                        'status': values[3],
                        'risk_score': int(values[4].split('/')[0])
                    }
                    devices.append(device)
            
            # If no scan data, try to get from last scan
            if not devices:
                devices = getattr(self, '_last_devices', [])
                alerts = getattr(self, '_last_alerts', [])
                
            # If still no data, run a quick scan
            if not devices and not alerts:
                self.add_activity("📊 No scan data available. Running quick scan for report...")
                try:
                    # Run a minimal scan
                    network_range = self.scanner.get_network_range()
                    scanned_devices = self.scanner.arp_scan(network_range)
                    devices, alerts = self.detector.analyze_network(scanned_devices)
                    self._last_devices = devices
                    self._last_alerts = alerts
                    self.add_activity(f"✅ Quick scan found {len(devices)} devices")
                except Exception as scan_error:
                    self.add_activity(f"⚠️ Quick scan failed: {scan_error}")
                    # Create sample data for demonstration
                    devices = [
                        {
                            'ip': '192.168.1.1',
                            'mac': '00:11:22:33:44:55',
                            'vendor': 'Demo Vendor',
                            'status': 'TRUSTED',
                            'risk_score': 10
                        }
                    ]
                    alerts = []
                    self.add_activity("📝 Using demo data for report")
                    
            # Generate report
            report_file = self.logger.generate_report(devices, alerts)
            
            # Display report content
            with open(report_file, 'r') as f:
                report_content = f.read()
                
            self.report_text.config(state='normal')
            self.report_text.delete('1.0', 'end')
            self.report_text.insert('1.0', report_content)
            self.report_text.config(state='disabled')
            
            self.add_activity(f"📊 Report generated: {report_file}")
            messagebox.showinfo("Report Generated", f"Security report saved to:\n{report_file}")
            
        except Exception as e:
            error_msg = f"Failed to generate report: {str(e)}"
            self.add_activity(f"❌ {error_msg}")
            messagebox.showerror("Report Error", error_msg)
            
    def open_settings(self):
        """Open settings dialog"""
        settings_dialog = SettingsDialog(self.root, self.settings_manager)
        settings_dialog.show()
        
    def check_for_updates(self):
        """Check for software updates with improved error handling"""
        try:
            import requests
            import subprocess
            import sys
            
            # Show checking dialog
            self.update_status("Checking for updates...")
            self.add_activity("🔄 Checking for software updates...")
            
            # Get current version (you can store this in a config file)
            current_version = "1.0.0"  # This should be read from a version file
            
            # Test internet connectivity first
            try:
                # Test with a simple request
                test_response = requests.get("https://www.google.com", timeout=5)
                if test_response.status_code != 200:
                    raise Exception("Internet connectivity test failed")
                print("[*] Internet connectivity confirmed")
            except Exception as e:
                print(f"[!] Internet connectivity test failed: {e}")
                messagebox.showerror(
                    "Connection Error", 
                    "Unable to connect to the internet.\n\n"
                    "Please check your internet connection and try again.\n\n"
                    "If you're behind a proxy or firewall, you may need to:\n"
                    "1. Configure your proxy settings\n"
                    "2. Allow this application through your firewall\n"
                    "3. Check if GitHub.com is accessible"
                )
                self.update_status("Ready")
                return
            
            # Check GitHub repository for latest version
            repo_url = "https://api.github.com/repos/StrykarBoston/RDDS/releases/latest"
            
            try:
                print(f"[*] Checking GitHub API: {repo_url}")
                response = requests.get(repo_url, timeout=15)
                print(f"[*] GitHub API response status: {response.status_code}")
                
                if response.status_code == 200:
                    release_data = response.json()
                    latest_version = release_data['tag_name'].lstrip('v')
                    download_url = release_data.get('zipball_url')
                    
                    print(f"[*] Current version: {current_version}")
                    print(f"[*] Latest version: {latest_version}")
                    
                    if latest_version > current_version:
                        # Update available
                        result = messagebox.askyesno(
                            "Update Available",
                            f"A new version ({latest_version}) is available!\n\n"
                            f"Current version: {current_version}\n"
                            f"Latest version: {latest_version}\n\n"
                            f"Release notes:\n{release_data.get('body', 'No release notes available.')}\n\n"
                            f"Would you like to download the update?"
                        )
                        
                        if result and download_url:
                            self.download_update(download_url, latest_version)
                    else:
                        messagebox.showinfo("Up to Date", f"You are running the latest version ({current_version})")
                        self.add_activity("✅ Software is up to date")
                elif response.status_code == 403:
                    messagebox.showerror(
                        "API Limit Reached", 
                        "GitHub API rate limit exceeded.\n\n"
                        "Please try again later or visit:\n"
                        "https://github.com/StrykarBoston/RDDS/releases"
                    )
                elif response.status_code == 404:
                    messagebox.showerror(
                        "Repository Not Found", 
                        "The RDDS repository was not found on GitHub.\n\n"
                        "Please check the repository name or visit:\n"
                        "https://github.com/StrykarBoston/RDDS"
                    )
                else:
                    messagebox.showerror(
                        "Update Check Failed", 
                        f"GitHub API returned status {response.status_code}.\n\n"
                        "Please check your internet connection and try again.\n\n"
                        "You can also check for updates manually at:\n"
                        "https://github.com/StrykarBoston/RDDS/releases"
                    )
                    
            except requests.exceptions.Timeout:
                messagebox.showerror(
                    "Timeout Error", 
                    "Request to GitHub API timed out.\n\n"
                    "Please check your internet connection and try again."
                )
            except requests.exceptions.ConnectionError as e:
                messagebox.showerror(
                    "Connection Error", 
                    f"Failed to connect to GitHub API.\n\n"
                    f"Error: {str(e)}\n\n"
                    "Please check your internet connection, proxy settings, or firewall."
                )
            except requests.RequestException as e:
                messagebox.showerror("Network Error", f"Failed to check for updates: {str(e)}")
                
        except ImportError:
            # Fallback method without requests library
            messagebox.showinfo(
                "Update Check",
                "Automatic update checking requires the 'requests' library.\n\n"
                "To install: pip install requests\n\n"
                "Alternatively, visit:\n"
                "https://github.com/StrykarBoston/RDDS/releases\n"
                "to check for updates manually."
            )
            
        self.update_status("Ready")
        
    def download_update(self, download_url, version):
        """Download and install update"""
        try:
            import requests
            import zipfile
            import os
            
            # Show progress dialog
            progress_dialog = tk.Toplevel(self.root)
            progress_dialog.title("Downloading Update")
            progress_dialog.geometry("400x150")
            progress_dialog.resizable(False, False)
            progress_dialog.transient(self.root)
            progress_dialog.grab_set()
            
            # Center dialog
            progress_dialog.update_idletasks()
            x = (progress_dialog.winfo_screenwidth() // 2) - (progress_dialog.winfo_width() // 2)
            y = (progress_dialog.winfo_screenheight() // 2) - (progress_dialog.winfo_height() // 2)
            progress_dialog.geometry(f"+{x}+{y}")
            
            tk.Label(progress_dialog, text=f"Downloading RDDS v{version}...", font=('Segoe UI', 12)).pack(pady=20)
            
            progress_bar = ttk.Progressbar(progress_dialog, mode='indeterminate')
            progress_bar.pack(fill='x', padx=20, pady=10)
            progress_bar.start()
            
            # Download in background thread
            def download_thread():
                try:
                    response = requests.get(download_url, stream=True)
                    response.raise_for_status()
                    
                    # Save to temporary file
                    temp_file = f"RDDS_v{version}.zip"
                    with open(temp_file, 'wb') as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                    
                    # Close progress dialog and show success
                    progress_dialog.after(0, progress_dialog.destroy)
                    self.root.after(0, lambda: messagebox.showinfo(
                        "Download Complete", 
                        f"Update downloaded to {temp_file}\n\n"
                        "Please extract the zip file and replace the current installation."
                    ))
                    self.add_activity(f"✅ Update downloaded: {temp_file}")
                    
                except Exception as e:
                    progress_dialog.after(0, progress_dialog.destroy)
                    self.root.after(0, lambda: messagebox.showerror("Download Failed", f"Failed to download update: {str(e)}"))
                    self.add_activity(f"❌ Update download failed: {str(e)}")
            
            threading.Thread(target=download_thread, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Update Error", f"Failed to start download: {str(e)}")
            self.add_activity(f"❌ Update error: {str(e)}")
        
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

if __name__ == "__main__":
    app = ModernRDDS_GUI()
    app.run()
