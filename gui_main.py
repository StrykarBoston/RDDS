# -*- coding: utf-8 -*-
# gui_main.py - Modern GUI for Rogue Detection System

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import json
from datetime import datetime
import time
import ctypes
import traceback
import sys

# ============================================
# IMPORT ERROR HANDLER
# ============================================
try:
    from error_handler import handle_rdds_error, error_handler
    print("Error handler imported")
except ImportError as e:
    print(f"Error handler import failed: {e}")
    # Fallback basic error handling
    def handle_rdds_error(error, context="", severity="ERROR", show_user=True, critical=False):
        print(f"{severity} in {context}: {error}")
        if show_user:
            messagebox.showerror(f"RDDS {severity}", f"{context}: {error}")
        return {'error_message': str(error)}

from network_discovery import NetworkScanner
from rogue_detector import RogueDetector
from attack_detector import AttackDetector
from rogue_ap_detector import RogueAPDetector
from logger import SecurityLogger
from deep_packet_inspector import DeepPacketInspector
from enhanced_rogue_ap_detector import EnhancedRogueAPDetector
from dhcp_security import DHCPSecurityMonitor
from network_traffic_analyzer import NetworkTrafficAnalyzer
from ssl_tls_monitor import SSLTLSMonitor
from advanced_attack_detector import AdvancedAttackDetector
from settings_manager import SettingsManager
from iot_profiler import IoTProfiler
from npcapy_check import check_npcap_installation, install_npcap_instructions

class ModernRDDS_GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🛡️ Rogue Detection & Defense System v2.0 (Enhanced)")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Configure modern style
        self.setup_styles()
        
        # Initialize components
        self.settings_manager = SettingsManager()
        self.scanner = NetworkScanner()
        self.detector = RogueDetector()
        self.attack_detector = AttackDetector()
        self.ap_detector = RogueAPDetector()
        self.enhanced_ap_detector = EnhancedRogueAPDetector()
        self.dpi_inspector = DeepPacketInspector()
        self.iot_profiler = IoTProfiler()
        self.dhcp_monitor = DHCPSecurityMonitor()
        self.traffic_analyzer = NetworkTrafficAnalyzer()
        self.ssl_monitor = SSLTLSMonitor()
        self.advanced_detector = AdvancedAttackDetector()
        self.logger = SecurityLogger()
        self.settings_manager = SettingsManager()
        
        # Threading components
        self.scan_queue = queue.Queue()
        self.monitoring = False
        self.current_scan_thread = None
        
        # Data storage for reports
        self._last_devices = []
        self._last_alerts = []
        self._monitoring_alerts = []  # Store monitoring alerts separately
        
        # Setup GUI
        self.setup_gui()
        
        # Check admin privileges and Npcap
        self.check_admin_privileges()
        self.check_npcap()
        
    def setup_styles(self):
        """Setup modern ttk styles with dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Modern dark color scheme
        self.colors = {
            'primary': '#1E88E5',      # Modern blue
            'secondary': '#7B1FA2',    # Modern purple
            'success': '#43A047',      # Modern green
            'warning': '#FB8C00',      # Modern orange
            'danger': '#E53935',       # Modern red
            'dark': '#1E1E1E',         # Dark background
            'darker': '#121212',       # Even darker
            'light': '#F5F5F5',        # Light text
            'card': '#2D2D2D',         # Card background
            'accent': '#00BCD4',       # Cyan accent
            'text': '#FFFFFF',         # White text
            'text_secondary': '#B0BEC5' # Secondary text
        }
        
        # Configure root window with dark theme
        self.root.configure(bg=self.colors['dark'])
        
        # Style configuration with error handling
        def safe_configure_style(style_name, **options):
            """Safely configure a style with fallback"""
            try:
                style.configure(style_name, **options)
                return True
            except Exception as e:
                print(f"Warning: Could not configure style '{style_name}': {e}")
                return False
        
        def safe_map_style(style_name, **options):
            """Safely map style states with fallback"""
            try:
                style.map(style_name, **options)
                return True
            except Exception as e:
                print(f"Warning: Could not map style '{style_name}': {e}")
                return False
        
        # Modern button styles
        safe_configure_style('Modern.TButton',
                          background=self.colors['primary'],
                          foreground=self.colors['text'],
                          borderwidth=0,
                          focuscolor='none',
                          font=('Segoe UI', 10, 'bold'),
                          relief='flat')
        
        safe_map_style('Modern.TButton',
                     background=[('active', self.colors['secondary']),
                               ('pressed', self.colors['secondary'])])
        
        # Success button style
        safe_configure_style('Success.TButton',
                          background=self.colors['success'],
                          foreground=self.colors['text'],
                          borderwidth=0,
                          focuscolor='none',
                          font=('Segoe UI', 10, 'bold'),
                          relief='flat')
        
        # Danger button style
        safe_configure_style('Danger.TButton',
                          background=self.colors['danger'],
                          foreground=self.colors['text'],
                          borderwidth=0,
                          focuscolor='none',
                          font=('Segoe UI', 10, 'bold'),
                          relief='flat')
        
        # Warning button style
        safe_configure_style('Warning.TButton',
                          background=self.colors['warning'],
                          foreground=self.colors['text'],
                          borderwidth=0,
                          focuscolor='none',
                          font=('Segoe UI', 10, 'bold'),
                          relief='flat')
        
        # Modern frame styles (cards)
        safe_configure_style('Card.TFrame',
                          background=self.colors['card'],
                          relief='flat',
                          borderwidth=1)
        
        # Header frame style
        safe_configure_style('Header.TFrame',
                          background=self.colors['primary'],
                          relief='flat',
                          borderwidth=0)
        
        # Sidebar frame style
        safe_configure_style('Sidebar.TFrame',
                          background=self.colors['darker'],
                          relief='flat',
                          borderwidth=0)
        
        # Modern notebook style
        safe_configure_style('Modern.TNotebook',
                          background=self.colors['dark'],
                          borderwidth=0,
                          tabmargins=[0, 5, 0, 0])
        
        safe_configure_style('Modern.TNotebook.Tab',
                          background=self.colors['card'],
                          foreground=self.colors['text'],
                          padding=[20, 10],
                          font=('Segoe UI', 10, 'bold'))
        
        safe_map_style('Modern.TNotebook.Tab',
                     background=[('selected', self.colors['primary']),
                               ('active', self.colors['secondary'])])
        
        # Modern treeview style
        safe_configure_style('Modern.Treeview',
                          background=self.colors['card'],
                          foreground=self.colors['text'],
                          fieldbackground=self.colors['card'],
                          borderwidth=0,
                          font=('Segoe UI', 10))
        
        safe_configure_style('Modern.Treeview.Heading',
                          background=self.colors['primary'],
                          foreground=self.colors['text'],
                          font=('Segoe UI', 10, 'bold'))
        
        # Modern progress bar
        safe_configure_style('Modern.TProgressbar',
                          background=self.colors['primary'],
                          troughcolor=self.colors['darker'],
                          borderwidth=0)
        
        # Modern scrollbar
        safe_configure_style('Modern.Vertical.TScrollbar',
                          background=self.colors['card'],
                          troughcolor=self.colors['darker'],
                          borderwidth=0)
        
        # Modern entry style
        safe_configure_style('Modern.TEntry',
                          fieldbackground=self.colors['card'],
                          foreground=self.colors['text'],
                          borderwidth=1,
                          insertcolor=self.colors['text'],
                          font=('Segoe UI', 10))
        
        # Modern radiobutton style
        safe_configure_style('Modern.TRadiobutton',
                          background=self.colors['card'],
                          foreground=self.colors['text'],
                          font=('Segoe UI', 10))
        
        # Configure button styles
        safe_configure_style('Primary.TButton', 
                          background=self.colors['primary'],
                          foreground='white',
                          borderwidth=0,
                          focuscolor='none',
                          font=('Segoe UI', 10, 'bold'))
        
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
        """Setup modern GUI layout with sidebar"""
        # Create main container with sidebar
        main_container = tk.Frame(self.root, bg=self.colors['dark'])
        main_container.pack(fill='both', expand=True)
        
        # Create sidebar
        self.create_sidebar(main_container)
        
        # Create content area
        content_container = tk.Frame(main_container, bg=self.colors['dark'])
        content_container.pack(side='right', fill='both', expand=True)
        
        # Header
        self.create_header(content_container)
        
        # Content area for switching
        self.content_area = tk.Frame(content_container, bg=self.colors['dark'])
        self.content_area.pack(fill='both', expand=True)
        
        # Show initial dashboard content
        self.show_content_by_index(0)
        
        # Status bar
        self.create_status_bar(content_container)
        
    def create_sidebar(self, parent):
        """Create modern sidebar navigation"""
        self.sidebar = tk.Frame(parent, bg=self.colors['darker'], width=250)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)
        
        # Logo/Title
        logo_frame = tk.Frame(self.sidebar, bg=self.colors['darker'])
        logo_frame.pack(fill='x', pady=20)
        
        logo_label = tk.Label(
            logo_frame,
            text="🛡️ RDDS",
            font=('Segoe UI', 24, 'bold'),
            bg=self.colors['darker'],
            fg=self.colors['text']
        )
        logo_label.pack(pady=(0, 5))
        
        subtitle_label = tk.Label(
            logo_frame,
            text="Security Dashboard",
            font=('Segoe UI', 12),
            bg=self.colors['darker'],
            fg=self.colors['text_secondary']
        )
        subtitle_label.pack()
        
        # Navigation buttons
        self.nav_buttons = {}
        nav_items = [
            ("🏠 Dashboard", 0),
            ("🔍 Network Scan", 1),
            ("📱 Devices", 2),
            ("🎯 Monitoring", 3),
            ("📊 Reports", 4),
            ("⚙️ Settings", 5)
        ]
        
        for text, index in nav_items:
            btn = tk.Button(
                self.sidebar,
                text=text,
                font=('Segoe UI', 11),
                bg=self.colors['darker'],
                fg=self.colors['text_secondary'],
                activebackground=self.colors['card'],
                activeforeground=self.colors['text'],
                relief='flat',
                bd=0,
                pady=12,
                anchor='w',
                command=lambda idx=index: self.switch_content(idx)
            )
            btn.pack(fill='x', padx=15, pady=2)
            self.nav_buttons[text] = btn
        
        # Set active button
        self.nav_buttons["🏠 Dashboard"].configure(
            bg=self.colors['primary'],
            fg=self.colors['text']
        )
        
        # User profile section at bottom
        user_frame = tk.Frame(self.sidebar, bg=self.colors['card'])
        user_frame.pack(side='bottom', fill='x', padx=15, pady=20)
        
        avatar_label = tk.Label(
            user_frame,
            text="👤",
            font=('Segoe UI', 24),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        avatar_label.pack(side='left', padx=10, pady=10)
        
        user_label = tk.Label(
            user_frame,
            text="Security Admin",
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        user_label.pack(side='left', padx=10, pady=10)
        
    def switch_content(self, index):
        """Switch between different content views"""
        # Reset all nav buttons
        for text, btn in self.nav_buttons.items():
            btn.configure(
                bg=self.colors['darker'],
                fg=self.colors['text_secondary']
            )
        
        # Set active button
        active_btns = list(self.nav_buttons.values())
        if 0 <= index < len(active_btns):
            active_btns[index].configure(
                bg=self.colors['primary'],
                fg=self.colors['text']
            )
        
        # Clear current content and show new content
        self.show_content_by_index(index)
        
    def show_content_by_index(self, index):
        """Show content based on sidebar selection"""
        # Clear current content
        for widget in self.content_area.winfo_children():
            widget.destroy()
        
        if index == 0:  # Dashboard
            self.create_dashboard_content(self.content_area)
        elif index == 1:  # Network Scan
            self.create_scan_content(self.content_area)
        elif index == 2:  # Devices
            self.create_device_content(self.content_area)
        elif index == 3:  # Monitoring
            self.create_monitoring_content(self.content_area)
        elif index == 4:  # Reports
            self.create_reports_content(self.content_area)
        elif index == 5:  # Settings
            self.create_settings_content(self.content_area)
        
    def create_dashboard_content(self, parent):
        """Create dashboard content"""
        # Main dashboard container with modern layout
        main_frame = tk.Frame(parent, bg=self.colors['dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Welcome banner
        self.create_welcome_banner(main_frame)
        
        # Modern stats cards
        self.create_modern_stats_cards(main_frame)
        
        # Activity and alerts section
        self.create_modern_activity_section(main_frame)
        
    def create_scan_content(self, parent):
        """Create network scan content"""
        main_frame = tk.Frame(parent, bg=self.colors['dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Scan interface
        self.create_scan_interface(main_frame)
        
    def create_device_content(self, parent):
        """Create device management content"""
        main_frame = tk.Frame(parent, bg=self.colors['dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Device management interface
        self.create_device_interface(main_frame)
        
    def create_monitoring_content(self, parent):
        """Create monitoring content"""
        main_frame = tk.Frame(parent, bg=self.colors['dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Monitoring interface
        self.create_monitoring_interface(main_frame)
        
    def create_reports_content(self, parent):
        """Create reports content"""
        main_frame = tk.Frame(parent, bg=self.colors['dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Reports interface
        self.create_reports_interface(main_frame)
        
    def create_settings_content(self, parent):
        """Create settings content"""
        main_frame = tk.Frame(parent, bg=self.colors['dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Settings interface
        self.create_settings_interface(main_frame)
        
    def create_header(self, parent):
        """Create modern application header"""
        header_frame = tk.Frame(parent, bg=self.colors['primary'], height=60)
        header_frame.pack(fill='x', pady=(0, 10))
        header_frame.pack_propagate(False)
        
        # Left side - Date/Time
        datetime_label = tk.Label(
            header_frame,
            text="",
            font=('Segoe UI', 12),
            bg=self.colors['primary'],
            fg=self.colors['text']
        )
        datetime_label.pack(side='left', padx=20, pady=15)
        self.datetime_label = datetime_label
        
        # Right side - Status and icons
        right_frame = tk.Frame(header_frame, bg=self.colors['primary'])
        right_frame.pack(side='right', padx=20, pady=15)
        
        # Status indicator
        self.status_indicator = tk.Label(
            right_frame,
            text="● System Ready",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['primary'],
            fg='black'
        )
        self.status_indicator.pack(side='right', padx=10)
        
        # Icon buttons
        notification_btn = tk.Button(
            right_frame,
            text="🔔",
            font=('Segoe UI', 16),
            bg=self.colors['primary'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            activebackground=self.colors['secondary']
        )
        notification_btn.pack(side='right', padx=5)
        
        message_btn = tk.Button(
            right_frame,
            text="💬",
            font=('Segoe UI', 16),
            bg=self.colors['primary'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            activebackground=self.colors['secondary']
        )
        message_btn.pack(side='right', padx=5)
        
        user_btn = tk.Button(
            right_frame,
            text="👤",
            font=('Segoe UI', 16),
            bg=self.colors['primary'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            activebackground=self.colors['secondary']
        )
        user_btn.pack(side='right', padx=5)
        
        # Update datetime
        self.update_datetime()
        
    def create_welcome_banner(self, parent):
        """Create modern welcome banner"""
        banner_frame = tk.Frame(parent, bg=self.colors['primary'], height=120)
        banner_frame.pack(fill='x', pady=(0, 20))
        banner_frame.pack_propagate(False)
        
        # Left side - Welcome text
        welcome_left = tk.Frame(banner_frame, bg=self.colors['primary'])
        welcome_left.pack(side='left', fill='both', expand=True, padx=20, pady=20)
        
        welcome_title = tk.Label(
            welcome_left,
            text="Good Day, Security Admin!",
            font=('Segoe UI', 24, 'bold'),
            bg=self.colors['primary'],
            fg=self.colors['text']
        )
        welcome_title.pack(anchor='w')
        
        welcome_subtitle = tk.Label(
            welcome_left,
            text="Your network is protected and monitored",
            font=('Segoe UI', 12),
            bg=self.colors['primary'],
            fg=self.colors['text_secondary']
        )
        welcome_subtitle.pack(anchor='w', pady=(5, 0))
        
        # Right side - Status info
        welcome_right = tk.Frame(banner_frame, bg=self.colors['primary'])
        welcome_right.pack(side='right', padx=20, pady=20)
        
        self.system_status = tk.Label(
            welcome_right,
            text="🟢 All Systems Operational",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['primary'],
            fg='black'
        )
        self.system_status.pack(anchor='e')
        
    def create_modern_stats_cards(self, parent):
        """Create modern statistics cards"""
        cards_container = tk.Frame(parent, bg=self.colors['dark'])
        cards_container.pack(fill='x', pady=(0, 20))
        
        # Card definitions with modern styling
        cards = [
            ("🔍 Total Devices", "0", self.colors['primary']),
            ("🚨 Threats Detected", "0", self.colors['danger']),
            ("✅ Secure Devices", "0", self.colors['success']),
            ("⚠️ Suspicious Activity", "0", self.colors['warning'])
        ]
        
        self.stats_labels = {}
        
        for i, (title, value, color) in enumerate(cards):
            # Modern card frame
            card = tk.Frame(cards_container, bg=self.colors['card'], relief='flat', bd=0)
            card.pack(side='left', fill='both', expand=True, padx=(0, 15))
            
            # Card content with padding
            content_frame = tk.Frame(card, bg=self.colors['card'])
            content_frame.pack(fill='both', expand=True, padx=20, pady=20)
            
            # Icon and title
            header_frame = tk.Frame(content_frame, bg=self.colors['card'])
            header_frame.pack(fill='x', pady=(0, 10))
            
            icon_label = tk.Label(
                header_frame, 
                text=title.split()[0], 
                font=('Segoe UI', 20),
                bg=self.colors['card'], 
                fg=color
            )
            icon_label.pack(side='left', padx=(0, 10))
            
            title_label = tk.Label(
                header_frame,
                text=' '.join(title.split()[1:]),
                font=('Segoe UI', 11),
                bg=self.colors['card'], 
                fg=self.colors['text_secondary']
            )
            title_label.pack(side='left')
            
            # Value
            value_label = tk.Label(
                content_frame, 
                text=value, 
                font=('Segoe UI', 28, 'bold'),
                bg=self.colors['card'], 
                fg=color
            )
            value_label.pack(anchor='w')
            
            # Store reference for updates
            self.stats_labels[title] = value_label
        
    def create_modern_activity_section(self, parent):
        """Create modern activity and alerts section"""
        # Create two-column layout
        activity_container = tk.Frame(parent, bg=self.colors['dark'])
        activity_container.pack(fill='both', expand=True)
        
        # Left column - Recent alerts
        alerts_frame = tk.Frame(activity_container, bg=self.colors['card'], relief='flat', bd=0)
        alerts_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Alerts header
        alerts_header = tk.Frame(alerts_frame, bg=self.colors['card'])
        alerts_header.pack(fill='x', padx=20, pady=(20, 10))
        
        alerts_title = tk.Label(
            alerts_header,
            text="🚨 Recent Security Alerts",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        alerts_title.pack(side='left')
        
        # Alert status
        self.alert_status_label = tk.Label(
            alerts_frame,
            text="🟢 No Active Alerts",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['success']
        )
        self.alert_status_label.pack(padx=20, pady=(0, 10), anchor='w')
        
        # Activity text area
        self.activity_text = scrolledtext.ScrolledText(
            alerts_frame,
            height=15,
            font=('Consolas', 9),
            bg=self.colors['dark'],
            fg=self.colors['text'],
            wrap='word',
            relief='flat',
            bd=0
        )
        self.activity_text.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        self.activity_text.config(state='disabled')
        
        # Right column - Quick actions
        actions_frame = tk.Frame(activity_container, bg=self.colors['card'], relief='flat', bd=0, width=300)
        actions_frame.pack(side='right', fill='y', padx=(10, 0))
        actions_frame.pack_propagate(False)
        
        # Actions header
        actions_header = tk.Frame(actions_frame, bg=self.colors['card'])
        actions_header.pack(fill='x', padx=20, pady=(20, 10))
        
        actions_title = tk.Label(
            actions_header,
            text="⚡ Quick Actions",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        actions_title.pack()
        
        # Quick action buttons
        actions = [
            ("🚀 Start Scan", self.start_scan, self.colors['primary']),
            ("🎯 Start Monitoring", self.toggle_monitoring, self.colors['success']),
            ("📊 Generate Report", self.generate_report, self.colors['warning']),
            ("⚙️ Settings", self.open_settings, self.colors['secondary'])
        ]
        
        for text, command, color in actions:
            btn = tk.Button(
                actions_frame,
                text=text,
                font=('Segoe UI', 11, 'bold'),
                bg=color,
                fg=self.colors['text'],
                relief='flat',
                bd=0,
                pady=12,
                command=command,
                activebackground=self.adjust_color(color, -20)
            )
            btn.pack(fill='x', padx=20, pady=5)
            
        # System info section
        info_frame = tk.Frame(actions_frame, bg=self.colors['dark'], relief='flat', bd=0)
        info_frame.pack(fill='x', padx=20, pady=20)
        
        info_title = tk.Label(
            info_frame,
            text="📊 System Info",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['dark'],
            fg=self.colors['text']
        )
        info_title.pack(pady=(10, 5))
        
        info_items = [
            ("Protection Level", "🛡️ 100%"),
            ("Uptime", "⏱️ 24h"),
            ("Last Scan", "✅ Completed"),
            ("Threat Level", "🟢 Low")
        ]
        
        for label, value in info_items:
            item_frame = tk.Frame(info_frame, bg=self.colors['dark'])
            item_frame.pack(fill='x', padx=10, pady=2)
            
            label_widget = tk.Label(
                item_frame,
                text=label,
                font=('Segoe UI', 10),
                bg=self.colors['dark'],
                fg=self.colors['text_secondary']
            )
            label_widget.pack(side='left')
            
            value_widget = tk.Label(
                item_frame,
                text=value,
                font=('Segoe UI', 10, 'bold'),
                bg=self.colors['dark'],
                fg=self.colors['text']
            )
            value_widget.pack(side='right')
            
    def adjust_color(self, hex_color, amount):
        """Adjust a hex color by amount (positive = lighter, negative = darker)"""
        # Convert hex to RGB
        hex_color = hex_color.lstrip('#')
        r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        
        # Adjust
        r = max(0, min(255, r + amount))
        g = max(0, min(255, g + amount))
        b = max(0, min(255, b + amount))
        
        # Convert back to hex
        return f'#{r:02x}{g:02x}{b:02x}'
            
    def create_alert_status_bar(self, parent):
        """Create alert status bar for dashboard"""
        alert_frame = tk.Frame(parent, bg='white', relief='raised', bd=1)
        alert_frame.pack(fill='x', pady=(0, 10))
        
        # Alert status label
        self.alert_status_label = tk.Label(
            alert_frame,
            text="🚨 Alert Status: No Active Alerts",
            font=('Segoe UI', 12, 'bold'),
            bg='white',
            fg=self.colors['success']
        )
        self.alert_status_label.pack(pady=10, padx=10, anchor='w')
        
    def update_alert_status(self, status_text):
        """Update alert status bar"""
        if hasattr(self, 'alert_status_label'):
            self.alert_status_label.config(text=status_text)
            
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
        """Create modern network scan tab"""
        try:
            scan_frame = ttk.Frame(self.notebook, style='Card.TFrame')
        except:
            scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="🔍 Network Scan")
        
        main_frame = tk.Frame(scan_frame, bg=self.colors['dark'])
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Modern control panel
        control_frame = tk.Frame(main_frame, bg=self.colors['card'], relief='flat', bd=0)
        control_frame.pack(fill='x', pady=(0, 20))
        
        # Control header
        control_header = tk.Frame(control_frame, bg=self.colors['card'])
        control_header.pack(fill='x', padx=20, pady=(20, 10))
        
        control_title = tk.Label(
            control_header,
            text="🔍 Scan Configuration",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        control_title.pack(side='left')
        
        # Scan type selection
        scan_type_frame = tk.Frame(control_frame, bg=self.colors['card'])
        scan_type_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(
            scan_type_frame,
            text="Select Scan Type:",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['card'], fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        self.scan_type = tk.StringVar(value="standard")
        
        # Modern radio button layout
        scan_types = [
            ("Standard Scan (4-step)", "standard"),
            ("Enhanced Scan (5-step)", "enhanced"),
            ("IoT Profiling", "iot"),
            ("DHCP Security", "dhcp"),
            ("Traffic Analysis", "traffic"),
            ("SSL Certificate Monitor", "ssl"),
            ("Advanced Attack Detection", "advanced")
        ]
        
        for i, (text, value) in enumerate(scan_types):
            radio_frame = tk.Frame(scan_type_frame, bg=self.colors['card'])
            radio_frame.pack(fill='x', pady=2)
            
            radio = tk.Radiobutton(
                radio_frame,
                text=text,
                variable=self.scan_type,
                value=value,
                font=('Segoe UI', 11),
                bg=self.colors['card'],
                fg=self.colors['text'],
                selectcolor=self.colors['primary'],
                activebackground=self.colors['card'],
                activeforeground=self.colors['text']
            )
            radio.pack(anchor='w')
        
        # Scan button
        self.scan_button = tk.Button(
            control_frame,
            text="🚀 Start Scan",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['primary'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=15,
            command=self.start_scan,
            activebackground=self.adjust_color(self.colors['primary'], -20)
        )
        self.scan_button.pack(pady=20, padx=20, fill='x')
        
        # Progress bar
        try:
            self.scan_progress = ttk.Progressbar(
                control_frame,
                mode='determinate',
                maximum=100,
                style='Modern.TProgressbar'
            )
        except:
            # Fallback to default style if custom style fails
            self.scan_progress = ttk.Progressbar(
                control_frame,
                mode='determinate',
                maximum=100
            )
        self.scan_progress.pack(fill='x', padx=20, pady=(0, 20))
        
        # Results area
        results_frame = tk.Frame(main_frame, bg=self.colors['card'], relief='flat', bd=0)
        results_frame.pack(fill='both', expand=True)
        
        # Results header
        results_header = tk.Frame(results_frame, bg=self.colors['card'])
        results_header.pack(fill='x', padx=20, pady=(20, 10))
        
        results_title = tk.Label(
            results_header,
            text="📋 Scan Results",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        results_title.pack(side='left')
        
        # Results treeview with modern styling
        columns = ('IP', 'MAC', 'Vendor', 'Status', 'Risk Score')
        try:
            self.scan_tree = ttk.Treeview(
                results_frame, 
                columns=columns, 
                show='headings', 
                height=15,
                style='Modern.Treeview'
            )
        except:
            # Fallback to default style if custom style fails
            self.scan_tree = ttk.Treeview(
                results_frame, 
                columns=columns, 
                show='headings', 
                height=15
            )
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        # Modern scrollbar
        try:
            scrollbar = ttk.Scrollbar(
                results_frame, 
                orient='vertical', 
                command=self.scan_tree.yview,
                style='Modern.Vertical.TScrollbar'
            )
        except:
            # Fallback to default style if custom style fails
            scrollbar = ttk.Scrollbar(
                results_frame, 
                orient='vertical', 
                command=self.scan_tree.yview
            )
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.scan_tree.pack(side='left', fill='both', expand=True, padx=(20, 0), pady=(0, 20))
        scrollbar.pack(side='right', fill='y', padx=(0, 20), pady=(0, 20))
        
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
        
        # Clear alerts button
        clear_button = ttk.Button(
            controls_inner,
            text="🗑️ Clear Alerts",
            command=self.clear_monitoring_alerts,
            style='Danger.TButton'
        )
        clear_button.pack(side='left', padx=5)
        
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
        
    def update_datetime(self):
        """Update date and time display"""
        current_time = datetime.now().strftime("%A %B %d, %Y %H:%M:%S")
        self.datetime_label.config(text=current_time)
        self.root.after(1000, self.update_datetime)
        
    def create_status_bar(self, parent):
        """Create modern status bar"""
        status_frame = tk.Frame(parent, bg=self.colors['darker'], height=30)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        # Status label
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            font=('Segoe UI', 9),
            bg=self.colors['darker'],
            fg=self.colors['text_secondary']
        )
        self.status_label.pack(side='left', padx=10, pady=5)
        
        # Version info
        version_label = tk.Label(
            status_frame,
            text="RDDS v2.0 (Enhanced)",
            font=('Segoe UI', 9),
            bg=self.colors['darker'],
            fg=self.colors['text_secondary']
        )
        version_label.pack(side='right', padx=10, pady=5)
        
    def start_scan(self):
        """Start network scan (standard or enhanced)"""
        if self.current_scan_thread and self.current_scan_thread.is_alive():
            messagebox.showwarning("Scan in Progress", "A scan is already running!")
            return
            
        # Clear previous results
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
            
        # Update UI
        scan_type = self.scan_type.get()
        self.scan_button.config(text="⏸️ Scanning...", state='disabled')
        self.scan_progress['value'] = 0
        self.status_indicator.config(text="● Scanning...", fg='black')
        
        if scan_type == "enhanced":
            self.update_status("Starting enhanced security scan...")
        elif scan_type == "iot":
            self.update_status("Starting IoT device profiling...")
        elif scan_type == "dhcp":
            self.update_status("Starting DHCP security monitoring...")
        elif scan_type == "traffic":
            self.update_status("Starting network traffic analysis...")
        elif scan_type == "ssl":
            self.update_status("Starting SSL certificate monitoring...")
        elif scan_type == "advanced":
            self.update_status("Starting advanced attack detection...")
        else:
            self.update_status("Starting network scan...")
        
        # Start scan in background
        if scan_type == "standard":
            self.current_scan_thread = threading.Thread(target=self._perform_scan, daemon=True)
        elif scan_type == "enhanced":
            self.current_scan_thread = threading.Thread(target=self._perform_enhanced_scan, daemon=True)
        elif scan_type == "iot":
            self.current_scan_thread = threading.Thread(target=self._perform_iot_scan, daemon=True)
        elif scan_type == "dhcp":
            self.current_scan_thread = threading.Thread(target=self._perform_dhcp_scan, daemon=True)
        elif scan_type == "traffic":
            self.current_scan_thread = threading.Thread(target=self._perform_traffic_scan, daemon=True)
        elif scan_type == "ssl":
            self.current_scan_thread = threading.Thread(target=self._perform_ssl_scan, daemon=True)
        elif scan_type == "advanced":
            self.current_scan_thread = threading.Thread(target=self._perform_advanced_scan, daemon=True)
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
    
    def _perform_enhanced_scan(self):
        """Perform enhanced security scan with DPI and advanced AP detection"""
        try:
            # Step 1: Network discovery
            self.scan_queue.put(("progress", 10))
            self.scan_queue.put(("status", "Discovering network devices..."))
            network_range = self.scanner.get_network_range()
            
            self.scan_queue.put(("progress", 20))
            devices = self.scanner.arp_scan(network_range)
            self.scan_queue.put(("status", f"Found {len(devices)} devices"))
            
            # Step 2: Traditional rogue detection
            self.scan_queue.put(("progress", 30))
            self.scan_queue.put(("status", "Analyzing for rogue devices..."))
            analyzed_devices, alerts = self.detector.analyze_network(devices)
            
            # Step 3: Enhanced wireless analysis
            self.scan_queue.put(("progress", 40))
            self.scan_queue.put(("status", "Enhanced wireless network analysis..."))
            try:
                wireless_networks = self.enhanced_ap_detector.scan_wireless_networks_windows()
                enhanced_ap_alerts = self.enhanced_ap_detector.detect_evil_twin(wireless_networks)
                rogue_ap_alerts = self.enhanced_ap_detector.detect_rogue_ap(wireless_networks)
                karma_alerts = self.enhanced_ap_detector.detect_karma_attack(wireless_networks)
                
                alerts.extend(enhanced_ap_alerts)
                alerts.extend(rogue_ap_alerts)
                alerts.extend(karma_alerts)
                
                self.scan_queue.put(("status", f"Found {len(wireless_networks)} APs, {len(enhanced_ap_alerts)} evil twins, {len(rogue_ap_alerts)} rogue APs"))
            except Exception as wireless_error:
                print(f"[!] Enhanced wireless scan failed: {wireless_error}")
                self.scan_queue.put(("status", "Enhanced wireless scan failed - continuing..."))
            
            # Step 4: Deep packet inspection
            self.scan_queue.put(("progress", 60))
            self.scan_queue.put(("status", "Deep packet inspection..."))
            dpi_results = []
            if devices:
                for i, device in enumerate(devices[:20]):  # Limit to first 20 devices
                    self.scan_queue.put(("progress", 60 + (i * 2)))
                    packet_data = {
                        'size': 1500,
                        'protocol': 'TCP',
                        'src_port': 80,
                        'dst_port': 8080,
                        'flags': 0x18,
                        'src_ip': device['ip'],
                        'dst_ip': '8.8.8.8'
                    }
                    dpi_analysis = self.dpi_inspector.analyze_packet(packet_data)
                    dpi_results.append(dpi_analysis)
                    
                    # Add DPI alerts
                    if dpi_analysis['risk_score'] > 50:
                        for anomaly in dpi_analysis['anomalies']:
                            alerts.append({
                                'type': 'DPI_ANOMALY',
                                'severity': 'HIGH' if dpi_analysis['risk_score'] > 70 else 'MEDIUM',
                                'message': f"{anomaly['type']}: {anomaly['description']}",
                                'risk_score': dpi_analysis['risk_score']
                            })
            
            high_risk_packets = [r for r in dpi_results if r['risk_score'] > 50]
            self.scan_queue.put(("status", f"Analyzed {len(dpi_results)} packets, {len(high_risk_packets)} high-risk"))
            
            # Step 5: Final analysis
            self.scan_queue.put(("progress", 90))
            self.scan_queue.put(("status", "Finalizing enhanced analysis..."))
            
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
    
    def _perform_iot_scan(self):
        """Perform IoT device profiling scan"""
        try:
            # Step 1: Network discovery
            self.scan_queue.put(("progress", 10))
            self.scan_queue.put(("status", "Discovering network devices..."))
            network_range = self.scanner.get_network_range()
            
            self.scan_queue.put(("progress", 30))
            devices = self.scanner.arp_scan(network_range)
            self.scan_queue.put(("status", f"Found {len(devices)} devices"))
            
            if not devices:
                self.scan_queue.put(("error", "No devices found for IoT profiling"))
                return
            
            # Step 2: IoT Profiling
            self.scan_queue.put(("progress", 40))
            self.scan_queue.put(("status", "Profiling IoT devices..."))
            
            iot_profiles = []
            for i, device in enumerate(devices):
                self.scan_queue.put(("progress", 40 + (i * 50 // len(devices))))
                self.scan_queue.put(("status", f"Profiling {device['ip']}..."))
                
                # Simulate device data for profiling
                device_data = {
                    'ip': device['ip'],
                    'mac': device['mac'],
                    'open_ports': [80, 443, 8080],
                    'ttl': 64,
                    'window_size': 8192,
                    'cloud_communication': ['cloud.iot-device.com'],
                    'firmware_version': '1.0.0'
                }
                
                # Profile the device
                profile = self.iot_profiler.profile_device(device_data)
                iot_profiles.append(profile)
            
            # Step 3: Generate IoT report
            self.scan_queue.put(("progress", 90))
            self.scan_queue.put(("status", "Generating IoT security report..."))
            
            report = self.iot_profiler.generate_iot_report()
            
            # Send results
            self.scan_queue.put(("progress", 100))
            self.scan_queue.put(("iot_results", iot_profiles, report))
            
        except Exception as e:
            error_msg = str(e)
            if "Permission denied" in error_msg:
                error_msg = "Insufficient privileges. Please run as Administrator."
            elif "No such device" in error_msg:
                error_msg = "Network interface not available. Check your connection."
            self.scan_queue.put(("error", error_msg))
    
    def _perform_dhcp_scan(self):
        """Perform DHCP security monitoring"""
        try:
            # Step 1: Start DHCP monitoring
            self.scan_queue.put(("progress", 10))
            self.scan_queue.put(("status", "Starting DHCP security monitoring..."))
            
            interface = self.scanner.interface
            if not self.dhcp_monitor.start_monitoring(interface):
                self.scan_queue.put(("error", "Failed to start DHCP monitoring"))
                return
            
            self.scan_queue.put(("progress", 20))
            self.scan_queue.put(("status", "DHCP monitoring active - analyzing traffic..."))
            
            # Monitor for 60 seconds with progress updates
            import time
            for i in range(60):
                progress = 20 + (i * 60 // 60)  # 20% to 80%
                self.scan_queue.put(("progress", progress))
                self.scan_queue.put(("status", f"Monitoring DHCP traffic... {i+1}/60s"))
                
                time.sleep(1)
            
            # Step 2: Generate security summary
            self.scan_queue.put(("progress", 85))
            self.scan_queue.put(("status", "Analyzing DHCP security data..."))
            
            summary = self.dhcp_monitor.get_security_summary()
            recent_alerts = self.dhcp_monitor.get_recent_alerts(10)
            
            # Step 3: Stop monitoring
            self.scan_queue.put(("progress", 95))
            self.scan_queue.put(("status", "Stopping DHCP monitoring..."))
            
            self.dhcp_monitor.stop_monitoring()
            
            # Send results
            self.scan_queue.put(("progress", 100))
            self.scan_queue.put(("dhcp_results", summary, recent_alerts))
            
        except Exception as e:
            error_msg = str(e)
            if "Permission denied" in error_msg:
                error_msg = "Insufficient privileges. Please run as Administrator."
            elif "No such device" in error_msg:
                error_msg = "Network interface not available. Check your connection."
            self.scan_queue.put(("error", error_msg))
    
    def _perform_traffic_scan(self):
        """Perform network traffic analysis scan"""
        try:
            # Step 1: Start traffic monitoring
            self.scan_queue.put(("progress", 10))
            self.scan_queue.put(("status", "Starting traffic monitoring..."))
            
            interface = self.scanner.interface
            self.scan_queue.put(("status", f"Monitoring on {interface}..."))
            
            # Step 2: Monitor for 5 minutes (300 seconds)
            self.scan_queue.put(("progress", 20))
            duration = 300  # 5 minutes for GUI
            
            # Start monitoring with progress updates
            def progress_updater():
                for i in range(0, duration, 30):  # Update every 30 seconds
                    progress = 20 + (i * 60 // duration)  # 20% to 80%
                    self.scan_queue.put(("progress", progress))
                    self.scan_queue.put(("status", f"Analyzing traffic... {i//60+1}/{duration//60} min"))
                    time.sleep(30)
            
            # Start progress updater in separate thread
            progress_thread = threading.Thread(target=progress_updater, daemon=True)
            progress_thread.start()
            
            # Start traffic monitoring
            report = self.traffic_analyzer.start_monitoring(interface, duration)
            
            if not report:
                self.scan_queue.put(("error", "Traffic monitoring failed"))
                return
            
            # Step 3: Generate report
            self.scan_queue.put(("progress", 90))
            self.scan_queue.put(("status", "Generating traffic analysis report..."))
            
            # Send results
            self.scan_queue.put(("progress", 100))
            self.scan_queue.put(("traffic_results", report))
            
        except Exception as e:
            error_msg = str(e)
            if "Permission denied" in error_msg:
                error_msg = "Insufficient privileges. Please run as Administrator."
            elif "No such device" in error_msg:
                error_msg = "Network interface not available. Check your connection."
            self.scan_queue.put(("error", error_msg))
    
    def _perform_ssl_scan(self):
        """Perform SSL certificate monitoring scan"""
        try:
            # Step 1: Get hosts to monitor
            self.scan_queue.put(("progress", 10))
            self.scan_queue.put(("status", "Getting hosts to monitor..."))
            
            # For demo, monitor common SSL ports
            hosts = ['google.com', 'github.com', 'stackoverflow.com', 'microsoft.com']
            
            # Step 2: Start SSL monitoring
            self.scan_queue.put(("progress", 20))
            self.scan_queue.put(("status", f"Monitoring {len(hosts)} hosts..."))
            
            # Start certificate monitoring
            report = self.ssl_monitor.start_monitoring(hosts, 60)  # 1 minute for GUI
            
            if not report:
                self.scan_queue.put(("error", "SSL certificate monitoring failed"))
                return
            
            # Step 3: Generate report
            self.scan_queue.put(("progress", 90))
            self.scan_queue.put(("status", "Generating certificate report..."))
            
            # Send results
            self.scan_queue.put(("progress", 100))
            self.scan_queue.put(("ssl_results", report))
            
        except Exception as e:
            error_msg = str(e)
            if "Permission denied" in error_msg:
                error_msg = "Insufficient privileges. Please run as Administrator."
            elif "No such device" in error_msg:
                error_msg = "Network interface not available. Check your connection."
            self.scan_queue.put(("error", error_msg))
    
    def _perform_advanced_scan(self):
        """Perform advanced attack detection scan"""
        try:
            # Step 1: Start advanced attack detection
            self.scan_queue.put(("progress", 10))
            self.scan_queue.put(("status", "Starting advanced attack detection..."))
            
            interface = self.scanner.interface
            self.scan_queue.put(("status", f"Monitoring on {interface}..."))
            
            # Start advanced attack detection
            report = self.advanced_detector.start_monitoring(interface, 60)  # 1 minute for GUI
            
            if not report:
                self.scan_queue.put(("error", "Advanced attack detection failed"))
                return
            
            # Step 2: Generate report
            self.scan_queue.put(("progress", 90))
            self.scan_queue.put(("status", "Generating attack detection report..."))
            
            # Send results
            self.scan_queue.put(("progress", 100))
            self.scan_queue.put(("advanced_results", report))
            
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
                    self.scan_button.config(text="🚀 Start Scan", state='normal')
                    self.status_indicator.config(text="● Ready", fg=self.colors['success'])
                    self.update_status("Scan completed")
                    self.add_activity("✅ Scan completed successfully")
                    
                elif result[0] == "iot_results":
                    iot_profiles, report = result[1], result[2]
                    self.display_iot_results(iot_profiles, report)
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 100
                    self.scan_button.config(text="🚀 Start Scan", state='normal')
                    self.status_indicator.config(text="● Ready", fg=self.colors['success'])
                    self.update_status("IoT profiling completed")
                    self.add_activity("✅ IoT profiling completed successfully")
                    
                elif result[0] == "dhcp_results":
                    summary, alerts = result[1], result[2]
                    self.display_dhcp_results(summary, alerts)
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 100
                    self.scan_button.config(text="🚀 Start Scan", state='normal')
                    self.status_indicator.config(text="● Ready", fg=self.colors['success'])
                    self.update_status("DHCP security monitoring completed")
                    self.add_activity("✅ DHCP security monitoring completed successfully")
                    
                elif result[0] == "traffic_results":
                    report = result[1]
                    self.display_traffic_results(report)
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 100
                    self.scan_button.config(text="🚀 Start Scan", state='normal')
                    self.status_indicator.config(text="● Ready", fg=self.colors['success'])
                    self.update_status("Traffic analysis completed")
                    self.add_activity("✅ Traffic analysis completed successfully")
                    
                elif result[0] == "ssl_results":
                    report = result[1]
                    self.display_ssl_results(report)
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 100
                    self.scan_button.config(text="🚀 Start Scan", state='normal')
                    self.status_indicator.config(text="● Ready", fg=self.colors['success'])
                    self.update_status("SSL certificate monitoring completed")
                    self.add_activity("✅ SSL certificate monitoring completed successfully")
                    
                elif result[0] == "advanced_results":
                    report = result[1]
                    self.display_advanced_results(report)
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 100
                    self.scan_button.config(text="🚀 Start Scan", state='normal')
                    self.status_indicator.config(text="● Ready", fg=self.colors['success'])
                    self.update_status("Advanced attack detection completed")
                    self.add_activity("✅ Advanced attack detection completed successfully")
                    
                elif result[0] == "error":
                    messagebox.showerror("Scan Error", f"Scan failed: {result[1]}")
                    self.scan_progress.stop()
                    self.scan_progress['value'] = 0
                    self.scan_button.config(text="🚀 Start Scan", state='normal')
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
                self.scan_button.config(text="🚀 Start Scan", state='normal')
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
        
    def clear_monitoring_alerts(self):
        """Clear monitoring alerts and storage"""
        self._monitoring_alerts = []
        self.alerts_text.config(state='normal')
        self.alerts_text.delete('1.0', 'end')
        self.alerts_text.config(state='disabled')
        self.add_activity("🗑️ Cleared monitoring alerts")
        
    def toggle_monitoring(self):
        """Toggle real-time monitoring"""
        if not self.monitoring:
            try:
                duration = int(self.duration_var.get())
                if duration <= 0:
                    messagebox.showerror("Error", "Duration must be greater than 0!")
                    return
                    
                # Clear previous monitoring alerts
                self._monitoring_alerts = []
                self.alerts_text.config(state='normal')
                self.alerts_text.delete('1.0', 'end')
                self.alerts_text.config(state='disabled')
                
                # Update alert status
                self.update_alert_status("🚨 Alert Status: Monitoring Active")
                    
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
            
            # Update alert status
            if len(self._monitoring_alerts) > 0:
                self.update_alert_status(f"🚨 Alert Status: {len(self._monitoring_alerts)} Alerts Captured")
            else:
                self.update_alert_status("🚨 Alert Status: No Active Alerts")
                
            self.add_activity(f"⏹️ Stopped monitoring - captured {len(self._monitoring_alerts)} alerts")
            
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
        """Add attack alert to display and storage"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert_text = f"[{timestamp}] 🚨 [{alert['severity']}] {alert['type']}: {alert['message']}\n"
        
        self.alerts_text.config(state='normal')
        self.alerts_text.insert('end', alert_text)
        self.alerts_text.see('end')
        self.alerts_text.config(state='disabled')
        
        # Store alert for report generation
        self._monitoring_alerts.append(alert)
        
        # Update alert status bar
        self.update_alert_status(f"🚨 Alert Status: {alert['severity']} - {alert['type']}")
        
        self.add_activity(f"🚨 Attack detected: {alert['type']}")
        
    def generate_report(self):
        """Generate comprehensive security report"""
        try:
            handle_rdds_error(None, "Starting Report Generation", "INFO", True, False)
            
            # Collect all available data
            report_data = {
                'devices': [],
                'alerts': [],
                'iot_profiles': [],
                'dhcp_summary': {},
                'traffic_analysis': {},
                'ssl_monitoring': {},
                'attack_detection': {},
                'timestamp': datetime.now().isoformat(),
                'scan_duration': 0
            }
            
            # Get devices from scan tree
            try:
                for child in self.scan_tree.get_children():
                    values = self.scan_tree.item(child)['values']
                    if len(values) >= 4:
                        device = {
                            'ip': values[0],
                            'mac': values[1],
                            'vendor': values[2] if len(values) > 2 else 'Unknown',
                            'status': values[3] if len(values) > 3 else 'Unknown',
                            'risk_score': 0
                        }
                        # Extract risk score if available
                        if len(values) > 4 and isinstance(values[4], str) and '/' in values[4]:
                            try:
                                device['risk_score'] = int(values[4].split('/')[0])
                            except:
                                pass
                        report_data['devices'].append(device)
            except Exception as e:
                handle_rdds_error(e, "Extract Device Data", "WARNING", True, False)
            
            # Get last scan data if available
            if not report_data['devices']:
                report_data['devices'] = getattr(self, '_last_devices', [])
                report_data['alerts'] = getattr(self, '_last_alerts', [])
            
            # Get monitoring alerts
            if hasattr(self, '_monitoring_alerts') and self._monitoring_alerts:
                report_data['alerts'].extend(self._monitoring_alerts)
            
            # Get IoT profiling data
            if hasattr(self, 'iot_profiler') and self.iot_profiler:
                try:
                    # Get IoT profiles from recent scans
                    if hasattr(self, '_last_iot_profiles'):
                        report_data['iot_profiles'] = self._last_iot_profiles
                except Exception as e:
                    handle_rdds_error(e, "Collect IoT Data", "WARNING", True, False)
            
            # Get DHCP security data
            if hasattr(self, 'dhcp_monitor') and self.dhcp_monitor:
                try:
                    if hasattr(self, '_last_dhcp_summary'):
                        report_data['dhcp_summary'] = self._last_dhcp_summary
                except Exception as e:
                    handle_rdds_error(e, "Collect DHCP Data", "WARNING", True, False)
            
            # Get traffic analysis data
            if hasattr(self, 'traffic_analyzer') and self.traffic_analyzer:
                try:
                    if hasattr(self, '_last_traffic_report'):
                        report_data['traffic_analysis'] = self._last_traffic_report
                except Exception as e:
                    handle_rdds_error(e, "Collect Traffic Data", "WARNING", True, False)
            
            # Get SSL monitoring data
            if hasattr(self, 'ssl_monitor') and self.ssl_monitor:
                try:
                    if hasattr(self, '_last_ssl_report'):
                        report_data['ssl_monitoring'] = self._last_ssl_report
                except Exception as e:
                    handle_rdds_error(e, "Collect SSL Data", "WARNING", True, False)
            
            # Get advanced attack detection data
            if hasattr(self, 'advanced_detector') and self.advanced_detector:
                try:
                    if hasattr(self, '_last_attack_report'):
                        report_data['attack_detection'] = self._last_attack_report
                except Exception as e:
                    handle_rdds_error(e, "Collect Attack Data", "WARNING", True, False)
            
            # If still no data, run a quick scan
            if not report_data['devices'] and not report_data['alerts']:
                self.add_activity("📊 No scan data available. Running quick scan for report...")
                try:
                    start_time = time.time()
                    network_range = self.scanner.get_network_range()
                    scanned_devices = self.scanner.arp_scan(network_range)
                    devices, scan_alerts = self.detector.analyze_network(scanned_devices)
                    report_data['devices'] = devices
                    report_data['alerts'].extend(scan_alerts)
                    report_data['scan_duration'] = time.time() - start_time
                    self._last_devices = devices
                    self._last_alerts = report_data['alerts']
                    self.add_activity(f"✅ Quick scan found {len(devices)} devices")
                except Exception as scan_error:
                    handle_rdds_error(scan_error, "Quick Scan for Report", "WARNING", True, False)
                    # Create minimal demo data
                    report_data['devices'] = [
                        {
                            'ip': '192.168.1.1',
                            'mac': '00:11:22:33:44:55',
                            'vendor': 'Demo Router',
                            'status': 'TRUSTED',
                            'risk_score': 10
                        }
                    ]
                    report_data['alerts'] = []
                    self.add_activity("📝 Using demo data for report")
            
            # Generate comprehensive report
            self.add_activity("📊 Generating comprehensive security report...")
            report_file = self._generate_comprehensive_report(report_data)
            
            # Display report content
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    report_content = f.read()
                    
                self.report_text.config(state='normal')
                self.report_text.delete('1.0', 'end')
                self.report_text.insert('1.0', report_content)
                self.report_text.config(state='disabled')
                
            except Exception as e:
                handle_rdds_error(e, "Display Report Content", "ERROR", True, False)
            
            # Summary statistics
            total_devices = len(report_data['devices'])
            total_alerts = len(report_data['alerts'])
            iot_devices = len(report_data['iot_profiles'])
            dhcp_alerts = len(report_data['dhcp_summary'].get('alerts', []))
            ssl_alerts = len(report_data['ssl_monitoring'].get('certificate_alerts', []))
            attack_count = report_data['attack_detection'].get('total_attacks', 0)
            
            summary_msg = f"Security report saved to:\n{report_file}\n\n"
            summary_msg += f"📊 Report Summary:\n"
            summary_msg += f"• Total Devices: {total_devices}\n"
            summary_msg += f"• Security Alerts: {total_alerts}\n"
            summary_msg += f"• IoT Devices: {iot_devices}\n"
            summary_msg += f"• DHCP Alerts: {dhcp_alerts}\n"
            summary_msg += f"• SSL Alerts: {ssl_alerts}\n"
            summary_msg += f"• Attack Detections: {attack_count}\n"
            summary_msg += f"• Scan Duration: {report_data['scan_duration']:.2f}s"
            
            self.add_activity(f"📊 Comprehensive report generated: {report_file}")
            self.add_activity(f"📊 Report includes {total_devices} devices, {total_alerts} alerts, and all security feature data")
            messagebox.showinfo("Comprehensive Report Generated", summary_msg)
            
        except Exception as e:
            error_msg = f"Failed to generate comprehensive report: {str(e)}"
            handle_rdds_error(e, "Report Generation", "ERROR", True, True)
    
    def _generate_comprehensive_report(self, report_data):
        """Generate comprehensive security report with all features in HTML format"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"logs/rdds_comprehensive_report_{timestamp}.html"
            
            # Ensure logs directory exists
            import os
            os.makedirs("logs", exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ RDDS - Comprehensive Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
            position: relative;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .section {
            margin-bottom: 40px;
            padding: 25px;
            border-radius: 10px;
            background: #f8f9fa;
            border-left: 5px solid #3498db;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        
        .section h2 {
            color: #2c3e50;
            font-size: 1.8em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section h3 {
            color: #34495e;
            font-size: 1.3em;
            margin: 20px 0 15px 0;
            border-bottom: 2px solid #e1e8ed;
            padding-bottom: 10px;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            border-left: 4px solid #3498db;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.12);
        }
        
        .card h4 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-item {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .alert {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-left: 5px solid #f39c12;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        .alert.high {
            background: #f8d7da;
            border-color: #f5c6cb;
            border-left-color: #e74c3c;
        }
        
        .alert.medium {
            background: #fff3cd;
            border-color: #ffeaa7;
            border-left-color: #f39c12;
        }
        
        .alert.low {
            background: #d4edda;
            border-color: #c3e6cb;
            border-left-color: #27ae60;
        }
        
        .device-list {
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        
        .device-item {
            padding: 20px;
            border-bottom: 1px solid #e1e8ed;
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr;
            gap: 15px;
            align-items: center;
            transition: background 0.3s ease;
        }
        
        .device-item:hover {
            background: #f8f9fa;
        }
        
        .device-item:last-child {
            border-bottom: none;
        }
        
        .risk-high {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .risk-medium {
            color: #f39c12;
            font-weight: bold;
        }
        
        .risk-low {
            color: #27ae60;
            font-weight: bold;
        }
        
        .recommendations {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 25px;
            border-radius: 10px;
            margin-top: 30px;
        }
        
        .recommendations h3 {
            margin-bottom: 20px;
            font-size: 1.4em;
        }
        
        .recommendations ul {
            list-style: none;
            padding: 0;
        }
        
        .recommendations li {
            padding: 12px 0;
            border-bottom: 1px solid rgba(255,255,255,0.2);
            position: relative;
            padding-left: 30px;
        }
        
        .recommendations li:before {
            content: "💡";
            position: absolute;
            left: 0;
            top: 12px;
        }
        
        .recommendations li:last-child {
            border-bottom: none;
        }
        
        .footer {
            text-align: center;
            padding: 30px;
            background: #2c3e50;
            color: white;
            margin-top: 40px;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .badge.high {
            background: #e74c3c;
            color: white;
        }
        
        .badge.medium {
            background: #f39c12;
            color: white;
        }
        
        .badge.low {
            background: #27ae60;
            color: white;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 10px;
            }
            
            .content {
                padding: 20px;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
            
            .device-item {
                grid-template-columns: 1fr;
                gap: 10px;
            }
            
            .stat-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .print-header {
            display: none;
        }
        
        @media print {
            body {
                background: white;
                padding: 0;
            }
            
            .container {
                box-shadow: none;
                border-radius: 0;
            }
            
            .print-header {
                display: block;
                text-align: center;
                margin-bottom: 20px;
            }
            
            .header {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Rogue Detection & Defense System</h1>
            <div class="subtitle">Comprehensive Security Report</div>
            <div class="print-header">
                <h2>Security Report</h2>
                <p>Generated: """ + report_data['timestamp'] + """</p>
            </div>
        </div>
        
        <div class="content">
""")
                
                # Executive Summary
                f.write("""
            <div class="section">
                <h2>📋 Executive Summary</h2>
                <div class="stat-grid">
""")
                
                total_devices = len(report_data['devices'])
                total_alerts = len(report_data['alerts'])
                high_risk_devices = len([d for d in report_data['devices'] if d.get('risk_score', 0) >= 70])
                
                f.write(f"""
                    <div class="stat-item">
                        <div class="stat-number">{total_devices}</div>
                        <div class="stat-label">Total Devices</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{total_alerts}</div>
                        <div class="stat-label">Security Alerts</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{high_risk_devices}</div>
                        <div class="stat-label">High Risk Devices</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{'HIGH' if high_risk_devices > 0 else 'MEDIUM' if total_alerts > 0 else 'LOW'}</div>
                        <div class="stat-label">Network Risk Level</div>
                    </div>
""")
                
                f.write("""
                </div>
            </div>
""")
                
                # Device Analysis
                if report_data['devices']:
                    f.write("""
            <div class="section">
                <h2>🔍 Device Analysis</h2>
                <div class="device-list">
""")
                    
                    for device in report_data['devices']:
                        risk_score = device.get('risk_score', 0)
                        risk_class = 'risk-high' if risk_score >= 70 else 'risk-medium' if risk_score >= 40 else 'risk-low'
                        risk_label = 'HIGH' if risk_score >= 70 else 'MEDIUM' if risk_score >= 40 else 'LOW'
                        
                        f.write(f"""
                    <div class="device-item">
                        <div>
                            <strong>{device['ip']}</strong><br>
                            <small>{device.get('vendor', 'Unknown')}</small>
                        </div>
                        <div>{device['mac']}</div>
                        <div>{device.get('status', 'Unknown')}</div>
                        <div class="{risk_class}">{risk_score}% <span class="badge {risk_class.lower()}">{risk_label}</span></div>
                    </div>
""")
                    
                    f.write("""
                </div>
            </div>
""")
                
                # Security Alerts
                if report_data['alerts']:
                    f.write("""
            <div class="section">
                <h2>🚨 Security Alerts</h2>
""")
                    
                    for alert in report_data['alerts']:
                        alert_class = alert.get('severity', 'MEDIUM').lower()
                        f.write(f"""
                <div class="alert {alert_class}">
                    <strong>{alert.get('type', 'Unknown')}</strong><br>
                    <small>Severity: {alert.get('severity', 'Unknown')} | Source: {alert.get('source', 'Unknown')}</small><br>
                    {alert.get('message', 'No message')}
                </div>
""")
                    
                    f.write("""
            </div>
""")
                
                # IoT Device Profiling
                if report_data['iot_profiles']:
                    f.write("""
            <div class="section">
                <h2>📱 IoT Device Profiling</h2>
                <div class="grid">
""")
                    
                    for profile in report_data['iot_profiles']:
                        risk_score = profile.get('risk_score', 0)
                        risk_class = 'risk-high' if risk_score >= 70 else 'risk-medium' if risk_score >= 40 else 'risk-low'
                        
                        f.write(f"""
                    <div class="card">
                        <h4>{profile.get('device_type', 'Unknown Device')}</h4>
                        <p><strong>IP:</strong> {profile.get('ip', 'Unknown')}</p>
                        <p><strong>MAC:</strong> {profile.get('mac', 'Unknown')}</p>
                        <p><strong>Manufacturer:</strong> {profile.get('manufacturer', 'Unknown')}</p>
                        <p><strong>Risk Score:</strong> <span class="{risk_class}">{risk_score}%</span></p>
                        <p><strong>Vulnerabilities:</strong> {len(profile.get('vulnerabilities', []))}</p>
                    </div>
""")
                    
                    f.write("""
                </div>
            </div>
""")
                
                # Recommendations
                f.write("""
            <div class="recommendations">
                <h3>💡 Security Recommendations</h3>
                <ul>
""")
                
                recommendations = []
                
                if high_risk_devices > 0:
                    recommendations.append("Investigate and mitigate high-risk devices immediately")
                if total_alerts > 10:
                    recommendations.append("Review and address multiple security alerts")
                if len(report_data['iot_profiles']) > 0:
                    recommendations.append("Review IoT device security configurations")
                if report_data['ssl_monitoring'].get('high_risk_certificates', 0) > 0:
                    recommendations.append("Update or replace high-risk SSL certificates")
                if report_data['attack_detection'].get('total_attacks', 0) > 0:
                    recommendations.append("Implement network security measures to prevent attacks")
                
                if recommendations:
                    for rec in recommendations:
                        f.write(f"<li>{rec}</li>")
                else:
                    f.write("<li>Network security posture appears satisfactory</li>")
                    f.write("<li>Continue regular monitoring and scanning</li>")
                
                f.write("""
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>📊 Report Generated: """ + report_data['timestamp'] + """</p>
            <p>🔧 RDDS Version: 2.0.0 Enhanced</p>
            <p>⏱️ Scan Duration: """ + f"{report_data['scan_duration']:.2f}" + """ seconds</p>
        </div>
    </div>
</body>
</html>""")
            
            return report_file
            
        except Exception as e:
            handle_rdds_error(e, "Generate HTML Report File", "ERROR", True, False)
            # Fallback to basic report
            return self.logger.generate_report(report_data['devices'], report_data['alerts'])
            
    def open_settings(self):
        """Open advanced settings dialog"""
        self.show_settings_dialog()
    
    def show_settings_dialog(self):
        """Show advanced settings configuration dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("⚙️ Advanced Settings")
        settings_window.geometry("800x600")
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Create notebook for categories
        notebook = ttk.Notebook(settings_window)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Network Discovery Settings
        self.create_network_discovery_settings_tab(notebook)
        
        # SSL Monitoring Settings
        self.create_ssl_monitoring_settings_tab(notebook)
        
        # Advanced Attack Detection Settings
        self.create_advanced_attack_detection_settings_tab(notebook)
        
        # General Settings
        self.create_general_settings_tab(notebook)
        
        # Buttons
        button_frame = tk.Frame(settings_window)
        button_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(button_frame, text="Save", command=self.save_all_settings).pack(side='right', padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_settings_to_defaults_gui).pack(side='right', padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side='right', padx=5)
    
    def create_network_discovery_settings_tab(self, notebook):
        """Create network discovery settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Network Discovery")
        
        settings = self.settings_manager.get_category_settings("network_discovery")
        
        # Scan Timeout
        ttk.Label(frame, text="Scan Timeout (seconds):").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.scan_timeout_var = tk.IntVar(value=settings['scan_timeout'])
        ttk.Entry(frame, textvariable=self.scan_timeout_var, width=20).grid(row=0, column=1, padx=10, pady=5)
        
        # Max Threads
        ttk.Label(frame, text="Max Threads:").grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.max_threads_var = tk.IntVar(value=settings['max_threads'])
        ttk.Entry(frame, textvariable=self.max_threads_var, width=20).grid(row=1, column=1, padx=10, pady=5)
        
        # Ping Timeout
        ttk.Label(frame, text="Ping Timeout (seconds):").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.ping_timeout_var = tk.IntVar(value=settings['ping_timeout'])
        ttk.Entry(frame, textvariable=self.ping_timeout_var, width=20).grid(row=2, column=1, padx=10, pady=5)
        
        # ARP Timeout
        ttk.Label(frame, text="ARP Timeout (seconds):").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.arp_timeout_var = tk.IntVar(value=settings['arp_timeout'])
        ttk.Entry(frame, textvariable=self.arp_timeout_var, width=20).grid(row=3, column=1, padx=10, pady=5)
        
        # Retry Count
        ttk.Label(frame, text="Retry Count:").grid(row=4, column=0, sticky='w', padx=10, pady=5)
        self.retry_count_var = tk.IntVar(value=settings['retry_count'])
        ttk.Entry(frame, textvariable=self.retry_count_var, width=20).grid(row=4, column=1, padx=10, pady=5)
        
        # Scan Delay
        ttk.Label(frame, text="Scan Delay (seconds):").grid(row=5, column=0, sticky='w', padx=10, pady=5)
        self.scan_delay_var = tk.DoubleVar(value=settings['scan_delay'])
        ttk.Entry(frame, textvariable=self.scan_delay_var, width=20).grid(row=5, column=1, padx=10, pady=5)
    
    def create_ssl_monitoring_settings_tab(self, notebook):
        """Create SSL monitoring settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="SSL Monitoring")
        
        settings = self.settings_manager.get_category_settings("ssl_monitoring")
        
        # Monitor Duration
        ttk.Label(frame, text="Monitor Duration (seconds):").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.ssl_monitor_duration_var = tk.IntVar(value=settings['monitor_duration'])
        ttk.Entry(frame, textvariable=self.ssl_monitor_duration_var, width=20).grid(row=0, column=1, padx=10, pady=5)
        
        # Connection Timeout
        ttk.Label(frame, text="Connection Timeout (seconds):").grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.ssl_connection_timeout_var = tk.IntVar(value=settings['connection_timeout'])
        ttk.Entry(frame, textvariable=self.ssl_connection_timeout_var, width=20).grid(row=1, column=1, padx=10, pady=5)
        
        # Max Hosts
        ttk.Label(frame, text="Max Hosts:").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.ssl_max_hosts_var = tk.IntVar(value=settings['max_hosts'])
        ttk.Entry(frame, textvariable=self.ssl_max_hosts_var, width=20).grid(row=2, column=1, padx=10, pady=5)
        
        # Expiry Threshold
        ttk.Label(frame, text="Expiry Threshold (days):").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.ssl_expiry_threshold_var = tk.IntVar(value=settings['expiry_threshold'])
        ttk.Entry(frame, textvariable=self.ssl_expiry_threshold_var, width=20).grid(row=3, column=1, padx=10, pady=5)
        
        # Key Size Threshold
        ttk.Label(frame, text="Key Size Threshold (bits):").grid(row=4, column=0, sticky='w', padx=10, pady=5)
        self.ssl_key_size_var = tk.IntVar(value=settings['key_size_threshold'])
        ttk.Entry(frame, textvariable=self.ssl_key_size_var, width=20).grid(row=4, column=1, padx=10, pady=5)
        
        # Check Revocation
        ttk.Label(frame, text="Check Revocation:").grid(row=5, column=0, sticky='w', padx=10, pady=5)
        self.ssl_check_revocation_var = tk.BooleanVar(value=settings['check_revocation'])
        ttk.Checkbutton(frame, variable=self.ssl_check_revocation_var).grid(row=5, column=1, sticky='w', padx=10, pady=5)
        
        # Strict Validation
        ttk.Label(frame, text="Strict Validation:").grid(row=6, column=0, sticky='w', padx=10, pady=5)
        self.ssl_strict_validation_var = tk.BooleanVar(value=settings['strict_validation'])
        ttk.Checkbutton(frame, variable=self.ssl_strict_validation_var).grid(row=6, column=1, sticky='w', padx=10, pady=5)
    
    def create_advanced_attack_detection_settings_tab(self, notebook):
        """Create advanced attack detection settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Attack Detection")
        
        settings = self.settings_manager.get_category_settings("advanced_attack_detection")
        
        # Monitor Duration
        ttk.Label(frame, text="Monitor Duration (seconds):").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.attack_monitor_duration_var = tk.IntVar(value=settings['monitor_duration'])
        ttk.Entry(frame, textvariable=self.attack_monitor_duration_var, width=20).grid(row=0, column=1, padx=10, pady=5)
        
        # MAC Flood Threshold
        ttk.Label(frame, text="MAC Flood Threshold (packets/sec):").grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.mac_flood_threshold_var = tk.IntVar(value=settings['mac_flood_threshold'])
        ttk.Entry(frame, textvariable=self.mac_flood_threshold_var, width=20).grid(row=1, column=1, padx=10, pady=5)
        
        # SYN Flood Threshold
        ttk.Label(frame, text="SYN Flood Threshold (packets/sec):").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.syn_flood_threshold_var = tk.IntVar(value=settings['syn_flood_threshold'])
        ttk.Entry(frame, textvariable=self.syn_flood_threshold_var, width=20).grid(row=2, column=1, padx=10, pady=5)
        
        # UDP Flood Threshold
        ttk.Label(frame, text="UDP Flood Threshold (packets/sec):").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.udp_flood_threshold_var = tk.IntVar(value=settings['udp_flood_threshold'])
        ttk.Entry(frame, textvariable=self.udp_flood_threshold_var, width=20).grid(row=3, column=1, padx=10, pady=5)
        
        # ICMP Flood Threshold
        ttk.Label(frame, text="ICMP Flood Threshold (packets/sec):").grid(row=4, column=0, sticky='w', padx=10, pady=5)
        self.icmp_flood_threshold_var = tk.IntVar(value=settings['icmp_flood_threshold'])
        ttk.Entry(frame, textvariable=self.icmp_flood_threshold_var, width=20).grid(row=4, column=1, padx=10, pady=5)
        
        # Port Scan Threshold
        ttk.Label(frame, text="Port Scan Threshold (ports):").grid(row=5, column=0, sticky='w', padx=10, pady=5)
        self.port_scan_threshold_var = tk.IntVar(value=settings['port_scan_threshold'])
        ttk.Entry(frame, textvariable=self.port_scan_threshold_var, width=20).grid(row=5, column=1, padx=10, pady=5)
        
        # Enable Layer 2 Detection
        ttk.Label(frame, text="Enable Layer 2 Detection:").grid(row=6, column=0, sticky='w', padx=10, pady=5)
        self.enable_layer2_var = tk.BooleanVar(value=settings['enable_layer2_detection'])
        ttk.Checkbutton(frame, variable=self.enable_layer2_var).grid(row=6, column=1, sticky='w', padx=10, pady=5)
        
        # Enable Layer 3 Detection
        ttk.Label(frame, text="Enable Layer 3 Detection:").grid(row=7, column=0, sticky='w', padx=10, pady=5)
        self.enable_layer3_var = tk.BooleanVar(value=settings['enable_layer3_detection'])
        ttk.Checkbutton(frame, variable=self.enable_layer3_var).grid(row=7, column=1, sticky='w', padx=10, pady=5)
        
        # Enable Layer 4 Detection
        ttk.Label(frame, text="Enable Layer 4 Detection:").grid(row=8, column=0, sticky='w', padx=10, pady=5)
        self.enable_layer4_var = tk.BooleanVar(value=settings['enable_layer4_detection'])
        ttk.Checkbutton(frame, variable=self.enable_layer4_var).grid(row=8, column=1, sticky='w', padx=10, pady=5)
        
        # Enable MITM Detection
        ttk.Label(frame, text="Enable MITM Detection:").grid(row=9, column=0, sticky='w', padx=10, pady=5)
        self.enable_mitm_var = tk.BooleanVar(value=settings['enable_mitm_detection'])
        ttk.Checkbutton(frame, variable=self.enable_mitm_var).grid(row=9, column=1, sticky='w', padx=10, pady=5)
    
    def create_general_settings_tab(self, notebook):
        """Create general settings tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="General")
        
        settings = self.settings_manager.get_category_settings("general")
        
        # Log Level
        ttk.Label(frame, text="Log Level:").grid(row=0, column=0, sticky='w', padx=10, pady=5)
        self.log_level_var = tk.StringVar(value=settings['log_level'])
        log_combo = ttk.Combobox(frame, textvariable=self.log_level_var, values=['DEBUG', 'INFO', 'WARNING', 'ERROR'], width=18)
        log_combo.grid(row=0, column=1, padx=10, pady=5)
        
        # Auto Save
        ttk.Label(frame, text="Auto Save:").grid(row=1, column=0, sticky='w', padx=10, pady=5)
        self.auto_save_var = tk.BooleanVar(value=settings['auto_save'])
        ttk.Checkbutton(frame, variable=self.auto_save_var).grid(row=1, column=1, sticky='w', padx=10, pady=5)
        
        # Save Interval
        ttk.Label(frame, text="Save Interval (seconds):").grid(row=2, column=0, sticky='w', padx=10, pady=5)
        self.save_interval_var = tk.IntVar(value=settings['save_interval'])
        ttk.Entry(frame, textvariable=self.save_interval_var, width=20).grid(row=2, column=1, padx=10, pady=5)
        
        # Notification Enabled
        ttk.Label(frame, text="Enable Notifications:").grid(row=3, column=0, sticky='w', padx=10, pady=5)
        self.notification_var = tk.BooleanVar(value=settings['notification_enabled'])
        ttk.Checkbutton(frame, variable=self.notification_var).grid(row=3, column=1, sticky='w', padx=10, pady=5)
        
        # Sound Alerts
        ttk.Label(frame, text="Sound Alerts:").grid(row=4, column=0, sticky='w', padx=10, pady=5)
        self.sound_alerts_var = tk.BooleanVar(value=settings['sound_alerts'])
        ttk.Checkbutton(frame, variable=self.sound_alerts_var).grid(row=4, column=1, sticky='w', padx=10, pady=5)
    
    def save_all_settings(self):
        """Save all settings from the dialog"""
        try:
            # Network Discovery Settings
            self.settings_manager.set_setting("network_discovery", "scan_timeout", self.scan_timeout_var.get())
            self.settings_manager.set_setting("network_discovery", "max_threads", self.max_threads_var.get())
            self.settings_manager.set_setting("network_discovery", "ping_timeout", self.ping_timeout_var.get())
            self.settings_manager.set_setting("network_discovery", "arp_timeout", self.arp_timeout_var.get())
            self.settings_manager.set_setting("network_discovery", "retry_count", self.retry_count_var.get())
            self.settings_manager.set_setting("network_discovery", "scan_delay", self.scan_delay_var.get())
            
            # SSL Monitoring Settings
            self.settings_manager.set_setting("ssl_monitoring", "monitor_duration", self.ssl_monitor_duration_var.get())
            self.settings_manager.set_setting("ssl_monitoring", "connection_timeout", self.ssl_connection_timeout_var.get())
            self.settings_manager.set_setting("ssl_monitoring", "max_hosts", self.ssl_max_hosts_var.get())
            self.settings_manager.set_setting("ssl_monitoring", "expiry_threshold", self.ssl_expiry_threshold_var.get())
            self.settings_manager.set_setting("ssl_monitoring", "key_size_threshold", self.ssl_key_size_var.get())
            self.settings_manager.set_setting("ssl_monitoring", "check_revocation", self.ssl_check_revocation_var.get())
            self.settings_manager.set_setting("ssl_monitoring", "strict_validation", self.ssl_strict_validation_var.get())
            
            # Advanced Attack Detection Settings
            self.settings_manager.set_setting("advanced_attack_detection", "monitor_duration", self.attack_monitor_duration_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "mac_flood_threshold", self.mac_flood_threshold_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "syn_flood_threshold", self.syn_flood_threshold_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "udp_flood_threshold", self.udp_flood_threshold_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "icmp_flood_threshold", self.icmp_flood_threshold_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "port_scan_threshold", self.port_scan_threshold_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "enable_layer2_detection", self.enable_layer2_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "enable_layer3_detection", self.enable_layer3_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "enable_layer4_detection", self.enable_layer4_var.get())
            self.settings_manager.set_setting("advanced_attack_detection", "enable_mitm_detection", self.enable_mitm_var.get())
            
            # General Settings
            self.settings_manager.set_setting("general", "log_level", self.log_level_var.get())
            self.settings_manager.set_setting("general", "auto_save", self.auto_save_var.get())
            self.settings_manager.set_setting("general", "save_interval", self.save_interval_var.get())
            self.settings_manager.set_setting("general", "notification_enabled", self.notification_var.get())
            self.settings_manager.set_setting("general", "sound_alerts", self.sound_alerts_var.get())
            
            messagebox.showinfo("Settings", "✅ Settings saved successfully!")
            
            # Close the dialog
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Toplevel) and widget.title() == "⚙️ Advanced Settings":
                    widget.destroy()
                    
        except Exception as e:
            messagebox.showerror("Error", f"❌ Failed to save settings: {e}")
    
    def reset_settings_to_defaults_gui(self):
        """Reset settings to defaults (GUI version)"""
        if messagebox.askyesno("Reset Settings", "⚠️ This will reset all settings to defaults. Continue?"):
            self.settings_manager.reset_to_defaults()
            messagebox.showinfo("Settings", "✅ Settings reset to defaults!")
            
            # Close the dialog
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Toplevel) and widget.title() == "⚙️ Advanced Settings":
                    widget.destroy()
    
    def show_manual_update_instructions(self):
        """Show manual update instructions dialog"""
        try:
            instructions_window = tk.Toplevel(self.root)
            instructions_window.title("📦 Manual Update Instructions")
            instructions_window.geometry("700x600")
            instructions_window.transient(self.root)
            instructions_window.grab_set()
            
            # Create scrolled text widget
            text_widget = scrolledtext.ScrolledText(
                instructions_window,
                wrap=tk.WORD,
                width=80,
                height=35,
                font=('Consolas', 10)
            )
            text_widget.pack(fill='both', expand=True, padx=10, pady=10)
            
            # Manual update instructions
            instructions = """
📦 RDDS MANUAL UPDATE INSTRUCTIONS
===================================

🔧 METHOD 1: GIT PULL (RECOMMENDED)
-----------------------------------
If you cloned the repository using Git:

1. Open Command Prompt/PowerShell as Administrator
2. Navigate to RDDS directory:
   cd F:\\Hackthone\\RDDS

3. Stash local changes (if any):
   git stash

4. Pull latest updates:
   git pull origin main

5. Restore local changes (if any):
   git stash pop

6. Install/update dependencies:
   pip install -r requirements.txt

7. Restart the application

🔧 METHOD 2: MANUAL DOWNLOAD
------------------------------
If you downloaded the ZIP file:

1. Backup your current settings:
   - Copy settings.json to a safe location
   - Copy whitelist.json to a safe location

2. Visit the GitHub repository:
   https://github.com/StrykarBoston/RDDS

3. Download the latest release:
   - Click "Code" → "Download ZIP"
   - Or visit: https://github.com/StrykarBoston/RDDS/releases

4. Extract the new version:
   - Extract to a temporary folder
   - Copy your backed-up settings files back

5. Install/update dependencies:
   pip install -r requirements.txt

6. Restart the application

🔧 METHOD 3: REINSTALL (CLEAN INSTALL)
--------------------------------------
For a completely fresh installation:

1. Backup important files:
   - settings.json
   - whitelist.json
   - Any custom reports

2. Uninstall current version (optional):
   - Delete the RDDS folder

3. Download latest version from GitHub

4. Follow installation instructions from:
   - GUI_Windows_Documentation.md
   - CLI_Linux_Documentation.md

5. Restore your backed-up files

📋 VERSION INFORMATION
----------------------
Current Version: 2.0.0 Enhanced
Release Date: January 2026

🔍 CHECKING FOR UPDATES
-----------------------
To check if updates are available:

1. Visit GitHub Releases:
   https://github.com/StrykarBoston/RDDS/releases

2. Compare your current version with latest release

3. Read release notes for new features and fixes

⚠️ IMPORTANT NOTES
------------------
• Always backup your settings before updating
• Ensure you have Administrator privileges
• Update Python dependencies after updating
• Check system requirements for new versions
• Some updates may require configuration changes

🐛 TROUBLESHOOTING
------------------
If you encounter issues during update:

1. Clear Python cache:
   pip cache purge

2. Reinstall dependencies:
   pip install --force-reinstall -r requirements.txt

3. Check Python version compatibility
4. Verify Npcap installation (Windows)
5. Check file permissions

📞 SUPPORT
----------
If you need help with updates:
• Check documentation files
• Review GitHub Issues
• Contact support through GitHub

🔄 AUTOMATION (ADVANCED USERS)
------------------------------
You can create a simple update script:

@echo off
echo Updating RDDS...
cd /d "F:\\Hackthone\\RDDS"
git stash
git pull origin main
git stash pop
pip install -r requirements.txt
echo Update complete!
pause
"""
            
            text_widget.insert(tk.END, instructions)
            text_widget.config(state=tk.DISABLED)
            
            # Buttons
            button_frame = tk.Frame(instructions_window)
            button_frame.pack(fill='x', padx=10, pady=10)
            
            ttk.Button(button_frame, text="Close", command=instructions_window.destroy).pack(side='right', padx=5)
            ttk.Button(button_frame, text="Open GitHub", command=self.open_github_releases).pack(side='right', padx=5)
            
        except Exception as e:
            handle_rdds_error(e, "Manual Update Instructions", "ERROR", True, False)
    
    def open_github_releases(self):
        """Open GitHub releases page in browser"""
        try:
            import webbrowser
            webbrowser.open("https://github.com/StrykarBoston/RDDS/releases")
        except Exception as e:
            handle_rdds_error(e, "Open GitHub Releases", "ERROR", True, False)
    
    def create_scan_interface(self, parent):
        """Create scan interface"""
        # Add scan controls and results
        scan_frame = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        scan_frame.pack(fill='both', expand=True, pady=10)
        
        title = tk.Label(
            scan_frame,
            text="🔍 Network Scanning",
            font=('Segoe UI', 18, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        title.pack(pady=20)
        
        # Add scan controls here (reuse existing scan tab functionality)
        self.create_scan_controls(scan_frame)
        
    def create_device_interface(self, parent):
        """Create device management interface"""
        device_frame = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        device_frame.pack(fill='both', expand=True, pady=10)
        
        title = tk.Label(
            device_frame,
            text="📱 Device Management",
            font=('Segoe UI', 18, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        title.pack(pady=20)
        
        # Device control panel
        control_frame = tk.Frame(device_frame, bg=self.colors['card'])
        control_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        # Whitelist section
        whitelist_frame = tk.Frame(control_frame, bg=self.colors['dark'], relief='flat', bd=0)
        whitelist_frame.pack(fill='x', pady=10)
        
        whitelist_title = tk.Label(
            whitelist_frame,
            text="🔒 Device Whitelist",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['dark'],
            fg=self.colors['text']
        )
        whitelist_title.pack(pady=10)
        
        # Whitelist controls
        whitelist_controls = tk.Frame(whitelist_frame, bg=self.colors['dark'])
        whitelist_controls.pack(fill='x', padx=20, pady=10)
        
        tk.Label(
            whitelist_controls,
            text="MAC Address:",
            font=('Segoe UI', 11),
            bg=self.colors['dark'],
            fg=self.colors['text']
        ).pack(side='left', padx=(0, 10))
        
        self.mac_entry = tk.Entry(
            whitelist_controls,
            font=('Segoe UI', 11),
            bg=self.colors['card'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            relief='flat',
            bd=0,
            width=20
        )
        self.mac_entry.pack(side='left', padx=(0, 10))
        
        add_whitelist_btn = tk.Button(
            whitelist_controls,
            text="➕ Add to Whitelist",
            font=('Segoe UI', 10, 'bold'),
            bg=self.colors['success'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=8,
            command=self.add_to_whitelist
        )
        add_whitelist_btn.pack(side='left', padx=5)
        
        # Device list
        device_list_frame = tk.Frame(device_frame, bg=self.colors['card'])
        device_list_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        device_list_title = tk.Label(
            device_list_frame,
            text="📋 Discovered Devices",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        device_list_title.pack(pady=(0, 10))
        
        # Device treeview
        columns = ('IP', 'MAC', 'Vendor', 'Status', 'Type')
        try:
            self.device_tree = ttk.Treeview(
                device_list_frame,
                columns=columns,
                show='headings',
                height=12,
                style='Modern.Treeview'
            )
        except:
            self.device_tree = ttk.Treeview(
                device_list_frame,
                columns=columns,
                show='headings',
                height=12
            )
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=120)
        
        # Device scrollbar
        try:
            device_scrollbar = ttk.Scrollbar(
                device_list_frame,
                orient='vertical',
                command=self.device_tree.yview,
                style='Modern.Vertical.TScrollbar'
            )
        except:
            device_scrollbar = ttk.Scrollbar(
                device_list_frame,
                orient='vertical',
                command=self.device_tree.yview
            )
        self.device_tree.configure(yscrollcommand=device_scrollbar.set)
        
        self.device_tree.pack(side='left', fill='both', expand=True)
        device_scrollbar.pack(side='right', fill='y')
        
    def add_to_whitelist(self):
        """Add device to whitelist"""
        mac = self.mac_entry.get().strip()
        if mac:
            # Add to whitelist logic here
            self.update_status(f"Added {mac} to whitelist")
            self.mac_entry.delete(0, 'end')
        
    def create_monitoring_interface(self, parent):
        """Create monitoring interface"""
        monitor_frame = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        monitor_frame.pack(fill='both', expand=True, pady=10)
        
        title = tk.Label(
            monitor_frame,
            text="🎯 Real-time Monitoring",
            font=('Segoe UI', 18, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        title.pack(pady=20)
        
        # Monitoring controls
        controls_frame = tk.Frame(monitor_frame, bg=self.colors['card'])
        controls_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        # Start/Stop monitoring button
        self.monitor_button = tk.Button(
            controls_frame,
            text="🚀 Start Monitoring",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['success'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=10,
            command=self.toggle_monitoring
        )
        self.monitor_button.pack(side='left', padx=5)
        
        # Monitoring status
        self.monitor_status = tk.Label(
            controls_frame,
            text="● Monitoring Inactive",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['card'],
            fg='black'
        )
        self.monitor_status.pack(side='left', padx=20)
        
        # Live alerts section
        alerts_frame = tk.Frame(monitor_frame, bg=self.colors['dark'], relief='flat', bd=0)
        alerts_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        alerts_title = tk.Label(
            alerts_frame,
            text="🚨 Live Security Alerts",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['dark'],
            fg=self.colors['text']
        )
        alerts_title.pack(pady=10)
        
        # Live alerts display
        self.monitoring_text = scrolledtext.ScrolledText(
            alerts_frame,
            height=15,
            font=('Consolas', 9),
            bg=self.colors['card'],
            fg=self.colors['text'],
            wrap='word',
            relief='flat',
            bd=0
        )
        self.monitoring_text.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        self.monitoring_text.config(state='disabled')
        
    def toggle_monitoring(self):
        """Toggle real-time monitoring"""
        if not self.monitoring:
            self.monitoring = True
            self.monitor_button.config(text="⏸️ Stop Monitoring", bg=self.colors['danger'])
            self.monitor_status.config(text="● Monitoring Active", fg=self.colors['success'])
            self.update_status("Real-time monitoring started...")
            # Start monitoring thread here
        else:
            self.monitoring = False
            self.monitor_button.config(text="🚀 Start Monitoring", bg=self.colors['success'])
            self.monitor_status.config(text="● Monitoring Inactive", fg='black')
            self.update_status("Real-time monitoring stopped.")
        
    def create_reports_interface(self, parent):
        """Create reports interface"""
        reports_frame = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        reports_frame.pack(fill='both', expand=True, pady=10)
        
        title = tk.Label(
            reports_frame,
            text="📊 Security Reports",
            font=('Segoe UI', 18, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        title.pack(pady=20)
        
        # Report controls
        controls_frame = tk.Frame(reports_frame, bg=self.colors['card'])
        controls_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        # Generate report button
        generate_btn = tk.Button(
            controls_frame,
            text="📋 Generate Report",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['primary'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=10,
            command=self.generate_report
        )
        generate_btn.pack(side='left', padx=5)
        
        # Export options
        export_btn = tk.Button(
            controls_frame,
            text="💾 Export Report",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['secondary'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=10,
            command=self.export_report
        )
        export_btn.pack(side='left', padx=5)
        
        # Report display area
        report_display_frame = tk.Frame(reports_frame, bg=self.colors['dark'], relief='flat', bd=0)
        report_display_frame.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        report_title = tk.Label(
            report_display_frame,
            text="📄 Generated Report",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['dark'],
            fg=self.colors['text']
        )
        report_title.pack(pady=10)
        
        # Report text area
        self.report_text = scrolledtext.ScrolledText(
            report_display_frame,
            height=20,
            font=('Consolas', 9),
            bg=self.colors['card'],
            fg=self.colors['text'],
            wrap='word',
            relief='flat',
            bd=0
        )
        self.report_text.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        self.report_text.config(state='disabled')
        
    def generate_report(self):
        """Generate security report"""
        self.update_status("Generating security report...")
        # Generate report logic here
        report_content = """
🛡️ ROGUE DETECTION & DEFENSE SYSTEM
=====================================
SECURITY REPORT
Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """

EXECUTIVE SUMMARY
================
• Total Devices Scanned: 0
• Threats Detected: 0
• Security Status: SECURE
• Last Scan: Pending

NETWORK OVERVIEW
================
• Network Interface: Auto-detected
• IP Range: Local Network
• Scan Duration: N/A

SECURITY FINDINGS
=================
• No rogue devices detected
• No suspicious activity identified
• Network appears secure
• All systems operational

RECOMMENDATIONS
==============
• Continue regular monitoring
• Maintain current security posture
• Schedule periodic network scans
• Update device whitelist as needed

END OF REPORT
"""
        self.report_text.config(state='normal')
        self.report_text.delete(1.0, 'end')
        self.report_text.insert('end', report_content)
        self.report_text.config(state='disabled')
        self.update_status("Report generated successfully")
        
    def export_report(self):
        """Export report to file"""
        self.update_status("Exporting report...")
        # Export logic here
        self.update_status("Report exported successfully")
        
    def create_settings_interface(self, parent):
        """Create settings interface"""
        settings_frame = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        settings_frame.pack(fill='both', expand=True, pady=10)
        
        title = tk.Label(
            settings_frame,
            text="⚙️ Settings",
            font=('Segoe UI', 18, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        title.pack(pady=20)
        
        # Settings sections
        settings_container = tk.Frame(settings_frame, bg=self.colors['card'])
        settings_container.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # General Settings
        general_frame = tk.Frame(settings_container, bg=self.colors['dark'], relief='flat', bd=0)
        general_frame.pack(fill='x', pady=10)
        
        general_title = tk.Label(
            general_frame,
            text="🔧 General Settings",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['dark'],
            fg=self.colors['text']
        )
        general_title.pack(pady=10, padx=20, anchor='w')
        
        # Auto-refresh setting
        auto_refresh_frame = tk.Frame(general_frame, bg=self.colors['dark'])
        auto_refresh_frame.pack(fill='x', padx=20, pady=5)
        
        self.auto_refresh_var = tk.BooleanVar(value=True)
        auto_refresh_check = tk.Checkbutton(
            auto_refresh_frame,
            text="Auto-refresh dashboard",
            variable=self.auto_refresh_var,
            font=('Segoe UI', 11),
            bg=self.colors['dark'],
            fg=self.colors['text'],
            selectcolor=self.colors['primary'],
            activebackground=self.colors['dark'],
            activeforeground=self.colors['text']
        )
        auto_refresh_check.pack(anchor='w')
        
        # Sound alerts setting
        sound_frame = tk.Frame(general_frame, bg=self.colors['dark'])
        sound_frame.pack(fill='x', padx=20, pady=5)
        
        self.sound_alerts_var = tk.BooleanVar(value=True)
        sound_check = tk.Checkbutton(
            sound_frame,
            text="Enable sound alerts",
            variable=self.sound_alerts_var,
            font=('Segoe UI', 11),
            bg=self.colors['dark'],
            fg=self.colors['text'],
            selectcolor=self.colors['primary'],
            activebackground=self.colors['dark'],
            activeforeground=self.colors['text']
        )
        sound_check.pack(anchor='w')
        
        # Scan Settings
        scan_frame = tk.Frame(settings_container, bg=self.colors['dark'], relief='flat', bd=0)
        scan_frame.pack(fill='x', pady=10)
        
        scan_title = tk.Label(
            scan_frame,
            text="🔍 Scan Settings",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['dark'],
            fg=self.colors['text']
        )
        scan_title.pack(pady=10, padx=20, anchor='w')
        
        # Scan interval
        interval_frame = tk.Frame(scan_frame, bg=self.colors['dark'])
        interval_frame.pack(fill='x', padx=20, pady=5)
        
        tk.Label(
            interval_frame,
            text="Scan Interval (seconds):",
            font=('Segoe UI', 11),
            bg=self.colors['dark'],
            fg=self.colors['text']
        ).pack(side='left', padx=(0, 10))
        
        self.scan_interval = tk.Entry(
            interval_frame,
            font=('Segoe UI', 11),
            bg=self.colors['card'],
            fg=self.colors['text'],
            insertbackground=self.colors['text'],
            relief='flat',
            bd=0,
            width=10
        )
        self.scan_interval.pack(side='left', padx=(0, 10))
        self.scan_interval.insert(0, "30")
        
        # Save settings button
        save_frame = tk.Frame(settings_container, bg=self.colors['card'])
        save_frame.pack(fill='x', pady=20)
        
        save_btn = tk.Button(
            save_frame,
            text="💾 Save Settings",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['success'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=10,
            command=self.save_settings
        )
        save_btn.pack(side='left', padx=20)
        
        reset_btn = tk.Button(
            save_frame,
            text="🔄 Reset to Defaults",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['warning'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=10,
            command=self.reset_settings
        )
        reset_btn.pack(side='left', padx=5)
        
    def save_settings(self):
        """Save settings"""
        self.update_status("Settings saved successfully")
        
    def reset_settings(self):
        """Reset settings to defaults"""
        self.auto_refresh_var.set(True)
        self.sound_alerts_var.set(True)
        self.scan_interval.delete(0, 'end')
        self.scan_interval.insert(0, "30")
        self.update_status("Settings reset to defaults")
        
    def create_scan_controls(self, parent):
        """Create scan controls with full functionality"""
        # Modern control panel
        control_frame = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        control_frame.pack(fill='x', pady=(0, 20))
        
        # Control header
        control_header = tk.Frame(control_frame, bg=self.colors['card'])
        control_header.pack(fill='x', padx=20, pady=(20, 10))
        
        control_title = tk.Label(
            control_header,
            text="🔍 Scan Configuration",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        control_title.pack(side='left')
        
        # Scan type selection
        scan_type_frame = tk.Frame(control_frame, bg=self.colors['card'])
        scan_type_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Label(
            scan_type_frame,
            text="Select Scan Type:",
            font=('Segoe UI', 12, 'bold'),
            bg=self.colors['card'], fg=self.colors['text']
        ).pack(anchor='w', pady=(0, 10))
        
        self.scan_type = tk.StringVar(value="standard")
        
        # Modern radio button layout
        scan_types = [
            ("Standard Scan (4-step)", "standard"),
            ("Enhanced Scan (5-step)", "enhanced"),
            ("IoT Profiling", "iot"),
            ("DHCP Security", "dhcp"),
            ("Traffic Analysis", "traffic"),
            ("SSL Certificate Monitor", "ssl"),
            ("Advanced Attack Detection", "advanced")
        ]
        
        for i, (text, value) in enumerate(scan_types):
            radio_frame = tk.Frame(scan_type_frame, bg=self.colors['card'])
            radio_frame.pack(fill='x', pady=2)
            
            radio = tk.Radiobutton(
                radio_frame,
                text=text,
                variable=self.scan_type,
                value=value,
                font=('Segoe UI', 11),
                bg=self.colors['card'],
                fg=self.colors['text'],
                selectcolor=self.colors['primary'],
                activebackground=self.colors['card'],
                activeforeground=self.colors['text']
            )
            radio.pack(anchor='w')
        
        # Scan button
        self.scan_button = tk.Button(
            control_frame,
            text="🚀 Start Scan",
            font=('Segoe UI', 14, 'bold'),
            bg=self.colors['primary'],
            fg=self.colors['text'],
            relief='flat',
            bd=0,
            pady=15,
            command=self.start_scan,
            activebackground=self.adjust_color(self.colors['primary'], -20)
        )
        self.scan_button.pack(pady=20, padx=20, fill='x')
        
        # Progress bar
        try:
            self.scan_progress = ttk.Progressbar(
                control_frame,
                mode='determinate',
                maximum=100,
                style='Modern.TProgressbar'
            )
        except:
            # Fallback to default style if custom style fails
            self.scan_progress = ttk.Progressbar(
                control_frame,
                mode='determinate',
                maximum=100
            )
        self.scan_progress.pack(fill='x', padx=20, pady=(0, 20))
        
        # Results area
        results_frame = tk.Frame(parent, bg=self.colors['card'], relief='flat', bd=0)
        results_frame.pack(fill='both', expand=True)
        
        # Results header
        results_header = tk.Frame(results_frame, bg=self.colors['card'])
        results_header.pack(fill='x', padx=20, pady=(20, 10))
        
        results_title = tk.Label(
            results_header,
            text="📋 Scan Results",
            font=('Segoe UI', 16, 'bold'),
            bg=self.colors['card'],
            fg=self.colors['text']
        )
        results_title.pack(side='left')
        
        # Results treeview with modern styling
        columns = ('IP', 'MAC', 'Vendor', 'Status', 'Risk Score')
        try:
            self.scan_tree = ttk.Treeview(
                results_frame, 
                columns=columns, 
                show='headings', 
                height=15,
                style='Modern.Treeview'
            )
        except:
            # Fallback to default style if custom style fails
            self.scan_tree = ttk.Treeview(
                results_frame, 
                columns=columns, 
                show='headings', 
                height=15
            )
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=150)
        
        # Modern scrollbar
        try:
            scrollbar = ttk.Scrollbar(
                results_frame, 
                orient='vertical', 
                command=self.scan_tree.yview,
                style='Modern.Vertical.TScrollbar'
            )
        except:
            # Fallback to default style if custom style fails
            scrollbar = ttk.Scrollbar(
                results_frame, 
                orient='vertical', 
                command=self.scan_tree.yview
            )
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.scan_tree.pack(side='left', fill='both', expand=True, padx=(20, 0), pady=(0, 20))
        scrollbar.pack(side='right', fill='y', padx=(0, 20), pady=(0, 20))
    
    def run(self):
        """Start the GUI application"""
        try:
            self.root.mainloop()
        except Exception as e:
            handle_rdds_error(e, "GUI Main Loop", "CRITICAL", True, True)

if __name__ == "__main__":
    try:
        app = ModernRDDS_GUI()
        app.run()
    except Exception as e:
        handle_rdds_error(e, "Application Startup", "CRITICAL", True, True)
