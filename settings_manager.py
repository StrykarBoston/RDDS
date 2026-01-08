# -*- coding: utf-8 -*-
# settings_manager.py - Advanced Settings Management for RDDS

import json
import os
from datetime import datetime

class SettingsManager:
    def __init__(self, settings_file='rdds_settings.json'):
        self.settings_file = settings_file
        self.default_settings = self._get_default_settings()
        self.settings = self.load_settings()
    
    def _get_default_settings(self):
        """Get default settings for all security features"""
        return {
            "network_discovery": {
                "scan_timeout": 10,
                "max_threads": 50,
                "ping_timeout": 2,
                "arp_timeout": 3,
                "retry_count": 3,
                "scan_delay": 0.1
            },
            "rogue_detection": {
                "arp_spoof_threshold": 5,
                "mac_spoof_threshold": 3,
                "detection_interval": 30,
                "alert_cooldown": 300,
                "auto_whitelist": False,
                "strict_mode": False
            },
            "rogue_ap_detection": {
                "scan_duration": 60,
                "channel_hop": True,
                "channel_hop_interval": 0.5,
                "signal_threshold": -80,
                "max_aps": 100,
                "evil_twin_detection": True,
                "rf_fingerprinting": False
            },
            "iot_profiling": {
                "scan_timeout": 15,
                "port_scan_timeout": 3,
                "max_ports": 1000,
                "fingerprint_timeout": 10,
                "device_database": "default",
                "auto_categorize": True,
                "deep_inspection": False
            },
            "dhcp_security": {
                "monitor_duration": 300,
                "dhcp_timeout": 5,
                "max_servers": 10,
                "detect_starvation": True,
                "detect_spoofing": True,
                "alert_threshold": 5,
                "auto_block": False
            },
            "traffic_analysis": {
                "monitor_duration": 300,
                "capture_filter": "",
                "max_flows": 10000,
                "flow_timeout": 60,
                "bandwidth_threshold": 1000000,  # 1MB/s
                "ddos_threshold": 1000,
                "exfiltration_threshold": 10000000,  # 10MB
                "protocol_analysis": True,
                "application_identification": True
            },
            "ssl_monitoring": {
                "monitor_duration": 300,
                "connection_timeout": 10,
                "max_hosts": 100,
                "expiry_threshold": 30,
                "key_size_threshold": 2048,
                "check_revocation": True,
                "check_transparency": False,
                "strict_validation": False
            },
            "advanced_attack_detection": {
                "monitor_duration": 300,
                "packet_buffer_size": 1000,
                "mac_flood_threshold": 100,
                "syn_flood_threshold": 1000,
                "udp_flood_threshold": 1000,
                "icmp_flood_threshold": 500,
                "port_scan_threshold": 50,
                "fragmentation_threshold": 100,
                "enable_layer2_detection": True,
                "enable_layer3_detection": True,
                "enable_layer4_detection": True,
                "enable_mitm_detection": True
            },
            "general": {
                "log_level": "INFO",
                "log_file": "rdds.log",
                "max_log_size": 10485760,  # 10MB
                "backup_count": 5,
                "auto_save": True,
                "save_interval": 300,
                "notification_enabled": True,
                "email_notifications": False,
                "sound_alerts": True
            },
            "gui": {
                "theme": "dark",
                "window_size": [1200, 800],
                "auto_refresh": True,
                "refresh_interval": 5,
                "max_display_items": 1000,
                "show_tooltips": True,
                "confirm_actions": True,
                "minimize_to_tray": False
            }
        }
    
    def load_settings(self):
        """Load settings from file"""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    loaded_settings = json.load(f)
                
                # Merge with default settings to ensure all keys exist
                settings = self.default_settings.copy()
                self._deep_update(settings, loaded_settings)
                return settings
            else:
                return self.default_settings.copy()
        except Exception as e:
            print(f"Error loading settings: {e}")
            return self.default_settings.copy()
    
    def _deep_update(self, base_dict, update_dict):
        """Deep update dictionary"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def save_settings(self):
        """Save settings to file"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4, default=str)
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False
    
    def get_setting(self, category, key, default=None):
        """Get specific setting value"""
        try:
            return self.settings.get(category, {}).get(key, default)
        except Exception:
            return default
    
    def set_setting(self, category, key, value):
        """Set specific setting value"""
        if category not in self.settings:
            self.settings[category] = {}
        self.settings[category][key] = value
        return self.save_settings()
    
    def get_category_settings(self, category):
        """Get all settings for a category"""
        return self.settings.get(category, {})
    
    def update_category_settings(self, category, settings_dict):
        """Update multiple settings in a category"""
        if category not in self.settings:
            self.settings[category] = {}
        self.settings[category].update(settings_dict)
        return self.save_settings()
    
    def reset_to_defaults(self, category=None):
        """Reset settings to defaults"""
        if category:
            self.settings[category] = self.default_settings[category].copy()
        else:
            self.settings = self.default_settings.copy()
        return self.save_settings()
    
    def export_settings(self, filename):
        """Export settings to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.settings, f, indent=4, default=str)
            return True
        except Exception as e:
            print(f"Error exporting settings: {e}")
            return False
    
    def import_settings(self, filename):
        """Import settings from file"""
        try:
            with open(filename, 'r') as f:
                imported_settings = json.load(f)
            self._deep_update(self.settings, imported_settings)
            return self.save_settings()
        except Exception as e:
            print(f"Error importing settings: {e}")
            return False
    
    def validate_settings(self):
        """Validate settings values"""
        validation_errors = []
        
        # Network discovery settings
        if self.get_setting("network_discovery", "scan_timeout") < 1:
            validation_errors.append("Network discovery scan_timeout must be >= 1")
        
        if self.get_setting("network_discovery", "max_threads") < 1:
            validation_errors.append("Network discovery max_threads must be >= 1")
        
        # Traffic analysis settings
        if self.get_setting("traffic_analysis", "monitor_duration") < 10:
            validation_errors.append("Traffic analysis monitor_duration must be >= 10")
        
        # SSL monitoring settings
        if self.get_setting("ssl_monitoring", "connection_timeout") < 1:
            validation_errors.append("SSL monitoring connection_timeout must be >= 1")
        
        # Advanced attack detection settings
        if self.get_setting("advanced_attack_detection", "monitor_duration") < 10:
            validation_errors.append("Advanced attack detection monitor_duration must be >= 10")
        
        return validation_errors
    
    def get_settings_summary(self):
        """Get a summary of current settings"""
        summary = {
            "total_categories": len(self.settings),
            "categories": list(self.settings.keys()),
            "last_modified": datetime.now().isoformat(),
            "settings_file": self.settings_file
        }
        return summary
    
    def backup_settings(self):
        """Create backup of current settings"""
        backup_file = f"{self.settings_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return self.export_settings(backup_file)
    
    def restore_backup(self, backup_file):
        """Restore settings from backup"""
        return self.import_settings(backup_file)
