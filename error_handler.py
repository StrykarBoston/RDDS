# -*- coding: utf-8 -*-
# error_handler.py - Advanced Error Handling System for RDDS

import sys
import traceback
import logging
from datetime import datetime
from typing import Optional, Dict, Any
import json
import os

class RDDSErrorHandler:
    """Advanced error handling system for RDDS"""
    
    def __init__(self, log_file: str = "rdds_errors.log"):
        self.log_file = log_file
        self.error_count = 0
        self.critical_errors = []
        self.setup_logging()
    
    def setup_logging(self):
        """Setup error logging"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.ERROR,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filemode='a'
        )
        self.logger = logging.getLogger('RDSErrorHandler')
    
    def handle_error(self, error: Exception, context: str = "", severity: str = "ERROR", 
                    show_user: bool = True, critical: bool = False) -> Dict[str, Any]:
        """
        Handle any error that occurs in RDDS
        
        Args:
            error: The exception that occurred
            context: Context where error occurred (function name, operation, etc.)
            severity: Error severity (ERROR, WARNING, CRITICAL)
            show_user: Whether to show error to user
            critical: Whether this is a critical error
        
        Returns:
            Dictionary with error details
        """
        self.error_count += 1
        error_id = f"ERR_{self.error_count:04d}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Get full traceback
        tb_str = traceback.format_exc()
        
        # Create error details
        error_details = {
            'error_id': error_id,
            'timestamp': datetime.now().isoformat(),
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'severity': severity,
            'traceback': tb_str,
            'critical': critical,
            'show_user': show_user
        }
        
        # Log the error
        self.logger.error(f"[{error_id}] {severity} in {context}: {error}")
        self.logger.error(f"Traceback: {tb_str}")
        
        # Store critical errors
        if critical:
            self.critical_errors.append(error_details)
        
        # Show user notification if needed
        if show_user:
            self.show_user_notification(error_details)
        
        return error_details
    
    def show_user_notification(self, error_details: Dict[str, Any]):
        """Show error notification to user"""
        severity_icons = {
            'ERROR': '❌',
            'WARNING': '⚠️',
            'CRITICAL': '🔴'
        }
        
        icon = severity_icons.get(error_details['severity'], '❓')
        
        print(f"\n{icon} RDDS Error Notification")
        print("=" * 50)
        print(f"Error ID: {error_details['error_id']}")
        print(f"Severity: {error_details['severity']}")
        print(f"Context: {error_details['context']}")
        print(f"Message: {error_details['error_message']}")
        
        if error_details['critical']:
            print("\n🔴 CRITICAL ERROR - This may affect system functionality!")
        
        # Provide user-friendly suggestions based on error type
        suggestions = self.get_error_suggestions(error_details)
        if suggestions:
            print("\n💡 Suggestions:")
            for suggestion in suggestions:
                print(f"  • {suggestion}")
        
        print(f"\n📋 Full error details logged to: {self.log_file}")
        print("=" * 50)
    
    def get_error_suggestions(self, error_details: Dict[str, Any]) -> list:
        """Get user-friendly suggestions based on error type"""
        error_msg = error_details['error_message'].lower()
        error_type = error_details['error_type']
        suggestions = []
        
        # Network-related errors
        if 'permission' in error_msg or 'access denied' in error_msg:
            suggestions.append("Run as Administrator/root")
            suggestions.append("Check firewall settings")
        
        if 'network' in error_msg or 'interface' in error_msg:
            suggestions.append("Check network connection")
            suggestions.append("Verify network adapter is enabled")
            suggestions.append("Try different network interface")
        
        # Import/module errors
        if error_type == 'ImportError' or 'module' in error_msg:
            suggestions.append("Install missing dependencies: pip install -r requirements.txt")
            suggestions.append("Check Python version compatibility")
        
        # Scapy errors
        if 'scapy' in error_msg:
            suggestions.append("Install Npcap (Windows) or libpcap (Linux)")
            suggestions.append("Run with Administrator privileges")
        
        # File/IO errors
        if 'file' in error_msg or 'directory' in error_msg:
            suggestions.append("Check file permissions")
            suggestions.append("Ensure directory exists")
            suggestions.append("Check disk space")
        
        # Memory errors
        if 'memory' in error_msg or 'out of memory' in error_msg:
            suggestions.append("Close other applications")
            suggestions.append("Reduce scan scope")
            suggestions.append("Increase system RAM")
        
        # SSL/TLS errors
        if 'ssl' in error_msg or 'certificate' in error_msg:
            suggestions.append("Check system date/time")
            suggestions.append("Verify SSL certificate validity")
        
        return suggestions
    
    def handle_network_error(self, error: Exception, operation: str) -> Dict[str, Any]:
        """Handle network-specific errors"""
        return self.handle_error(
            error, 
            context=f"Network Operation: {operation}",
            severity="ERROR",
            show_user=True,
            critical=True
        )
    
    def handle_scan_error(self, error: Exception, scan_type: str) -> Dict[str, Any]:
        """Handle scanning-specific errors"""
        return self.handle_error(
            error,
            context=f"Scan Operation: {scan_type}",
            severity="WARNING",
            show_user=True,
            critical=False
        )
    
    def handle_import_error(self, error: Exception, module_name: str) -> Dict[str, Any]:
        """Handle import-specific errors"""
        return self.handle_error(
            error,
            context=f"Module Import: {module_name}",
            severity="CRITICAL",
            show_user=True,
            critical=True
        )
    
    def handle_file_error(self, error: Exception, file_path: str, operation: str) -> Dict[str, Any]:
        """Handle file operation errors"""
        return self.handle_error(
            error,
            context=f"File Operation: {operation} - {file_path}",
            severity="ERROR",
            show_user=True,
            critical=False
        )
    
    def get_error_summary(self) -> Dict[str, Any]:
        """Get summary of all errors"""
        return {
            'total_errors': self.error_count,
            'critical_errors': len(self.critical_errors),
            'last_error_time': datetime.now().isoformat(),
            'error_log_file': self.log_file
        }
    
    def export_errors(self, export_file: str = None) -> str:
        """Export errors to JSON file"""
        if export_file is None:
            export_file = f"rdds_errors_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(export_file, 'w') as f:
                json.dump({
                    'summary': self.get_error_summary(),
                    'critical_errors': self.critical_errors
                }, f, indent=2)
            return export_file
        except Exception as e:
            self.handle_error(e, "Error Export", "ERROR", False, False)
            return ""

# Global error handler instance
error_handler = RDDSErrorHandler()

def handle_rdds_error(error: Exception, context: str = "", severity: str = "ERROR", 
                     show_user: bool = True, critical: bool = False) -> Dict[str, Any]:
    """Convenience function for handling RDDS errors"""
    return error_handler.handle_error(error, context, severity, show_user, critical)
