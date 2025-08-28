"""
Cybersecurity Web Threat Analysis - Utilities Module
====================================================

This module provides utility functions and helper classes for the cybersecurity
threat analysis project.
"""

import pandas as pd
import numpy as np
import sqlite3
import json
import pickle
import os
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Any, Optional
import warnings
warnings.filterwarnings('ignore')

class DatabaseManager:
    """Database operations for cybersecurity data."""
    
    def __init__(self, db_path="../data/cyber_threats.db"):
        self.db_path = db_path
        self.ensure_database_exists()
    
    def ensure_database_exists(self):
        """Create database and tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create main threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                src_ip TEXT,
                dst_ip TEXT,
                src_country TEXT,
                dst_port INTEGER,
                protocol TEXT,
                bytes_in INTEGER,
                bytes_out INTEGER,
                anomaly_score REAL,
                threat_level TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create summary statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_stats (
                date DATE PRIMARY KEY,
                total_connections INTEGER,
                suspicious_connections INTEGER,
                top_country TEXT,
                avg_bytes_in REAL,
                avg_bytes_out REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def insert_threat_data(self, df):
        """Insert threat data into database."""
        conn = sqlite3.connect(self.db_path)
        
        # Prepare data for insertion
        threat_data = []
        for _, row in df.iterrows():
            threat_data.append((
                row.get('creation_time'),
                row.get('src_ip'),
                row.get('dst_ip'),
                row.get('src_ip_country_code'),
                row.get('dst_port'),
                row.get('protocol'),
                row.get('bytes_in'),
                row.get('bytes_out'),
                row.get('anomaly_score', 0),
                row.get('anomaly', 'Normal')
            ))
        
        cursor = conn.cursor()
        cursor.executemany('''
            INSERT INTO threats (timestamp, src_ip, dst_ip, src_country, dst_port, 
                               protocol, bytes_in, bytes_out, anomaly_score, threat_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', threat_data)
        
        conn.commit()
        conn.close()
        print(f"✅ Inserted {len(threat_data)} records into database")
    
    def get_daily_stats(self, days=30):
        """Get daily statistics for the dashboard."""
        conn = sqlite3.connect(self.db_path)
        
        query = '''
            SELECT 
                DATE(timestamp) as date,
                COUNT(*) as total_connections,
                SUM(CASE WHEN threat_level = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_connections,
                AVG(bytes_in) as avg_bytes_in,
                AVG(bytes_out) as avg_bytes_out
            FROM threats 
            WHERE timestamp >= date('now', '-{} days')
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
        '''.format(days)
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    
    def get_top_threats(self, limit=10):
        """Get top threatening countries/IPs."""
        conn = sqlite3.connect(self.db_path)
        
        query = '''
            SELECT 
                src_country,
                COUNT(*) as threat_count,
                AVG(anomaly_score) as avg_anomaly_score,
                SUM(bytes_in + bytes_out) as total_bytes
            FROM threats 
            WHERE threat_level = 'Suspicious'
            GROUP BY src_country
            ORDER BY threat_count DESC
            LIMIT ?
        '''
        
        df = pd.read_sql_query(query, conn, params=[limit])
        conn.close()
        return df

class ConfigManager:
    """Configuration management for the project."""
    
    def __init__(self, config_path="../config.json"):
        self.config_path = config_path
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from JSON file."""
        default_config = {
            "data_paths": {
                "raw_data": "../data/CloudWatch_Traffic_Web_Attack.csv",
                "processed_data": "../data/transformed_cyber_data.csv",
                "results_data": "../data/anomaly_detected_data.csv"
            },
            "model_params": {
                "isolation_forest": {
                    "contamination": 0.05,
                    "n_estimators": 200,
                    "random_state": 42
                },
                "random_forest": {
                    "n_estimators": 200,
                    "max_depth": 10,
                    "random_state": 42
                }
            },
            "dashboard": {
                "host": "127.0.0.1",
                "port": 8050,
                "debug": True,
                "auto_refresh_interval": 30000
            },
            "security": {
                "high_risk_ports": [22, 23, 53, 80, 135, 139, 443, 445, 993, 995],
                "suspicious_countries": ["CN", "RU", "KP"],
                "anomaly_threshold": -0.1
            }
        }
        
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                return {**default_config, **config}
            else:
                self.save_config(default_config)
                return default_config
        except Exception as e:
            print(f"⚠️ Error loading config: {e}. Using defaults.")
            return default_config
    
    def save_config(self, config=None):
        """Save configuration to JSON file."""
        if config is None:
            config = self.config
        
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"✅ Configuration saved to {self.config_path}")
        except Exception as e:
            print(f"❌ Error saving config: {e}")
    
    def get(self, key_path, default=None):
        """Get configuration value using dot notation."""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value

class Logger:
    """Logging utility for the project."""
    
    def __init__(self, name="CyberThreatAnalysis", level=logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            
            # File handler
            os.makedirs("../logs", exist_ok=True)
            file_handler = logging.FileHandler("../logs/cyber_analysis.log")
            file_handler.setLevel(level)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)
            
            self.logger.addHandler(console_handler)
            self.logger.addHandler(file_handler)
    
    def info(self, message):
        self.logger.info(message)
    
    def error(self, message):
        self.logger.error(message)
    
    def warning(self, message):
        self.logger.warning(message)
    
    def debug(self, message):
        self.logger.debug(message)

class DataValidator:
    """Data validation utilities."""
    
    @staticmethod
    def validate_ip_address(ip):
        """Validate IP address format."""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    @staticmethod
    def validate_port(port):
        """Validate port number."""
        try:
            return 1 <= int(port) <= 65535
        except:
            return False
    
    @staticmethod
    def validate_country_code(code):
        """Validate country code format."""
        return isinstance(code, str) and len(code) == 2 and code.isalpha()
    
    @staticmethod
    def validate_dataset(df):
        """Validate the cybersecurity dataset."""
        issues = []
        
        # Check required columns
        required_cols = ['src_ip', 'dst_ip', 'src_ip_country_code', 'dst_port', 'protocol']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            issues.append(f"Missing columns: {missing_cols}")
        
        # Check data types
        if 'bytes_in' in df.columns and not pd.api.types.is_numeric_dtype(df['bytes_in']):
            issues.append("bytes_in should be numeric")
        
        if 'bytes_out' in df.columns and not pd.api.types.is_numeric_dtype(df['bytes_out']):
            issues.append("bytes_out should be numeric")
        
        # Check for suspicious values
        if 'bytes_in' in df.columns and (df['bytes_in'] < 0).any():
            issues.append("Negative values found in bytes_in")
        
        if 'bytes_out' in df.columns and (df['bytes_out'] < 0).any():
            issues.append("Negative values found in bytes_out")
        
        return issues

class MetricsCalculator:
    """Calculate various security metrics and KPIs."""
    
    @staticmethod
    def calculate_threat_score(df):
        """Calculate overall threat score for the network."""
        if 'anomaly' not in df.columns:
            return 0
        
        suspicious_ratio = (df['anomaly'] == 'Suspicious').mean()
        
        # Weight by traffic volume
        if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
            suspicious_data = df[df['anomaly'] == 'Suspicious']
            if len(suspicious_data) > 0:
                avg_suspicious_traffic = (suspicious_data['bytes_in'] + suspicious_data['bytes_out']).mean()
                avg_normal_traffic = df[df['anomaly'] == 'Normal'][['bytes_in', 'bytes_out']].sum(axis=1).mean()
                traffic_ratio = avg_suspicious_traffic / (avg_normal_traffic + 1)
                threat_score = (suspicious_ratio * 0.7 + traffic_ratio * 0.3) * 100
            else:
                threat_score = suspicious_ratio * 100
        else:
            threat_score = suspicious_ratio * 100
        
        return min(threat_score, 100)
    
    @staticmethod
    def get_top_risk_countries(df, top_n=10):
        """Get countries with highest risk scores."""
        if 'src_ip_country_code' not in df.columns or 'anomaly' not in df.columns:
            return pd.DataFrame()
        
        country_stats = df.groupby('src_ip_country_code').agg({
            'anomaly': lambda x: (x == 'Suspicious').sum(),
            'bytes_in': 'sum',
            'bytes_out': 'sum'
        }).reset_index()
        
        country_stats['total_connections'] = df['src_ip_country_code'].value_counts()
        country_stats['risk_score'] = (
            country_stats['anomaly'] / country_stats['total_connections'] * 100
        )
        
        return country_stats.sort_values('risk_score', ascending=False).head(top_n)
    
    @staticmethod
    def calculate_port_risk_analysis(df):
        """Analyze port-based security risks."""
        if 'dst_port' not in df.columns:
            return pd.DataFrame()
        
        high_risk_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995]
        
        port_stats = df.groupby('dst_port').agg({
            'anomaly': lambda x: (x == 'Suspicious').sum() if 'anomaly' in df.columns else 0,
            'bytes_in': 'sum',
            'bytes_out': 'sum'
        }).reset_index()
        
        port_stats['is_high_risk'] = port_stats['dst_port'].isin(high_risk_ports)
        port_stats['connection_count'] = df['dst_port'].value_counts()
        
        return port_stats.sort_values('connection_count', ascending=False)

class ReportGenerator:
    """Generate various reports and exports."""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.logger = Logger("ReportGenerator")
    
    def generate_executive_summary(self, df):
        """Generate executive summary of threats."""
        summary = {
            "total_connections": len(df),
            "suspicious_connections": (df['anomaly'] == 'Suspicious').sum() if 'anomaly' in df.columns else 0,
            "threat_score": MetricsCalculator.calculate_threat_score(df),
            "top_threat_countries": MetricsCalculator.get_top_risk_countries(df, 5).to_dict('records'),
            "total_data_volume": (df['bytes_in'].sum() + df['bytes_out'].sum()) / (1024**3) if 'bytes_in' in df.columns else 0,
            "analysis_period": {
                "start": df['creation_time'].min() if 'creation_time' in df.columns else "N/A",
                "end": df['creation_time'].max() if 'creation_time' in df.columns else "N/A"
            },
            "generated_at": datetime.now().isoformat()
        }
        
        return summary
    
    def export_to_excel(self, df, filepath="../reports/cybersecurity_report.xlsx"):
        """Export analysis results to Excel."""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                # Main data
                df.to_excel(writer, sheet_name='Raw_Data', index=False)
                
                # Summary statistics
                if 'anomaly' in df.columns:
                    summary_df = df.groupby('anomaly').agg({
                        'bytes_in': ['count', 'sum', 'mean'],
                        'bytes_out': ['count', 'sum', 'mean']
                    }).round(2)
                    summary_df.to_excel(writer, sheet_name='Summary_Stats')
                
                # Country analysis
                if 'src_ip_country_code' in df.columns:
                    country_analysis = MetricsCalculator.get_top_risk_countries(df)
                    country_analysis.to_excel(writer, sheet_name='Country_Analysis', index=False)
            
            self.logger.info(f"Excel report exported to {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting to Excel: {e}")
            return False

# Utility functions
def format_bytes(bytes_value):
    """Format bytes into human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def format_number(number):
    """Format large numbers with commas."""
    return f"{number:,}"

def get_risk_level(score):
    """Get risk level based on score."""
    if score >= 80:
        return "Critical", "#FF4444"
    elif score >= 60:
        return "High", "#FF8800"
    elif score >= 40:
        return "Medium", "#FFAA00"
    elif score >= 20:
        return "Low", "#88CC00"
    else:
        return "Minimal", "#44CC44"

def validate_file_exists(filepath):
    """Check if file exists and is readable."""
    return os.path.exists(filepath) and os.access(filepath, os.R_OK)

# Initialize global utilities
config_manager = ConfigManager()
logger = Logger()
db_manager = DatabaseManager()

def main():
    """Example usage of utilities."""
    print("🛠️ Cybersecurity Analysis Utilities")
    print("=" * 40)
    
    # Test configuration
    print(f"Database path: {config_manager.get('data_paths.raw_data')}")
    print(f"Dashboard port: {config_manager.get('dashboard.port')}")
    
    # Test validation
    validator = DataValidator()
    print(f"Valid IP (192.168.1.1): {validator.validate_ip_address('192.168.1.1')}")
    print(f"Valid Port (8080): {validator.validate_port(8080)}")
    
    # Test metrics
    sample_data = pd.DataFrame({
        'anomaly': ['Normal', 'Suspicious', 'Normal', 'Suspicious'],
        'bytes_in': [1000, 5000, 800, 3000],
        'bytes_out': [500, 2000, 400, 1500]
    })
    
    threat_score = MetricsCalculator.calculate_threat_score(sample_data)
    print(f"Sample threat score: {threat_score:.2f}")
    
    logger.info("Utilities module test completed successfully")

if __name__ == "__main__":
    main()