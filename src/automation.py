"""
Cybersecurity Web Threat Analysis - Automation & Live Data Module
================================================================

This module provides automation features including scheduled data refresh,
real-time streaming simulation, and automated threat detection workflows.
"""

import pandas as pd
import numpy as np
import time
import schedule
import threading
import logging
from datetime import datetime, timedelta
import sqlite3
import os
import json
import requests
from pathlib import Path
import sys

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import our modules
try:
    from model_evaluation import ModelEvaluator
    from eda import CyberThreatEDA
except ImportError as e:
    print(f"Warning: Could not import custom modules: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CyberSecurityAutomation:
    """
    Main automation class for cybersecurity threat analysis system.
    """
    
    def __init__(self, config_path="../config/automation_config.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.is_running = False
        self.threads = []
        
        # Initialize directories
        self.setup_directories()
        
        # Initialize models
        self.evaluator = None
        self.eda = None
        
    def load_config(self):
        """Load automation configuration."""
        default_config = {
            "data_refresh_interval": 300,  # 5 minutes
            "threat_check_interval": 60,   # 1 minute
            "backup_interval": 3600,       # 1 hour
            "data_sources": {
                "primary_csv": "../data/CloudWatch_Traffic_Web_Attack.csv",
                "backup_csv": "../data/transformed_cyber_data.csv",
                "api_endpoint": "http://localhost:5000",
                "database_path": "../data/suspicious_activity.db"
            },
            "thresholds": {
                "high_threat_percentage": 15.0,
                "critical_connections_threshold": 100,
                "anomaly_score_threshold": 0.7
            },
            "notifications": {
                "email_alerts": False,
                "log_alerts": True,
                "api_webhooks": []
            }
        }
        
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
            else:
                # Create default config file
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                with open(self.config_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
                logger.info(f"Created default config file: {self.config_path}")
                return default_config
                
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return default_config
    
    def setup_directories(self):
        """Setup required directories."""
        directories = [
            "../data",
            "../models",
            "../logs",
            "../config",
            "../backups",
            "../reports"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        logger.info("Directory structure initialized")
    
    def generate_synthetic_data(self, n_samples=100):
        """Generate synthetic cybersecurity data for simulation."""
        np.random.seed(int(time.time()) % 1000)  # Dynamic seed
        
        # Realistic country codes with threat probabilities
        countries = ['US', 'CN', 'RU', 'DE', 'GB', 'JP', 'IN', 'BR', 'CA', 'FR', 'KR', 'IT']
        country_weights = [0.25, 0.18, 0.15, 0.10, 0.08, 0.06, 0.05, 0.04, 0.03, 0.03, 0.02, 0.01]
        
        protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'SSH', 'FTP']
        protocol_weights = [0.35, 0.25, 0.20, 0.12, 0.05, 0.03]
        
        # Generate data with some time-based patterns
        current_hour = datetime.now().hour
        
        # Increase threat activity during certain hours (simulate attack patterns)
        threat_multiplier = 1.0
        if 22 <= current_hour or current_hour <= 6:  # Night hours
            threat_multiplier = 2.5
        elif 12 <= current_hour <= 14:  # Lunch hours
            threat_multiplier = 1.8
        
        df = pd.DataFrame({
            'src_ip': [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(n_samples)],
            'dst_ip': [f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}" for _ in range(n_samples)],
            'src_ip_country_code': np.random.choice(countries, n_samples, p=country_weights),
            'dst_port': np.random.choice([22, 23, 53, 80, 135, 139, 443, 445, 993, 995, 8080, 3389], n_samples),
            'protocol': np.random.choice(protocols, n_samples, p=protocol_weights),
            'bytes_in': np.random.lognormal(8, 1.5, n_samples).astype(int),
            'bytes_out': np.random.lognormal(7, 1.5, n_samples).astype(int),
            'creation_time': [datetime.now() - timedelta(minutes=np.random.randint(0, 60)) for _ in range(n_samples)],
            'time': [datetime.now() - timedelta(minutes=np.random.randint(0, 60)) for _ in range(n_samples)],
            'response.code': np.random.choice([200, 404, 403, 500, 301], n_samples, p=[0.60, 0.20, 0.10, 0.05, 0.05])
        })
        
        # Add derived features
        df['total_bytes'] = df['bytes_in'] + df['bytes_out']
        df['bytes_ratio'] = df['bytes_out'] / (df['bytes_in'] + 1)
        df['hour'] = df['time'].dt.hour
        df['date'] = df['time'].dt.date
        df['day_of_week'] = df['time'].dt.day_name()
        
        # Create threat levels with time-based adjustment
        base_high_threat_ratio = 0.1
        adjusted_ratio = min(base_high_threat_ratio * threat_multiplier, 0.4)
        
        df['threat_level'] = pd.cut(
            df['total_bytes'] * np.random.uniform(0.5, 2.0, n_samples),  # Add some randomness
            bins=[0, 10000, 100000, 1000000, float('inf')],
            labels=['Low', 'Medium', 'High', 'Critical']
        )
        
        # Force some high/critical threats based on time
        high_threat_count = int(n_samples * adjusted_ratio)
        if high_threat_count > 0:
            high_indices = np.random.choice(df.index, high_threat_count, replace=False)
            df.loc[high_indices, 'threat_level'] = np.random.choice(['High', 'Critical'], high_threat_count, p=[0.7, 0.3])
        
        # Add anomaly scores and suspicious flags
        df['anomaly_score'] = np.random.normal(0, 0.3, n_samples)
        df['is_suspicious'] = (
            df['threat_level'].isin(['High', 'Critical']) | 
            (df['anomaly_score'] > 0.5)
        ).astype(int)
        
        return df
    
    def simulate_real_time_data_stream(self):
        """Simulate real-time data streaming."""
        logger.info("Starting real-time data stream simulation")
        
        while self.is_running:
            try:
                # Generate new data batch
                new_data = self.generate_synthetic_data(n_samples=np.random.randint(10, 50))
                
                # Append to existing data file
                data_file = self.config['data_sources']['primary_csv']
                
                if os.path.exists(data_file):
                    # Append to existing file
                    new_data.to_csv(data_file, mode='a', header=False, index=False)
                else:
                    # Create new file
                    new_data.to_csv(data_file, index=False)
                
                logger.info(f"Added {len(new_data)} new records to data stream")
                
                # Check for immediate threats
                self.check_immediate_threats(new_data)
                
                # Wait for next batch
                time.sleep(self.config['data_refresh_interval'])
                
            except Exception as e:
                logger.error(f"Error in real-time data stream: {e}")
                time.sleep(30)  # Wait before retrying
    
    def check_immediate_threats(self, df):
        """Check for immediate threats in new data."""
        try:
            # Calculate threat statistics
            total_connections = len(df)
            suspicious_connections = df['is_suspicious'].sum() if 'is_suspicious' in df.columns else 0
            threat_percentage = (suspicious_connections / total_connections * 100) if total_connections > 0 else 0
            
            critical_threats = len(df[df['threat_level'] == 'Critical']) if 'threat_level' in df.columns else 0
            
            # Check thresholds
            alerts = []
            
            if threat_percentage > self.config['thresholds']['high_threat_percentage']:
                alerts.append({
                    'type': 'HIGH_THREAT_PERCENTAGE',
                    'severity': 'HIGH',
                    'message': f"Threat percentage ({threat_percentage:.1f}%) exceeds threshold ({self.config['thresholds']['high_threat_percentage']}%)",
                    'data': {
                        'threat_percentage': threat_percentage,
                        'suspicious_connections': suspicious_connections,
                        'total_connections': total_connections
                    }
                })
            
            if critical_threats > 0:
                alerts.append({
                    'type': 'CRITICAL_THREATS_DETECTED',
                    'severity': 'CRITICAL',
                    'message': f"Detected {critical_threats} critical threats",
                    'data': {
                        'critical_threats': critical_threats,
                        'threat_sources': df[df['threat_level'] == 'Critical']['src_ip_country_code'].value_counts().to_dict()
                    }
                })
            
            # Process alerts
            for alert in alerts:
                self.process_alert(alert)
                
        except Exception as e:
            logger.error(f"Error checking immediate threats: {e}")
    
    def process_alert(self, alert):
        """Process security alerts."""
        timestamp = datetime.now().isoformat()
        
        # Log alert
        if self.config['notifications']['log_alerts']:
            logger.warning(f"SECURITY ALERT [{alert['severity']}]: {alert['message']}")
        
        # Save to database
        try:
            self.save_alert_to_database(alert, timestamp)
        except Exception as e:
            logger.error(f"Error saving alert to database: {e}")
        
        # Send webhook notifications
        for webhook_url in self.config['notifications']['api_webhooks']:
            try:
                self.send_webhook_alert(webhook_url, alert, timestamp)
            except Exception as e:
                logger.error(f"Error sending webhook alert: {e}")
    
    def save_alert_to_database(self, alert, timestamp):
        """Save alert to SQLite database."""
        db_path = self.config['data_sources']['database_path']
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create alerts table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                alert_type TEXT,
                severity TEXT,
                message TEXT,
                data JSON
            )
        ''')
        
        # Insert alert
        cursor.execute('''
            INSERT INTO security_alerts (timestamp, alert_type, severity, message, data)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            timestamp,
            alert['type'],
            alert['severity'],
            alert['message'],
            json.dumps(alert.get('data', {}))
        ))
        
        conn.commit()
        conn.close()
    
    def send_webhook_alert(self, webhook_url, alert, timestamp):
        """Send alert via webhook."""
        payload = {
            'timestamp': timestamp,
            'alert': alert,
            'source': 'cybersecurity_automation'
        }
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        
        logger.info(f"Webhook alert sent to {webhook_url}")
    
    def scheduled_data_refresh(self):
        """Scheduled data refresh and processing."""
        logger.info("Starting scheduled data refresh")
        
        try:
            # Load current data
            data_file = self.config['data_sources']['primary_csv']
            
            if os.path.exists(data_file):
                df = pd.read_csv(data_file)
                
                # Clean old data (keep last 24 hours)
                if 'time' in df.columns:
                    df['time'] = pd.to_datetime(df['time'], errors='coerce')
                    cutoff_time = datetime.now() - timedelta(hours=24)
                    df = df[df['time'] >= cutoff_time]
                    
                    # Save cleaned data
                    df.to_csv(data_file, index=False)
                    logger.info(f"Cleaned data, kept {len(df)} recent records")
                
                # Run automated analysis
                self.run_automated_analysis(df)
                
            else:
                logger.warning(f"Data file not found: {data_file}")
                
        except Exception as e:
            logger.error(f"Error in scheduled data refresh: {e}")
    
    def run_automated_analysis(self, df):
        """Run automated threat analysis."""
        try:
            logger.info("Running automated threat analysis")
            
            # Initialize EDA if not done
            if self.eda is None:
                from eda import CyberThreatEDA
                self.eda = CyberThreatEDA()
            
            # Get top suspicious IPs
            suspicious_df = self.eda.get_top_suspicious_ips(df, top_n=10)
            
            if suspicious_df is not None and len(suspicious_df) > 0:
                # Generate automated report
                report_data = {
                    'timestamp': datetime.now().isoformat(),
                    'total_records': len(df),
                    'suspicious_records': len(suspicious_df),
                    'threat_percentage': (len(suspicious_df) / len(df)) * 100,
                    'top_threat_countries': suspicious_df['src_ip_country_code'].value_counts().head(5).to_dict(),
                    'top_protocols': suspicious_df['protocol'].value_counts().head(3).to_dict() if 'protocol' in suspicious_df.columns else {},
                    'average_bytes': suspicious_df['total_bytes'].mean() if 'total_bytes' in suspicious_df.columns else 0
                }
                
                # Save report
                report_file = f"../reports/automated_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(report_file, 'w') as f:
                    json.dump(report_data, f, indent=2)
                
                logger.info(f"Automated analysis report saved: {report_file}")
                
                # Check if ML models need retraining
                self.check_model_performance(df)
                
        except Exception as e:
            logger.error(f"Error in automated analysis: {e}")
    
    def check_model_performance(self, df):
        """Check if ML models need retraining."""
        try:
            # Initialize model evaluator if not done
            if self.evaluator is None:
                from model_evaluation import ModelEvaluator
                self.evaluator = ModelEvaluator()
            
            # Check if we have enough new data for retraining
            if len(df) > 1000:  # Minimum threshold for retraining
                logger.info("Sufficient data for model retraining check")
                
                # Prepare data for ML
                X_train, X_test, y_train, y_test, features = self.evaluator.prepare_data_for_ml(df)
                
                if X_train is not None:
                    # Train models and evaluate
                    models, results = self.evaluator.train_models(X_train, y_train, X_test, y_test)
                    
                    # Save updated models
                    self.evaluator.save_models("../models/")
                    
                    logger.info("Models retrained and saved successfully")
                
        except Exception as e:
            logger.error(f"Error checking model performance: {e}")
    
    def backup_data(self):
        """Create backup of critical data."""
        logger.info("Starting data backup")
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = f"../backups/backup_{timestamp}"
            os.makedirs(backup_dir, exist_ok=True)
            
            # Backup data files
            data_files = [
                self.config['data_sources']['primary_csv'],
                self.config['data_sources']['database_path']
            ]
            
            for file_path in data_files:
                if os.path.exists(file_path):
                    filename = os.path.basename(file_path)
                    backup_path = os.path.join(backup_dir, filename)
                    
                    if file_path.endswith('.db'):
                        # For SQLite database, use proper backup
                        conn = sqlite3.connect(file_path)
                        backup_conn = sqlite3.connect(backup_path)
                        conn.backup(backup_conn)
                        backup_conn.close()
                        conn.close()
                    else:
                        # For other files, simple copy
                        import shutil
                        shutil.copy2(file_path, backup_path)
                    
                    logger.info(f"Backed up {filename}")
            
            # Backup models
            models_dir = "../models"
            if os.path.exists(models_dir):
                backup_models_dir = os.path.join(backup_dir, "models")
                import shutil
                shutil.copytree(models_dir, backup_models_dir, dirs_exist_ok=True)
                logger.info("Backed up models directory")
            
            # Cleanup old backups (keep last 7 days)
            self.cleanup_old_backups()
            
            logger.info(f"Backup completed: {backup_dir}")
            
        except Exception as e:
            logger.error(f"Error in data backup: {e}")
    
    def cleanup_old_backups(self):
        """Remove backups older than 7 days."""
        try:
            backups_dir = "../backups"
            cutoff_date = datetime.now() - timedelta(days=7)
            
            for item in os.listdir(backups_dir):
                item_path = os.path.join(backups_dir, item)
                if os.path.isdir(item_path) and item.startswith('backup_'):
                    # Extract date from backup folder name
                    try:
                        backup_date_str = item.replace('backup_', '')[:8]  # YYYYMMDD
                        backup_date = datetime.strptime(backup_date_str, '%Y%m%d')
                        
                        if backup_date < cutoff_date:
                            import shutil
                            shutil.rmtree(item_path)
                            logger.info(f"Removed old backup: {item}")
                    except ValueError:
                        # Skip folders that don't match expected format
                        continue
                        
        except Exception as e:
            logger.error(f"Error cleaning up old backups: {e}")
    
    def schedule_tasks(self):
        """Schedule all automated tasks."""
        # Schedule data refresh every 5 minutes
        schedule.every(self.config['data_refresh_interval']).seconds.do(self.scheduled_data_refresh)
        
        # Schedule backup every hour
        schedule.every(self.config['backup_interval']).seconds.do(self.backup_data)
        
        # Schedule daily analysis at 6 AM
        schedule.every().day.at("06:00").do(self.run_daily_analysis)
        
        # Schedule weekly model retraining on Sundays at 2 AM
        schedule.every().sunday.at("02:00").do(self.weekly_model_retrain)
        
        logger.info("All tasks scheduled successfully")
    
    def run_daily_analysis(self):
        """Run comprehensive daily analysis."""
        logger.info("Starting daily analysis")
        
        try:
            # Load last 24 hours of data
            data_file = self.config['data_sources']['primary_csv']
            
            if os.path.exists(data_file):
                df = pd.read_csv(data_file)
                
                if 'time' in df.columns:
                    df['time'] = pd.to_datetime(df['time'], errors='coerce')
                    yesterday = datetime.now() - timedelta(days=1)
                    daily_df = df[df['time'] >= yesterday]
                    
                    # Generate comprehensive report
                    self.generate_daily_report(daily_df)
                    
        except Exception as e:
            logger.error(f"Error in daily analysis: {e}")
    
    def generate_daily_report(self, df):
        """Generate comprehensive daily security report."""
        try:
            report = {
                'date': datetime.now().strftime('%Y-%m-%d'),
                'summary': {
                    'total_connections': len(df),
                    'suspicious_connections': df['is_suspicious'].sum() if 'is_suspicious' in df.columns else 0,
                    'unique_source_ips': df['src_ip'].nunique() if 'src_ip' in df.columns else 0,
                    'unique_countries': df['src_ip_country_code'].nunique() if 'src_ip_country_code' in df.columns else 0,
                    'total_data_volume_gb': df['total_bytes'].sum() / (1024**3) if 'total_bytes' in df.columns else 0
                },
                'threats': {
                    'critical_threats': len(df[df['threat_level'] == 'Critical']) if 'threat_level' in df.columns else 0,
                    'high_threats': len(df[df['threat_level'] == 'High']) if 'threat_level' in df.columns else 0,
                    'top_threat_countries': df[df['threat_level'].isin(['High', 'Critical'])]['src_ip_country_code'].value_counts().head(10).to_dict() if 'threat_level' in df.columns else {},
                    'threat_trend': 'increasing'  # Could be calculated by comparing with previous days
                },
                'recommendations': [
                    "Continue monitoring high-risk countries",
                    "Review firewall rules for critical threats",
                    "Update threat intelligence feeds",
                    "Schedule security team review"
                ]
            }
            
            # Save daily report
            report_file = f"../reports/daily_report_{datetime.now().strftime('%Y%m%d')}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Daily report generated: {report_file}")
            
        except Exception as e:
            logger.error(f"Error generating daily report: {e}")
    
    def weekly_model_retrain(self):
        """Weekly model retraining with full dataset."""
        logger.info("Starting weekly model retraining")
        
        try:
            # Load all available data
            data_file = self.config['data_sources']['primary_csv']
            
            if os.path.exists(data_file):
                df = pd.read_csv(data_file)
                
                if len(df) > 5000:  # Ensure sufficient data
                    # Initialize model evaluator
                    if self.evaluator is None:
                        from model_evaluation import ModelEvaluator
                        self.evaluator = ModelEvaluator()
                    
                    # Retrain all models
                    X_train, X_test, y_train, y_test, features = self.evaluator.prepare_data_for_ml(df)
                    
                    if X_train is not None:
                        # Train models
                        models, results = self.evaluator.train_models(X_train, y_train, X_test, y_test)
                        
                        # Generate model evaluation report
                        comparison_df = self.evaluator.create_precision_recall_f1_table()
                        
                        # Save models
                        self.evaluator.save_models("../models/")
                        
                        # Save evaluation report
                        report_file = f"../reports/weekly_model_evaluation_{datetime.now().strftime('%Y%m%d')}.csv"
                        comparison_df.to_csv(report_file, index=False)
                        
                        logger.info("Weekly model retraining completed successfully")
                    
                else:
                    logger.warning("Insufficient data for model retraining")
                    
        except Exception as e:
            logger.error(f"Error in weekly model retraining: {e}")
    
    def start(self):
        """Start the automation system."""
        logger.info("Starting Cybersecurity Automation System")
        
        self.is_running = True
        
        # Schedule all tasks
        self.schedule_tasks()
        
        # Start real-time data stream in separate thread
        stream_thread = threading.Thread(target=self.simulate_real_time_data_stream, daemon=True)
        stream_thread.start()
        self.threads.append(stream_thread)
        
        # Start scheduler in separate thread
        def run_scheduler():
            while self.is_running:
                schedule.run_pending()
                time.sleep(10)
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        self.threads.append(scheduler_thread)
        
        logger.info("Automation system started successfully")
        
        # Keep main thread alive
        try:
            while self.is_running:
                time.sleep(60)
                logger.info("Automation system running...")
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
            self.stop()
    
    def stop(self):
        """Stop the automation system."""
        logger.info("Stopping Cybersecurity Automation System")
        
        self.is_running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=5)
        
        logger.info("Automation system stopped")

def main():
    """Main function to run the automation system."""
    print("🚀 Cybersecurity Automation System")
    print("=" * 50)
    
    # Create automation instance
    automation = CyberSecurityAutomation()
    
    try:
        # Start the system
        automation.start()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        automation.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        automation.stop()

if __name__ == "__main__":
    main()