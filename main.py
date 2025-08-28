"""
Cybersecurity Web Threat Analysis - Main Integration Module
==========================================================

This is the main entry point for the complete cybersecurity threat analysis system.
It integrates all components: EDA, ML models, dashboard, API, and automation.
"""

import os
import sys
import argparse
import logging
from datetime import datetime
import subprocess
import time
import threading
import signal

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/main.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CyberSecuritySystem:
    """
    Main system orchestrator for the cybersecurity threat analysis platform.
    """
    
    def __init__(self):
        self.processes = {}
        self.threads = {}
        self.is_running = False
        self.setup_directories()
    
    def setup_directories(self):
        """Create necessary directories."""
        directories = [
            'data', 'models', 'logs', 'config', 
            'backups', 'reports', 'notebooks'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        logger.info("Directory structure initialized")
    
    def run_eda_analysis(self):
        """Run comprehensive EDA analysis."""
        logger.info("🔍 Running Exploratory Data Analysis...")
        
        try:
            from src.eda import CyberThreatEDA
            
            # Initialize EDA
            eda = CyberThreatEDA()
            
            # Load data
            data_file = "data/CloudWatch_Traffic_Web_Attack.csv"
            if not os.path.exists(data_file):
                data_file = "data/transformed_cyber_data.csv"
            
            if os.path.exists(data_file):
                df = eda.load_data(data_file)
                
                if df is not None:
                    # Run all EDA functions
                    print("\n📊 Basic Dataset Information:")
                    eda.basic_info(df)
                    
                    print("\n🚨 Top Suspicious IPs Analysis:")
                    eda.get_top_suspicious_ips(df)
                    
                    print("\n⏰ Time-based Attack Trends:")
                    eda.plot_time_based_attack_trends(df, save_path="reports/time_trends.png")
                    
                    print("\n🗺️ Geographic Threat Visualization:")
                    eda.create_geo_visualization_map(df)
                    
                    print("\n🌐 Attack Type vs Country Analysis:")
                    eda.analyze_attack_type_vs_country(df, save_path="reports/attack_analysis.png")
                    
                    # Generate complete EDA report
                    eda.generate_eda_report(df, save_dir="reports/")
                    
                    logger.info("✅ EDA analysis completed successfully")
                    return True
            else:
                logger.error("❌ No data file found for EDA analysis")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error in EDA analysis: {e}")
            return False
    
    def train_ml_models(self):
        """Train and evaluate ML models."""
        logger.info("🤖 Training Machine Learning Models...")
        
        try:
            from src.model_evaluation import ModelEvaluator
            
            # Load data
            data_file = "data/CloudWatch_Traffic_Web_Attack.csv"
            if not os.path.exists(data_file):
                data_file = "data/transformed_cyber_data.csv"
            
            if os.path.exists(data_file):
                import pandas as pd
                df = pd.read_csv(data_file)
                
                # Initialize model evaluator
                evaluator = ModelEvaluator()
                
                # Prepare data
                X_train, X_test, y_train, y_test, features = evaluator.prepare_data_for_ml(df)
                
                if X_train is not None:
                    # Train models
                    models, results = evaluator.train_models(X_train, y_train, X_test, y_test)
                    
                    # Evaluate models
                    print("\n📈 ROC/AUC Curves:")
                    evaluator.plot_roc_auc_curves(save_path="reports/roc_curves.png")
                    
                    print("\n📋 Model Performance Comparison:")
                    comparison_df = evaluator.create_precision_recall_f1_table()
                    
                    print("\n📊 Model Comparison Chart:")
                    evaluator.create_model_comparison_chart(save_path="reports/model_comparison.png")
                    
                    print("\n🔧 Hyperparameter Tuning:")
                    best_model, best_params, best_score = evaluator.hyperparameter_tuning(X_train, y_train)
                    
                    # Save models
                    evaluator.save_models("models/")
                    
                    logger.info("✅ ML model training completed successfully")
                    return True
            else:
                logger.error("❌ No data file found for ML training")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error in ML model training: {e}")
            return False
    
    def start_dashboard(self):
        """Start the Streamlit dashboard."""
        logger.info("🖥️ Starting Streamlit Dashboard...")
        
        try:
            # Start dashboard in subprocess
            dashboard_cmd = [
                sys.executable, "-m", "streamlit", "run", 
                "dashboard/app.py", 
                "--server.port=8501",
                "--server.address=0.0.0.0",
                "--server.headless=true"
            ]
            
            process = subprocess.Popen(
                dashboard_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            
            self.processes['dashboard'] = process
            logger.info("✅ Dashboard started on http://localhost:8501")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error starting dashboard: {e}")
            return False
    
    def start_api(self):
        """Start the Flask API."""
        logger.info("🌐 Starting Flask API...")
        
        try:
            # Start API in subprocess
            api_cmd = [sys.executable, "src/deployment.py"]
            
            process = subprocess.Popen(
                api_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            
            self.processes['api'] = process
            logger.info("✅ API started on http://localhost:5000")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error starting API: {e}")
            return False
    
    def start_automation(self):
        """Start the automation system."""
        logger.info("🤖 Starting Automation System...")
        
        try:
            # Start automation in subprocess
            automation_cmd = [sys.executable, "src/automation.py"]
            
            process = subprocess.Popen(
                automation_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            
            self.processes['automation'] = process
            logger.info("✅ Automation system started")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error starting automation: {e}")
            return False
    
    def check_dependencies(self):
        """Check if all required dependencies are installed."""
        logger.info("🔍 Checking system dependencies...")
        
        required_packages = [
            'streamlit', 'pandas', 'numpy', 'matplotlib', 'seaborn',
            'plotly', 'scikit-learn', 'flask', 'flask-cors', 'schedule',
            'requests', 'joblib'
        ]
        
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                logger.info(f"✅ {package} - OK")
            except ImportError:
                missing_packages.append(package)
                logger.warning(f"❌ {package} - MISSING")
        
        if missing_packages:
            logger.error(f"Missing packages: {', '.join(missing_packages)}")
            logger.info("Install missing packages with: pip install " + " ".join(missing_packages))
            return False
        
        logger.info("✅ All dependencies satisfied")
        return True
    
    def install_requirements(self):
        """Install requirements from requirements.txt."""
        logger.info("📦 Installing requirements...")
        
        try:
            if os.path.exists("requirements.txt"):
                cmd = [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.info("✅ Requirements installed successfully")
                    return True
                else:
                    logger.error(f"❌ Error installing requirements: {result.stderr}")
                    return False
            else:
                logger.warning("❌ requirements.txt not found")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error installing requirements: {e}")
            return False
    
    def create_sample_data(self):
        """Create sample data if no data files exist."""
        logger.info("📊 Creating sample data...")
        
        try:
            data_file = "data/CloudWatch_Traffic_Web_Attack.csv"
            
            if not os.path.exists(data_file):
                # Import automation to use its data generation
                from src.automation import CyberSecurityAutomation
                
                automation = CyberSecurityAutomation()
                sample_df = automation.generate_synthetic_data(n_samples=2000)
                
                sample_df.to_csv(data_file, index=False)
                logger.info(f"✅ Sample data created: {data_file}")
                return True
            else:
                logger.info("✅ Data file already exists")
                return True
                
        except Exception as e:
            logger.error(f"❌ Error creating sample data: {e}")
            return False
    
    def run_full_analysis(self):
        """Run the complete analysis pipeline."""
        logger.info("🚀 Starting Full Analysis Pipeline...")
        
        # Step 1: Create sample data if needed
        if not self.create_sample_data():
            return False
        
        # Step 2: Run EDA
        if not self.run_eda_analysis():
            logger.warning("⚠️ EDA analysis failed, continuing...")
        
        # Step 3: Train ML models
        if not self.train_ml_models():
            logger.warning("⚠️ ML model training failed, continuing...")
        
        logger.info("✅ Full analysis pipeline completed")
        return True
    
    def start_full_system(self):
        """Start the complete cybersecurity system."""
        logger.info("🚀 STARTING COMPLETE CYBERSECURITY SYSTEM")
        logger.info("=" * 60)
        
        self.is_running = True
        
        # Check dependencies
        if not self.check_dependencies():
            logger.error("❌ Dependency check failed")
            return False
        
        # Create sample data
        self.create_sample_data()
        
        # Start all components
        components_started = []
        
        # Start API
        if self.start_api():
            components_started.append("API")
            time.sleep(3)  # Give API time to start
        
        # Start Dashboard
        if self.start_dashboard():
            components_started.append("Dashboard")
            time.sleep(3)  # Give dashboard time to start
        
        # Start Automation
        if self.start_automation():
            components_started.append("Automation")
        
        if components_started:
            logger.info(f"✅ Started components: {', '.join(components_started)}")
            
            # Display access information
            print("\n🎉 CYBERSECURITY SYSTEM STARTED SUCCESSFULLY!")
            print("=" * 50)
            print("📊 Dashboard: http://localhost:8501")
            print("🌐 API: http://localhost:5000")
            print("🤖 Automation: Running in background")
            print("\n💡 Press Ctrl+C to stop all services")
            print("=" * 50)
            
            # Keep system running
            try:
                while self.is_running:
                    time.sleep(10)
                    # Check if processes are still running
                    for name, process in self.processes.items():
                        if process.poll() is not None:
                            logger.warning(f"⚠️ {name} process stopped unexpectedly")
            
            except KeyboardInterrupt:
                logger.info("🛑 Shutdown signal received")
                self.stop_all()
        
        else:
            logger.error("❌ Failed to start any components")
            return False
        
        return True
    
    def stop_all(self):
        """Stop all running processes."""
        logger.info("🛑 Stopping all services...")
        
        self.is_running = False
        
        # Stop all processes
        for name, process in self.processes.items():
            try:
                logger.info(f"Stopping {name}...")
                process.terminate()
                process.wait(timeout=10)
                logger.info(f"✅ {name} stopped")
            except subprocess.TimeoutExpired:
                logger.warning(f"⚠️ Force killing {name}")
                process.kill()
            except Exception as e:
                logger.error(f"❌ Error stopping {name}: {e}")
        
        # Stop threads
        for name, thread in self.threads.items():
            logger.info(f"Stopping {name} thread...")
            thread.join(timeout=5)
        
        logger.info("✅ All services stopped")

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info("Received shutdown signal")
    if 'system' in globals():
        system.stop_all()
    sys.exit(0)

def main():
    """Main function with command line interface."""
    parser = argparse.ArgumentParser(description="Cybersecurity Web Threat Analysis System")
    
    parser.add_argument('--mode', choices=['full', 'dashboard', 'api', 'automation', 'analysis'], 
                       default='full', help='System mode to run')
    parser.add_argument('--install-deps', action='store_true', 
                       help='Install dependencies from requirements.txt')
    parser.add_argument('--check-deps', action='store_true', 
                       help='Check system dependencies')
    parser.add_argument('--create-data', action='store_true', 
                       help='Create sample data')
    
    args = parser.parse_args()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize system
    global system
    system = CyberSecuritySystem()
    
    # Handle command line options
    if args.install_deps:
        system.install_requirements()
        return
    
    if args.check_deps:
        system.check_dependencies()
        return
    
    if args.create_data:
        system.create_sample_data()
        return
    
    # Run based on mode
    if args.mode == 'full':
        system.start_full_system()
    
    elif args.mode == 'dashboard':
        system.create_sample_data()
        system.start_dashboard()
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            system.stop_all()
    
    elif args.mode == 'api':
        system.create_sample_data()
        system.start_api()
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            system.stop_all()
    
    elif args.mode == 'automation':
        system.create_sample_data()
        system.start_automation()
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            system.stop_all()
    
    elif args.mode == 'analysis':
        system.run_full_analysis()

if __name__ == "__main__":
    print("🛡️ CYBERSECURITY WEB THREAT ANALYSIS SYSTEM")
    print("=" * 60)
    print("🚀 Advanced AI-Powered Threat Detection Platform")
    print("📊 Real-time Analytics & Machine Learning")
    print("=" * 60)
    
    main()