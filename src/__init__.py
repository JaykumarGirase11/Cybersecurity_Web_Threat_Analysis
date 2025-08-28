"""
Cybersecurity Web Threat Analysis Package
==========================================

A comprehensive cybersecurity threat analysis package that provides advanced
machine learning-based threat detection, interactive dashboards, and detailed
security analytics for network traffic analysis.

Author: Your Name
Version: 1.0.0
License: MIT

Main Components:
- Data preprocessing and feature engineering
- Machine learning models (Isolation Forest, Random Forest)
- Interactive dashboard with real-time visualizations
- Comprehensive threat analysis and reporting
- Database management and SQL analytics
- Export capabilities (Excel, PDF)

Usage:
    from src.preprocess import CyberDataPreprocessor
    from src.model_training import CyberThreatMLModels
    from src.eda import CyberThreatEDA
    from src.utils import DatabaseManager, ConfigManager
    
Example:
    # Data preprocessing
    preprocessor = CyberDataPreprocessor()
    df = preprocessor.preprocess_pipeline("data/raw_data.csv")
    
    # Machine learning
    ml_models = CyberThreatMLModels()
    results = ml_models.train_complete_pipeline(df)
    
    # Run dashboard
    python dashboard/app.py
"""

__version__ = "1.0.0"
__author__ = "Cybersecurity Analysis Team"
__email__ = "security@yourcompany.com"
__license__ = "MIT"

# Package metadata
PACKAGE_NAME = "cybersecurity_threat_analysis"
DESCRIPTION = "Advanced cybersecurity threat analysis with ML and interactive dashboards"
KEYWORDS = ["cybersecurity", "threat analysis", "machine learning", "dashboard", "anomaly detection"]

# Import main classes for easy access
try:
    from .preprocess import CyberDataPreprocessor
    from .model_training import CyberThreatMLModels
    from .eda import CyberThreatEDA
    from .utils import (
        DatabaseManager, 
        ConfigManager, 
        Logger, 
        MetricsCalculator,
        ReportGenerator
    )
    
    # Define what gets imported with "from src import *"
    __all__ = [
        'CyberDataPreprocessor',
        'CyberThreatMLModels', 
        'CyberThreatEDA',
        'DatabaseManager',
        'ConfigManager',
        'Logger',
        'MetricsCalculator',
        'ReportGenerator'
    ]
    
except ImportError as e:
    # Handle import errors gracefully
    print(f"Warning: Some modules could not be imported: {e}")
    __all__ = []

# Configuration
DEFAULT_CONFIG = {
    "data_dir": "../data/",
    "model_dir": "../models/",
    "reports_dir": "../reports/",
    "logs_dir": "../logs/"
}

def get_version():
    """Get the package version."""
    return __version__

def get_info():
    """Get package information."""
    return {
        "name": PACKAGE_NAME,
        "version": __version__,
        "description": DESCRIPTION,
        "author": __author__,
        "license": __license__,
        "keywords": KEYWORDS
    }

def setup_directories():
    """Create necessary directories for the project."""
    import os
    
    directories = [
        "../data/",
        "../models/", 
        "../reports/",
        "../logs/",
        "../assets/"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    print("✅ Project directories created successfully!")

# Initialize logging
def setup_logging():
    """Setup logging configuration for the package."""
    import logging
    import os
    
    # Create logs directory if it doesn't exist
    os.makedirs("../logs", exist_ok=True)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('../logs/cybersecurity_analysis.log'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Cybersecurity Threat Analysis package initialized")
    
    return logger

# Package initialization
logger = setup_logging()
setup_directories()

# Welcome message
def print_welcome():
    """Print welcome message with package information."""
    print("🛡️" + "="*60 + "🛡️")
    print("   CYBERSECURITY WEB THREAT ANALYSIS DASHBOARD")
    print("="*64)
    print(f"📦 Package: {PACKAGE_NAME}")
    print(f"🔧 Version: {__version__}")
    print(f"👨‍💻 Author: {__author__}")
    print(f"📝 License: {__license__}")
    print("="*64)
    print("🚀 Features:")
    print("   • Advanced Machine Learning Threat Detection")
    print("   • Real-time Interactive Dashboard")
    print("   • Comprehensive Data Analysis & Visualization")
    print("   • Automated Report Generation")
    print("   • SQL Analytics & Database Management")
    print("   • Geographic Threat Mapping")
    print("   • Protocol & Port Security Analysis")
    print("="*64)
    print("🎯 Quick Start:")
    print("   1. Install dependencies: pip install -r requirements.txt")
    print("   2. Run data analysis: python -m src.preprocess")
    print("   3. Train ML models: python -m src.model_training")
    print("   4. Launch dashboard: python dashboard/app.py")
    print("   5. Open browser: http://localhost:8050")
    print("🛡️" + "="*60 + "🛡️")

# Print welcome message when package is imported
if __name__ != "__main__":
    print_welcome()

def main():
    """Main entry point for the package."""
    print_welcome()
    
    print("\n🔧 Initializing Cybersecurity Threat Analysis System...")
    
    try:
        # Import and initialize main components
        from .utils import ConfigManager, DatabaseManager
        
        config = ConfigManager()
        db = DatabaseManager()
        
        print("✅ Configuration loaded successfully")
        print("✅ Database initialized successfully")
        print("✅ System ready for threat analysis!")
        
        print("\n📊 Available Commands:")
        print("   • python -m src.preprocess    - Run data preprocessing")
        print("   • python -m src.model_training - Train ML models")
        print("   • python -m src.eda          - Generate EDA report")
        print("   • python dashboard/app.py    - Launch dashboard")
        
    except Exception as e:
        print(f"❌ Error initializing system: {e}")
        print("💡 Please check your installation and try again")

if __name__ == "__main__":
    main()