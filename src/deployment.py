"""
Cybersecurity Web Threat Analysis - Flask API for Real-time Predictions
======================================================================

This module provides a Flask API to serve real-time predictions from trained models.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import joblib
import os
import logging
from datetime import datetime
import sqlite3
from sklearn.preprocessing import StandardScaler, LabelEncoder
import warnings
warnings.filterwarnings('ignore')

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for frontend integration

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for models and scalers
models = {}
scaler = None
label_encoders = {}

def load_trained_models():
    """Load pre-trained models from disk."""
    global models, scaler, label_encoders
    
    models_dir = "../models/"
    
    try:
        # Load models
        model_files = {
            'isolation_forest': 'isolation_forest_model.joblib',
            'random_forest': 'random_forest_model.joblib',
            'logistic_regression': 'logistic_regression_model.joblib'
        }
        
        for model_name, filename in model_files.items():
            filepath = os.path.join(models_dir, filename)
            if os.path.exists(filepath):
                models[model_name] = joblib.load(filepath)
                logger.info(f"Loaded {model_name} model successfully")
            else:
                logger.warning(f"Model file not found: {filepath}")
        
        # Load scaler
        scaler_path = os.path.join(models_dir, "scaler.joblib")
        if os.path.exists(scaler_path):
            scaler = joblib.load(scaler_path)
            logger.info("Loaded scaler successfully")
        else:
            scaler = StandardScaler()
            logger.warning("Scaler not found, using new StandardScaler")
        
        # Load label encoders
        encoder_files = ['protocol_encoder.joblib', 'country_encoder.joblib']
        for encoder_file in encoder_files:
            encoder_path = os.path.join(models_dir, encoder_file)
            if os.path.exists(encoder_path):
                encoder_name = encoder_file.replace('_encoder.joblib', '')
                label_encoders[encoder_name] = joblib.load(encoder_path)
                logger.info(f"Loaded {encoder_name} encoder successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"Error loading models: {e}")
        return False

def preprocess_request_data(data):
    """Preprocess incoming request data for model prediction."""
    try:
        # Create DataFrame from request data
        df = pd.DataFrame([data])
        
        # Required features for ML models
        feature_columns = []
        
        # Numerical features
        numerical_cols = ['bytes_in', 'bytes_out', 'dst_port']
        for col in numerical_cols:
            if col in df.columns:
                feature_columns.append(col)
                df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Create derived features
        if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
            df['total_bytes'] = df['bytes_in'] + df['bytes_out']
            df['bytes_ratio'] = df['bytes_out'] / (df['bytes_in'] + 1)
            feature_columns.extend(['total_bytes', 'bytes_ratio'])
        
        # Encode categorical features
        if 'protocol' in df.columns and 'protocol' in label_encoders:
            try:
                df['protocol_encoded'] = label_encoders['protocol'].transform(df['protocol'])
                feature_columns.append('protocol_encoded')
            except ValueError:
                # Handle unknown protocol
                df['protocol_encoded'] = 0
                feature_columns.append('protocol_encoded')
        
        if 'src_ip_country_code' in df.columns and 'country' in label_encoders:
            try:
                df['country_encoded'] = label_encoders['country'].transform(df['src_ip_country_code'])
                feature_columns.append('country_encoded')
            except ValueError:
                # Handle unknown country
                df['country_encoded'] = 0
                feature_columns.append('country_encoded')
        
        # Time-based features
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            df['hour'] = df['timestamp'].dt.hour
            df['day_of_week'] = df['timestamp'].dt.dayofweek
            feature_columns.extend(['hour', 'day_of_week'])
        else:
            # Use current time if no timestamp provided
            now = datetime.now()
            df['hour'] = now.hour
            df['day_of_week'] = now.weekday()
            feature_columns.extend(['hour', 'day_of_week'])
        
        # Select and fill missing values
        X = df[feature_columns].fillna(0)
        
        # Scale features
        if scaler:
            X_scaled = scaler.transform(X)
        else:
            X_scaled = X.values
        
        return X_scaled, feature_columns
        
    except Exception as e:
        logger.error(f"Error preprocessing data: {e}")
        return None, None

def log_suspicious_activity(data, prediction_results):
    """Log suspicious activity to database."""
    try:
        db_path = "../data/suspicious_activity.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                src_country TEXT,
                protocol TEXT,
                dst_port INTEGER,
                bytes_in INTEGER,
                bytes_out INTEGER,
                total_bytes INTEGER,
                threat_level TEXT,
                isolation_forest_score REAL,
                random_forest_probability REAL,
                is_suspicious INTEGER
            )
        ''')
        
        # Insert suspicious activity
        cursor.execute('''
            INSERT INTO suspicious_activity 
            (src_ip, dst_ip, src_country, protocol, dst_port, bytes_in, bytes_out, 
             total_bytes, threat_level, isolation_forest_score, random_forest_probability, is_suspicious)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('src_ip', 'Unknown'),
            data.get('dst_ip', 'Unknown'),
            data.get('src_ip_country_code', 'Unknown'),
            data.get('protocol', 'Unknown'),
            data.get('dst_port', 0),
            data.get('bytes_in', 0),
            data.get('bytes_out', 0),
            data.get('bytes_in', 0) + data.get('bytes_out', 0),
            prediction_results.get('threat_level', 'Unknown'),
            prediction_results.get('isolation_forest_score', 0),
            prediction_results.get('random_forest_probability', 0),
            1 if prediction_results.get('is_suspicious', False) else 0
        ))
        
        conn.commit()
        conn.close()
        
        logger.info("Suspicious activity logged to database")
        
    except Exception as e:
        logger.error(f"Error logging to database: {e}")

@app.route('/', methods=['GET'])
def home():
    """API home endpoint."""
    return jsonify({
        'message': 'Cybersecurity Threat Analysis API',
        'version': '1.0.0',
        'status': 'active',
        'available_endpoints': [
            '/predict',
            '/health',
            '/models',
            '/stats'
        ]
    })

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'models_loaded': len(models),
        'scaler_loaded': scaler is not None
    })

@app.route('/models', methods=['GET'])
def get_models_info():
    """Get information about loaded models."""
    model_info = {}
    
    for model_name, model in models.items():
        model_info[model_name] = {
            'type': type(model).__name__,
            'loaded': True
        }
    
    return jsonify({
        'models': model_info,
        'scaler_loaded': scaler is not None,
        'encoders_loaded': list(label_encoders.keys())
    })

@app.route('/predict', methods=['POST'])
def predict_threat():
    """Main prediction endpoint."""
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Preprocess data
        X_scaled, features = preprocess_request_data(data)
        
        if X_scaled is None:
            return jsonify({'error': 'Error preprocessing data'}), 400
        
        # Make predictions with available models
        predictions = {}
        
        # Isolation Forest (Anomaly Detection)
        if 'isolation_forest' in models:
            iso_prediction = models['isolation_forest'].predict(X_scaled)[0]
            iso_score = models['isolation_forest'].decision_function(X_scaled)[0]
            predictions['isolation_forest'] = {
                'is_anomaly': iso_prediction == -1,
                'anomaly_score': float(iso_score),
                'confidence': abs(float(iso_score))
            }
        
        # Random Forest (Classification)
        if 'random_forest' in models:
            rf_prediction = models['random_forest'].predict(X_scaled)[0]
            rf_probability = models['random_forest'].predict_proba(X_scaled)[0]
            predictions['random_forest'] = {
                'is_threat': bool(rf_prediction),
                'threat_probability': float(rf_probability[1]) if len(rf_probability) > 1 else float(rf_probability[0]),
                'confidence': float(max(rf_probability))
            }
        
        # Logistic Regression
        if 'logistic_regression' in models:
            lr_prediction = models['logistic_regression'].predict(X_scaled)[0]
            lr_probability = models['logistic_regression'].predict_proba(X_scaled)[0]
            predictions['logistic_regression'] = {
                'is_threat': bool(lr_prediction),
                'threat_probability': float(lr_probability[1]) if len(lr_probability) > 1 else float(lr_probability[0]),
                'confidence': float(max(lr_probability))
            }
        
        # Determine overall threat assessment
        threat_indicators = []
        
        if 'isolation_forest' in predictions:
            threat_indicators.append(predictions['isolation_forest']['is_anomaly'])
        
        if 'random_forest' in predictions:
            threat_indicators.append(predictions['random_forest']['is_threat'])
        
        if 'logistic_regression' in predictions:
            threat_indicators.append(predictions['logistic_regression']['is_threat'])
        
        # Calculate overall threat level
        threat_count = sum(threat_indicators)
        total_models = len(threat_indicators)
        
        if threat_count == 0:
            overall_threat = 'Low'
            is_suspicious = False
        elif threat_count / total_models < 0.5:
            overall_threat = 'Medium'
            is_suspicious = False
        elif threat_count / total_models < 0.8:
            overall_threat = 'High'
            is_suspicious = True
        else:
            overall_threat = 'Critical'
            is_suspicious = True
        
        # Prepare response
        response = {
            'timestamp': datetime.now().isoformat(),
            'predictions': predictions,
            'overall_assessment': {
                'threat_level': overall_threat,
                'is_suspicious': is_suspicious,
                'confidence_score': threat_count / total_models if total_models > 0 else 0,
                'models_agreement': f"{threat_count}/{total_models}"
            },
            'input_features': dict(zip(features, X_scaled[0].tolist())) if features else {},
            'recommendations': generate_recommendations(overall_threat, predictions)
        }
        
        # Log suspicious activity
        if is_suspicious:
            log_suspicious_activity(data, response['overall_assessment'])
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in prediction: {e}")
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

def generate_recommendations(threat_level, predictions):
    """Generate security recommendations based on threat level."""
    recommendations = []
    
    if threat_level == 'Critical':
        recommendations = [
            "🚨 IMMEDIATE ACTION REQUIRED",
            "Block source IP immediately",
            "Escalate to security team",
            "Monitor for additional attacks from same source",
            "Review firewall rules and access controls"
        ]
    elif threat_level == 'High':
        recommendations = [
            "⚠️ High priority investigation needed",
            "Monitor source IP closely",
            "Review connection patterns",
            "Consider temporary access restrictions",
            "Alert security team"
        ]
    elif threat_level == 'Medium':
        recommendations = [
            "🔍 Increased monitoring recommended",
            "Log all activities from this source",
            "Review for pattern anomalies",
            "Consider rate limiting"
        ]
    else:
        recommendations = [
            "✅ Normal traffic pattern",
            "Continue standard monitoring",
            "No immediate action required"
        ]
    
    return recommendations

@app.route('/stats', methods=['GET'])
def get_statistics():
    """Get API usage statistics."""
    try:
        db_path = "../data/suspicious_activity.db"
        
        if not os.path.exists(db_path):
            return jsonify({
                'total_predictions': 0,
                'suspicious_activities': 0,
                'threat_distribution': {},
                'message': 'No statistics available yet'
            })
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get total predictions (assuming we log all suspicious ones)
        cursor.execute("SELECT COUNT(*) FROM suspicious_activity")
        total_suspicious = cursor.fetchone()[0]
        
        # Get threat level distribution
        cursor.execute("""
            SELECT threat_level, COUNT(*) 
            FROM suspicious_activity 
            GROUP BY threat_level
        """)
        threat_dist = dict(cursor.fetchall())
        
        # Get recent activity (last 24 hours)
        cursor.execute("""
            SELECT COUNT(*) 
            FROM suspicious_activity 
            WHERE timestamp > datetime('now', '-1 day')
        """)
        recent_activity = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_suspicious_activities': total_suspicious,
            'recent_activity_24h': recent_activity,
            'threat_distribution': threat_dist,
            'api_status': 'active',
            'last_updated': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({'error': f'Statistics unavailable: {str(e)}'}), 500

@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """Batch prediction endpoint for multiple requests."""
    try:
        data = request.get_json()
        
        if not data or 'requests' not in data:
            return jsonify({'error': 'No batch requests provided'}), 400
        
        requests_data = data['requests']
        batch_results = []
        
        for i, req_data in enumerate(requests_data):
            try:
                # Preprocess individual request
                X_scaled, features = preprocess_request_data(req_data)
                
                if X_scaled is None:
                    batch_results.append({
                        'index': i,
                        'error': 'Preprocessing failed',
                        'status': 'failed'
                    })
                    continue
                
                # Quick prediction (only use fastest model)
                if 'isolation_forest' in models:
                    iso_prediction = models['isolation_forest'].predict(X_scaled)[0]
                    iso_score = models['isolation_forest'].decision_function(X_scaled)[0]
                    
                    batch_results.append({
                        'index': i,
                        'is_suspicious': iso_prediction == -1,
                        'anomaly_score': float(iso_score),
                        'threat_level': 'High' if iso_prediction == -1 else 'Low',
                        'status': 'success'
                    })
                else:
                    batch_results.append({
                        'index': i,
                        'error': 'No models available',
                        'status': 'failed'
                    })
                    
            except Exception as e:
                batch_results.append({
                    'index': i,
                    'error': str(e),
                    'status': 'failed'
                })
        
        return jsonify({
            'batch_results': batch_results,
            'total_processed': len(batch_results),
            'successful': len([r for r in batch_results if r.get('status') == 'success']),
            'failed': len([r for r in batch_results if r.get('status') == 'failed']),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in batch prediction: {e}")
        return jsonify({'error': f'Batch prediction failed: {str(e)}'}), 500

if __name__ == '__main__':
    # Load models on startup
    logger.info("Starting Cybersecurity Threat Analysis API...")
    
    if load_trained_models():
        logger.info("Models loaded successfully")
    else:
        logger.warning("Some models failed to load, API will work with available models")
    
    # Create models directory if it doesn't exist
    os.makedirs("../models/", exist_ok=True)
    os.makedirs("../data/", exist_ok=True)
    
    # Run Flask app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,  # Set to False for production
        threaded=True
    )