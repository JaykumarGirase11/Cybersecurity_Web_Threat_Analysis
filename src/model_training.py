"""
Cybersecurity Web Threat Analysis - Machine Learning Module
===========================================================

This module handles machine learning model training, evaluation, and prediction
for cybersecurity threat detection and anomaly analysis.
"""

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.cluster import DBSCAN, KMeans
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

class CyberThreatMLModels:
    """
    Comprehensive machine learning class for cybersecurity threat analysis.
    """
    
    def __init__(self):
        self.isolation_forest = None
        self.random_forest = None
        self.dbscan = None
        self.kmeans = None
        self.models_trained = False
        
    def load_processed_data(self, filepath):
        """Load preprocessed cybersecurity dataset."""
        try:
            df = pd.read_csv(filepath)
            print(f"✅ Processed dataset loaded! Shape: {df.shape}")
            return df
        except Exception as e:
            print(f"❌ Error loading dataset: {e}")
            return None
    
    def prepare_features(self, df):
        """
        Prepare feature sets for machine learning models.
        
        Args:
            df (pd.DataFrame): Processed dataset
            
        Returns:
            dict: Dictionary containing different feature sets
        """
        print("🔧 Preparing feature sets for ML models...")
        
        # Scaled numeric features for anomaly detection
        scaled_features = [col for col in df.columns if col.startswith('scaled_')]
        
        # All engineered features
        feature_cols = scaled_features + [col for col in df.columns if col.startswith('src_ip_country_code_') or col.startswith('protocol_')]
        
        # Time-based features
        time_features = ['hour_of_day', 'day_of_week'] if 'hour_of_day' in df.columns else []
        
        # Risk features
        risk_features = ['port_risk_score'] if 'port_risk_score' in df.columns else []
        
        feature_sets = {
            'anomaly_features': scaled_features,
            'classification_features': feature_cols + time_features + risk_features,
            'clustering_features': scaled_features + time_features,
            'all_features': list(set(feature_cols + time_features + risk_features))
        }
        
        print(f"   • Anomaly detection features: {len(feature_sets['anomaly_features'])}")
        print(f"   • Classification features: {len(feature_sets['classification_features'])}")
        print(f"   • Clustering features: {len(feature_sets['clustering_features'])}")
        
        return feature_sets
    
    def train_isolation_forest(self, df, features, contamination=0.05):
        """
        Train Isolation Forest for anomaly detection.
        
        Args:
            df (pd.DataFrame): Dataset
            features (list): Feature columns
            contamination (float): Expected proportion of anomalies
            
        Returns:
            pd.DataFrame: Dataset with anomaly predictions
        """
        print("🌲 Training Isolation Forest for anomaly detection...")
        
        # Filter existing features
        existing_features = [col for col in features if col in df.columns]
        X = df[existing_features]
        
        # Initialize and train model
        self.isolation_forest = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        
        # Fit and predict
        anomaly_labels = self.isolation_forest.fit_predict(X)
        df['anomaly_score'] = self.isolation_forest.decision_function(X)
        df['anomaly'] = np.where(anomaly_labels == -1, 'Suspicious', 'Normal')
        
        # Calculate statistics
        anomaly_count = (df['anomaly'] == 'Suspicious').sum()
        normal_count = (df['anomaly'] == 'Normal').sum()
        
        print(f"   • Model trained successfully!")
        print(f"   • Normal traffic: {normal_count:,} ({normal_count/len(df)*100:.1f}%)")
        print(f"   • Suspicious traffic: {anomaly_count:,} ({anomaly_count/len(df)*100:.1f}%)")
        
        return df
    
    def train_random_forest_classifier(self, df, features, target='anomaly'):
        """
        Train Random Forest classifier for supervised learning.
        
        Args:
            df (pd.DataFrame): Dataset with anomaly labels
            features (list): Feature columns
            target (str): Target column name
            
        Returns:
            dict: Training results and metrics
        """
        print("🌳 Training Random Forest classifier...")
        
        # Prepare data
        existing_features = [col for col in features if col in df.columns]
        X = df[existing_features]
        y = df[target].map({'Normal': 0, 'Suspicious': 1})
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Initialize and train model
        self.random_forest = RandomForestClassifier(
            n_estimators=200,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        self.random_forest.fit(X_train, y_train)
        
        # Make predictions
        y_pred = self.random_forest.predict(X_test)
        y_pred_proba = self.random_forest.predict_proba(X_test)[:, 1]
        
        # Calculate metrics
        accuracy = self.random_forest.score(X_test, y_test)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        
        # Cross-validation
        cv_scores = cross_val_score(self.random_forest, X_train, y_train, cv=5)
        
        print(f"   • Model trained successfully!")
        print(f"   • Test Accuracy: {accuracy:.3f}")
        print(f"   • ROC AUC Score: {roc_auc:.3f}")
        print(f"   • Cross-validation Score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
        
        return {
            'model': self.random_forest,
            'accuracy': accuracy,
            'roc_auc': roc_auc,
            'cv_scores': cv_scores,
            'classification_report': classification_report(y_test, y_pred),
            'confusion_matrix': confusion_matrix(y_test, y_pred),
            'feature_importance': dict(zip(existing_features, self.random_forest.feature_importances_))
        }
    
    def perform_clustering(self, df, features):
        """
        Perform clustering analysis using DBSCAN and K-Means.
        
        Args:
            df (pd.DataFrame): Dataset
            features (list): Feature columns for clustering
            
        Returns:
            pd.DataFrame: Dataset with cluster labels
        """
        print("🎯 Performing clustering analysis...")
        
        # Prepare data
        existing_features = [col for col in features if col in df.columns]
        X = df[existing_features]
        
        # DBSCAN Clustering
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        df['dbscan_cluster'] = self.dbscan.fit_predict(X)
        
        # K-Means Clustering
        self.kmeans = KMeans(n_clusters=5, random_state=42)
        df['kmeans_cluster'] = self.kmeans.fit_predict(X)
        
        # Statistics
        dbscan_clusters = len(set(df['dbscan_cluster'])) - (1 if -1 in df['dbscan_cluster'] else 0)
        kmeans_clusters = len(set(df['kmeans_cluster']))
        
        print(f"   • DBSCAN clusters found: {dbscan_clusters}")
        print(f"   • K-Means clusters: {kmeans_clusters}")
        print(f"   • DBSCAN noise points: {(df['dbscan_cluster'] == -1).sum()}")
        
        return df
    
    def get_feature_importance(self, top_n=10):
        """Get top feature importances from Random Forest."""
        if self.random_forest is None:
            return None
            
        feature_importance = dict(zip(
            self.random_forest.feature_names_in_,
            self.random_forest.feature_importances_
        ))
        
        return dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:top_n])
    
    def predict_new_data(self, new_data, model_type='isolation_forest'):
        """
        Make predictions on new data.
        
        Args:
            new_data (pd.DataFrame): New data for prediction
            model_type (str): Type of model to use
            
        Returns:
            np.array: Predictions
        """
        if model_type == 'isolation_forest' and self.isolation_forest is not None:
            return self.isolation_forest.predict(new_data)
        elif model_type == 'random_forest' and self.random_forest is not None:
            return self.random_forest.predict(new_data)
        else:
            print(f"❌ Model {model_type} not trained yet!")
            return None
    
    def save_models(self, model_dir="../models/"):
        """Save trained models to disk."""
        import os
        os.makedirs(model_dir, exist_ok=True)
        
        if self.isolation_forest is not None:
            joblib.dump(self.isolation_forest, f"{model_dir}isolation_forest.pkl")
            print(f"   • Isolation Forest saved to {model_dir}isolation_forest.pkl")
        
        if self.random_forest is not None:
            joblib.dump(self.random_forest, f"{model_dir}random_forest.pkl")
            print(f"   • Random Forest saved to {model_dir}random_forest.pkl")
        
        if self.kmeans is not None:
            joblib.dump(self.kmeans, f"{model_dir}kmeans.pkl")
            print(f"   • K-Means saved to {model_dir}kmeans.pkl")
    
    def load_models(self, model_dir="../models/"):
        """Load trained models from disk."""
        try:
            self.isolation_forest = joblib.load(f"{model_dir}isolation_forest.pkl")
            self.random_forest = joblib.load(f"{model_dir}random_forest.pkl")
            self.kmeans = joblib.load(f"{model_dir}kmeans.pkl")
            print("✅ Models loaded successfully!")
            self.models_trained = True
        except Exception as e:
            print(f"❌ Error loading models: {e}")
    
    def train_complete_pipeline(self, df):
        """
        Train all models in a complete pipeline.
        
        Args:
            df (pd.DataFrame): Processed dataset
            
        Returns:
            dict: Complete training results
        """
        print("🚀 Starting complete ML training pipeline...")
        print("=" * 60)
        
        # Prepare features
        feature_sets = self.prepare_features(df)
        
        # Train Isolation Forest
        df = self.train_isolation_forest(df, feature_sets['anomaly_features'])
        
        # Train Random Forest Classifier
        rf_results = self.train_random_forest_classifier(df, feature_sets['classification_features'])
        
        # Perform Clustering
        df = self.perform_clustering(df, feature_sets['clustering_features'])
        
        # Save models
        self.save_models()
        
        self.models_trained = True
        
        print("=" * 60)
        print("🎉 Complete ML pipeline training finished!")
        
        return {
            'processed_data': df,
            'random_forest_results': rf_results,
            'feature_sets': feature_sets
        }

def main():
    """Example usage of the ML training pipeline."""
    # Initialize ML models
    ml_models = CyberThreatMLModels()
    
    # Load processed data
    df = ml_models.load_processed_data("../data/transformed_cyber_data.csv")
    
    if df is not None:
        # Train complete pipeline
        results = ml_models.train_complete_pipeline(df)
        
        # Save final results
        results['processed_data'].to_csv("../data/ml_results_data.csv", index=False)
        
        # Display feature importance
        feature_importance = ml_models.get_feature_importance()
        if feature_importance:
            print("\n🎯 Top 10 Most Important Features:")
            for i, (feature, importance) in enumerate(feature_importance.items(), 1):
                print(f"   {i:2d}. {feature:<30} {importance:.4f}")

if __name__ == "__main__":
    main()