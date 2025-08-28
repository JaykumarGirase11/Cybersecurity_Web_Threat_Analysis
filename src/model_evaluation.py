"""
Cybersecurity Web Threat Analysis - Model Evaluation Module
===========================================================

This module provides comprehensive model evaluation and comparison capabilities
for machine learning models in cybersecurity threat analysis.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import SVM
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix, roc_curve, auc, 
                           precision_recall_curve, f1_score, accuracy_score, 
                           precision_score, recall_score)
from sklearn.preprocessing import StandardScaler, LabelEncoder
import joblib
import warnings
warnings.filterwarnings('ignore')

class ModelEvaluator:
    """
    Comprehensive model evaluation and comparison class for cybersecurity models.
    """
    
    def __init__(self, figsize=(12, 8)):
        self.figsize = figsize
        self.models = {}
        self.results = {}
        self.color_palette = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FECA57', '#FF9FF3', '#54A0FF']
        
    def prepare_data_for_ml(self, df, target_column='is_suspicious'):
        """Prepare data for machine learning models."""
        print("🔧 PREPARING DATA FOR MACHINE LEARNING")
        print("=" * 50)
        
        # Create target variable if not exists
        if target_column not in df.columns:
            if 'anomaly' in df.columns:
                df[target_column] = (df['anomaly'] == 'Suspicious').astype(int)
            elif 'threat_level' in df.columns:
                df[target_column] = df['threat_level'].isin(['High', 'Critical']).astype(int)
            else:
                # Create synthetic target based on bytes threshold
                if 'total_bytes' in df.columns:
                    threshold = df['total_bytes'].quantile(0.9)
                    df[target_column] = (df['total_bytes'] > threshold).astype(int)
                else:
                    print("❌ Cannot create target variable")
                    return None, None, None, None
        
        # Select features for ML
        feature_columns = []
        
        # Numerical features
        numerical_cols = ['bytes_in', 'bytes_out', 'total_bytes', 'dst_port', 'session_duration']
        for col in numerical_cols:
            if col in df.columns:
                feature_columns.append(col)
        
        # Create derived features
        if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
            df['bytes_ratio'] = df['bytes_out'] / (df['bytes_in'] + 1)
            feature_columns.append('bytes_ratio')
        
        # Encode categorical features
        if 'protocol' in df.columns:
            le_protocol = LabelEncoder()
            df['protocol_encoded'] = le_protocol.fit_transform(df['protocol'])
            feature_columns.append('protocol_encoded')
        
        if 'src_ip_country_code' in df.columns:
            le_country = LabelEncoder()
            df['country_encoded'] = le_country.fit_transform(df['src_ip_country_code'])
            feature_columns.append('country_encoded')
        
        # Time-based features
        time_cols = ['creation_time', 'time', 'timestamp']
        for time_col in time_cols:
            if time_col in df.columns:
                df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
                df['hour'] = df[time_col].dt.hour
                df['day_of_week'] = df[time_col].dt.dayofweek
                feature_columns.extend(['hour', 'day_of_week'])
                break
        
        # Prepare final dataset
        X = df[feature_columns].fillna(0)
        y = df[target_column]
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        print(f"✅ Data prepared successfully!")
        print(f"   • Features: {len(feature_columns)}")
        print(f"   • Training samples: {len(X_train):,}")
        print(f"   • Test samples: {len(X_test):,}")
        print(f"   • Positive class ratio: {y.mean():.3f}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test, feature_columns
    
    def train_models(self, X_train, y_train, X_test, y_test):
        """Train multiple ML models for comparison."""
        print("\n🤖 TRAINING MACHINE LEARNING MODELS")
        print("=" * 50)
        
        # Define models to train
        models_config = {
            'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'Isolation Forest': IsolationForest(contamination=0.1, random_state=42),
            'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
        }
        
        # Train each model
        for name, model in models_config.items():
            print(f"\n📊 Training {name}...")
            
            try:
                if name == 'Isolation Forest':
                    # Isolation Forest is unsupervised
                    model.fit(X_train)
                    y_pred = model.predict(X_test)
                    # Convert -1 to 1 (anomaly) and 1 to 0 (normal)
                    y_pred = np.where(y_pred == -1, 1, 0)
                    y_pred_proba = model.decision_function(X_test)
                else:
                    # Supervised models
                    model.fit(X_train, y_train)
                    y_pred = model.predict(X_test)
                    if hasattr(model, 'predict_proba'):
                        y_pred_proba = model.predict_proba(X_test)[:, 1]
                    else:
                        y_pred_proba = y_pred
                
                # Store model and results
                self.models[name] = model
                self.results[name] = {
                    'y_pred': y_pred,
                    'y_pred_proba': y_pred_proba,
                    'y_test': y_test
                }
                
                print(f"   ✅ {name} trained successfully!")
                
            except Exception as e:
                print(f"   ❌ Error training {name}: {e}")
        
        return self.models, self.results
    
    def plot_roc_auc_curves(self, save_path=None):
        """Plot ROC/AUC curves for all models."""
        print("\n📈 PLOTTING ROC/AUC CURVES")
        print("=" * 50)
        
        plt.figure(figsize=(12, 8))
        
        for i, (name, results) in enumerate(self.results.items()):
            y_test = results['y_test']
            y_pred_proba = results['y_pred_proba']
            
            # Calculate ROC curve
            if name == 'Isolation Forest':
                # For Isolation Forest, use decision function scores
                fpr, tpr, _ = roc_curve(y_test, -y_pred_proba)  # Negative because lower scores = anomalies
            else:
                fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            
            roc_auc = auc(fpr, tpr)
            
            plt.plot(fpr, tpr, color=self.color_palette[i], lw=2, 
                    label=f'{name} (AUC = {roc_auc:.3f})')
        
        # Plot diagonal line
        plt.plot([0, 1], [0, 1], color='gray', lw=2, linestyle='--', alpha=0.5, label='Random Classifier')
        
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate', fontsize=12, fontweight='bold')
        plt.ylabel('True Positive Rate', fontsize=12, fontweight='bold')
        plt.title('🎯 ROC Curves Comparison - Model Performance', fontsize=14, fontweight='bold')
        plt.legend(loc="lower right", fontsize=10)
        plt.grid(True, alpha=0.3)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print AUC scores
        print("\n📊 AUC SCORES SUMMARY:")
        for name, results in self.results.items():
            y_test = results['y_test']
            y_pred_proba = results['y_pred_proba']
            
            if name == 'Isolation Forest':
                fpr, tpr, _ = roc_curve(y_test, -y_pred_proba)
            else:
                fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            
            roc_auc = auc(fpr, tpr)
            print(f"   • {name:20s}: {roc_auc:.3f}")
    
    def create_precision_recall_f1_table(self):
        """Create comprehensive comparison tables for precision, recall, F1-score."""
        print("\n📋 PRECISION, RECALL, F1-SCORE COMPARISON")
        print("=" * 50)
        
        comparison_data = []
        
        for name, results in self.results.items():
            y_test = results['y_test']
            y_pred = results['y_pred']
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='binary', zero_division=0)
            recall = recall_score(y_test, y_pred, average='binary', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='binary', zero_division=0)
            
            comparison_data.append({
                'Model': name,
                'Accuracy': accuracy,
                'Precision': precision,
                'Recall': recall,
                'F1-Score': f1
            })
        
        # Create DataFrame
        comparison_df = pd.DataFrame(comparison_data)
        
        # Display table
        print("\n📊 PERFORMANCE METRICS TABLE:")
        print(comparison_df.round(4).to_string(index=False))
        
        # Create visualization
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('📊 Model Performance Metrics Comparison', fontsize=16, fontweight='bold')
        
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        
        for i, metric in enumerate(metrics):
            row, col = i // 2, i % 2
            
            bars = axes[row, col].bar(comparison_df['Model'], comparison_df[metric], 
                                    color=self.color_palette[:len(comparison_df)], alpha=0.8)
            axes[row, col].set_title(f'{metric} Comparison', fontweight='bold', fontsize=14)
            axes[row, col].set_ylabel(metric, fontweight='bold')
            axes[row, col].set_ylim(0, 1)
            axes[row, col].grid(True, alpha=0.3)
            axes[row, col].tick_params(axis='x', rotation=45)
            
            # Add value labels on bars
            for bar, value in zip(bars, comparison_df[metric]):
                axes[row, col].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                                  f'{value:.3f}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.show()
        
        # Create interactive Plotly comparison
        fig_interactive = go.Figure()
        
        for metric in metrics:
            fig_interactive.add_trace(go.Bar(
                name=metric,
                x=comparison_df['Model'],
                y=comparison_df[metric],
                text=comparison_df[metric].round(3),
                textposition='auto',
            ))
        
        fig_interactive.update_layout(
            title='🎯 Interactive Model Performance Comparison',
            xaxis_title='Models',
            yaxis_title='Score',
            barmode='group',
            height=600,
            showlegend=True
        )
        
        fig_interactive.show()
        
        return comparison_df
    
    def hyperparameter_tuning(self, X_train, y_train, model_name='Random Forest'):
        """Hyperparameter tuning using GridSearchCV."""
        print(f"\n🔧 HYPERPARAMETER TUNING FOR {model_name.upper()}")
        print("=" * 50)
        
        if model_name == 'Random Forest':
            model = RandomForestClassifier(random_state=42)
            param_grid = {
                'n_estimators': [50, 100, 200],
                'max_depth': [10, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            }
        elif model_name == 'Logistic Regression':
            model = LogisticRegression(random_state=42, max_iter=1000)
            param_grid = {
                'C': [0.1, 1, 10, 100],
                'penalty': ['l1', 'l2'],
                'solver': ['liblinear', 'saga']
            }
        else:
            print(f"❌ Hyperparameter tuning not implemented for {model_name}")
            return None
        
        # Perform grid search
        print("🔍 Performing grid search...")
        grid_search = GridSearchCV(
            model, param_grid, cv=5, scoring='f1', n_jobs=-1, verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        
        # Results
        print(f"\n✅ Best parameters found:")
        for param, value in grid_search.best_params_.items():
            print(f"   • {param}: {value}")
        
        print(f"\n📊 Best cross-validation F1-score: {grid_search.best_score_:.4f}")
        
        # Plot parameter importance
        results_df = pd.DataFrame(grid_search.cv_results_)
        
        if model_name == 'Random Forest':
            # Plot n_estimators vs score
            plt.figure(figsize=(15, 5))
            
            plt.subplot(1, 3, 1)
            estimators_scores = results_df.groupby('param_n_estimators')['mean_test_score'].mean()
            plt.plot(estimators_scores.index, estimators_scores.values, 'o-', linewidth=2, markersize=8)
            plt.title('N_estimators vs F1-Score', fontweight='bold')
            plt.xlabel('N_estimators')
            plt.ylabel('Mean F1-Score')
            plt.grid(True, alpha=0.3)
            
            plt.subplot(1, 3, 2)
            depth_scores = results_df.groupby('param_max_depth')['mean_test_score'].mean()
            plt.plot(range(len(depth_scores)), depth_scores.values, 'o-', linewidth=2, markersize=8)
            plt.title('Max_depth vs F1-Score', fontweight='bold')
            plt.xlabel('Max_depth')
            plt.ylabel('Mean F1-Score')
            plt.xticks(range(len(depth_scores)), depth_scores.index)
            plt.grid(True, alpha=0.3)
            
            plt.subplot(1, 3, 3)
            split_scores = results_df.groupby('param_min_samples_split')['mean_test_score'].mean()
            plt.plot(split_scores.index, split_scores.values, 'o-', linewidth=2, markersize=8)
            plt.title('Min_samples_split vs F1-Score', fontweight='bold')
            plt.xlabel('Min_samples_split')
            plt.ylabel('Mean F1-Score')
            plt.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.show()
        
        return grid_search.best_estimator_, grid_search.best_params_, grid_search.best_score_
    
    def create_model_comparison_chart(self, save_path=None):
        """Create comprehensive model comparison chart."""
        print("\n📊 CREATING MODEL COMPARISON CHART")
        print("=" * 50)
        
        # Prepare data for comparison
        model_names = list(self.results.keys())
        metrics_data = {
            'Model': model_names,
            'Accuracy': [],
            'Precision': [],
            'Recall': [],
            'F1-Score': [],
            'AUC': []
        }
        
        for name, results in self.results.items():
            y_test = results['y_test']
            y_pred = results['y_pred']
            y_pred_proba = results['y_pred_proba']
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='binary', zero_division=0)
            recall = recall_score(y_test, y_pred, average='binary', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='binary', zero_division=0)
            
            # Calculate AUC
            if name == 'Isolation Forest':
                fpr, tpr, _ = roc_curve(y_test, -y_pred_proba)
            else:
                fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
            roc_auc = auc(fpr, tpr)
            
            metrics_data['Accuracy'].append(accuracy)
            metrics_data['Precision'].append(precision)
            metrics_data['Recall'].append(recall)
            metrics_data['F1-Score'].append(f1)
            metrics_data['AUC'].append(roc_auc)
        
        # Create radar chart
        fig = go.Figure()
        
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC']
        
        for i, model in enumerate(model_names):
            values = [metrics_data[metric][i] for metric in metrics]
            values.append(values[0])  # Close the radar chart
            
            fig.add_trace(go.Scatterpolar(
                r=values,
                theta=metrics + [metrics[0]],
                fill='toself',
                name=model,
                line_color=self.color_palette[i]
            ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 1]
                )),
            showlegend=True,
            title="🎯 Model Performance Radar Chart",
            title_x=0.5,
            height=600
        )
        
        fig.show()
        
        # Create heatmap
        comparison_df = pd.DataFrame(metrics_data)
        comparison_df = comparison_df.set_index('Model')
        
        plt.figure(figsize=(10, 6))
        sns.heatmap(comparison_df.T, annot=True, cmap='RdYlBu_r', center=0.5, 
                   fmt='.3f', cbar_kws={'label': 'Performance Score'})
        plt.title('🔥 Model Performance Heatmap', fontsize=14, fontweight='bold')
        plt.ylabel('Metrics', fontweight='bold')
        plt.xlabel('Models', fontweight='bold')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print best model
        avg_scores = comparison_df.mean(axis=1).sort_values(ascending=False)
        print(f"\n🏆 BEST PERFORMING MODELS (by average score):")
        for i, (model, score) in enumerate(avg_scores.items(), 1):
            print(f"   {i}. {model}: {score:.3f}")
        
        return comparison_df
    
    def save_models(self, save_dir="../models/"):
        """Save trained models to disk."""
        import os
        os.makedirs(save_dir, exist_ok=True)
        
        print(f"\n💾 SAVING MODELS TO {save_dir}")
        print("=" * 50)
        
        for name, model in self.models.items():
            filename = f"{save_dir}{name.lower().replace(' ', '_')}_model.joblib"
            joblib.dump(model, filename)
            print(f"   ✅ {name} saved to {filename}")
        
        print("✅ All models saved successfully!")

def main():
    """Example usage of the Model Evaluation module."""
    # Load data (replace with your data loading logic)
    print("🚀 CYBERSECURITY MODEL EVALUATION EXAMPLE")
    print("=" * 60)
    
    # This would be replaced with actual data loading
    # df = pd.read_csv("../data/cybersecurity_data.csv")
    
    # For demonstration, create sample data
    np.random.seed(42)
    n_samples = 1000
    
    sample_data = {
        'bytes_in': np.random.lognormal(8, 1.5, n_samples),
        'bytes_out': np.random.lognormal(7, 1.5, n_samples),
        'dst_port': np.random.choice([22, 80, 443, 8080, 3389], n_samples),
        'protocol': np.random.choice(['TCP', 'UDP', 'HTTP'], n_samples),
        'src_ip_country_code': np.random.choice(['US', 'CN', 'RU', 'DE'], n_samples),
    }
    
    df = pd.DataFrame(sample_data)
    df['total_bytes'] = df['bytes_in'] + df['bytes_out']
    
    # Initialize evaluator
    evaluator = ModelEvaluator()
    
    # Prepare data
    X_train, X_test, y_train, y_test, features = evaluator.prepare_data_for_ml(df)
    
    if X_train is not None:
        # Train models
        models, results = evaluator.train_models(X_train, y_train, X_test, y_test)
        
        # Evaluate models
        evaluator.plot_roc_auc_curves()
        comparison_df = evaluator.create_precision_recall_f1_table()
        evaluator.create_model_comparison_chart()
        
        # Hyperparameter tuning
        best_model, best_params, best_score = evaluator.hyperparameter_tuning(X_train, y_train)
        
        # Save models
        evaluator.save_models()

if __name__ == "__main__":
    main()