"""
Cybersecurity Web Threat Analysis - Data Preprocessing Module
============================================================

This module handles data cleaning, transformation, and feature engineering
for cybersecurity threat analysis.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class CyberDataPreprocessor:
    """
    A comprehensive data preprocessing class for cybersecurity threat analysis.
    """
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.encoder = OneHotEncoder(sparse_output=False)
        self.is_fitted = False
    
    def load_data(self, filepath):
        """Load the cybersecurity dataset."""
        try:
            df = pd.read_csv(filepath)
            print(f"✅ Dataset loaded successfully! Shape: {df.shape}")
            return df
        except Exception as e:
            print(f"❌ Error loading dataset: {e}")
            return None
    
    def clean_data(self, df):
        """
        Perform comprehensive data cleaning.
        
        Args:
            df (pd.DataFrame): Raw dataset
            
        Returns:
            pd.DataFrame: Cleaned dataset
        """
        print("🧹 Starting data cleaning process...")
        
        # Remove duplicates
        initial_rows = len(df)
        df = df.drop_duplicates()
        print(f"   • Removed {initial_rows - len(df)} duplicate rows")
        
        # Convert time columns to datetime
        time_columns = ['creation_time', 'end_time', 'time']
        for col in time_columns:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col], errors='coerce')
                print(f"   • Converted {col} to datetime")
        
        # Standardize country codes
        if 'src_ip_country_code' in df.columns:
            df['src_ip_country_code'] = df['src_ip_country_code'].str.upper()
            print("   • Standardized country codes to uppercase")
        
        # Handle missing values
        missing_before = df.isnull().sum().sum()
        
        # Fill numeric columns with median
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if df[col].isnull().sum() > 0:
                df[col].fillna(df[col].median(), inplace=True)
        
        # Fill categorical columns with mode
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            if df[col].isnull().sum() > 0:
                df[col].fillna(df[col].mode()[0] if not df[col].mode().empty else 'Unknown', inplace=True)
        
        missing_after = df.isnull().sum().sum()
        print(f"   • Handled {missing_before - missing_after} missing values")
        
        print("✅ Data cleaning completed!")
        return df
    
    def engineer_features(self, df):
        """
        Create new features for analysis.
        
        Args:
            df (pd.DataFrame): Cleaned dataset
            
        Returns:
            pd.DataFrame: Dataset with engineered features
        """
        print("🔧 Engineering new features...")
        
        # Session duration in seconds
        if 'creation_time' in df.columns and 'end_time' in df.columns:
            df['session_duration'] = (df['end_time'] - df['creation_time']).dt.total_seconds()
            df['session_duration'] = df['session_duration'].fillna(0)
            print("   • Created session_duration feature")
        
        # Average packet size
        if 'bytes_in' in df.columns and 'bytes_out' in df.columns and 'session_duration' in df.columns:
            df['total_bytes'] = df['bytes_in'] + df['bytes_out']
            df['avg_packet_size'] = df['total_bytes'] / (df['session_duration'] + 1)  # +1 to avoid division by zero
            df['avg_packet_size'] = df['avg_packet_size'].replace([np.inf, -np.inf], 0)
            print("   • Created avg_packet_size feature")
        
        # Traffic ratio
        if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
            df['traffic_ratio'] = df['bytes_in'] / (df['bytes_out'] + 1)  # +1 to avoid division by zero
            df['traffic_ratio'] = df['traffic_ratio'].replace([np.inf, -np.inf], 0)
            print("   • Created traffic_ratio feature")
        
        # Hour of day feature
        if 'creation_time' in df.columns:
            df['hour_of_day'] = df['creation_time'].dt.hour
            print("   • Created hour_of_day feature")
        
        # Day of week feature
        if 'creation_time' in df.columns:
            df['day_of_week'] = df['creation_time'].dt.dayofweek
            print("   • Created day_of_week feature")
        
        # Risk score based on port
        high_risk_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995]
        if 'dst_port' in df.columns:
            df['port_risk_score'] = df['dst_port'].apply(lambda x: 1 if x in high_risk_ports else 0)
            print("   • Created port_risk_score feature")
        
        print("✅ Feature engineering completed!")
        return df
    
    def scale_features(self, df, numeric_features=None):
        """
        Scale numeric features using StandardScaler.
        
        Args:
            df (pd.DataFrame): Dataset with features
            numeric_features (list): List of numeric features to scale
            
        Returns:
            pd.DataFrame: Dataset with scaled features
        """
        print("📊 Scaling numeric features...")
        
        if numeric_features is None:
            numeric_features = ['bytes_in', 'bytes_out', 'session_duration', 'avg_packet_size', 'traffic_ratio']
        
        # Filter features that exist in the dataset
        existing_features = [col for col in numeric_features if col in df.columns]
        
        if existing_features:
            scaled_values = self.scaler.fit_transform(df[existing_features])
            scaled_df = pd.DataFrame(
                scaled_values, 
                columns=[f"scaled_{col}" for col in existing_features], 
                index=df.index
            )
            df = pd.concat([df, scaled_df], axis=1)
            print(f"   • Scaled {len(existing_features)} numeric features")
        
        print("✅ Feature scaling completed!")
        return df
    
    def encode_categorical(self, df, categorical_features=None):
        """
        Encode categorical features using OneHotEncoder.
        
        Args:
            df (pd.DataFrame): Dataset with features
            categorical_features (list): List of categorical features to encode
            
        Returns:
            pd.DataFrame: Dataset with encoded features
        """
        print("🏷️ Encoding categorical features...")
        
        if categorical_features is None:
            categorical_features = ['src_ip_country_code', 'protocol']
        
        # Filter features that exist in the dataset
        existing_features = [col for col in categorical_features if col in df.columns]
        
        if existing_features:
            encoded = self.encoder.fit_transform(df[existing_features])
            encoded_df = pd.DataFrame(
                encoded,
                columns=self.encoder.get_feature_names_out(existing_features),
                index=df.index
            )
            df = pd.concat([df, encoded_df], axis=1)
            print(f"   • Encoded {len(existing_features)} categorical features")
        
        print("✅ Categorical encoding completed!")
        return df
    
    def preprocess_pipeline(self, filepath, save_path=None):
        """
        Complete preprocessing pipeline.
        
        Args:
            filepath (str): Path to raw dataset
            save_path (str): Path to save processed dataset
            
        Returns:
            pd.DataFrame: Fully processed dataset
        """
        print("🚀 Starting complete preprocessing pipeline...")
        print("=" * 60)
        
        # Load data
        df = self.load_data(filepath)
        if df is None:
            return None
        
        # Clean data
        df = self.clean_data(df)
        
        # Engineer features
        df = self.engineer_features(df)
        
        # Scale numeric features
        df = self.scale_features(df)
        
        # Encode categorical features
        df = self.encode_categorical(df)
        
        # Save processed data
        if save_path:
            df.to_csv(save_path, index=False)
            print(f"💾 Processed dataset saved to: {save_path}")
        
        print("=" * 60)
        print("🎉 Preprocessing pipeline completed successfully!")
        print(f"📊 Final dataset shape: {df.shape}")
        
        self.is_fitted = True
        return df

def main():
    """Example usage of the preprocessing pipeline."""
    preprocessor = CyberDataPreprocessor()
    
    # Run the complete pipeline
    processed_df = preprocessor.preprocess_pipeline(
        filepath="../data/CloudWatch_Traffic_Web_Attack.csv",
        save_path="../data/processed_cyber_data.csv"
    )
    
    if processed_df is not None:
        print("\n📋 Processing Summary:")
        print(f"   • Total rows: {len(processed_df):,}")
        print(f"   • Total columns: {len(processed_df.columns)}")
        print(f"   • Numeric features: {len(processed_df.select_dtypes(include=[np.number]).columns)}")
        print(f"   • Memory usage: {processed_df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")

if __name__ == "__main__":
    main()