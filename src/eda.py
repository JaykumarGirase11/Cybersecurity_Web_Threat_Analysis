"""
Cybersecurity Web Threat Analysis - Exploratory Data Analysis Module
====================================================================

This module provides comprehensive exploratory data analysis and visualization
capabilities for cybersecurity threat analysis.
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import warnings
warnings.filterwarnings('ignore')

# Set styling for better visualizations
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class CyberThreatEDA:
    """
    Comprehensive EDA class for cybersecurity threat analysis.
    """
    
    def __init__(self, figsize=(12, 8)):
        self.figsize = figsize
        self.color_palette = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FECA57', '#FF9FF3', '#54A0FF']
        
    def load_data(self, filepath):
        """Load cybersecurity dataset."""
        try:
            df = pd.read_csv(filepath)
            print(f"✅ Dataset loaded successfully! Shape: {df.shape}")
            return df
        except Exception as e:
            print(f"❌ Error loading dataset: {e}")
            return None
    
    def basic_info(self, df):
        """Display basic dataset information."""
        print("📊 BASIC DATASET INFORMATION")
        print("=" * 50)
        print(f"Dataset Shape: {df.shape}")
        print(f"Memory Usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
        print(f"Duplicate Rows: {df.duplicated().sum()}")
        print(f"Missing Values: {df.isnull().sum().sum()}")
        
        print("\n📋 COLUMN INFORMATION:")
        print(df.dtypes)
        
        print("\n📈 NUMERICAL COLUMNS SUMMARY:")
        print(df.describe())
        
        print("\n🏷️ CATEGORICAL COLUMNS SUMMARY:")
        categorical_cols = df.select_dtypes(include=['object']).columns
        for col in categorical_cols:
            print(f"\n{col}: {df[col].nunique()} unique values")
            print(df[col].value_counts().head())
    
    def plot_data_distribution(self, df, save_path=None):
        """Plot distribution of key numerical features."""
        numeric_cols = ['bytes_in', 'bytes_out', 'session_duration', 'avg_packet_size']
        existing_cols = [col for col in numeric_cols if col in df.columns]
        
        if not existing_cols:
            print("❌ No numerical columns found for distribution plot")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('🔍 Distribution of Key Network Traffic Features', fontsize=16, fontweight='bold')
        
        for i, col in enumerate(existing_cols[:4]):
            row, col_idx = i // 2, i % 2
            
            # Histogram with KDE
            sns.histplot(data=df, x=col, kde=True, ax=axes[row, col_idx], 
                        color=self.color_palette[i], alpha=0.7)
            axes[row, col_idx].set_title(f'Distribution of {col.replace("_", " ").title()}', 
                                       fontweight='bold')
            axes[row, col_idx].grid(True, alpha=0.3)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_protocol_analysis(self, df, save_path=None):
        """Analyze protocol distribution and usage patterns."""
        if 'protocol' not in df.columns:
            print("❌ Protocol column not found")
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))
        fig.suptitle('🌐 Network Protocol Analysis', fontsize=16, fontweight='bold')
        
        # Protocol count
        protocol_counts = df['protocol'].value_counts()
        sns.countplot(data=df, x='protocol', ax=axes[0], palette='viridis')
        axes[0].set_title('Protocol Usage Count', fontweight='bold')
        axes[0].tick_params(axis='x', rotation=45)
        axes[0].grid(True, alpha=0.3)
        
        # Protocol pie chart
        axes[1].pie(protocol_counts.values, labels=protocol_counts.index, autopct='%1.1f%%',
                   colors=self.color_palette[:len(protocol_counts)])
        axes[1].set_title('Protocol Distribution', fontweight='bold')
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_geographic_analysis(self, df, save_path=None):
        """Analyze geographic distribution of traffic sources."""
        if 'src_ip_country_code' not in df.columns:
            print("❌ Source country column not found")
            return
        
        # Top countries by traffic count
        top_countries = df['src_ip_country_code'].value_counts().head(15)
        
        fig, axes = plt.subplots(2, 1, figsize=(14, 12))
        fig.suptitle('🌍 Geographic Traffic Analysis', fontsize=16, fontweight='bold')
        
        # Horizontal bar chart
        sns.barplot(x=top_countries.values, y=top_countries.index, ax=axes[0], palette='coolwarm')
        axes[0].set_title('Top 15 Countries by Traffic Volume', fontweight='bold')
        axes[0].set_xlabel('Number of Connections')
        axes[0].grid(True, alpha=0.3)
        
        # Traffic by country (bytes)
        if 'bytes_in' in df.columns:
            country_bytes = df.groupby('src_ip_country_code')['bytes_in'].sum().sort_values(ascending=False).head(10)
            sns.barplot(x=country_bytes.values, y=country_bytes.index, ax=axes[1], palette='plasma')
            axes[1].set_title('Top 10 Countries by Data Volume (Bytes In)', fontweight='bold')
            axes[1].set_xlabel('Total Bytes In')
            axes[1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_port_security_analysis(self, df, save_path=None):
        """Analyze destination port patterns and security implications."""
        if 'dst_port' not in df.columns:
            print("❌ Destination port column not found")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('🔒 Port Security Analysis', fontsize=16, fontweight='bold')
        
        # Top ports
        top_ports = df['dst_port'].value_counts().head(10)
        sns.barplot(x=top_ports.values, y=top_ports.index, ax=axes[0, 0], palette='rocket')
        axes[0, 0].set_title('Top 10 Destination Ports', fontweight='bold')
        axes[0, 0].grid(True, alpha=0.3)
        
        # Port distribution
        sns.histplot(data=df, x='dst_port', bins=50, ax=axes[0, 1], color='orange', alpha=0.7)
        axes[0, 1].set_title('Destination Port Distribution', fontweight='bold')
        axes[0, 1].grid(True, alpha=0.3)
        
        # High-risk ports analysis
        high_risk_ports = [22, 23, 53, 80, 135, 139, 443, 445, 993, 995]
        risk_data = df[df['dst_port'].isin(high_risk_ports)]
        
        if len(risk_data) > 0:
            sns.countplot(data=risk_data, x='dst_port', ax=axes[1, 0], palette='Reds')
            axes[1, 0].set_title('High-Risk Port Activity', fontweight='bold')
            axes[1, 0].tick_params(axis='x', rotation=45)
            axes[1, 0].grid(True, alpha=0.3)
        
        # Port vs bytes analysis
        if 'bytes_in' in df.columns:
            port_bytes = df.groupby('dst_port')['bytes_in'].mean().sort_values(ascending=False).head(10)
            sns.barplot(x=port_bytes.values, y=port_bytes.index, ax=axes[1, 1], palette='viridis')
            axes[1, 1].set_title('Average Bytes In by Port', fontweight='bold')
            axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_time_series_analysis(self, df, save_path=None):
        """Analyze temporal patterns in the traffic data."""
        time_cols = ['creation_time', 'end_time', 'time']
        time_col = None
        
        for col in time_cols:
            if col in df.columns:
                time_col = col
                break
        
        if time_col is None:
            print("❌ No time column found for temporal analysis")
            return
        
        # Convert to datetime if not already
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
        df_time = df.dropna(subset=[time_col])
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('⏰ Temporal Traffic Analysis', fontsize=16, fontweight='bold')
        
        # Traffic by hour
        df_time['hour'] = df_time[time_col].dt.hour
        hourly_traffic = df_time['hour'].value_counts().sort_index()
        axes[0, 0].plot(hourly_traffic.index, hourly_traffic.values, marker='o', linewidth=2, color='#FF6B6B')
        axes[0, 0].set_title('Traffic by Hour of Day', fontweight='bold')
        axes[0, 0].set_xlabel('Hour')
        axes[0, 0].set_ylabel('Traffic Count')
        axes[0, 0].grid(True, alpha=0.3)
        
        # Traffic by day of week
        df_time['day_of_week'] = df_time[time_col].dt.day_name()
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        daily_traffic = df_time['day_of_week'].value_counts().reindex(day_order)
        axes[0, 1].bar(daily_traffic.index, daily_traffic.values, color=self.color_palette[:7])
        axes[0, 1].set_title('Traffic by Day of Week', fontweight='bold')
        axes[0, 1].tick_params(axis='x', rotation=45)
        axes[0, 1].grid(True, alpha=0.3)
        
        # Traffic trend over time
        df_time['date'] = df_time[time_col].dt.date
        daily_counts = df_time['date'].value_counts().sort_index()
        axes[1, 0].plot(daily_counts.index, daily_counts.values, linewidth=2, color='#4ECDC4')
        axes[1, 0].set_title('Daily Traffic Trend', fontweight='bold')
        axes[1, 0].tick_params(axis='x', rotation=45)
        axes[1, 0].grid(True, alpha=0.3)
        
        # Heatmap: Hour vs Day of week
        if len(df_time) > 0:
            pivot_data = df_time.groupby(['day_of_week', 'hour']).size().unstack(fill_value=0)
            pivot_data = pivot_data.reindex(day_order)
            sns.heatmap(pivot_data, ax=axes[1, 1], cmap='YlOrRd', annot=False, cbar_kws={'label': 'Traffic Count'})
            axes[1, 1].set_title('Traffic Heatmap: Day vs Hour', fontweight='bold')
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_anomaly_analysis(self, df, save_path=None):
        """Analyze anomaly detection results if available."""
        if 'anomaly' not in df.columns:
            print("❌ Anomaly column not found. Run anomaly detection first.")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('🚨 Anomaly Detection Analysis', fontsize=16, fontweight='bold')
        
        # Anomaly distribution
        anomaly_counts = df['anomaly'].value_counts()
        colors = ['#4ECDC4', '#FF6B6B']
        axes[0, 0].pie(anomaly_counts.values, labels=anomaly_counts.index, autopct='%1.1f%%', colors=colors)
        axes[0, 0].set_title('Normal vs Suspicious Traffic', fontweight='bold')
        
        # Anomaly score distribution
        if 'anomaly_score' in df.columns:
            sns.histplot(data=df, x='anomaly_score', hue='anomaly', ax=axes[0, 1], alpha=0.7)
            axes[0, 1].set_title('Anomaly Score Distribution', fontweight='bold')
            axes[0, 1].grid(True, alpha=0.3)
        
        # Bytes scatter plot with anomalies
        if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
            scatter_colors = {'Normal': '#4ECDC4', 'Suspicious': '#FF6B6B'}
            for anomaly_type in df['anomaly'].unique():
                subset = df[df['anomaly'] == anomaly_type]
                axes[1, 0].scatter(subset['bytes_in'], subset['bytes_out'], 
                                 c=scatter_colors.get(anomaly_type, '#999999'), 
                                 label=anomaly_type, alpha=0.6, s=20)
            axes[1, 0].set_xlabel('Bytes In')
            axes[1, 0].set_ylabel('Bytes Out')
            axes[1, 0].set_title('Traffic Pattern: Bytes In vs Bytes Out', fontweight='bold')
            axes[1, 0].legend()
            axes[1, 0].grid(True, alpha=0.3)
        
        # Anomalies by country
        if 'src_ip_country_code' in df.columns:
            anomaly_by_country = df[df['anomaly'] == 'Suspicious']['src_ip_country_code'].value_counts().head(10)
            if len(anomaly_by_country) > 0:
                sns.barplot(x=anomaly_by_country.values, y=anomaly_by_country.index, ax=axes[1, 1], palette='Reds')
                axes[1, 1].set_title('Top Countries with Suspicious Activity', fontweight='bold')
                axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def create_interactive_plotly_dashboard(self, df):
        """Create interactive Plotly visualizations."""
        print("🎨 Creating interactive Plotly visualizations...")
        
        # Traffic overview
        if 'bytes_in' in df.columns and 'bytes_out' in df.columns:
            fig1 = px.scatter(df.sample(min(5000, len(df))), x='bytes_in', y='bytes_out', 
                            color='anomaly' if 'anomaly' in df.columns else None,
                            title='Interactive Traffic Pattern Analysis',
                            hover_data=['src_ip_country_code', 'dst_port'] if all(col in df.columns for col in ['src_ip_country_code', 'dst_port']) else None)
            fig1.show()
        
        # Geographic distribution
        if 'src_ip_country_code' in df.columns:
            country_counts = df['src_ip_country_code'].value_counts().head(20)
            fig2 = px.bar(x=country_counts.values, y=country_counts.index, 
                         orientation='h', title='Traffic by Country (Top 20)')
            fig2.show()
    
    def generate_eda_report(self, df, save_dir="../reports/"):
        """Generate comprehensive EDA report."""
        import os
        os.makedirs(save_dir, exist_ok=True)
        
        print("📊 Generating comprehensive EDA report...")
        print("=" * 50)
        
        # Basic information
        self.basic_info(df)
        
        # Generate all visualizations
        self.plot_data_distribution(df, f"{save_dir}data_distribution.png")
        self.plot_protocol_analysis(df, f"{save_dir}protocol_analysis.png")
        self.plot_geographic_analysis(df, f"{save_dir}geographic_analysis.png")
        self.plot_port_security_analysis(df, f"{save_dir}port_analysis.png")
        self.plot_time_series_analysis(df, f"{save_dir}temporal_analysis.png")
        
        if 'anomaly' in df.columns:
            self.plot_anomaly_analysis(df, f"{save_dir}anomaly_analysis.png")
        
        # Create interactive dashboard
        self.create_interactive_plotly_dashboard(df)
        
        print("✅ EDA report generated successfully!")
        print(f"📁 Visualizations saved to: {save_dir}")

    def get_top_suspicious_ips(self, df, top_n=10):
        """Function to display top 10 suspicious IPs/countries."""
        print(f"🚨 TOP {top_n} SUSPICIOUS IP ADDRESSES")
        print("=" * 50)
        
        if 'is_suspicious' in df.columns:
            suspicious_df = df[df['is_suspicious'] == 1]
        elif 'anomaly' in df.columns:
            suspicious_df = df[df['anomaly'] == 'Suspicious']
        elif 'threat_level' in df.columns:
            suspicious_df = df[df['threat_level'].isin(['High', 'Critical'])]
        else:
            print("❌ No suspicious activity indicator found")
            return None
        
        if len(suspicious_df) == 0:
            print("✅ No suspicious activity detected")
            return None
        
        # Top suspicious IPs
        if 'src_ip' in suspicious_df.columns:
            top_ips = suspicious_df['src_ip'].value_counts().head(top_n)
            print(f"\n🔍 Top {top_n} Suspicious IP Addresses:")
            for i, (ip, count) in enumerate(top_ips.items(), 1):
                country = suspicious_df[suspicious_df['src_ip'] == ip]['src_ip_country_code'].iloc[0] if 'src_ip_country_code' in suspicious_df.columns else 'Unknown'
                total_bytes = suspicious_df[suspicious_df['src_ip'] == ip]['total_bytes'].sum() if 'total_bytes' in suspicious_df.columns else 0
                print(f"  {i:2d}. {ip:15s} | Country: {country:3s} | Incidents: {count:4d} | Total Bytes: {total_bytes:>10,d}")
        
        # Top suspicious countries
        if 'src_ip_country_code' in suspicious_df.columns:
            top_countries = suspicious_df['src_ip_country_code'].value_counts().head(top_n)
            print(f"\n🌍 Top {top_n} Suspicious Countries:")
            for i, (country, count) in enumerate(top_countries.items(), 1):
                threat_percentage = (count / len(suspicious_df)) * 100
                avg_bytes = suspicious_df[suspicious_df['src_ip_country_code'] == country]['total_bytes'].mean() if 'total_bytes' in suspicious_df.columns else 0
                print(f"  {i:2d}. {country:3s} | Incidents: {count:4d} | Threat %: {threat_percentage:5.1f}% | Avg Bytes: {avg_bytes:>10,.0f}")
        
        return suspicious_df
    
    def plot_time_based_attack_trends(self, df, save_path=None):
        """Time-based attack trends (hourly/daily charts)."""
        print("⏰ ANALYZING TIME-BASED ATTACK TRENDS")
        print("=" * 50)
        
        # Find time column
        time_cols = ['creation_time', 'time', 'timestamp', 'end_time']
        time_col = None
        for col in time_cols:
            if col in df.columns:
                time_col = col
                break
        
        if time_col is None:
            print("❌ No time column found")
            return
        
        # Convert to datetime
        df[time_col] = pd.to_datetime(df[time_col], errors='coerce')
        df_time = df.dropna(subset=[time_col])
        
        # Identify suspicious traffic
        if 'is_suspicious' in df_time.columns:
            suspicious_df = df_time[df_time['is_suspicious'] == 1]
        elif 'anomaly' in df_time.columns:
            suspicious_df = df_time[df_time['anomaly'] == 'Suspicious']
        elif 'threat_level' in df_time.columns:
            suspicious_df = df_time[df_time['threat_level'].isin(['High', 'Critical'])]
        else:
            suspicious_df = df_time
        
        fig, axes = plt.subplots(2, 2, figsize=(18, 12))
        fig.suptitle('🕐 Time-Based Attack Trends Analysis', fontsize=16, fontweight='bold')
        
        # Hourly attack patterns
        df_time['hour'] = df_time[time_col].dt.hour
        suspicious_df['hour'] = suspicious_df[time_col].dt.hour
        
        hourly_normal = df_time['hour'].value_counts().sort_index()
        hourly_suspicious = suspicious_df['hour'].value_counts().sort_index()
        
        axes[0, 0].plot(hourly_normal.index, hourly_normal.values, 'b-o', label='Normal Traffic', linewidth=2, markersize=6)
        axes[0, 0].plot(hourly_suspicious.index, hourly_suspicious.values, 'r-s', label='Suspicious Traffic', linewidth=2, markersize=6)
        axes[0, 0].set_title('Hourly Attack Patterns', fontweight='bold', fontsize=14)
        axes[0, 0].set_xlabel('Hour of Day')
        axes[0, 0].set_ylabel('Number of Incidents')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        axes[0, 0].set_xticks(range(0, 24))
        
        # Daily attack patterns
        df_time['day_of_week'] = df_time[time_col].dt.day_name()
        suspicious_df['day_of_week'] = suspicious_df[time_col].dt.day_name()
        
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        daily_normal = df_time['day_of_week'].value_counts().reindex(day_order)
        daily_suspicious = suspicious_df['day_of_week'].value_counts().reindex(day_order)
        
        x = np.arange(len(day_order))
        width = 0.35
        
        axes[0, 1].bar(x - width/2, daily_normal.values, width, label='Normal Traffic', color='#4ECDC4', alpha=0.8)
        axes[0, 1].bar(x + width/2, daily_suspicious.values, width, label='Suspicious Traffic', color='#FF6B6B', alpha=0.8)
        axes[0, 1].set_title('Daily Attack Patterns', fontweight='bold', fontsize=14)
        axes[0, 1].set_xlabel('Day of Week')
        axes[0, 1].set_ylabel('Number of Incidents')
        axes[0, 1].set_xticks(x)
        axes[0, 1].set_xticklabels([day[:3] for day in day_order])
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3)
        
        # Attack trend over time (daily)
        df_time['date'] = df_time[time_col].dt.date
        suspicious_df['date'] = suspicious_df[time_col].dt.date
        
        daily_attacks = suspicious_df['date'].value_counts().sort_index()
        if len(daily_attacks) > 0:
            axes[1, 0].plot(daily_attacks.index, daily_attacks.values, 'r-o', linewidth=2, markersize=4)
            axes[1, 0].set_title('Attack Trend Over Time', fontweight='bold', fontsize=14)
            axes[1, 0].set_xlabel('Date')
            axes[1, 0].set_ylabel('Suspicious Incidents')
            axes[1, 0].tick_params(axis='x', rotation=45)
            axes[1, 0].grid(True, alpha=0.3)
        
        # Heatmap: Hour vs Day for suspicious activity
        if len(suspicious_df) > 0:
            pivot_data = suspicious_df.groupby(['day_of_week', 'hour']).size().unstack(fill_value=0)
            pivot_data = pivot_data.reindex(day_order)
            sns.heatmap(pivot_data, ax=axes[1, 1], cmap='Reds', annot=True, fmt='d', 
                       cbar_kws={'label': 'Suspicious Incidents'})
            axes[1, 1].set_title('Suspicious Activity Heatmap: Day vs Hour', fontweight='bold', fontsize=14)
            axes[1, 1].set_xlabel('Hour of Day')
            axes[1, 1].set_ylabel('Day of Week')
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
        
        # Print summary statistics
        print(f"\n📊 ATTACK TREND SUMMARY:")
        print(f"   • Peak attack hour: {hourly_suspicious.idxmax()}:00 ({hourly_suspicious.max()} incidents)")
        print(f"   • Peak attack day: {daily_suspicious.idxmax()} ({daily_suspicious.max()} incidents)")
        print(f"   • Total suspicious incidents: {len(suspicious_df):,}")
        print(f"   • Average incidents per hour: {len(suspicious_df)/24:.1f}")
        print(f"   • Average incidents per day: {len(suspicious_df)/7:.1f}")
    
    def create_geo_visualization_map(self, df, save_path=None):
        """Geo-visualization map of suspicious IP locations using Plotly."""
        print("🗺️ CREATING GEOGRAPHIC THREAT VISUALIZATION")
        print("=" * 50)
        
        if 'src_ip_country_code' not in df.columns:
            print("❌ Country code column not found")
            return None
        
        # Identify suspicious traffic
        if 'is_suspicious' in df.columns:
            suspicious_df = df[df['is_suspicious'] == 1]
        elif 'anomaly' in df.columns:
            suspicious_df = df[df['anomaly'] == 'Suspicious']
        elif 'threat_level' in df.columns:
            suspicious_df = df[df['threat_level'].isin(['High', 'Critical'])]
        else:
            suspicious_df = df
        
        # Calculate threat statistics by country
        country_stats = df.groupby('src_ip_country_code').agg({
            'src_ip': 'count',
            'total_bytes': 'sum' if 'total_bytes' in df.columns else 'size',
        }).rename(columns={'src_ip': 'total_connections'})
        
        if len(suspicious_df) > 0:
            suspicious_stats = suspicious_df.groupby('src_ip_country_code').agg({
                'src_ip': 'count',
                'total_bytes': 'sum' if 'total_bytes' in suspicious_df.columns else 'size',
            }).rename(columns={'src_ip': 'suspicious_connections'})
            
            country_stats = country_stats.join(suspicious_stats, how='left').fillna(0)
            country_stats['threat_percentage'] = (country_stats['suspicious_connections'] / country_stats['total_connections']) * 100
        else:
            country_stats['suspicious_connections'] = 0
            country_stats['threat_percentage'] = 0
        
        country_stats = country_stats.reset_index()
        
        # Create interactive world map using Plotly
        fig = px.choropleth(
            country_stats,
            locations="src_ip_country_code",
            color="threat_percentage",
            hover_name="src_ip_country_code",
            hover_data={
                "total_connections": ":,",
                "suspicious_connections": ":,",
                "threat_percentage": ":.1f"
            },
            color_continuous_scale="Reds",
            title="🌍 Global Cybersecurity Threat Distribution",
            labels={
                "threat_percentage": "Threat %",
                "total_connections": "Total Connections",
                "suspicious_connections": "Suspicious"
            }
        )
        
        fig.update_layout(
            title_font_size=16,
            title_x=0.5,
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type='natural earth'
            ),
            width=1200,
            height=700
        )
        
        # Show the map
        fig.show()
        
        # Create bubble map for top threat countries
        top_threats = country_stats.nlargest(20, 'suspicious_connections')
        
        if len(top_threats) > 0:
            # Country coordinates (approximate)
            country_coords = {
                'US': (39.8283, -98.5795), 'CN': (35.8617, 104.1954), 'RU': (61.5240, 105.3188),
                'DE': (51.1657, 10.4515), 'GB': (55.3781, -3.4360), 'JP': (36.2048, 138.2529),
                'IN': (20.5937, 78.9629), 'BR': (-14.2350, -51.9253), 'CA': (56.1304, -106.3468),
                'FR': (46.6034, 1.8883), 'KR': (35.9078, 127.7669), 'IT': (41.8719, 12.5674),
                'ES': (40.4637, -3.7492), 'AU': (-25.2744, 133.7751), 'NL': (52.1326, 5.2913),
                'CH': (46.8182, 8.2275), 'SE': (60.1282, 18.6435), 'NO': (60.4720, 8.4689),
                'MX': (23.6345, -102.5528), 'AR': (-38.4161, -63.6167)
            }
            
            # Add coordinates to dataframe
            top_threats['lat'] = top_threats['src_ip_country_code'].map(lambda x: country_coords.get(x, (0, 0))[0])
            top_threats['lon'] = top_threats['src_ip_country_code'].map(lambda x: country_coords.get(x, (0, 0))[1])
            
            # Remove countries without coordinates
            top_threats = top_threats[(top_threats['lat'] != 0) | (top_threats['lon'] != 0)]
            
            if len(top_threats) > 0:
                fig2 = px.scatter_geo(
                    top_threats,
                    lat='lat',
                    lon='lon',
                    size='suspicious_connections',
                    color='threat_percentage',
                    hover_name='src_ip_country_code',
                    hover_data={
                        'total_connections': ':,',
                        'suspicious_connections': ':,',
                        'threat_percentage': ':.1f'
                    },
                    color_continuous_scale='Reds',
                    title='🎯 Top Threat Sources - Bubble Map',
                    size_max=50
                )
                
                fig2.update_layout(
                    title_font_size=16,
                    title_x=0.5,
                    geo=dict(
                        projection_type='natural earth',
                        showland=True,
                        landcolor='rgb(243, 243, 243)',
                        coastlinecolor='rgb(204, 204, 204)',
                    ),
                    width=1200,
                    height=600
                )
                
                fig2.show()
        
        # Print summary
        print(f"\n📊 GEOGRAPHIC THREAT SUMMARY:")
        top_5_threats = country_stats.nlargest(5, 'threat_percentage')
        for i, row in enumerate(top_5_threats.itertuples(), 1):
            print(f"   {i}. {row.src_ip_country_code}: {row.threat_percentage:.1f}% threat rate ({int(row.suspicious_connections)} suspicious)")
        
        return fig
    
    def analyze_attack_type_vs_country(self, df, save_path=None):
        """Attack type vs source country analysis."""
        print("🌐 ATTACK TYPE VS SOURCE COUNTRY ANALYSIS")
        print("=" * 50)
        
        if 'src_ip_country_code' not in df.columns:
            print("❌ Country code column not found")
            return
        
        # Determine attack types based on available data
        attack_types = []
        
        # Protocol-based attack classification
        if 'protocol' in df.columns:
            attack_types.append('protocol')
        
        # Port-based attack classification
        if 'dst_port' in df.columns:
            df['attack_type_port'] = df['dst_port'].apply(self._classify_port_attack)
            attack_types.append('attack_type_port')
        
        # Threat level based
        if 'threat_level' in df.columns:
            attack_types.append('threat_level')
        
        # Bytes-based attack classification
        if 'total_bytes' in df.columns:
            df['attack_type_bytes'] = pd.cut(df['total_bytes'], 
                                           bins=[0, 1000, 10000, 100000, float('inf')],
                                           labels=['Small', 'Medium', 'Large', 'Massive'])
            attack_types.append('attack_type_bytes')
        
        if not attack_types:
            print("❌ No attack type classification possible with available data")
            return
        
        fig, axes = plt.subplots(2, 2, figsize=(20, 16))
        fig.suptitle('🔍 Attack Type vs Source Country Analysis', fontsize=16, fontweight='bold')
        
        # Protocol vs Country
        if 'protocol' in attack_types:
            protocol_country = pd.crosstab(df['src_ip_country_code'], df['protocol'])
            top_countries = df['src_ip_country_code'].value_counts().head(10).index
            protocol_country_top = protocol_country.loc[top_countries]
            
            protocol_country_top.plot(kind='bar', stacked=True, ax=axes[0, 0], 
                                    color=self.color_palette[:len(protocol_country_top.columns)])
            axes[0, 0].set_title('Protocol Distribution by Country (Top 10)', fontweight='bold', fontsize=14)
            axes[0, 0].set_xlabel('Country')
            axes[0, 0].set_ylabel('Number of Connections')
            axes[0, 0].legend(title='Protocol', bbox_to_anchor=(1.05, 1), loc='upper left')
            axes[0, 0].tick_params(axis='x', rotation=45)
            axes[0, 0].grid(True, alpha=0.3)
        
        # Port-based attacks vs Country
        if 'attack_type_port' in attack_types:
            port_country = pd.crosstab(df['src_ip_country_code'], df['attack_type_port'])
            port_country_top = port_country.loc[top_countries] if 'top_countries' in locals() else port_country.head(10)
            
            port_country_top.plot(kind='bar', stacked=True, ax=axes[0, 1],
                                color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'])
            axes[0, 1].set_title('Port-based Attack Types by Country', fontweight='bold', fontsize=14)
            axes[0, 1].set_xlabel('Country')
            axes[0, 1].set_ylabel('Number of Attacks')
            axes[0, 1].legend(title='Attack Type', bbox_to_anchor=(1.05, 1), loc='upper left')
            axes[0, 1].tick_params(axis='x', rotation=45)
            axes[0, 1].grid(True, alpha=0.3)
        
        # Threat level vs Country
        if 'threat_level' in attack_types:
            threat_country = pd.crosstab(df['src_ip_country_code'], df['threat_level'])
            threat_country_top = threat_country.loc[top_countries] if 'top_countries' in locals() else threat_country.head(10)
            
            threat_country_top.plot(kind='bar', stacked=True, ax=axes[1, 0],
                                  color=['#00FF00', '#FFFF00', '#FF8000', '#FF0000'])
            axes[1, 0].set_title('Threat Level Distribution by Country', fontweight='bold', fontsize=14)
            axes[1, 0].set_xlabel('Country')
            axes[1, 0].set_ylabel('Number of Incidents')
            axes[1, 0].legend(title='Threat Level', bbox_to_anchor=(1.05, 1), loc='upper left')
            axes[1, 0].tick_params(axis='x', rotation=45)
            axes[1, 0].grid(True, alpha=0.3)
        
        # Attack size vs Country
        if 'attack_type_bytes' in attack_types:
            bytes_country = pd.crosstab(df['src_ip_country_code'], df['attack_type_bytes'])
            bytes_country_top = bytes_country.loc[top_countries] if 'top_countries' in locals() else bytes_country.head(10)
            
            bytes_country_top.plot(kind='bar', stacked=True, ax=axes[1, 1],
                                 color=['#90EE90', '#FFD700', '#FF8C00', '#DC143C'])
            axes[1, 1].set_title('Attack Size Distribution by Country', fontweight='bold', fontsize=14)
            axes[1, 1].set_xlabel('Country')
            axes[1, 1].set_ylabel('Number of Attacks')
            axes[1, 1].legend(title='Attack Size', bbox_to_anchor=(1.05, 1), loc='upper left')
            axes[1, 1].tick_params(axis='x', rotation=45)
            axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
        
        # Create interactive heatmap
        if 'protocol' in attack_types:
            fig_interactive = px.imshow(
                protocol_country_top.values,
                x=protocol_country_top.columns,
                y=protocol_country_top.index,
                color_continuous_scale='Reds',
                title='Interactive Protocol vs Country Heatmap',
                labels=dict(x="Protocol", y="Country", color="Count")
            )
            fig_interactive.update_layout(width=800, height=600)
            fig_interactive.show()
        
        # Print analysis summary
        print(f"\n📊 ATTACK TYPE ANALYSIS SUMMARY:")
        if 'protocol' in df.columns:
            most_common_protocol = df['protocol'].value_counts().index[0]
            print(f"   • Most common protocol: {most_common_protocol}")
        
        if 'threat_level' in df.columns:
            high_threat_countries = df[df['threat_level'].isin(['High', 'Critical'])]['src_ip_country_code'].value_counts().head(3)
            print(f"   • Top 3 high-threat countries: {', '.join(high_threat_countries.index)}")
        
        if 'attack_type_port' in df.columns:
            most_common_attack = df['attack_type_port'].value_counts().index[0]
            print(f"   • Most common attack type: {most_common_attack}")
    
    def _classify_port_attack(self, port):
        """Classify attack type based on destination port."""
        if port in [22, 23]:
            return 'Remote Access'
        elif port in [80, 443, 8080, 8443]:
            return 'Web Attack'
        elif port in [53]:
            return 'DNS Attack'
        elif port in [21, 22]:
            return 'File Transfer'
        elif port in [25, 110, 143, 993, 995]:
            return 'Email Attack'
        elif port in [135, 139, 445]:
            return 'Windows Service'
        elif port in [3389]:
            return 'RDP Attack'
        elif port in [1433, 3306, 5432]:
            return 'Database Attack'
        else:
            return 'Other'

def main():
    """Example usage of the EDA module."""
    # Initialize EDA class
    eda = CyberThreatEDA()
    
    # Load data
    df = eda.load_data("../data/anomaly_detected_data.csv")
    
    if df is not None:
        # Generate complete EDA report
        eda.generate_eda_report(df)

if __name__ == "__main__":
    main()