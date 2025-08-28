import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# 🔒 Enhanced Cybersecurity Dashboard Configuration
st.set_page_config(
    page_title="🔒 Cybersecurity Web Threat Analysis Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 🎨 Enhanced Custom CSS with cybersecurity theme
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&display=swap');
    
    .main-header {
        font-family: 'Orbitron', monospace;
        font-size: 3rem;
        font-weight: 900;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 2rem;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
    }
    
    .cyber-metric {
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        padding: 1.5rem;
        border-radius: 15px;
        border: 2px solid #00ff41;
        color: white;
        text-align: center;
        box-shadow: 0 8px 32px rgba(0, 255, 65, 0.2);
        backdrop-filter: blur(10px);
    }
    
    .threat-alert-critical {
        background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
        border: 2px solid #ff0000;
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        margin: 1rem 0;
        box-shadow: 0 8px 32px rgba(255, 0, 0, 0.3);
        animation: pulse 2s infinite;
    }
    
    .threat-alert-high {
        background: linear-gradient(135deg, #ffa726 0%, #fb8c00 100%);
        border: 2px solid #ff9800;
        padding: 1rem;
        border-radius: 10px;
        color: white;
        margin: 1rem 0;
    }
    
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0.7); }
        70% { box-shadow: 0 0 0 10px rgba(255, 0, 0, 0); }
        100% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0); }
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #2c3e50 0%, #34495e 100%);
    }
    
    .stTab {
        background-color: rgba(255, 255, 255, 0.05);
        border-radius: 10px;
        margin: 5px;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_and_clean_data():
    """🧹 Load and comprehensively clean cybersecurity data"""
    try:
        # 📊 Load data with error handling
        df = pd.read_csv('data/CloudWatch_Traffic_Web_Attack.csv')
        st.success(f"✅ Data loaded successfully! Shape: {df.shape}")
        
        # 🧹 Data Cleaning Pipeline
        
        # 1️⃣ Remove duplicates
        initial_rows = len(df)
        df.drop_duplicates(inplace=True)
        if initial_rows > len(df):
            st.info(f"🧹 Removed {initial_rows - len(df)} duplicate rows")
        
        # 2️⃣ Handle time columns with robust error handling
        time_columns = ['creation_time', 'end_time', 'time']
        for col in time_columns:
            if col in df.columns:
                try:
                    df[col] = pd.to_datetime(df[col], errors='coerce')
                except Exception as e:
                    st.warning(f"⚠️ Could not convert {col} to datetime: {e}")
        
        # 3️⃣ Standardize country codes
        if 'src_ip_country_code' in df.columns:
            df['src_ip_country_code'] = df['src_ip_country_code'].str.upper()
        
        # 4️⃣ Create session duration with error handling
        if 'creation_time' in df.columns and 'end_time' in df.columns:
            df['session_duration'] = (df['end_time'] - df['creation_time']).dt.total_seconds()
            df['session_duration'] = df['session_duration'].clip(lower=0.1)  # Minimum 0.1 seconds
        
        # 5️⃣ Clean numeric columns
        numeric_columns = ['bytes_in', 'bytes_out', 'dst_port']
        for col in numeric_columns:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
                df[col] = df[col].fillna(0)
        
        # 6️⃣ Feature Engineering
        df['total_bytes'] = df['bytes_in'] + df['bytes_out']
        df['bytes_ratio'] = df['bytes_out'] / (df['bytes_in'] + 1)
        
        # Time-based features
        if 'time' in df.columns and not df['time'].isna().all():
            df['hour'] = df['time'].dt.hour
            df['day_of_week'] = df['time'].dt.day_name()
            df['date'] = df['time'].dt.date
        
        # 7️⃣ Create threat severity levels
        df['threat_level'] = pd.cut(df['total_bytes'], 
                                  bins=[0, 10000, 100000, 1000000, float('inf')],
                                  labels=['🟢 Low', '🟡 Medium', '🟠 High', '🔴 Critical'])
        
        # 8️⃣ Advanced packet analysis
        if 'session_duration' in df.columns:
            df['avg_packet_size'] = df['total_bytes'] / df['session_duration']
            df['avg_packet_size'] = df['avg_packet_size'].replace([np.inf, -np.inf], np.nan)
            df['avg_packet_size'] = df['avg_packet_size'].fillna(df['avg_packet_size'].median())
        
        return df
        
    except FileNotFoundError:
        st.error("❌ Data file not found. Please check the file path: 'data/CloudWatch_Traffic_Web_Attack.csv'")
        return None
    except Exception as e:
        st.error(f"❌ Error loading data: {e}")
        return None

def create_bytes_distribution_analysis(df):
    """📊 Create comprehensive bytes distribution analysis"""
    st.subheader("📊 Interactive Bytes Traffic Analysis")
    
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('📈 Bytes In Distribution', '📈 Bytes Out Distribution', 
                       '🔄 Bytes In vs Out Correlation', '📦 Traffic Volume Comparison'),
        specs=[[{'secondary_y': False}, {'secondary_y': False}],
               [{'secondary_y': False}, {'secondary_y': False}]]
    )
    
    # Histogram for Bytes In
    fig.add_trace(
        go.Histogram(x=df['bytes_in'], name='Bytes In', nbinsx=50, 
                    opacity=0.7, marker_color='#00ff41'),
        row=1, col=1
    )
    
    # Histogram for Bytes Out
    fig.add_trace(
        go.Histogram(x=df['bytes_out'], name='Bytes Out', nbinsx=50,
                    opacity=0.7, marker_color='#ff6b6b'),
        row=1, col=2
    )
    
    # Scatter plot (sample for performance)
    sample_df = df.sample(min(1000, len(df)))
    fig.add_trace(
        go.Scatter(x=sample_df['bytes_in'], y=sample_df['bytes_out'], mode='markers',
                  name='Correlation', marker=dict(size=4, opacity=0.6, color='#4ecdc4')),
        row=2, col=1
    )
    
    # Box plots
    fig.add_trace(
        go.Box(y=df['bytes_in'], name='Bytes In', marker_color='#00ff41'),
        row=2, col=2
    )
    fig.add_trace(
        go.Box(y=df['bytes_out'], name='Bytes Out', marker_color='#ff6b6b'),
        row=2, col=2
    )
    
    fig.update_layout(
        height=800,
        title_text='📊 Interactive Bytes Traffic Analysis Dashboard',
        showlegend=True,
        template='plotly_dark'
    )
    
    st.plotly_chart(fig, use_container_width=True)

def create_geographic_analysis(df):
    """🗺️ Create interactive geographic threat analysis"""
    st.subheader("🗺️ Global Threat Intelligence Map")
    
    if 'src_ip_country_code' in df.columns:
        col1, col2 = st.columns(2)
        
        with col1:
            country_counts = df['src_ip_country_code'].value_counts().head(20)
            
            fig = px.bar(
                x=country_counts.values,
                y=country_counts.index,
                orientation='h',
                title='🌍 Top 20 Countries by Attack Volume',
                labels={'x': 'Number of Attacks', 'y': 'Country Code'},
                color=country_counts.values,
                color_continuous_scale='Reds',
                template='plotly_dark'
            )
            
            fig.update_layout(
                height=600,
                yaxis={'categoryorder': 'total ascending'}
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Treemap visualization
            fig_tree = px.treemap(
                names=country_counts.head(15).index,
                values=country_counts.head(15).values,
                title='🌳 Attack Distribution Treemap',
                template='plotly_dark'
            )
            fig_tree.update_layout(height=600)
            st.plotly_chart(fig_tree, use_container_width=True)

def create_protocol_analysis(df):
    """🌐 Create interactive protocol distribution analysis"""
    st.subheader("🌐 Protocol Security Analysis")
    
    if 'protocol' in df.columns:
        col1, col2 = st.columns(2)
        
        with col1:
            protocol_counts = df['protocol'].value_counts()
            
            fig = px.bar(
                x=protocol_counts.index,
                y=protocol_counts.values,
                title='🔌 Protocol Distribution Analysis',
                labels={'x': 'Protocol Type', 'y': 'Number of Connections'},
                color=protocol_counts.values,
                color_continuous_scale='viridis',
                template='plotly_dark'
            )
            
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            fig_pie = px.pie(
                values=protocol_counts.values,
                names=protocol_counts.index,
                title='🥧 Protocol Distribution Overview',
                template='plotly_dark'
            )
            fig_pie.update_layout(height=500)
            st.plotly_chart(fig_pie, use_container_width=True)

def create_port_analysis(df):
    """🎯 Create interactive destination port analysis"""
    st.subheader("🎯 Port Attack Intelligence")
    
    if 'dst_port' in df.columns:
        col1, col2 = st.columns(2)
        
        with col1:
            port_counts = df['dst_port'].value_counts().head(10)
            
            fig = px.bar(
                x=port_counts.index.astype(str),
                y=port_counts.values,
                title='🎯 Top 10 Most Targeted Ports',
                labels={'x': 'Port Number', 'y': 'Attack Count'},
                color=port_counts.values,
                color_continuous_scale='plasma',
                template='plotly_dark'
            )
            
            # Add port service information
            port_services = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
                25: 'SMTP', 53: 'DNS', 110: 'POP3', 143: 'IMAP'
            }
            
            fig.update_traces(
                hovertemplate='<b>Port:</b> %{x}<br><b>Attacks:</b> %{y}<br><extra></extra>'
            )
            fig.update_layout(height=500)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Port threat level analysis
            if 'threat_level' in df.columns:
                port_threat = df.groupby(['dst_port', 'threat_level']).size().reset_index(name='count')
                top_ports = df['dst_port'].value_counts().head(10).index
                port_threat_filtered = port_threat[port_threat['dst_port'].isin(top_ports)]
                
                fig_stacked = px.bar(
                    port_threat_filtered,
                    x='dst_port',
                    y='count',
                    color='threat_level',
                    title='🚨 Threat Levels by Port',
                    template='plotly_dark'
                )
                fig_stacked.update_layout(height=500)
                st.plotly_chart(fig_stacked, use_container_width=True)

def create_temporal_analysis(df):
    """⏰ Create interactive time-based analysis"""
    st.subheader("⏰ Temporal Attack Pattern Analysis")
    
    if 'hour' in df.columns:
        col1, col2 = st.columns(2)
        
        with col1:
            hourly_attacks = df['hour'].value_counts().sort_index()
            
            fig = px.line(
                x=hourly_attacks.index,
                y=hourly_attacks.values,
                title='🕐 Attack Patterns by Hour of Day',
                labels={'x': 'Hour (24-hour format)', 'y': 'Number of Attacks'},
                markers=True,
                template='plotly_dark'
            )
            
            fig.update_layout(
                xaxis=dict(tickmode='linear', tick0=0, dtick=2),
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            if 'day_of_week' in df.columns:
                day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                daily_attacks = df['day_of_week'].value_counts().reindex(day_order)
                
                fig_day = px.bar(
                    x=daily_attacks.index,
                    y=daily_attacks.values,
                    title='📅 Weekly Attack Distribution',
                    labels={'x': 'Day of Week', 'y': 'Number of Attacks'},
                    color=daily_attacks.values,
                    color_continuous_scale='blues',
                    template='plotly_dark'
                )
                fig_day.update_layout(height=400)
                st.plotly_chart(fig_day, use_container_width=True)

def main():
    """🚀 Main dashboard application"""
    
    # 🔒 Header with cyber styling
    st.markdown('''
    <div class="main-header">
        🔒 CYBERSECURITY THREAT INTELLIGENCE DASHBOARD 🔒
    </div>
    ''', unsafe_allow_html=True)
    
    # 📊 Load and clean data
    with st.spinner('🔄 Loading and processing cybersecurity data...'):
        df = load_and_clean_data()
    
    if df is None:
        st.error("❌ Failed to load data. Please check if the data file exists.")
        return
    
    # 🔍 Sidebar filters
    st.sidebar.markdown("## 🔍 Intelligence Filters")
    st.sidebar.markdown("---")
    
    # Country filter
    if 'src_ip_country_code' in df.columns:
        countries = sorted(df['src_ip_country_code'].unique())
        selected_countries = st.sidebar.multiselect(
            "🌍 Select Countries", 
            countries, 
            default=countries[:10] if len(countries) > 10 else countries
        )
    else:
        selected_countries = []
    
    # Protocol filter
    if 'protocol' in df.columns:
        protocols = sorted(df['protocol'].unique())
        selected_protocols = st.sidebar.multiselect(
            "🔌 Select Protocols", 
            protocols, 
            default=protocols
        )
    else:
        selected_protocols = []
    
    # Threat level filter
    if 'threat_level' in df.columns:
        threat_levels = df['threat_level'].unique()
        selected_threat_levels = st.sidebar.multiselect(
            "⚠️ Select Threat Levels", 
            threat_levels, 
            default=threat_levels
        )
    else:
        selected_threat_levels = []
    
    # Apply filters
    filtered_df = df.copy()
    if selected_countries and 'src_ip_country_code' in df.columns:
        filtered_df = filtered_df[filtered_df['src_ip_country_code'].isin(selected_countries)]
    if selected_protocols and 'protocol' in df.columns:
        filtered_df = filtered_df[filtered_df['protocol'].isin(selected_protocols)]
    if selected_threat_levels and 'threat_level' in df.columns:
        filtered_df = filtered_df[filtered_df['threat_level'].isin(selected_threat_levels)]
    
    # 📊 Key Metrics Dashboard
    st.markdown("## 📊 Threat Intelligence Metrics")
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total_attacks = len(filtered_df)
        st.markdown(f'''
        <div class="cyber-metric">
            <h3>🚨 Total Threats</h3>
            <h2>{total_attacks:,}</h2>
        </div>
        ''', unsafe_allow_html=True)
    
    with col2:
        unique_ips = filtered_df['src_ip'].nunique() if 'src_ip' in filtered_df.columns else 0
        st.markdown(f'''
        <div class="cyber-metric">
            <h3>🌐 Unique IPs</h3>
            <h2>{unique_ips:,}</h2>
        </div>
        ''', unsafe_allow_html=True)
    
    with col3:
        total_gb = filtered_df['total_bytes'].sum() / (1024**3) if 'total_bytes' in filtered_df.columns else 0
        st.markdown(f'''
        <div class="cyber-metric">
            <h3>📊 Data (GB)</h3>
            <h2>{total_gb:.2f}</h2>
        </div>
        ''', unsafe_allow_html=True)
    
    with col4:
        critical_threats = len(filtered_df[filtered_df['threat_level'] == '🔴 Critical']) if 'threat_level' in filtered_df.columns else 0
        st.markdown(f'''
        <div class="cyber-metric">
            <h3>🔴 Critical</h3>
            <h2>{critical_threats:,}</h2>
        </div>
        ''', unsafe_allow_html=True)
    
    with col5:
        countries_affected = filtered_df['src_ip_country_code'].nunique() if 'src_ip_country_code' in filtered_df.columns else 0
        st.markdown(f'''
        <div class="cyber-metric">
            <h3>🌍 Countries</h3>
            <h2>{countries_affected:,}</h2>
        </div>
        ''', unsafe_allow_html=True)
    
    # 🚨 Critical threat alerts
    if critical_threats > 0:
        st.markdown(f'''
        <div class="threat-alert-critical">
            <h2>🚨 CRITICAL THREAT ALERT 🚨</h2>
            <p><strong>{critical_threats}</strong> critical threats detected requiring immediate attention!</p>
            <p>🔴 Initiate emergency response protocols immediately!</p>
        </div>
        ''', unsafe_allow_html=True)
    
    st.markdown("---")
    
    # 📈 Interactive Analysis Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "📊 Traffic Analysis", 
        "🗺️ Geographic Intel", 
        "🌐 Protocol Analysis",
        "🎯 Port Intelligence", 
        "⏰ Temporal Patterns",
        "📋 Raw Intelligence"
    ])
    
    with tab1:
        create_bytes_distribution_analysis(filtered_df)
        
        # Additional scatter analysis
        if len(filtered_df) > 0:
            st.subheader("🔄 Advanced Traffic Correlation")
            sample_df = filtered_df.sample(min(2000, len(filtered_df)))
            
            fig_advanced = px.scatter(
                sample_df,
                x='bytes_in',
                y='bytes_out',
                color='threat_level' if 'threat_level' in sample_df.columns else None,
                size='total_bytes' if 'total_bytes' in sample_df.columns else None,
                hover_data=['src_ip_country_code', 'protocol'] if all(col in sample_df.columns for col in ['src_ip_country_code', 'protocol']) else None,
                title="🔄 Multi-dimensional Traffic Analysis",
                log_x=True,
                log_y=True,
                template='plotly_dark'
            )
            fig_advanced.update_layout(height=600)
            st.plotly_chart(fig_advanced, use_container_width=True)
    
    with tab2:
        create_geographic_analysis(filtered_df)
    
    with tab3:
        create_protocol_analysis(filtered_df)
    
    with tab4:
        create_port_analysis(filtered_df)
    
    with tab5:
        create_temporal_analysis(filtered_df)
    
    with tab6:
        st.subheader("📋 Raw Threat Intelligence Data")
        
        # Search functionality
        search_term = st.text_input("🔍 Search by IP address or country:")
        if search_term:
            search_cols = ['src_ip', 'src_ip_country_code']
            mask = pd.Series(False, index=filtered_df.index)
            for col in search_cols:
                if col in filtered_df.columns:
                    mask |= filtered_df[col].astype(str).str.contains(search_term, case=False, na=False)
            display_df = filtered_df[mask]
        else:
            display_df = filtered_df
        
        st.write(f"📊 Showing {len(display_df)} records out of {len(filtered_df)} filtered records")
        
        # Display key columns
        display_columns = ['time', 'src_ip', 'src_ip_country_code', 'protocol', 
                          'bytes_in', 'bytes_out', 'total_bytes', 'threat_level', 
                          'dst_port']
        
        # Filter columns that exist
        available_columns = [col for col in display_columns if col in display_df.columns]
        
        st.dataframe(
            display_df[available_columns].head(100),
            use_container_width=True,
            height=500
        )
        
        # Download functionality
        if len(display_df) > 0:
            csv_data = display_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Intelligence Report (CSV)",
                data=csv_data,
                file_name=f"threat_intelligence_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    # 📊 Footer statistics
    st.markdown("---")
    st.markdown("### 📊 Session Statistics")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📈 Records Processed", f"{len(df):,}")
    with col2:
        st.metric("🔍 Records Filtered", f"{len(filtered_df):,}")
    with col3:
        filter_percentage = (len(filtered_df) / len(df) * 100) if len(df) > 0 else 0
        st.metric("📊 Filter Efficiency", f"{filter_percentage:.1f}%")
    with col4:
        st.metric("⏱️ Last Updated", datetime.now().strftime("%H:%M:%S"))

if __name__ == "__main__":
    main()