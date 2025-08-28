# 📚 API Reference & Developer Guide
## Elite Cybersecurity Web Threat Analysis System

### 🎯 API Overview

This document provides comprehensive API reference for developers working with the Elite Cybersecurity Web Threat Analysis System, including internal functions, data structures, and extension points.

---

## 🔧 Core Data Processing API

### **ThreatDataLoader Class**

#### **Class Definition:**
```python
class ThreatDataLoader:
    """
    Primary data loading and preprocessing class
    Handles multiple data sources and formats
    """
    
    def __init__(self, data_sources: List[str] = None):
        """
        Initialize data loader
        
        Args:
            data_sources: List of data file paths
        """
        self.data_sources = data_sources or [
            "data/CloudWatch_Traffic_Web_Attack.csv",
            "data/transformed_cyber_data.csv",
            "data/anomaly_detected_data.csv"
        ]
        self.df = None
        self.processed = False
```

#### **Methods:**

##### **load_data()**
```python
def load_data(self) -> pd.DataFrame:
    """
    Load cybersecurity data from configured sources
    
    Returns:
        pd.DataFrame: Processed cybersecurity dataset
        
    Raises:
        FileNotFoundError: If no data sources found
        ValueError: If data format is invalid
        
    Example:
        >>> loader = ThreatDataLoader()
        >>> df = loader.load_data()
        >>> print(df.shape)
        (2000, 15)
    """
```

##### **validate_data()**
```python
def validate_data(self, df: pd.DataFrame) -> bool:
    """
    Validate data quality and schema
    
    Args:
        df: DataFrame to validate
        
    Returns:
        bool: True if data is valid
        
    Validation Rules:
        - Required columns present
        - Data types correct
        - No critical missing values
        - Port numbers in valid range (0-65535)
        - IP addresses in valid format
    """
```

##### **preprocess_data()**
```python
def preprocess_data(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply preprocessing transformations
    
    Args:
        df: Raw data DataFrame
        
    Returns:
        pd.DataFrame: Preprocessed data
        
    Transformations:
        - Convert timestamps to datetime
        - Calculate derived fields
        - Create threat level categories
        - Generate anomaly scores
    """
```

---

## 📊 Visualization API

### **ChartGenerator Class**

#### **Class Definition:**
```python
class ChartGenerator:
    """
    Professional chart generation for cybersecurity data
    Uses Plotly for interactive visualizations
    """
    
    def __init__(self, theme: str = "dark"):
        """
        Initialize chart generator
        
        Args:
            theme: Visual theme ('dark', 'light', 'cyber')
        """
        self.theme = theme
        self.color_palette = self._get_color_palette()
```

#### **Geographic Charts:**

##### **create_country_threat_map()**
```python
def create_country_threat_map(self, 
                            df: pd.DataFrame, 
                            top_n: int = 15) -> go.Figure:
    """
    Create geographic threat distribution chart
    
    Args:
        df: Cybersecurity data
        top_n: Number of top countries to display
        
    Returns:
        plotly.graph_objects.Figure: Interactive bar chart
        
    Features:
        - Horizontal bar chart
        - Color-coded by threat count
        - Hover information
        - Responsive design
        
    Example:
        >>> generator = ChartGenerator()
        >>> fig = generator.create_country_threat_map(df)
        >>> fig.show()
    """
```

##### **create_threat_level_pie()**
```python
def create_threat_level_pie(self, df: pd.DataFrame) -> go.Figure:
    """
    Create threat level distribution pie chart
    
    Args:
        df: Cybersecurity data with 'threat_level' column
        
    Returns:
        plotly.graph_objects.Figure: Pie chart
        
    Configuration:
        - Color mapping: Low=Green, Medium=Yellow, High=Orange, Critical=Red
        - Percentage labels inside slices
        - Interactive hover information
    """
```

#### **Time Series Charts:**

##### **create_traffic_timeline()**
```python
def create_traffic_timeline(self, df: pd.DataFrame) -> go.Figure:
    """
    Create dual-axis time series chart
    
    Args:
        df: Data with 'hour', 'total_bytes', 'src_ip' columns
        
    Returns:
        plotly.graph_objects.Figure: Multi-subplot time series
        
    Subplots:
        1. Hourly traffic volume (MB)
        2. Connection frequency
        
    Features:
        - Filled area charts
        - Different colors for each metric
        - Synchronized x-axis
    """
```

#### **Advanced Analytics Charts:**

##### **create_scatter_analysis()**
```python
def create_scatter_analysis(self, 
                          df: pd.DataFrame,
                          x_col: str = "bytes_in",
                          y_col: str = "bytes_out") -> go.Figure:
    """
    Create scatter plot for traffic analysis
    
    Args:
        df: Data for analysis
        x_col: X-axis column name
        y_col: Y-axis column name
        
    Returns:
        plotly.graph_objects.Figure: Scatter plot
        
    Features:
        - Color by threat level
        - Size by total bytes
        - Logarithmic scaling
        - Interactive hover data
    """
```

---

## 🤖 Machine Learning API

### **ThreatAnalyzer Class**

#### **Anomaly Detection:**

##### **detect_anomalies()**
```python
def detect_anomalies(self, 
                    df: pd.DataFrame,
                    method: str = "isolation_forest") -> np.ndarray:
    """
    Detect anomalous network behavior
    
    Args:
        df: Network traffic data
        method: Algorithm ('isolation_forest', 'one_class_svm', 'statistical')
        
    Returns:
        np.ndarray: Anomaly scores (-1 for anomalies, 1 for normal)
        
    Algorithms:
        - isolation_forest: Isolation Forest (default)
        - one_class_svm: One-Class SVM
        - statistical: Z-score based detection
        
    Example:
        >>> analyzer = ThreatAnalyzer()
        >>> anomalies = analyzer.detect_anomalies(df)
        >>> df['is_anomaly'] = anomalies == -1
    """
```

##### **calculate_threat_scores()**
```python
def calculate_threat_scores(self, df: pd.DataFrame) -> pd.Series:
    """
    Calculate comprehensive threat scores
    
    Args:
        df: Network data with required columns
        
    Returns:
        pd.Series: Threat scores (0.0 to 1.0)
        
    Scoring Factors:
        - Traffic volume (40%)
        - Source country risk (30%)
        - Port risk level (20%)
        - Protocol risk (10%)
        
    Score Ranges:
        - 0.0-0.25: Low threat
        - 0.25-0.50: Medium threat
        - 0.50-0.75: High threat
        - 0.75-1.0: Critical threat
    """
```

#### **Pattern Recognition:**

##### **detect_port_scanning()**
```python
def detect_port_scanning(self, 
                        df: pd.DataFrame,
                        min_ports: int = 5,
                        time_window: int = 60) -> List[dict]:
    """
    Identify potential port scanning activities
    
    Args:
        df: Network traffic data
        min_ports: Minimum unique ports for detection
        time_window: Time window in minutes
        
    Returns:
        List[dict]: Detected port scan events
        
    Detection Criteria:
        - Multiple unique destination ports
        - Short time window
        - Low average bytes per connection
        - Single source IP
        
    Output Format:
        [
            {
                'src_ip': '192.168.1.100',
                'ports_scanned': [22, 23, 80, 443, 8080],
                'scan_duration': 45.2,
                'total_attempts': 127
            }
        ]
    """
```

---

## 🎨 UI Components API

### **Dashboard Components**

#### **MetricsDisplay Class:**

##### **create_metric_card()**
```python
def create_metric_card(self,
                      title: str,
                      value: Union[int, float, str],
                      delta: str = None,
                      delta_color: str = "normal") -> None:
    """
    Create animated metric card
    
    Args:
        title: Metric title
        value: Primary metric value
        delta: Change indicator
        delta_color: Color theme ('normal', 'inverse', 'off')
        
    Features:
        - Glass morphism styling
        - Hover animations
        - Professional typography
        - Responsive design
        
    Example:
        >>> metrics = MetricsDisplay()
        >>> metrics.create_metric_card(
        ...     title="🌐 Total Connections",
        ...     value="2,456",
        ...     delta="+123 new"
        ... )
    """
```

#### **FilterPanel Class:**

##### **create_sidebar_filters()**
```python
def create_sidebar_filters(self, df: pd.DataFrame) -> dict:
    """
    Generate comprehensive filter panel
    
    Args:
        df: Data for filter options
        
    Returns:
        dict: Filter selections
        
    Filters Generated:
        - Time range selector
        - Country multi-select
        - Protocol multi-select
        - Threat level multi-select
        - Port range slider
        - Data volume threshold
        - Real-time toggle
        
    Return Format:
        {
            'time_range': 'Last 7 Days',
            'countries': ['US', 'CN', 'RU'],
            'protocols': ['TCP', 'HTTP'],
            'threat_levels': ['High', 'Critical'],
            'port_range': (0, 65535),
            'min_bytes': 1000,
            'real_time': True
        }
    """
```

---

## 🔍 Data Analysis API

### **StatisticalAnalysis Class**

#### **Traffic Analysis:**

##### **get_hourly_patterns()**
```python
def get_hourly_patterns(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Analyze traffic patterns by hour
    
    Args:
        df: Time-series network data
        
    Returns:
        pd.DataFrame: Hourly statistics
        
    Columns:
        - hour: Hour of day (0-23)
        - connection_count: Number of connections
        - total_bytes: Sum of bytes transferred
        - avg_bytes: Average bytes per connection
        - threat_percentage: Percentage of threats
        
    Example:
        >>> analyzer = StatisticalAnalysis()
        >>> hourly = analyzer.get_hourly_patterns(df)
        >>> peak_hour = hourly.loc[hourly['connection_count'].idxmax(), 'hour']
    """
```

##### **get_country_statistics()**
```python
def get_country_statistics(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Generate comprehensive country-based statistics
    
    Args:
        df: Network data with country codes
        
    Returns:
        pd.DataFrame: Country statistics
        
    Metrics:
        - total_connections: Connection count
        - unique_ips: Distinct source IPs
        - threat_count: Number of threats
        - threat_percentage: Threat rate
        - avg_bytes: Average traffic volume
        - risk_score: Calculated risk score
    """
```

#### **Protocol Analysis:**

##### **analyze_protocol_patterns()**
```python
def analyze_protocol_patterns(self, df: pd.DataFrame) -> dict:
    """
    Comprehensive protocol usage analysis
    
    Args:
        df: Network data with protocol information
        
    Returns:
        dict: Protocol analysis results
        
    Analysis:
        - Usage distribution
        - Threat rates by protocol
        - Average traffic volumes
        - Time-based patterns
        - Anomaly detection
        
    Return Format:
        {
            'distribution': {'TCP': 0.45, 'HTTP': 0.30, ...},
            'threat_rates': {'TCP': 0.15, 'HTTP': 0.08, ...},
            'avg_bytes': {'TCP': 15420, 'HTTP': 8920, ...},
            'hourly_patterns': DataFrame,
            'anomalies': ['Unusual SSH traffic at 3 AM']
        }
    """
```

---

## 📤 Export & Reporting API

### **DataExporter Class**

#### **Export Functions:**

##### **export_to_csv()**
```python
def export_to_csv(self, 
                 df: pd.DataFrame, 
                 filename: str = None,
                 columns: List[str] = None) -> str:
    """
    Export data to CSV format
    
    Args:
        df: Data to export
        filename: Output filename (auto-generated if None)
        columns: Specific columns to export
        
    Returns:
        str: Generated filename
        
    Features:
        - Automatic timestamp in filename
        - Column selection
        - UTF-8 encoding
        - Optimized for large datasets
    """
```

##### **generate_threat_report()**
```python
def generate_threat_report(self, 
                          df: pd.DataFrame,
                          format: str = "json") -> Union[dict, str]:
    """
    Generate comprehensive threat intelligence report
    
    Args:
        df: Analyzed cybersecurity data
        format: Output format ('json', 'html', 'pdf')
        
    Returns:
        Union[dict, str]: Report data or filename
        
    Report Sections:
        - Executive summary
        - Key metrics
        - Geographic analysis
        - Temporal patterns
        - Threat recommendations
        - Technical details
        
    Example:
        >>> exporter = DataExporter()
        >>> report = exporter.generate_threat_report(df)
        >>> print(report['executive_summary'])
    """
```

---

## 🔒 Security & Validation API

### **SecurityValidator Class**

#### **Input Validation:**

##### **sanitize_user_input()**
```python
def sanitize_user_input(self, user_input: str) -> str:
    """
    Sanitize user search inputs
    
    Args:
        user_input: Raw user input
        
    Returns:
        str: Sanitized input
        
    Sanitization:
        - Remove special characters
        - Limit length
        - Escape HTML entities
        - Validate IP format
    """
```

##### **validate_data_schema()**
```python
def validate_data_schema(self, df: pd.DataFrame) -> List[str]:
    """
    Validate data against expected schema
    
    Args:
        df: DataFrame to validate
        
    Returns:
        List[str]: Validation errors (empty if valid)
        
    Validations:
        - Required columns present
        - Data types correct
        - Value ranges valid
        - Foreign key constraints
    """
```

---

## 🚀 Performance & Caching API

### **PerformanceOptimizer Class**

#### **Caching Functions:**

##### **cache_data_load()**
```python
@st.cache_data(ttl=300)
def cache_data_load(data_path: str) -> pd.DataFrame:
    """
    Cached data loading with TTL
    
    Args:
        data_path: Path to data file
        
    Returns:
        pd.DataFrame: Cached data
        
    Cache Configuration:
        - TTL: 5 minutes
        - Memory-based storage
        - Automatic invalidation
    """
```

##### **optimize_dataframe()**
```python
def optimize_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
    """
    Optimize DataFrame for visualization
    
    Args:
        df: Large DataFrame
        
    Returns:
        pd.DataFrame: Optimized DataFrame
        
    Optimizations:
        - Sample large datasets
        - Convert data types
        - Remove unnecessary columns
        - Aggregate where appropriate
    """
```

---

## 🔌 Extension Points

### **Custom Plugin Interface**

#### **BasePlugin Class:**
```python
class BasePlugin:
    """
    Base class for dashboard plugins
    """
    
    def __init__(self, name: str):
        self.name = name
        self.enabled = True
    
    def process_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Override to add custom data processing"""
        return df
    
    def create_visualization(self, df: pd.DataFrame) -> go.Figure:
        """Override to add custom charts"""
        raise NotImplementedError
    
    def get_metrics(self, df: pd.DataFrame) -> dict:
        """Override to add custom metrics"""
        return {}
```

#### **Plugin Registration:**
```python
def register_plugin(plugin: BasePlugin) -> None:
    """
    Register custom plugin
    
    Args:
        plugin: Plugin instance
        
    Example:
        >>> class MyPlugin(BasePlugin):
        ...     def create_visualization(self, df):
        ...         return px.bar(df, x='country', y='count')
        ...
        >>> register_plugin(MyPlugin("Custom Analysis"))
    """
```

---

## 📋 Error Handling

### **Custom Exceptions:**

```python
class CyberSecError(Exception):
    """Base exception for cybersecurity analysis"""
    pass

class DataValidationError(CyberSecError):
    """Raised when data validation fails"""
    pass

class VisualizationError(CyberSecError):
    """Raised when chart generation fails"""
    pass

class SecurityError(CyberSecError):
    """Raised for security-related issues"""
    pass
```

---

## 🧪 Testing Utilities

### **TestDataGenerator Class:**

```python
class TestDataGenerator:
    """Generate test data for development and testing"""
    
    @staticmethod
    def create_sample_threats(n_records: int = 1000) -> pd.DataFrame:
        """
        Generate realistic cybersecurity test data
        
        Args:
            n_records: Number of records to generate
            
        Returns:
            pd.DataFrame: Test dataset
        """
```

---

**📚 API Reference Complete**

*This comprehensive API reference provides developers with all necessary information to extend, customize, and integrate with the Elite Cybersecurity Web Threat Analysis System.*