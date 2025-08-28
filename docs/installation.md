# 🚀 Installation & Setup Guide
## Elite Cybersecurity Web Threat Analysis System

### 📋 System Requirements

#### **Minimum Requirements:**
- **Operating System:** Windows 10/11, macOS 10.14+, or Linux Ubuntu 18.04+
- **Python:** Version 3.8 or higher (Recommended: Python 3.11+)
- **RAM:** 8 GB minimum (16 GB recommended)
- **Storage:** 2 GB free space
- **Internet:** Required for initial setup and real-time updates

#### **Recommended Specifications:**
- **CPU:** Intel i5 or AMD Ryzen 5 (or equivalent)
- **RAM:** 16 GB or higher
- **Storage:** SSD with 5 GB free space
- **Network:** Stable broadband connection

---

## 🛠️ Installation Process

### **Step 1: Python Environment Setup**

#### **Option A: Using Python Virtual Environment (Recommended)**
```bash
# Create virtual environment
python -m venv cybersec_env

# Activate virtual environment
# On Windows:
cybersec_env\Scripts\activate
# On macOS/Linux:
source cybersec_env/bin/activate
```

#### **Option B: Using Conda Environment**
```bash
# Create conda environment
conda create -n cybersec_env python=3.11

# Activate environment
conda activate cybersec_env
```

### **Step 2: Clone or Download Project**

#### **Option A: Git Clone (Recommended)**
```bash
git clone https://github.com/your-username/Cybersecurity_Web_Threat_Analysis.git
cd Cybersecurity_Web_Threat_Analysis
```

#### **Option B: Direct Download**
1. Download the project ZIP file
2. Extract to your desired location
3. Navigate to the project directory

### **Step 3: Install Dependencies**

```bash
# Install all required packages
pip install -r requirements.txt

# Alternative: Install packages individually
pip install streamlit pandas plotly numpy scikit-learn matplotlib seaborn jupyter
```

### **Step 4: Verify Installation**

```bash
# Check Python version
python --version

# Check installed packages
pip list

# Verify Streamlit installation
streamlit --version
```

---

## 🏃‍♂️ Quick Start Guide

### **1. Launch the Dashboard**
```bash
# Navigate to dashboard directory
cd dashboard

# Start the Streamlit application
streamlit run app.py
```

### **2. Access the Interface**
- **Local Access:** http://localhost:8501
- **Network Access:** http://your-ip-address:8501
- **Alternative Ports:** 8502, 8503, 8504 (if 8501 is busy)

### **3. First-Time Setup**
1. ✅ **Data Loading:** The system will automatically load sample data
2. ✅ **Interface Loading:** Wait for the dashboard to fully initialize
3. ✅ **Feature Testing:** Try different filters and visualizations

---

## 🔧 Advanced Configuration

### **Custom Data Integration**

#### **Using Your Own Data:**
1. **Prepare CSV File:** Ensure your data matches the expected format
2. **Place in Data Directory:** Copy to `data/` folder
3. **Update Configuration:** Modify `app.py` to point to your data file

#### **Expected Data Format:**
```csv
src_ip,dst_ip,src_ip_country_code,dst_port,protocol,bytes_in,bytes_out,timestamp,threat_level
192.168.1.1,10.0.0.1,US,80,HTTP,1024,2048,2024-01-01 12:00:00,Low
```

### **Environment Variables**
Create a `.env` file in the project root:
```env
# Dashboard Configuration
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_HEADLESS=true
STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Data Configuration
DATA_SOURCE=CloudWatch_Traffic_Web_Attack.csv
ENABLE_REAL_TIME=true
UPDATE_INTERVAL=30

# Security Settings
ENABLE_CORS=false
MAX_UPLOAD_SIZE=200
```

---

## 🐳 Docker Deployment (Advanced)

### **Option 1: Using Docker**

#### **Create Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

#### **Build and Run:**
```bash
# Build Docker image
docker build -t cybersec-dashboard .

# Run container
docker run -p 8501:8501 cybersec-dashboard
```

### **Option 2: Using Docker Compose**

#### **Create docker-compose.yml:**
```yaml
version: '3.8'
services:
  cybersec-dashboard:
    build: .
    ports:
      - "8501:8501"
    volumes:
      - ./data:/app/data
    environment:
      - STREAMLIT_SERVER_HEADLESS=true
    restart: unless-stopped
```

#### **Deploy:**
```bash
docker-compose up -d
```

---

## 🔍 Troubleshooting

### **Common Issues & Solutions**

#### **Issue 1: Port Already in Use**
```bash
# Solution: Use different port
streamlit run app.py --server.port 8502
```

#### **Issue 2: Module Import Errors**
```bash
# Solution: Reinstall dependencies
pip uninstall -r requirements.txt -y
pip install -r requirements.txt
```

#### **Issue 3: Data Loading Errors**
```bash
# Solution: Check data file format and location
ls -la data/
python -c "import pandas as pd; print(pd.read_csv('data/CloudWatch_Traffic_Web_Attack.csv').shape)"
```

#### **Issue 4: Performance Issues**
```bash
# Solution: Increase system resources or reduce data size
# Edit app.py and modify sample size:
# sample_df = df.sample(min(1000, len(df)))  # Reduce from 1000 to 500
```

### **Debug Mode**
```bash
# Run in debug mode
streamlit run app.py --logger.level debug

# Check system resources
python -c "import psutil; print(f'RAM: {psutil.virtual_memory().percent}%')"
```

---

## 📊 Data Management

### **Sample Data Location**
```
data/
├── CloudWatch_Traffic_Web_Attack.csv    # Primary dataset
├── anomaly_detected_data.csv           # ML processed data
└── transformed_cyber_data.csv          # Cleaned dataset
```

### **Data Backup & Restore**
```bash
# Backup current data
cp -r data/ data_backup_$(date +%Y%m%d)/

# Restore from backup
cp -r data_backup_20240826/ data/
```

---

## 🔒 Security Considerations

### **Network Security:**
- **Firewall Rules:** Configure appropriate firewall rules for port 8501
- **HTTPS Setup:** For production, set up SSL/TLS certificates
- **Access Control:** Implement authentication if deploying publicly

### **Data Security:**
- **Data Encryption:** Ensure sensitive data is encrypted at rest
- **Access Logs:** Monitor dashboard access and usage
- **Regular Updates:** Keep dependencies updated for security patches

---

## 🚀 Performance Optimization

### **System Optimization:**
```bash
# Increase Python memory limit
export PYTHONMALLOC=malloc

# Optimize Streamlit performance
streamlit run app.py --server.maxUploadSize 1000
```

### **Code Optimization:**
- **Data Sampling:** Reduce dataset size for faster loading
- **Caching:** Utilize Streamlit's `@st.cache_data` decorator
- **Lazy Loading:** Load charts only when tabs are accessed

---

## 📱 Mobile & Responsive Access

### **Mobile Optimization:**
- ✅ **Responsive Design:** Dashboard automatically adapts to screen size
- ✅ **Touch-Friendly:** All controls are touch-optimized
- ✅ **Mobile Charts:** Plotly charts work seamlessly on mobile devices

### **Access URLs:**
- **Desktop:** http://localhost:8501
- **Mobile (Same Network):** http://your-computer-ip:8501
- **Tablet:** Optimized layout for tablet viewing

---

## 📞 Support & Maintenance

### **Getting Help:**
1. **Documentation:** Check this guide and other docs/ files
2. **Error Logs:** Check terminal/console output for error messages
3. **GitHub Issues:** Report bugs and feature requests
4. **Community:** Join cybersecurity analytics communities

### **Regular Maintenance:**
```bash
# Update dependencies (monthly)
pip install --upgrade -r requirements.txt

# Clear cache (weekly)
streamlit cache clear

# Check system health
python -c "import streamlit as st; print(st.__version__)"
```

---

## ✅ Installation Checklist

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] Project files downloaded/cloned
- [ ] Dependencies installed successfully
- [ ] Dashboard launches without errors
- [ ] All visualizations load properly
- [ ] Filters and controls work correctly
- [ ] Data exports function properly
- [ ] Mobile access tested (optional)
- [ ] Security settings configured (for production)

---

**🎉 Congratulations! Your Elite Cybersecurity Dashboard is now ready to use!**

*For detailed usage instructions, please refer to the User Guide (user_guide.md)*