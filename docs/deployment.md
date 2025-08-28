# 🚀 Deployment Guide
## Elite Cybersecurity Web Threat Analysis System

### 🎯 Deployment Overview

This guide covers multiple deployment scenarios for the Elite Cybersecurity Web Threat Analysis System, from development environments to enterprise production deployments.

---

## 🏠 Local Development Deployment

### **Quick Development Setup**
```bash
# 1. Clone and setup
git clone <repository-url>
cd Cybersecurity_Web_Threat_Analysis

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run development server
cd dashboard
streamlit run app.py
```

### **Development Configuration**
```python
# .streamlit/config.toml
[server]
port = 8501
headless = false
enableCORS = true
enableWebsocketCompression = false

[browser]
gatherUsageStats = false
showErrorDetails = true

[theme]
primaryColor = "#00f5ff"
backgroundColor = "#0a0a0a"
secondaryBackgroundColor = "#1a1a2e"
textColor = "#ffffff"
```

---

## 🐳 Docker Deployment

### **Single Container Deployment**

#### **Create Dockerfile:**
```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 cybersec && chown -R cybersec:cybersec /app
USER cybersec

# Expose port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Run application
CMD ["streamlit", "run", "dashboard/app.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true"]
```

#### **Build and Run:**
```bash
# Build image
docker build -t cybersec-dashboard:latest .

# Run container
docker run -d \
  --name cybersec-dashboard \
  -p 8501:8501 \
  -v $(pwd)/data:/app/data:ro \
  --restart unless-stopped \
  cybersec-dashboard:latest

# Check logs
docker logs cybersec-dashboard

# Access dashboard
open http://localhost:8501
```

### **Docker Compose Deployment**

#### **docker-compose.yml:**
```yaml
version: '3.8'

services:
  cybersec-dashboard:
    build: .
    container_name: cybersec-dashboard
    ports:
      - "8501:8501"
    volumes:
      - ./data:/app/data:ro
      - ./logs:/app/logs
    environment:
      - STREAMLIT_SERVER_HEADLESS=true
      - STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
      - PYTHONUNBUFFERED=1
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8501/_stcore/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  nginx:
    image: nginx:alpine
    container_name: cybersec-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - cybersec-dashboard
    restart: unless-stopped

volumes:
  logs:
```

#### **Deploy with Docker Compose:**
```bash
# Deploy services
docker-compose up -d

# Scale dashboard instances
docker-compose up -d --scale cybersec-dashboard=3

# Monitor services
docker-compose logs -f

# Update deployment
docker-compose pull && docker-compose up -d
```

---

## ☁️ Cloud Deployment

### **AWS Deployment**

#### **Option 1: AWS ECS (Elastic Container Service)**
```yaml
# ecs-task-definition.json
{
  "family": "cybersec-dashboard",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::account:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "cybersec-dashboard",
      "image": "your-account.dkr.ecr.region.amazonaws.com/cybersec-dashboard:latest",
      "portMappings": [
        {
          "containerPort": 8501,
          "protocol": "tcp"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/cybersec-dashboard",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

#### **Deploy to ECS:**
```bash
# Build and push to ECR
aws ecr get-login-password --region us-west-2 | docker login --username AWS --password-stdin account.dkr.ecr.us-west-2.amazonaws.com
docker build -t cybersec-dashboard .
docker tag cybersec-dashboard:latest account.dkr.ecr.us-west-2.amazonaws.com/cybersec-dashboard:latest
docker push account.dkr.ecr.us-west-2.amazonaws.com/cybersec-dashboard:latest

# Create ECS service
aws ecs create-service \
  --cluster cybersec-cluster \
  --service-name cybersec-dashboard \
  --task-definition cybersec-dashboard:1 \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-12345,subnet-67890],securityGroups=[sg-abcdef],assignPublicIp=ENABLED}"
```

#### **Option 2: AWS EC2 with Auto Scaling**
```bash
#!/bin/bash
# user-data.sh for EC2 instances

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker
systemctl start docker
systemctl enable docker

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Deploy application
cd /opt
git clone https://github.com/your-repo/Cybersecurity_Web_Threat_Analysis.git
cd Cybersecurity_Web_Threat_Analysis
docker-compose up -d

# Setup CloudWatch monitoring
yum install -y amazon-cloudwatch-agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/cloudwatch-config.json -s
```

### **Google Cloud Platform Deployment**

#### **Google Cloud Run:**
```yaml
# cloudbuild.yaml
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/cybersec-dashboard:$BUILD_ID', '.']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/cybersec-dashboard:$BUILD_ID']
  - name: 'gcr.io/cloud-builders/gcloud'
    args: ['run', 'deploy', 'cybersec-dashboard',
           '--image', 'gcr.io/$PROJECT_ID/cybersec-dashboard:$BUILD_ID',
           '--platform', 'managed',
           '--region', 'us-central1',
           '--allow-unauthenticated',
           '--memory', '2Gi',
           '--cpu', '2',
           '--port', '8501']
```

#### **Deploy to Cloud Run:**
```bash
# Enable APIs
gcloud services enable cloudbuild.googleapis.com run.googleapis.com

# Submit build
gcloud builds submit --config cloudbuild.yaml

# Access service
gcloud run services describe cybersec-dashboard --region us-central1 --format 'value(status.url)'
```

### **Microsoft Azure Deployment**

#### **Azure Container Instances:**
```yaml
# azure-container-group.yaml
apiVersion: 2021-03-01
location: eastus
name: cybersec-dashboard
properties:
  containers:
  - name: cybersec-dashboard
    properties:
      image: your-registry.azurecr.io/cybersec-dashboard:latest
      ports:
      - port: 8501
        protocol: TCP
      resources:
        requests:
          cpu: 1.0
          memoryInGB: 2.0
  osType: Linux
  ipAddress:
    type: Public
    ports:
    - protocol: TCP
      port: 8501
  restartPolicy: Always
type: Microsoft.ContainerInstance/containerGroups
```

---

## 🏢 Enterprise Production Deployment

### **High Availability Setup**

#### **Load Balancer Configuration (Nginx):**
```nginx
# nginx.conf
upstream cybersec_backend {
    least_conn;
    server cybersec-app-1:8501 max_fails=3 fail_timeout=30s;
    server cybersec-app-2:8501 max_fails=3 fail_timeout=30s;
    server cybersec-app-3:8501 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name cybersec.company.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cybersec.company.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location / {
        proxy_pass http://cybersec_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # WebSocket support
        proxy_read_timeout 86400;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
```

### **Kubernetes Deployment**

#### **Kubernetes Manifests:**
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cybersec-dashboard
  labels:
    app: cybersec-dashboard
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cybersec-dashboard
  template:
    metadata:
      labels:
        app: cybersec-dashboard
    spec:
      containers:
      - name: cybersec-dashboard
        image: your-registry/cybersec-dashboard:latest
        ports:
        - containerPort: 8501
        env:
        - name: STREAMLIT_SERVER_HEADLESS
          value: "true"
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /_stcore/health
            port: 8501
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /_stcore/health
            port: 8501
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: cybersec-dashboard-service
spec:
  selector:
    app: cybersec-dashboard
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8501
  type: LoadBalancer

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cybersec-dashboard-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
  - hosts:
    - cybersec.company.com
    secretName: cybersec-tls
  rules:
  - host: cybersec.company.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: cybersec-dashboard-service
            port:
              number: 80
```

#### **Deploy to Kubernetes:**
```bash
# Apply manifests
kubectl apply -f deployment.yaml

# Check deployment status
kubectl get pods -l app=cybersec-dashboard
kubectl get services
kubectl get ingress

# Scale deployment
kubectl scale deployment cybersec-dashboard --replicas=5

# Update deployment
kubectl set image deployment/cybersec-dashboard cybersec-dashboard=your-registry/cybersec-dashboard:v2.0
```

---

## 📊 Monitoring & Observability

### **Application Monitoring**

#### **Prometheus Configuration:**
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'cybersec-dashboard'
    static_configs:
      - targets: ['cybersec-dashboard:8501']
    metrics_path: /metrics
    scrape_interval: 30s
```

#### **Grafana Dashboard:**
```json
{
  "dashboard": {
    "title": "Cybersecurity Dashboard Metrics",
    "panels": [
      {
        "title": "Active Sessions",
        "type": "stat",
        "targets": [
          {
            "expr": "streamlit_active_sessions"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(streamlit_request_duration_seconds[5m])"
          }
        ]
      }
    ]
  }
}
```

### **Log Management**

#### **Centralized Logging (ELK Stack):**
```yaml
# logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][app] == "cybersec-dashboard" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} - %{LOGLEVEL:level} - %{GREEDYDATA:message}" }
    }
    date {
      match => [ "timestamp", "ISO8601" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "cybersec-dashboard-%{+YYYY.MM.dd}"
  }
}
```

---

## 🔒 Security Hardening

### **SSL/TLS Configuration**
```bash
# Generate SSL certificate (Let's Encrypt)
certbot --nginx -d cybersec.company.com

# Or use manual certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/cybersec.key \
  -out /etc/ssl/certs/cybersec.crt
```

### **Firewall Rules**
```bash
# UFW (Ubuntu)
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw deny 8501/tcp   # Block direct access to Streamlit
ufw enable

# iptables
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 8501 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 8501 -j DROP
```

### **Environment Variables Security**
```bash
# Use secrets management
export STREAMLIT_SERVER_ENABLE_CORS=false
export STREAMLIT_SERVER_ENABLE_XSRF_PROTECTION=true
export STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

# Or use Docker secrets
echo "secure_secret_key" | docker secret create streamlit_secret -
```

---

## 📈 Performance Optimization

### **Production Optimizations**
```python
# .streamlit/config.toml for production
[server]
maxUploadSize = 1000
maxMessageSize = 1000
enableCORS = false
enableXsrfProtection = true

[browser]
gatherUsageStats = false

[global]
dataFrameSerialization = "legacy"
```

### **Caching Strategy**
```python
# Enhanced caching for production
@st.cache_data(ttl=300)  # 5-minute TTL
def load_data():
    """Cached data loading with TTL"""
    return process_data()

@st.cache_resource
def init_ml_models():
    """Cache ML models"""
    return load_models()
```

---

## 🧪 Testing in Production

### **Health Checks**
```bash
# Simple health check
curl -f http://localhost:8501/_stcore/health

# Detailed health check script
#!/bin/bash
HEALTH_URL="http://localhost:8501/_stcore/health"
DASHBOARD_URL="http://localhost:8501"

# Check health endpoint
if curl -f $HEALTH_URL > /dev/null 2>&1; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    exit 1
fi

# Check dashboard loading
if curl -f $DASHBOARD_URL > /dev/null 2>&1; then
    echo "✅ Dashboard accessible"
else
    echo "❌ Dashboard not accessible"
    exit 1
fi
```

### **Load Testing**
```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8501/

# Using wrk
wrk -t12 -c400 -d30s http://localhost:8501/
```

---

## 🚀 Deployment Checklist

### **Pre-Deployment:**
- [ ] Code review completed
- [ ] Unit tests passing
- [ ] Integration tests passing
- [ ] Security scan completed
- [ ] Performance testing done
- [ ] Documentation updated

### **Deployment:**
- [ ] Backup current version
- [ ] Deploy to staging environment
- [ ] Smoke tests in staging
- [ ] Deploy to production
- [ ] Health checks passing
- [ ] Monitoring alerts configured

### **Post-Deployment:**
- [ ] Monitor application logs
- [ ] Check performance metrics
- [ ] Verify all features working
- [ ] Monitor for errors
- [ ] Update team on deployment status

---

**🎉 Your Elite Cybersecurity Dashboard is now ready for enterprise deployment!**

*Choose the deployment method that best fits your infrastructure and security requirements.*