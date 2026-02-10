# VAPT Framework - Complete Documentation

## 🎯 **Enterprise VAPT Engine v2.3 - Complete Guide**

A comprehensive Dockerized Vulnerability Assessment and Penetration Testing framework with 40+ security tools, AI-powered vulnerability normalization, and integrated reporting.

---

## 📋 **Table of Contents**

1. [Overview & Features](#overview--features)
2. [Quick Start](#quick-start)
3. [System Requirements](#system-requirements)
4. [Installation & Setup](#installation--setup)
5. [Architecture](#architecture)
6. [Security Tools](#security-tools)
7. [Execution Modes](#execution-modes)
8. [Running Assessments](#running-assessments)
9. [AI Integration](#ai-integration)
10. [DetectDojo Integration](#detectdojo-integration)
11. [Output Structure](#output-structure)
12. [Configuration](#configuration)
13. [Production Deployment](#production-deployment)
14. [Network Strategy](#network-strategy)
15. [Troubleshooting](#troubleshooting)
16. [Security Best Practices](#security-best-practices)

---

## 🎯 **Overview & Features**

### **Core Features**
- **40+ Security Tools**: Comprehensive reconnaissance, network scanning, web assessment
- **AI Integration**: Qwen 0.5B model for vulnerability normalization and correlation
- **Multi-Mode Execution**: Strict, modular, and unified scanning modes
- **Dockerized**: Fully containerized for consistent environments
- **Automated Reporting**: HTML and JSON reports with executive summaries
- **DetectDojo Integration**: Centralized findings correlation and management

### **Key Benefits**
- **Enterprise-Ready**: Production-grade security assessment framework
- **AI-Powered Analysis**: Intelligent vulnerability normalization and scoring
- **Comprehensive Coverage**: 8 assessment phases covering all attack surfaces
- **Scalable**: Parallel processing and resource optimization
- **Compliant**: Built-in authorization guardrails and ethical scanning

---

## 🚀 **Quick Start**

### **Prerequisites**
- Docker and Docker Compose
- 4GB+ RAM available (8GB+ recommended)
- Docker socket access
- Authorization to scan target domains

### **5-Minute Setup**
```bash
# 1. Clone and prepare
git clone <repository-url>
cd /var/production
chmod +x *.sh */*.sh

# 2. Start services
docker-compose up -d

# 3. Run assessment
./run_enhanced_merged.sh example.com --mode strict
```

### **Basic Usage**
```bash
# Main enhanced framework (recommended)
./run_enhanced_merged.sh example.com

# With verbose output
./run_enhanced_merged.sh example.com --verbose

# Different execution modes
./run_enhanced_merged.sh example.com --mode strict    # Sequential (default)
./run_enhanced_merged.sh example.com --mode modular   # Phase-based
./run_enhanced_merged.sh example.com --mode unified   # Best effort

# Dry run to see commands without executing
./run_enhanced_merged.sh example.com --dry-run
```

---

## 💻 **System Requirements**

### **Minimum Requirements**
- **OS**: Linux (Ubuntu 20.04+, Debian, or CentOS)
- **RAM**: 4GB (8GB+ recommended for large scans)
- **CPU**: 2 cores (4+ cores recommended)
- **Disk**: 50GB free space (for logs, models, and reports)
- **Network**: Internet access (for tool downloads and model pulls)

### **Required Software**
- Docker Engine 20.10+
- Docker Compose 2.0+
- Git
- curl
- jq (JSON processor)

### **Install Prerequisites**

#### On Ubuntu/Debian:
```bash
# Update package manager
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add current user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install utilities
sudo apt-get install -y git curl jq
```

---

## 🏗️ **Installation & Setup**

### **Step 1: Clone Repository**
```bash
git clone <repository-url>
cd /var/production
```

### **Step 2: Set File Permissions**
```bash
# Make all scripts executable
chmod +x *.sh
chmod +x */*.sh
chmod +x send_to_detectdojo.sh
```

### **Step 3: Build Docker Images**
```bash
# Build all images (may take 30-45 minutes on first run)
docker-compose build

# If building individual services:
docker-compose build qwen-0.5b-normalizer
docker-compose build detectdojo
docker-compose build kalivapt
```

### **Step 4: Create Logs Directory**
```bash
# Create logs directory
mkdir -p logs
chmod 777 logs

# Create subdirectories for each component
mkdir -p logs/{vapt,detectdojo,qwen}
```

### **Step 5: Start Services**
```bash
# Start all services in background
docker-compose up -d

# Check service status
docker-compose ps

# Expected output:
# NAME                              STATUS              PORTS
# qwen-0.5b-normalizer-prod        Up 2 minutes        8080/tcp
# detectdojo-server                 Up 2 minutes        8081/tcp
# kalivapt                          Up 2 minutes
```

### **Step 6: Verify Services**
```bash
# Check Qwen normalizer health
curl http://localhost:8080/health | jq .

# Check DetectDojo health
curl http://localhost:8081/health | jq .
```

---

## 🏛️ **Architecture**

### **Component Overview**
```
├── run_enhanced_merged.sh           # 🎯 MAIN PROJECT - Enhanced VAPT Engine v2.3
├── Dockerfile                       # Custom VAPT tools container (40+ tools)
├── docker-compose.yml              # Service orchestration
├── detectdojo/                     # Vulnerability correlation platform
├── qwen-0.5b-normalizer/         # AI vulnerability normalization service
└── logs/                          # Assessment outputs and reports
```

### **Service Architecture**
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   run_enhanced  │───▶│   DetectDojo    │───▶│   Qwen 0.5B    │
│   VAPT Engine   │    │   Correlation   │    │   AI Service    │
│   (40+ tools)   │    │   Platform      │    │   Normalizer    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Raw Tool       │    │  Normalized     │    │  AI-Processed   │
│  Outputs       │    │  Findings      │    │  Vulnerabilities│
│  (JSON/TXT)    │    │  (JSON)        │    │  (Scored)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### **Data Flow**
1. **VAPT Engine** runs 40+ security tools → produces raw outputs
2. **DetectDojo** receives tool outputs → calls normalizer for AI processing
3. **Qwen AI** normalizes and scores vulnerabilities → returns structured data
4. **DetectDojo** deduplicates, correlates, stores findings → exposes API + reports

---

## 🛠️ **Security Tools**

### **🔍 Phase 1: Reconnaissance (9 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **subfinder** | Subdomain discovery | Rule-Based |
| **assetfinder** | Asset discovery | Rule-Based |
| **whois** | Domain information | Rule-Based |
| **dnsrecon** | DNS reconnaissance | Rule-Based |
| **dig** | DNS queries | Rule-Based |
| **whatweb** | Web technology identification | Rule-Based |
| **waybackurls** | URL discovery from archives | Rule-Based |
| **gau** | Get All URLs | Rule-Based |

### **🌐 Phase 2: Network Scanning (6+ tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **naabu** | Fast port scanner | Rule-Based |
| **rustscan** | Ultra-fast port scanning | Rule-Based |
| **httpx** | HTTP probe | Rule-Based |
| **nmap*** | Comprehensive network mapping | Rule-Based |
| **masscan*** | Fast port discovery | Rule-Based |

### **🛡️ Phase 3: Vulnerability Assessment (3 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **nuclei** | Vulnerability scanner with templates | **AI Processing** |
| **searchsploit** | Exploit database search | **AI Processing** |
| **nmap_vulners** | Nmap vulners script for CVE detection | **AI Processing** |

### **🌍 Phase 4: Web Security (7 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **feroxbuster** | Directory/file brute-force | Rule-Based |
| **katana** | Web crawler | Rule-Based |
| **nikto** | Web server vulnerability scanner | **AI Processing** |
| **ffuf** | Fast web fuzzer | Rule-Based |
| **dirsearch** | Directory scanner | Rule-Based |
| **wapiti** | Web application vulnerability scanner | **AI Processing** |
| **OWASP ZAP** | Comprehensive web security testing | **AI Processing** |

### **🔒 Phase 5: SSL/TLS Security (3 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **sslyze** | SSL/TLS configuration analyzer | Rule-Based |
| **sslscan** | SSL configuration scanner | Rule-Based |
| **testssl.sh** | Comprehensive SSL testing | Rule-Based |

### **🗄️ Phase 6: Database Security (5 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **sqlmap** | SQL injection detection and exploitation | **AI Processing** |
| **db_ports** | Database port scanning | Rule-Based |
| **redis_test** | Redis connectivity test | Rule-Based |
| **postgres_test** | PostgreSQL connectivity test | Rule-Based |
| **mysql_test** | MySQL connectivity test | Rule-Based |

### **🐳 Phase 7: Container & Cloud Security (4 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **metadata_check** | Cloud metadata exposure test | Rule-Based |
| **docker_registry** | Docker registry exposure test | Rule-Based |
| **k8s_api** | Kubernetes API exposure test | Rule-Based |
| **kubeaudit** | Kubernetes security audit | Rule-Based |

---

## ⚙️ **Execution Modes**

### **🔒 Strict Mode (Recommended)**
- **Sequential execution** with path discovery
- **40+ tools** executed in order
- **Error handling** with retry logic
- **Best for**: Comprehensive assessments

### **🧩 Modular Mode**
- **Phase-based modular execution**
- **Each phase** runs independently
- **Partial results** available
- **Best for**: Targeted assessments

### **🔄 Unified Mode**
- **Simplified unified execution**
- **Best effort** approach
- **Fast results** prioritized
- **Best for**: Quick assessments

---

## 🎯 **Running Assessments**

### **Method 1: Direct Execution**
```bash
# Basic assessment
./run_enhanced_merged.sh example.com

# With options
./run_enhanced_merged.sh example.com --verbose
./run_enhanced_merged.sh example.com --mode strict
./run_enhanced_merged.sh example.com --dry-run
```

### **Method 2: Docker Execution**
```bash
# Run assessment inside container
docker-compose exec kalivapt /opt/run_enhanced_merged.sh example.com

# With options:
docker-compose exec kalivapt /opt/run_enhanced_merged.sh example.com --verbose
docker-compose exec kalivapt /opt/run_enhanced_merged.sh example.com --mode strict
```

### **Method 3: Scheduled Assessments (Cron)**
```bash
# Create a cron script
cat > /opt/vapt-ai/run_assessment.sh << 'EOF'
#!/bin/bash

TARGET_DOMAIN="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/kalivapt/assessment_${TARGET_DOMAIN}_${TIMESTAMP}.log"

cd /opt/vapt-ai
docker-compose exec kalivapt /opt/run_enhanced_merged.sh "$TARGET_DOMAIN" >> "$LOG_FILE" 2>&1

# Send notification on completion
if [ $? -eq 0 ]; then
    echo "✓ Assessment completed for $TARGET_DOMAIN" | mail -s "VAPT Complete" admin@example.com
else
    echo "✗ Assessment failed for $TARGET_DOMAIN" | mail -s "VAPT Failed" admin@example.com
fi
EOF

chmod +x /opt/vapt-ai/run_assessment.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add line: 0 2 * * * /opt/vapt-ai/run_assessment.sh example.com
```

---

## 🤖 **AI Integration**

### **Qwen 0.5B Normalizer Service**
- **Port**: 8080
- **Purpose**: Vulnerability normalization and scoring
- **Model**: Qwen 0.5B for efficient processing
- **Features**: Context-aware analysis, severity assignment, remediation suggestions

### **AI-Processed Tools (6 tools)**
Need contextual analysis, severity assignment, and remediation:
- `nuclei`, `nikto`, `zap`, `sqlmap`, `nmap_vulners`, `searchsploit`

### **AI Processing Flow**
```bash
# Tool output → JSON normalization → AI analysis → Structured findings
nuclei_output.json → DetectDojo → Qwen AI → Scored vulnerabilities → Database
```

### **AI Service Health Check**
```bash
curl http://localhost:8080/health | jq .

# Expected response:
# {
#   "status": "healthy",
#   "service": "qwen-0.5b-normalizer",
#   "model_loaded": true
# }
```

---

## 🔗 **DetectDojo Integration**

### **DetectDojo Correlation Platform**
- **Port**: 8081
- **Purpose**: Findings orchestration and reporting
- **Features**: Deduplication, correlation, scoring, reporting

### **REST API Endpoints**
- **GET /health** → Service health
- **POST /api/findings/add** → Add raw tool output
- **GET /api/findings/<assessment_id>** → Get deduplicated findings
- **GET /api/report/<assessment_id>** → Get security report (JSON)
- **GET /api/report/<assessment_id>/html** → Get HTML report
- **GET /api/assessments** → List all assessments

### **Example: Send Findings**
```bash
curl -X POST http://localhost:8081/api/findings/add \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "nuclei",
    "target_domain": "example.com",
    "tool_output": "[raw nuclei JSON output here]"
  }'
```

### **Example: Get Reports**
```bash
# List all assessments
curl http://localhost:8081/api/assessments | jq .

# Get specific report (JSON)
ASSESSMENT_ID="assessment_example_com_20260204"
curl http://localhost:8081/api/report/$ASSESSMENT_ID | jq .

# Get HTML report
curl http://localhost:8081/api/report/$ASSESSMENT_ID/html > report.html
```

---

## 📁 **Output Structure**

### **Directory Layout**
```
/var/log/output/<domain>_<date>/
├── recon/                   # Reconnaissance results (9 tools)
├── network/                 # Network scanning results (6+ tools)
├── vuln/                    # Vulnerability assessment (3 tools)
├── web/                     # Web security results (7 tools)
├── ssl/                     # SSL/TLS analysis (3 tools)
├── database/                # Database security results (5 tools)
├── container/               # Container/cloud security (4 tools)
├── processing_queue/         # Background processing
├── vapt_report.md          # Comprehensive security assessment report
└── executive_summary.txt    # Executive summary
```

### **Report Types**
- **vapt_report.md**: Comprehensive markdown report
- **HTML Reports**: Via DetectDojo API
- **JSON Findings**: Structured data for integration
- **Executive Summary**: High-level overview

---

## ⚙️ **Configuration**

### **Environment Variables**
```bash
# VAPT Configuration
TARGET_DOMAIN=example.com
ASSESSMENT_MODE=strict

# AI Service Configuration
AI_SERVICE_URL=http://qwen-0.5b-normalizer:8080
NORMALIZER_URL=http://qwen-0.5b-normalizer:8080

# DetectDojo Configuration
DETECTDOJO_URL=http://detectdojo:8081

# Enable/Disable Integrations
ENABLE_QWEN_INTEGRATION=true
ENABLE_DETECTDOJO_INTEGRATION=true
```

### **Resource Limits**
- **CPU Limit**: 1.5 cores
- **Memory Limit**: 2GB
- **Parallel Scans**: 1 (configurable)
- **Scan Timeout**: 600 seconds

### **Legal & Ethical Considerations**
- Authorization guardrails built-in
- Ethical scanning requirements
- Legal compliance checks
- Unauthorized scanning prevention

---

## 🚀 **Production Deployment**

### **Step 1: Prepare Remote Server**
```bash
# SSH into remote server
ssh user@your-remote-server.com

# Create application directory
mkdir -p /opt/vapt-ai
cd /opt/vapt-ai

# Copy repository
git clone <repository-url> .
```

### **Step 2: Configure Environment**
```bash
# Create .env file for production
cat > .env << 'EOF'
# VAPT Configuration
TARGET_DOMAIN=example.com
ASSESSMENT_MODE=strict

# AI Service Configuration
AI_SERVICE_URL=http://qwen-0.5b-normalizer:8080
NORMALIZER_URL=http://qwen-0.5b-normalizer:8080

# DetectDojo Configuration
DETECTDOJO_URL=http://detectdojo:8081

# Enable/Disable Integrations
ENABLE_QWEN_INTEGRATION=true
ENABLE_DETECTDOJO_INTEGRATION=true
EOF

# Make it readable only by owner (security)
chmod 600 .env
```

### **Step 3: Production Docker Compose**
```yaml
version: '3.8'

services:
  qwen-0.5b-normalizer:
    build:
      context: ./qwen-0.5b-normalizer
      dockerfile: Dockerfile
    container_name: qwen-0.5b-normalizer-prod
    restart: always
    ports:
      - "8080:8080"
    cpus: "2"
    mem_limit: "4g"
    memswap_limit: "4g"
    volumes:
      - /var/log/qwen-0.5b:/app/logs
      - qwen_data:/app/models
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 120s
    environment:
      - OLLAMA_URL=http://ollama:11434
      - PYTHONUNBUFFERED=1
      - MAX_MEMORY=2000
      - TOKEN_LIMIT=512

  detectdojo:
    build:
      context: ./detectdojo
      dockerfile: Dockerfile
    container_name: detectdojo-server-prod
    restart: always
    ports:
      - "8081:8081"
    cpus: "1"
    mem_limit: "2g"
    volumes:
      - /var/log/detectdojo:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    environment:
      - NORMALIZER_URL=http://qwen-0.5b-normalizer:8080
      - PYTHONUNBUFFERED=1
    depends_on:
      - qwen-0.5b-normalizer

  kalivapt:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: kalivapt-prod
    restart: always
    volumes:
      - ./run_enhanced_merged.sh:/opt/run_enhanced_merged.sh:ro
      - /var/log/output:/var/log/output
      - /var/log/kalivapt:/var/log/kalivapt
    command: tail -f /dev/null
    environment:
      - TARGET_DOMAIN=example.com
      - AI_SERVICE_URL=http://qwen-0.5b-normalizer:8080
      - DETECTDOJO_URL=http://detectdojo:8081

networks:
  vapt-network:
    driver: bridge

volumes:
  qwen_data:
    driver: local
```

### **Step 4: Setup Reverse Proxy with Nginx**
```bash
# Install Nginx
sudo apt-get install -y nginx

# Create Nginx config
sudo tee /etc/nginx/sites-available/vapt << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL certificates (use Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Basic authentication
    auth_basic "VAPT Dashboard";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # DetectDojo API proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8081;
    }

    # Root path
    location / {
        return 301 /api/assessments;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/vapt /etc/nginx/sites-enabled/vapt
sudo rm -f /etc/nginx/sites-enabled/default

# Create basic auth file
sudo apt-get install -y apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin

# Test and restart Nginx
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🌐 **Network Strategy**

### **Smart Network Scanning**
The framework intelligently distinguishes between port discovery inputs and actual network risk findings:

### **Port Scanner Inputs (2 tools) - Pipeline Feed**
```bash
# naabu (50+ ports) → Feed to nmap for detailed scanning
naabu.txt → extract hosts → nmap detailed scans → naabu_nmap_*.xml → DetectDojo

# rustscan (50+ ports) → Feed to nmap for detailed scanning  
rustscan.xml → extract hosts → nmap detailed scans → rustscan_nmap_*.xml → DetectDojo
```

### **Network Risk Tools (3 tools) - Direct Import**
```bash
# nmap_* (any) → Direct to DetectDojo (network risk)
nmap_comprehensive_*.xml → Rule-Based → DetectDojo

# masscan_* (any) → Direct to DetectDojo (network risk)
masscan_*.txt → Rule-Based → DetectDojo

# httpx (many hosts) → Direct to DetectDojo (network risk)
httpx.txt → Rule-Based → DetectDojo
```

### **Benefits**
- **Smart Resource Management**: Skip basic port lists, focus on detailed scans
- **Enhanced Coverage**: Large port discoveries trigger detailed nmap scans
- **Clean Risk Assessment**: Only network risk data sent to DetectDojo

---

## 🔧 **Troubleshooting**

### **Container Won't Start**
```bash
# Check service status
docker-compose ps

# View full logs
docker-compose logs [service-name]

# Rebuild service
docker-compose build --no-cache [service-name]
docker-compose up -d [service-name]
```

### **Ollama Model Download Fails**
```bash
# Check Ollama service
curl http://localhost:11434/api/tags

# Manual model pull
docker-compose exec ollama ollama pull qwen:0.5b

# Check available disk space
df -h /var/lib/docker/volumes/

# If low on space, clean up:
docker system prune -a
```

### **Normalization Timeout**
```bash
# Increase timeout in docker-compose.yml
healthcheck:
  start_period: 180s  # Increase from 90s

# Restart service:
docker-compose up -d qwen-0.5b-normalizer
```

### **DetectDojo Can't Connect to Normalizer**
```bash
# Test connectivity
docker-compose exec detectdojo curl -v http://qwen-0.5b-normalizer:8080/health

# Check network
docker network ls
docker network inspect kali-vapt_vapt-network

# Restart both services
docker-compose restart qwen-0.5b-normalizer detectdojo
```

### **Out of Memory**
```bash
# Increase Docker memory limits
docker update --memory 4g --memory-swap 4g qwen-0.5b-normalizer-prod

# OR edit docker-compose.yml:
mem_limit: "4g"
memswap_limit: "4g"

# Restart:
docker-compose up -d qwen-0.5b-normalizer
```

### **Common Issues & Solutions**

#### **FFUF Command Not Found**
- **Issue**: FFUF using wrong syntax
- **Solution**: Ensure `/FUZZ` keyword in URL
- **Example**: `ffuf -w wordlist.txt -u https://target.com/FUZZ`

#### **URL Deduplication Fails**
- **Issue**: Missing `uro` tool
- **Solution**: Use `sort -u` instead
- **Example**: `cat urls.txt | sort -u > deduplicated_urls.txt`

#### **JSON Parsing Errors**
- **Issue**: Line-delimited JSON vs array JSON
- **Solution**: Use `jq -s .` for line-delimited JSON
- **Example**: `jq -s . naabu_output.json`

---

## 🛡️ **Security Best Practices**

### **1. Use Environment Variables for Secrets**
```bash
# Never hardcode credentials. Use .env file:
# .env
OLLAMA_API_KEY=your-secret-key
DETECTDOJO_API_KEY=your-api-key

# Load in docker-compose:
environment:
  - OLLAMA_API_KEY=${OLLAMA_API_KEY}
```

### **2. Restrict Network Access**
```bash
# Only expose services internally
# Remove ports: directives for internal services
# Use reverse proxy (Nginx) for external access
```

### **3. Enable TLS/HTTPS**
```bash
# Always use HTTPS in production
# Use Let's Encrypt (free) or commercial certificates
# Enforce in Nginx config: return 301 https://...
```

### **4. Monitor Logs**
```bash
# Enable log rotation
docker-compose logs --tail 100  # Last 100 lines
docker logs --follow [container]  # Follow real-time logs

# Archive logs
tar -czf logs_backup_$(date +%Y%m%d).tar.gz /var/log/{ollama,qwen-0.5b,detectdojo}
```

### **5. Backup Data**
```bash
# Backup Docker volumes
docker run --rm -v qwen_data:/data -v /backup:/backup alpine tar czf /backup/qwen_data.tar.gz /data

# Backup assessment results
sudo tar -czf /backup/vapt_assessments_$(date +%Y%m%d).tar.gz /var/log/output/

# Setup automated backups (cron)
0 3 * * * sudo tar -czf /backup/vapt_assessments_$(date +\%Y\%m\%d).tar.gz /var/log/output/
```

### **6. Resource Management**
```bash
# Monitor resource usage
docker stats

# Set memory limits
docker update --memory 4g [container-name]

# Monitor disk usage
df -h
du -sh /var/log/output/
```

---

## 📊 **Quick Reference**

### **Common Commands**
```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f [service-name]

# Run assessment
./run_enhanced_merged.sh example.com

# Check health
curl http://localhost:8081/health | jq .

# Get reports
curl http://localhost:8081/api/assessments | jq .

# Monitor disk usage
df -h

# Monitor memory
free -h

# Check running containers
docker ps
```

### **Service Ports**
- **Qwen AI Service**: 8080
- **DetectDojo Service**: 8081
- **Ollama Service**: 11434

### **Important Files**
- **Main Script**: `run_enhanced_merged.sh`
- **Docker Compose**: `docker-compose.yml`
- **Dockerfile**: `Dockerfile`
- **Output Directory**: `/var/log/output/`

---

## 🎉 **Conclusion**

The VAPT Framework v2.3 is a comprehensive, enterprise-ready security assessment platform featuring:

- **40+ Security Tools** across 8 assessment phases
- **AI-Powered Analysis** with Qwen 0.5B normalization
- **DetectDojo Integration** for centralized findings management
- **Production-Ready** deployment with Docker containers
- **Comprehensive Reporting** in multiple formats
- **Security Best Practices** built-in

### **Next Steps**
1. **Deploy** using the production deployment guide
2. **Configure** environment variables for your environment
3. **Run** initial assessments to validate functionality
4. **Monitor** services and logs for optimal performance
5. **Scale** as needed for your assessment requirements

### **Support & Maintenance**
- Regular updates to security tools and templates
- AI model improvements and optimizations
- Community support and contributions
- Enterprise support options available

---

**Status: 🟢 PRODUCTION READY**

Your VAPT Framework is now fully operational and ready for comprehensive security assessments! 🚀
