# Setup & Deployment Guide - Kali VAPT Framework

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Development Setup](#local-development-setup)
3. [Production Deployment](#production-deployment)
4. [Running VAPT Assessments](#running-vapt-assessments)
5. [Accessing Reports](#accessing-reports)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+, Debian, or CentOS)
- **RAM**: Minimum 8GB (16GB recommended for large scans)
- **CPU**: 4 cores (8+ cores recommended)
- **Disk**: 50GB free space (for logs, models, and reports)
- **Network**: Internet access (for tool downloads and model pulls)

### Required Software
- Docker Engine 20.10+
- Docker Compose 2.0+
- Git
- curl
- jq (JSON processor)

### Install Prerequisites

#### On Ubuntu/Debian:
```bash
# Update package manager
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add current user to docker group (to run without sudo)
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install utilities
sudo apt-get install -y git curl jq

# Verify installations
docker --version
docker-compose --version
```

#### On CentOS/RHEL:
```bash
# Install Docker using yum
sudo yum install -y docker

# Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install utilities
sudo yum install -y git curl jq
```

---

## Local Development Setup

### Step 1: Clone the Repository

```bash
# Clone the repository
git clone <repository-url>
cd kali-vapt

# List directory structure
ls -la
```

### Step 2: Set File Permissions

```bash
# Make all scripts executable
chmod +x *.sh
chmod +x */*.sh
chmod +x send_to_detectdojo.sh
```

### Step 3: Build Docker Images

```bash
# Build all images (may take 30-45 minutes on first run)
docker-compose build

# If building individual services:
docker-compose build qwen-0.5b-normalizer
docker-compose build detectdojo
docker-compose build kalivapt
```

### Step 4: Create Logs Directory

```bash
# Create logs directory
mkdir -p logs
chmod 777 logs

# Create subdirectories for each component
mkdir -p logs/{vapt,detectdojo,qwen}
```

### Step 5: Start Services

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

# View service logs
docker-compose logs -f qwen-0.5b-normalizer-prod  # AI Normalizer logs
docker-compose logs -f detectdojo-server          # DetectDojo logs
docker-compose logs -f kalivapt                   # VAPT engine logs
```

### Step 6: Verify Services are Running

```bash
# Check Qwen normalizer health
curl http://localhost:8080/health | jq .

# Expected response:
# {
#   "status": "healthy",
#   "service": "qwen-0.5b-normalizer",
#   "model_loaded": true
# }

# Check DetectDojo health
curl http://localhost:8081/health | jq .

# Expected response:
# {
#   "status": "healthy",
#   "service": "detectdojo"
# }
```

### Step 7: Run First Assessment (Local Testing)

```bash
# Run VAPT scan on a public domain
./run_enhanced.sh example.com

# Wait for scan to complete (10-30 minutes depending on domain)

# Check logs
tail -f logs/run_enhanced.log
```

---

## Production Deployment

### Step 1: Prepare Remote Server

```bash
# SSH into remote server
ssh user@your-remote-server.com

# Create application directory
mkdir -p /opt/vapt-ai
cd /opt/vapt-ai

# Copy repository
git clone <repository-url> .
# OR download zip and extract
# wget https://github.com/your-repo/archive/main.zip
# unzip main.zip && mv kali-vapt-main/* . && rm -rf kali-vapt-main main.zip
```

### Step 2: Configure Environment Variables

```bash
# Create .env file for production
cat > .env << 'EOF'
# VAPT Configuration
TARGET_DOMAIN=example.com
ASSESSMENT_MODE=strict

# AI Service Configuration
AI_SERVICE_URL=http://qwen-0.5b-normalizer:8080
NORMALIZER_URL=http://qwen-0.5b-normalizer:8080
OLLAMA_URL=http://ollama:11434

# DetectDojo Configuration
DETECTDOJO_URL=http://detectdojo:8081

# Ollama Configuration
OLLAMA_HOST=0.0.0.0
MODEL_PATH=/app/models
MAX_MEMORY=1800
TOKEN_LIMIT=512

# Flask Configuration
FLASK_ENV=production
PYTHONUNBUFFERED=1

# Enable/Disable Integrations
ENABLE_QWEN_INTEGRATION=true
ENABLE_DETECTDOJO_INTEGRATION=true
EOF

# Make it readable only by owner (security)
chmod 600 .env
```

### Step 3: Configure docker-compose.yml (Production)

```bash
# Create production override file
cat > docker-compose.prod.yml << 'EOF'
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    container_name: ollama-prod
    restart: always
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
      - /var/log/ollama:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 5
    environment:
      - OLLAMA_HOST=0.0.0.0
    networks:
      - vapt-network

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
      - /var/log/output:/var/log/output
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
    depends_on:
      - ollama
    networks:
      - vapt-network
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"

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
    networks:
      - vapt-network
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"

  kalivapt:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: kalivapt-prod
    restart: always
    volumes:
      - ./run_enhanced.sh:/opt/run_enhanced.sh:ro
      - /var/log/output:/var/log/output
      - /var/log/kalivapt:/var/log/kalivapt
    command: tail -f /dev/null
    environment:
      - TARGET_DOMAIN=example.com
      - AI_SERVICE_URL=http://qwen-0.5b-normalizer:8080
      - DETECTDOJO_URL=http://detectdojo:8081
    networks:
      - vapt-network
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "3"

networks:
  vapt-network:
    driver: bridge

volumes:
  ollama_data:
    driver: local
  qwen_data:
    driver: local
EOF
```

### Step 4: Start Production Services

```bash
# Create log directories
sudo mkdir -p /var/log/{ollama,qwen-0.5b,detectdojo,kalivapt,output}
sudo chown -R $USER:$USER /var/log/{ollama,qwen-0.5b,detectdojo,kalivapt,output}
sudo chmod -R 755 /var/log/{ollama,qwen-0.5b,detectdojo,kalivapt,output}

# Build images (may take 1-2 hours on first run due to model downloads)
docker-compose -f docker-compose.yml -f docker-compose.prod.yml build

# Start services
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Monitor startup (wait for models to download)
docker-compose -f docker-compose.yml -f docker-compose.prod.yml logs -f

# This will take 5-15 minutes for Ollama to pull the Qwen model
# Wait for log messages:
# qwen-0.5b-normalizer-prod  | ✓ Qwen 0.5B model already available
# qwen-0.5b-normalizer-prod  | Starting Flask API...
```

### Step 5: Configure Firewall (If Applicable)

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 8080/tcp    # Qwen (internal only - see below)
sudo ufw allow 8081/tcp    # DetectDojo (internal only - see below)
sudo ufw enable

# IMPORTANT: In production, do NOT expose 8080 and 8081 to the internet.
# Use a reverse proxy (nginx) to secure access with authentication.
```

### Step 6: Setup Reverse Proxy with Nginx (Recommended)

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
# Enter password when prompted

# Test and restart Nginx
sudo nginx -t
sudo systemctl restart nginx
```

### Step 7: Setup SSL Certificate with Let's Encrypt

```bash
# Install Certbot
sudo apt-get install -y certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --standalone -d your-domain.com

# Auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer

# Verify auto-renewal
sudo certbot renew --dry-run
```

---

## Running VAPT Assessments

### Method 1: Direct Docker Execution

```bash
# Run assessment inside kalivapt container
docker-compose exec kalivapt /opt/run_enhanced.sh example.com

# With options:
docker-compose exec kalivapt /opt/run_enhanced.sh example.com --verbose
docker-compose exec kalivapt /opt/run_enhanced.sh example.com --mode strict
docker-compose exec kalivapt /opt/run_enhanced.sh example.com --dry-run
```

### Method 2: From Host (Production)

```bash
# SSH into server
ssh user@your-remote-server.com

# Navigate to VAPT directory
cd /opt/vapt-ai

# Run assessment
docker-compose exec kalivapt /opt/run_enhanced.sh example.com --verbose

# Monitor progress
docker-compose logs -f kalivapt
```

### Method 3: Scheduled Assessments (Cron)

```bash
# Create a cron script
cat > /opt/vapt-ai/run_assessment.sh << 'EOF'
#!/bin/bash

TARGET_DOMAIN="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/kalivapt/assessment_${TARGET_DOMAIN}_${TIMESTAMP}.log"

cd /opt/vapt-ai
docker-compose exec kalivapt /opt/run_enhanced.sh "$TARGET_DOMAIN" >> "$LOG_FILE" 2>&1

# Send notification on completion
if [ $? -eq 0 ]; then
    echo "✓ Assessment completed for $TARGET_DOMAIN" | mail -s "VAPT Complete" admin@example.com
    # Download report
    ASSESSMENT_ID=$(docker-compose exec detectdojo curl -s http://localhost:8081/api/assessments | jq -r '.assessments[0].assessment_id')
    docker-compose exec detectdojo curl -s http://localhost:8081/api/report/$ASSESSMENT_ID/html > /var/log/output/${TARGET_DOMAIN}_report.html
else
    echo "✗ Assessment failed for $TARGET_DOMAIN" | mail -s "VAPT Failed" admin@example.com
fi
EOF

chmod +x /opt/vapt-ai/run_assessment.sh

# Add to crontab (daily at 2 AM)
crontab -e

# Add line:
# 0 2 * * * /opt/vapt-ai/run_assessment.sh example.com
```

---

## Accessing Reports

### Via API

```bash
# List all assessments
curl -u admin:password https://your-domain.com/api/assessments | jq .

# Get specific report (JSON)
ASSESSMENT_ID="assessment_example_com_20260204"
curl -u admin:password https://your-domain.com/api/report/$ASSESSMENT_ID | jq .

# Get HTML report
curl -u admin:password https://your-domain.com/api/report/$ASSESSMENT_ID/html > report.html
```

### Via Web Browser

```
1. Open browser: https://your-domain.com
2. Enter credentials (username: admin, password: [your-password])
3. Click on any assessment to view details
4. Download HTML report
```

### Via Local Development

```bash
# Local assessments (without Nginx)
curl http://localhost:8081/api/assessments | jq .

# Get assessment ID from response, then:
ASSESSMENT_ID="assessment_example_com_20260204"
curl http://localhost:8081/api/report/$ASSESSMENT_ID/html > report.html

# Open in browser
open report.html  # macOS
xdg-open report.html  # Linux
start report.html  # Windows
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check service status
docker-compose ps

# View full logs
docker-compose logs [service-name]

# Rebuild service
docker-compose build --no-cache [service-name]
docker-compose up -d [service-name]
```

### Ollama Model Download Fails

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

### Normalization Timeout

```bash
# Increase timeout in docker-compose.yml
# Under qwen-0.5b-normalizer service, adjust:
healthcheck:
  start_period: 180s  # Increase from 90s

# Restart service:
docker-compose up -d qwen-0.5b-normalizer
```

### DetectDojo Can't Connect to Normalizer

```bash
# Test connectivity
docker-compose exec detectdojo curl -v http://qwen-0.5b-normalizer:8080/health

# Check network
docker network ls
docker network inspect kali-vapt_vapt-network

# Restart both services
docker-compose restart qwen-0.5b-normalizer detectdojo
```

### Out of Memory

```bash
# Increase Docker memory limits
docker update --memory 4g --memory-swap 4g qwen-0.5b-normalizer-prod

# OR edit docker-compose.yml:
mem_limit: "4g"
memswap_limit: "4g"

# Restart:
docker-compose up -d qwen-0.5b-normalizer
```

### Cleanup & Reset

```bash
# Stop all services
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Full cleanup
docker system prune -a --volumes
```

---

## Security Best Practices

### 1. Use Environment Variables for Secrets

```bash
# Never hardcode credentials. Use .env file:
# .env
OLLAMA_API_KEY=your-secret-key
DETECTDOJO_API_KEY=your-api-key

# Load in docker-compose:
environment:
  - OLLAMA_API_KEY=${OLLAMA_API_KEY}
```

### 2. Restrict Network Access

```bash
# Only expose services internally
# Remove ports: directives for internal services
# Use reverse proxy (Nginx) for external access
```

### 3. Enable TLS/HTTPS

```bash
# Always use HTTPS in production
# Use Let's Encrypt (free) or commercial certificates
# Enforce in Nginx config: return 301 https://...
```

### 4. Monitor Logs

```bash
# Enable log rotation
docker-compose logs --tail 100  # Last 100 lines
docker logs --follow [container]  # Follow real-time logs

# Archive logs
tar -czf logs_backup_$(date +%Y%m%d).tar.gz /var/log/{ollama,qwen-0.5b,detectdojo}
```

### 5. Backup Data

```bash
# Backup Docker volumes
docker run --rm -v qwen_data:/data -v /backup:/backup alpine tar czf /backup/qwen_data.tar.gz /data

# Backup assessment results
sudo tar -czf /backup/vapt_assessments_$(date +%Y%m%d).tar.gz /var/log/output/

# Setup automated backups (cron)
0 3 * * * sudo tar -czf /backup/vapt_assessments_$(date +\%Y\%m\%d).tar.gz /var/log/output/
```

---

## Quick Reference

### Common Commands

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f [service-name]

# Run assessment
docker-compose exec kalivapt /opt/run_enhanced.sh example.com

# Check health
curl http://localhost:8081/health | jq .

# Get reports
curl http://localhost:8081/api/assessments | jq .

# SSH to server
ssh user@your-remote-server.com

# Monitor disk usage
df -h

# Monitor memory
free -h

# Check running containers
docker ps
```

---

## Support & Documentation

- **DEPLOYMENT.md**: Production deployment best practices
- **INTEGRATION_GUIDE.md**: API integration and workflow details
- **SECURITY_REPORT.md**: Security analysis and improvements
- **README.md**: Project overview and features
