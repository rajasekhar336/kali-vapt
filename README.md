# Kali VAPT - Vulnerability Assessment and Penetration Testing Framework

A comprehensive Dockerized VAPT automation framework with 40+ security tools, AI-powered vulnerability normalization, and integrated reporting.

## Features

- **40+ Security Tools**: Comprehensive reconnaissance, network scanning, web assessment
- **AI Integration**: Qwen 0.5B model for vulnerability normalization and correlation
- **Multi-Mode Execution**: Strict, modular, and unified scanning modes
- **Dockerized**: Fully containerized for consistent environments
- **Automated Reporting**: HTML and JSON reports with executive summaries

## Quick Start

### Prerequisites
- Docker and Docker Compose
- 4GB+ RAM available
- Docker socket access
- Authorization to scan target domains

### Setup

1. **Clone and prepare:**
```bash
git clone <repository-url>
cd /var/production
chmod +x *.sh */*.sh
```

2. **Start AI services (optional but recommended):**
```bash
# Start AI normalization service
cd qwen-0.5b-normalizer
./qwen-0.5b-docker.sh start

# Start DetectDojo correlation service
cd ../detectdojo
./detectdojo-service.sh

cd ..
```

3. **Run VAPT assessment:**
```bash
# Main enhanced framework (recommended)
./run_enhanced.sh example.com

# With verbose output
./run_enhanced.sh example.com --verbose

# Different execution modes
./run_enhanced.sh example.com --mode strict    # Sequential (default)
./run_enhanced.sh example.com --mode modular   # Phase-based
./run_enhanced.sh example.com --mode unified   # Best effort

# Dry run to see commands without executing
./run_enhanced.sh example.com --dry-run
```

## Architecture

```
├── run_enhanced.sh             # 🎯 MAIN PROJECT - Enhanced VAPT Engine v2.3
├── Dockerfile                   # Custom VAPT tools container (40+ tools)
├── docker-compose.yml          # Service orchestration
├── run.sh                      # Basic VAPT execution (legacy)
├── detectdojo/                 # Vulnerability correlation platform
├── qwen-0.5b-normalizer/       # AI vulnerability normalization service
└── logs/                       # Assessment outputs and reports
```

## 🎯 Main Project: run_enhanced.sh

This is the core VAPT automation framework featuring:

### **8 Assessment Phases:**
1. **Reconnaissance** - Subdomain discovery, OSINT, information gathering
2. **Network Scanning** - Port discovery, service enumeration, OS fingerprinting  
3. **Vulnerability Assessment** - Automated vulnerability scanning with nuclei
4. **Web Security** - Application testing, crawling, OWASP ZAP integration
5. **SSL/TLS Security** - Certificate analysis, encryption testing
6. **Database Security** - SQL injection testing, database port scanning
7. **Container & Cloud** - Kubernetes, Docker registry, cloud metadata checks
8. **Reporting & Correlation** - AI-powered analysis and comprehensive reports

### **Key Features:**
- **40+ Security Tools** integrated in single framework
- **3 Execution Modes**: strict, modular, unified
- **AI Integration**: Qwen 0.5B for vulnerability normalization
- **Parallel Processing**: Optimized tool execution with resource management
- **Error Handling**: Retry logic and graceful failure recovery
- **Legal Compliance**: Authorization guardrails and ethical scanning
- **Comprehensive Reporting**: HTML reports with executive summaries

## Services

- **Port 8080**: Qwen 0.5B AI Service
- **Port 8081**: DetectDojo Correlation Platform
- **Custom Container**: VAPT Tools Framework

## Execution Modes

- **Strict**: Sequential execution with path discovery (40+ tools)
- **Modular**: Phase-based modular execution  
- **Unified**: Simplified unified execution

## Output Structure

```
/var/log/output/<domain>/
├── recon/         # Reconnaissance results
├── network/       # Network scanning
├── vuln/          # Vulnerability assessment
├── web/           # Web security testing
├── ssl/           # SSL/TLS analysis
└── report/        # HTML reports
```

## Security Tools Included

### Reconnaissance
- amass, subfinder, assetfinder, theHarvester
- waybackurls, gau

### Network Scanning  
- nmap, masscan, rustscan, naabu

### Web Security
- nikto, gobuster, ffuf, katana, wapiti

### Vulnerability Assessment
- nuclei, sqlmap

### SSL/TLS
- sslyze, sslscan, testssl.sh

## Configuration

Environment variables in `docker-compose.yml`:
- `TARGET_DOMAIN`: Target for assessment
- `AI_SERVICE_URL`: Qwen service endpoint
- `DETECTDOJO_URL`: Correlation platform endpoint

## Contributing

1. Fork the repository
2. Create feature branch
3. Submit pull request

## License

MIT License - see LICENSE file for details
