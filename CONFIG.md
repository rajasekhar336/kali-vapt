# VAPT Framework Configuration

## Main Project: run_enhanced.sh

The Enhanced VAPT Engine v2.3 is a comprehensive security assessment framework featuring:

### Core Configuration
- **Docker Image**: rajatherise/kali-vapt-image:latest
- **Output Directory**: /var/log/output/
- **Log File**: /var/production/logs/execution.log
- **Execution Modes**: strict, modular, unified

### AI Integration
- **Qwen 0.5B Service**: http://localhost:8080
- **DetectDojo Service**: http://localhost:8081
- **Background Processing**: Parallel tool output normalization

### Resource Limits
- **CPU Limit**: 1.5 cores
- **Memory Limit**: 2GB
- **Parallel Scans**: 1 (configurable)
- **Scan Timeout**: 600 seconds

### Security Tools Included (40+)

#### Phase 1: Reconnaissance
- amass (subdomain enumeration)
- assetfinder (asset discovery)
- subfinder (subdomain discovery)
- whois (domain information)
- dnsrecon (DNS reconnaissance)
- dig (DNS queries)
- whatweb (web technology identification)
- waybackurls (URL discovery)
- gau (Get All URLs)

#### Phase 2: Network Scanning
- naabu (port scanner)
- nmap (network mapper)
- masscan (fast port scanner)
- rustscan (ultra-fast port scanner)
- httpx (HTTP probe)

#### Phase 3: Vulnerability Assessment
- nuclei (vulnerability scanner)
- searchsploit (exploit database)
- nmap vulners script

#### Phase 4: Web Security
- gobuster (directory brute-force)
- katana (web crawler)
- nikto (web server scanner)
- ffuf (fast web fuzzer)
- dirsearch (directory scanner)
- wapiti (web application scanner)
- OWASP ZAP (comprehensive web security)

#### Phase 5: SSL/TLS Security
- sslyze (SSL/TLS analyzer)
- sslscan (SSL configuration scanner)
- testssl.sh (SSL testing)

#### Phase 6: Database Security
- sqlmap (SQL injection testing)
- Database port scanning (MySQL, PostgreSQL, Redis, etc.)

#### Phase 7: Container & Cloud Security
- Cloud metadata exposure checks
- Docker registry exposure testing
- Kubernetes API exposure checks
- kubeaudit (Kubernetes security audit)

### Output Structure
```
/var/log/output/<domain>_<date>/
├── recon/           # Reconnaissance results
├── network/         # Network scanning results
├── vuln/            # Vulnerability assessment
├── web/             # Web security testing
├── ssl/             # SSL/TLS analysis
├── database/        # Database security testing
├── container/       # Container/cloud security
├── reports/         # Generated reports
├── executive_summary.txt
├── vapt_report.html
└── execution.log
```

### Environment Variables
- `TARGET_DOMAIN`: Target for assessment
- `AI_SERVICE_URL`: Qwen service endpoint
- `DETECTDOJO_URL`: DetectDojo service endpoint
- `I_HAVE_AUTHORIZATION`: Skip authorization prompt (set to "yes")

### Legal & Ethical Considerations
- Authorization guardrails built-in
- Ethical scanning requirements
- Legal compliance checks
- Unauthorized scanning prevention

### Performance Optimization
- Parallel tool execution where possible
- Resource monitoring and management
- Error handling with retry logic
- Graceful failure recovery
- Background processing for AI analysis
