#!/bin/bash

# VAPT Engine - Main Execution Script (Dockerized)
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
TARGET_DOMAIN=''
VERBOSE=false
DRY_RUN=false
DOCKER_IMAGE='rajatherise/kali-vapt-image:latest'
OUTPUT_DIR='/var/production/output'
LOG_FILE='/var/production/logs/execution.log'

# Banner
banner() {
    echo -e "${CYAN}"
    cat << 'BANNEREOF'
 _____ ____  ____    _    _     _   ____    _  __ _____ ___ 
| ____|  _ \/ ___|  / \  | |   | | |  _ \  / \| |/ |_   _/ _ |  _| | |_) \___ \ / _ \ | |   | | | | | |/ _ \| \| ' / | | | | | |
| |___|  _ < ___ ) / ___ \| |___| |_| | |_| / ___ \ .  \| | | | |_| |
|_____|_| \_\____/_/   \_\_____|_____|____/_/   \_\_|\_|\_|   \___/___/
                                                                        
VAPT Engine v2.0 - Dockerized
BANNEREOF
    echo -e "${NC}"
}

# Usage
usage() {
    echo "Usage: $0 <target_domain> [options]"
    echo "Options:"
    echo "  -h, --help       Show help"
    echo "  -v, --verbose    Verbose output"
    echo "  --dry-run        Show commands without executing"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com --verbose"
    echo "  $0 example.com --dry-run"
}

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"; }

# Docker execution
run_docker() {
    local cmd="$1"
    local target_output="${OUTPUT_DIR}/${TARGET_DOMAIN}"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} docker run --rm -v ${target_output}:/opt/work ${DOCKER_IMAGE} $cmd"
        return 0
    fi
    
    if [[ "$VERBOSE" == true ]]; then
        log_info "Executing: $cmd"
    fi
    
    docker run --rm -v "${target_output}:/opt/work" "${DOCKER_IMAGE}" bash -c "cd /opt/work && $cmd"
}

# Check Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon not running"
        exit 1
    fi
    
    if ! docker image inspect "${DOCKER_IMAGE}" &> /dev/null; then
        log_info "Pulling Docker image: ${DOCKER_IMAGE}"
        docker pull "${DOCKER_IMAGE}"
    fi
}

# Initialize directories
init_directories() {
    log_info "Initializing output directories"
    local target_output="${OUTPUT_DIR}/${TARGET_DOMAIN}"
    local subdirs=("recon" "network" "vuln" "web" "ssl" "database" "report")
    
    mkdir -p "${target_output}"
    for subdir in "${subdirs[@]}"; do
        mkdir -p "${target_output}/${subdir}"
    done
    
    # Create metadata
    cat > "${target_output}/scan_metadata.json" << EOF
{
    "target_domain": "${TARGET_DOMAIN}",
    "scan_date": "$(date -Iseconds)",
    "framework_version": "2.0",
    "docker_image": "${DOCKER_IMAGE}"
}
EOF
    
    log_ok "Directories initialized"
}

# Phase 1: Reconnaissance
run_reconnaissance() {
    log_info "Starting Phase 1: RECONNAISSANCE"
    
    log_info "Running amass..."
    run_docker "amass enum -passive -d ${TARGET_DOMAIN} -o recon/amass.txt"
    
    log_info "Running assetfinder..."
    run_docker "assetfinder --subs-only ${TARGET_DOMAIN} > recon/assetfinder.txt"
    
    log_info "Running subfinder..."
    run_docker "subfinder -d ${TARGET_DOMAIN} -o recon/subfinder.txt"
    
    log_info "Running whois..."
    run_docker "whois ${TARGET_DOMAIN} > recon/whois.txt || echo 'No WHOIS data' > recon/whois.txt"
    
    log_info "Running theHarvester..."
    run_docker "theHarvester -d ${TARGET_DOMAIN} -l 100 -b all -f recon/theHarvester.html"
    
    log_ok "Reconnaissance completed"
}

# Phase 2: Network Scanning
run_network() {
    log_info "Starting Phase 2: NETWORK SCANNING"
    
    local target_ip=$(dig +short "${TARGET_DOMAIN}" | head -1)
    [[ -z "$target_ip" ]] && target_ip="${TARGET_DOMAIN}"
    
    log_info "Running naabu..."
    run_docker "naabu -host ${target_ip} -p - -o network/naabu.txt"
    
    log_info "Running nmap..."
    run_docker "nmap -sS -sV -oA network/nmap ${target_ip}"
    
    log_info "Running rustscan..."
    run_docker "rustscan -a ${target_ip} -- -sV > network/rustscan.txt"
    
    log_ok "Network scanning completed"
}

# Phase 3: Vulnerability Assessment
run_vulnerability() {
    log_info "Starting Phase 3: VULNERABILITY ASSESSMENT"
    
    log_info "Running nuclei..."
    run_docker "nuclei -u ${TARGET_DOMAIN} -severity critical,high,medium -o vuln/nuclei.txt"
    
    log_ok "Vulnerability assessment completed"
}

# Phase 4: Web Security
run_web() {
    log_info "Starting Phase 4: WEB SECURITY"
    
    log_info "Running katana..."
    run_docker "katana -u https://${TARGET_DOMAIN} -o web/katana.txt"
    
    log_info "Running gobuster..."
    run_docker "gobuster dir -u https://${TARGET_DOMAIN} -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o web/gobuster.txt"
    
    log_info "Running nikto..."
    run_docker "nikto -h https://${TARGET_DOMAIN} -o web/nikto.txt"
    
    log_ok "Web security completed"
}

# Phase 5: SSL/TLS Security
run_ssl() {
    log_info "Starting Phase 5: SSL/TLS SECURITY"
    
    log_info "Running sslyze..."
    run_docker "sslyze --regular ${TARGET_DOMAIN}:443 --json-out ssl/sslyze.json"
    
    log_info "Running sslscan..."
    run_docker "sslscan ${TARGET_DOMAIN}:443 > ssl/sslscan.txt"
    
    log_ok "SSL/TLS security completed"
}

# Phase 6: Reporting
run_reporting() {
    log_info "Starting Phase 6: REPORTING"
    local target_output="${OUTPUT_DIR}/${TARGET_DOMAIN}"
    local report_dir="${target_output}/report"
    
    # Create executive summary
    cat > "${target_output}/executive_summary.txt" << EOF
VAPT Assessment Report - Executive Summary
============================================

Target: ${TARGET_DOMAIN}
Date: $(date)
Framework: VAPT Engine v2.0
Docker Image: ${DOCKER_IMAGE}

Assessment Phases Completed:
✓ Reconnaissance: Asset discovery and OSINT
✓ Network Scanning: Port scanning and service enumeration  
✓ Vulnerability Assessment: Automated vulnerability scanning
✓ Web Application Security: Web application testing
✓ SSL/TLS Security: Certificate and encryption analysis

Recommendations:
1. Review all discovered vulnerabilities and prioritize remediation
2. Implement proper SSL/TLS configuration
3. Regular security assessments recommended
4. Monitor for new security advisories

Full detailed reports available in the respective phase directories.
EOF
    
    # Create HTML report
    cat > "${report_dir}/report.html" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>VAPT Assessment Report - ${TARGET_DOMAIN}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>VAPT Assessment Report</h1>
        <h2>${TARGET_DOMAIN}</h2>
        <p>Generated on $(date)</p>
    </div>
    
    <div class="section">
        <h3>Assessment Overview</h3>
        <p>Comprehensive VAPT assessment conducted using VAPT Engine v2.0</p>
        <p>Docker image: ${DOCKER_IMAGE}</p>
    </div>
    
    <div class="section">
        <h3>Executive Summary</h3>
        <pre>$(cat "${target_output}/executive_summary.txt")</pre>
    </div>
    
    <div class="section">
        <h3>Report Sections</h3>
        <ul>
            <li><a href="../recon/">Reconnaissance Results</a></li>
            <li><a href="../network/">Network Scanning Results</a></li>
            <li><a href="../vuln/">Vulnerability Results</a></li>
            <li><a href="../web/">Web Security Results</a></li>
            <li><a href="../ssl/">SSL/TLS Results</a></li>
        </ul>
    </div>
</body>
</html>
EOF
    
    log_ok "Reporting completed"
    log_info "HTML report: ${report_dir}/report.html"
    log_info "Executive summary: ${target_output}/executive_summary.txt"
}

# Main function
main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$TARGET_DOMAIN" ]]; then
                    TARGET_DOMAIN="$1"
                else
                    log_error "Multiple targets provided"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$TARGET_DOMAIN" ]]; then
        log_error "Target domain required"
        usage
        exit 1
    fi
    
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "=== VAPT Engine Execution Log ===" > "$LOG_FILE"
    echo "Start: $(date)" >> "$LOG_FILE"
    echo "Target: $TARGET_DOMAIN" >> "$LOG_FILE"
    
    banner
    log_info "Checking prerequisites"
    check_docker
    init_directories
    
    run_reconnaissance
    run_network
    run_vulnerability
    run_web
    run_ssl
    run_reporting
    
    echo "End: $(date)" >> "$LOG_FILE"
    
    if [[ "$DRY_RUN" != true ]]; then
        echo ""
        log_info "VAPT Assessment completed successfully"
        log_info "Results: ${OUTPUT_DIR}/${TARGET_DOMAIN}"
        log_info "HTML report: ${OUTPUT_DIR}/${TARGET_DOMAIN}/report/report.html"
        log_info "Log: $LOG_FILE"
    fi
}

main "$@"
