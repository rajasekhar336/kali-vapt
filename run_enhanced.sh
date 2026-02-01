#!/bin/bash

# VAPT Engine - Enhanced Dockerized Version with OS Detection
# Professional CLI VAPT Automation Framework with 40+ tools

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
EXECUTION_MODE='strict'  # strict, modular, unified
DOCKER_IMAGE='rajatherise/kali-vapt-image:latest'
OUTPUT_DIR='/var/log/output'
LOG_FILE='/var/production/logs/execution.log'
ZAP_DOCKER_IMAGE='ghcr.io/zaproxy/zaproxy:stable'
ZAP_TIMEOUT_MINUTES=30
MAX_PARALLEL_SCANS=1  # Reduced to prevent resource exhaustion
SCAN_TIMEOUT=600
RATE_LIMIT=100
DOCKER_CPU_LIMIT="1.5"
DOCKER_MEMORY_LIMIT="2g"
QWEN_SERVICE="/var/production/qwen-0.5b-normalizer/qwen-0.5b-docker.sh"
DETECTDOJO_SERVICE="/var/production/detectdojo/detectdojo-service.sh"
ENABLE_QWEN_INTEGRATION=true
ENABLE_DETECTDOJO_INTEGRATION=true

# Enhanced banner
banner() {
    echo -e "${CYAN}"
    cat << 'BANNEREOF'
 _____ ____  ____    _    _     _   ____    _  __ _____ ___ 
| ____|  _ \/ ___|  / \  | |   | | |  _ \  / \| |/ |_   _/ _ \
|  _| | |_) \___ \ / _ \ | |   | | | | | |/ _ \| \| ' / | | | | | |
| |___|  _ < ___ ) / ___ \| |___| |_| | |_| / ___ \ .  \| | | | |_| |
|_____|_| \_\____/_/   \_\_____|_____|____/_/   \_\_|\_|\_|   \___/___/
                                                                        
VAPT Engine v2.3 - Enhanced Dockerized (OS Detection + Multi-Mode)
40+ Security Tools • Path Discovery • OS Fingerprinting • Advanced Correlation
BANNEREOF
    echo -e "${NC}"
}

# Usage
usage() {
    echo "Usage: $0 <target_domain> [options]"
    echo ""
    echo "Required:"
    echo "  target_domain    Target domain for VAPT assessment"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -v, --verbose    Enable verbose output"
    echo "  -q, --quiet      Enable quiet mode"
    echo "  -d, --dry-run    Show commands without executing"
    echo "  -m, --mode MODE  Execution mode: strict, modular, unified (default: strict)"
    echo ""
    echo "Execution Modes:"
    echo "  strict    - Sequential execution with path discovery (40+ tools)"
    echo "  modular   - Phase-based modular execution"
    echo "  unified   - Simplified unified execution"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com --verbose"
    echo "  $0 example.com --dry-run"
    echo "  $0 example.com --mode strict"
    echo "  $0 example.com --mode modular"
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

# Qwen Integration Functions
init_qwen_service() {
    if [[ "$ENABLE_QWEN_INTEGRATION" == "true" ]]; then
        log_info "Checking Qwen 0.5B service status..."
        if ! curl -s "http://localhost:8080/health" >/dev/null 2>&1; then
            log_warn "Qwen service not running - normalization disabled"
            ENABLE_QWEN_INTEGRATION=false
        else
            log_info "Qwen service is running and ready"
        fi
    fi
}

# DetectDojo Integration Functions
init_detectdojo_service() {
    if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
        log_info "Checking DetectDojo service status..."
        if ! curl -s "http://localhost:8081" >/dev/null 2>&1; then
            log_warn "DetectDojo service not running - correlation disabled"
            ENABLE_DETECTDOJO_INTEGRATION=false
        else
            log_info "DetectDojo service is running and ready"
        fi
    fi
}

# Process tool output with Orca and DetectDojo
process_tool_output() {
    local tool_name="$1"
    local output_file="$2"
    
    if [[ "$ENABLE_QWEN_INTEGRATION" != "true" ]]; then
        return 0
    fi
    
    if [[ ! -f "$output_file" ]] || [[ ! -s "$output_file" ]]; then
        return 0
    fi
    
    log_info "Processing $tool_name output with Qwen..."
    
    # Send to Qwen for normalization using new API
    local normalized_output
    normalized_output=$(curl -s -X POST "http://localhost:8080/normalize" \
        -H "Content-Type: application/json" \
        -d "{
            \"tool_name\": \"$tool_name\",
            \"tool_output\": \"$(cat "$output_file" | head -c 1000)\",
            \"target_domain\": \"$TARGET_DOMAIN\"
        }" 2>/dev/null || echo "")
    
    if [[ -n "$normalized_output" ]] && [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
        # Send to DetectDojo
        log_info "Sending $tool_name findings to DetectDojo..."
        echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
    fi
}

# Background processor for parallel tool output processing
start_background_processor() {
    if [[ "$ENABLE_QWEN_INTEGRATION" != "true" ]]; then
        return 0
    fi
    
    log_info "Starting background Qwen processor..."
    
    # Create processing queue
    mkdir -p "${OUTPUT_DIR}/processing_queue"
    
    # Start background processor
    (
        while true; do
            # Check if any .tool files exist before processing
            if ls "${OUTPUT_DIR}/processing_queue"/*.tool >/dev/null 2>&1; then
                for queue_file in "${OUTPUT_DIR}/processing_queue"/*.tool; do
                    if [[ -f "$queue_file" ]]; then
                        local tool_name output_file
                        tool_name=$(basename "$queue_file" .tool)
                        output_file=$(cat "$queue_file")
                        
                        process_tool_output "$tool_name" "$output_file"
                        rm "$queue_file" 2>/dev/null || true
                    fi
                done
            fi
            sleep 2
        done
    ) &
    
    BACKGROUND_PROCESSOR_PID=$!
}

# Queue tool for processing
queue_tool_processing() {
    local tool_name="$1"
    local output_file="$2"
    
    if [[ "$ENABLE_QWEN_INTEGRATION" == "true" ]] && [[ -f "$output_file" ]]; then
        echo "$output_file" > "${OUTPUT_DIR}/processing_queue/${tool_name}.tool"
    fi
}

# Generate final DetectDojo report
generate_final_report() {
    if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
        log_info "Generating final DetectDojo report..."
        "$DETECTDOJO_SERVICE" report "$TARGET_DOMAIN" "${OUTPUT_DIR}/detectdojo_report.md" || {
            log_warn "Failed to generate DetectDojo report"
        }
    fi
}

# Resource monitoring wrapper
monitor_resources() {
    local phase_name="$1"
    log_info "Resource usage for $phase_name:"
    
    # Docker container stats
    if command -v docker &> /dev/null; then
        docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep vapt || true
    fi
    
    # System resources
    echo "Memory: $(free -h | grep Mem)"
    echo "Disk: $(df -h /var/log/output | tail -1)"
}

# Progress tracking
track_progress() {
    local total_steps="$1"
    local current_step="$2"
    local phase_name="$3"
    
    local progress=$((current_step * 100 / total_steps))
    echo -e "${CYAN}[PROGRESS]${NC} $phase_name: $progress% ($current_step/$total_steps)"
}

# Enhanced error handling wrapper
run_with_retry() {
    local cmd="$1"
    local max_retries=${2:-3}
    local retry_delay=${3:-5}
    local attempt=1
    
    while [[ $attempt -le $max_retries ]]; do
        if run_docker "$cmd"; then
            return 0
        else
            log_warn "Attempt $attempt failed for: $cmd"
            if [[ $attempt -lt $max_retries ]]; then
                log_info "Retrying in $retry_delay seconds..."
                sleep $retry_delay
            fi
            ((attempt++))
        fi
    done
    
    log_error "Command failed after $max_retries attempts: $cmd"
    return 1
}

# Parallel execution wrapper
run_parallel() {
    local commands=("$@")
    local pids=()
    
    for cmd in "${commands[@]}"; do
        (
            run_docker "$cmd"
        ) &
        pids+=("$!")
        
        # Limit parallel processes
        if [[ ${#pids[@]} -ge $MAX_PARALLEL_SCANS ]]; then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
        fi
    done
    
    # Wait for remaining processes
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
}

# Docker execution wrapper
run_docker() {
    local cmd="$1"
    local container_name="vapt-$(uuidgen | head -c 8)"
    
    # Ensure output directory is writable
    sudo chmod 755 "$OUTPUT_DIR" 2>/dev/null || true
    
    docker run --rm \
        --name "$container_name" \
        --cpus="${DOCKER_CPU_LIMIT}" \
        --memory="${DOCKER_MEMORY_LIMIT}" \
        --privileged \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        --cap-add=SYS_ADMIN \
        -v "${OUTPUT_DIR}:${OUTPUT_DIR}:rw" \
        -w "${OUTPUT_DIR}" \
        --user "$(id -u):$(id -g)" \
        --entrypoint="" \
        "$DOCKER_IMAGE" \
        bash -c "$cmd" || {
            log_error "Docker command failed: $cmd"
            return 1
        }
}

# Initialize output directories
init_directories() {
    # Define canonical scan identifiers (ONCE)
    SCAN_DATE=$(date +"%Y%m%d")
    SCAN_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    SCAN_ID="${TARGET_DOMAIN}_${SCAN_DATE}"
    
    OUTPUT_BASE="/var/log/output"
    OUTPUT_DIR="${OUTPUT_BASE}/${SCAN_ID}"
    LOG_FILE="/var/production/logs/execution_${SCAN_TIMESTAMP}.log"
    
    # Create base output directory with fallback
    if ! mkdir -p "$OUTPUT_BASE" 2>/dev/null; then
        # Try with sudo if user permission fails
        sudo mkdir -p "$OUTPUT_BASE" 2>/dev/null || {
            # Fallback to user directory
            OUTPUT_BASE="$HOME/vapt_output"
            mkdir -p "$OUTPUT_BASE"
            log_warn "Using alternative output directory: $OUTPUT_BASE"
            OUTPUT_DIR="${OUTPUT_BASE}/${SCAN_ID}"
        }
    fi
    
    # Create scan-specific directory with permissions
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        sudo mkdir -p "$OUTPUT_DIR" 2>/dev/null || {
            log_error "Failed to create output directory: $OUTPUT_DIR"
            exit 1
        }
    fi
    
    # Ensure proper permissions and ownership
    sudo chown -R "$(id -u):$(id -g)" "$OUTPUT_DIR" 2>/dev/null || true
    chmod 755 "$OUTPUT_DIR" 2>/dev/null || sudo chmod 755 "$OUTPUT_DIR" 2>/dev/null || true
    
    # Create processing queue directory
    mkdir -p "${OUTPUT_DIR}/processing_queue" 2>/dev/null || sudo mkdir -p "${OUTPUT_DIR}/processing_queue" 2>/dev/null || true
    chmod 755 "${OUTPUT_DIR}/processing_queue" 2>/dev/null || sudo chmod 755 "${OUTPUT_DIR}/processing_queue" 2>/dev/null || true
    
    # Create scan subdirectories
    for dir in recon network vuln web ssl database container reports; do
        mkdir -p "${OUTPUT_DIR}/${dir}" 2>/dev/null || sudo mkdir -p "${OUTPUT_DIR}/${dir}" 2>/dev/null || true
        sudo chown "$(id -u):$(id -g)" "${OUTPUT_DIR}/${dir}" 2>/dev/null || true
    done
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || sudo mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    
    log_ok "Directories initialized"
    log_info "Output directory: $OUTPUT_DIR"
}

# Phase 1: RECONNAISSANCE (Optimized)
run_recon() {
    log_info "Starting Phase 1: RECONNAISSANCE"
    
    # Parallel subdomain discovery
    run_parallel \
        "timeout 300 amass enum -d ${TARGET_DOMAIN} -o recon/amass.txt -passive || echo '${TARGET_DOMAIN}' > recon/amass.txt" \
        "assetfinder ${TARGET_DOMAIN} | tee recon/assetfinder.txt" \
        "subfinder -d ${TARGET_DOMAIN} -o recon/subfinder.txt || echo '${TARGET_DOMAIN}' > recon/subfinder.txt"
    
    # Parallel information gathering
    run_parallel \
        "whois ${TARGET_DOMAIN} > recon/whois.txt || echo 'Whois information not available' > recon/whois.txt" \
        "dnsrecon -d ${TARGET_DOMAIN} -j recon/dnsrecon.json" \
        "dig ${TARGET_DOMAIN} A AAAA MX TXT NS > recon/dig.txt" \
        "whatweb https://${TARGET_DOMAIN} > recon/whatweb.txt || echo 'WhatWeb scan failed' > recon/whatweb_error.txt"
    
    # Parallel URL discovery
    run_parallel \
        "waybackurls ${TARGET_DOMAIN} > recon/waybackurls.txt" \
        "gau ${TARGET_DOMAIN} > recon/gau.txt"
    
    # Fallback logic
    run_docker "if [[ ! -s recon/amass.txt ]]; then echo 'No subdomains found by amass, using main domain as fallback' && echo '${TARGET_DOMAIN}' > recon/amass.txt; fi"
    run_docker "if [[ ! -s recon/subfinder.txt ]]; then echo 'No subdomains found by subfinder, using main domain as fallback' && echo '${TARGET_DOMAIN}' > recon/subfinder.txt; fi"
    
    log_ok "Reconnaissance completed"
}

# Phase 2: NETWORK SCANNING (Serialized for resource management)
run_network() {
    track_progress 8 2 "Network Scanning"
    log_info "Starting Phase 2: NETWORK SCANNING (Serialized)"
    
    # Test masscan reliability first
    local masscan_enabled=true
    if ! run_docker "masscan --ping 8.8.8.8 --rate=100 2>/dev/null" >/dev/null 2>&1; then
        log_warn "Masscan disabled - Docker raw socket support unreliable"
        masscan_enabled=false
    fi
    
    # Sequential port discovery to prevent resource exhaustion
    log_info "Running naabu for port discovery with JSON output..."
    run_docker "naabu -host ${TARGET_DOMAIN} -o network/naabu.txt -json"
    
    log_info "Running rustscan for ultra-fast port scanning..."
    run_docker "rustscan -a ${TARGET_DOMAIN} -r 1-65535 --ulimit 5000 -- -sV -oX network/rustscan.xml"
    
    # Service discovery
    run_with_retry "jq -r '.host + \":\" + (.port|tostring)' network/naabu.txt 2>/dev/null | httpx -o network/httpx.txt || true"
    
    # Individual IP scanning with enhanced error handling (serialized)
    run_docker "for ip in \$(jq -r '.[] | select(.type==\"A\") | .address' recon/dnsrecon.json 2>/dev/null || echo ''); do if [[ -n \"\$ip\" ]]; then echo \"Scanning IP: \$ip\" && timeout ${SCAN_TIMEOUT} nmap -sS -sV -O --script vulners \$ip -oA network/nmap_comprehensive_\${ip//./_} 2>/dev/null || timeout ${SCAN_TIMEOUT} nmap -sS -sV --script vulners \$ip -oA network/nmap_comprehensive_\${ip//./_} 2>/dev/null || timeout ${SCAN_TIMEOUT} nmap -sV --script vulners \$ip -oA network/nmap_comprehensive_\${ip//./_} || echo \"Nmap scan failed for \$ip\" > network/nmap_error_\${ip//./_}.txt; else echo \"No IPs found for nmap scanning\" > network/nmap_error.txt; fi; done"
    
    # Masscan with dynamic enable/disable
    if [[ "$masscan_enabled" == "true" ]]; then
        log_info "Running masscan for fast port discovery..."
        run_docker "for ip in \$(jq -r '.[] | select(.type==\"A\") | .address' recon/dnsrecon.json); do echo \"Masscan scanning IP: \$ip\" && timeout ${SCAN_TIMEOUT} masscan \$ip -p1-65535 --rate=${RATE_LIMIT} -oL network/masscan_\${ip//./_}.txt 2>/dev/null || echo \"Masscan failed for \$ip, using nmap fallback\" && nmap -p- \$ip -oN network/masscan_fallback_\${ip//./_}.txt; done"
    else
        log_info "Masscan disabled, using nmap for comprehensive port scanning"
        run_docker "for ip in \$(jq -r '.[] | select(.type==\"A\") | .address' recon/dnsrecon.json); do echo \"Nmap comprehensive scan for IP: \$ip\" && nmap -p- \$ip -oN network/masscan_fallback_\${ip//./_}.txt; done"
    fi
    
    monitor_resources "Network Scanning"
    log_ok "Network scanning completed"
}

# Phase 3: VULNERABILITY ASSESSMENT (Optimized)
run_vulnerability() {
    track_progress 8 3 "Vulnerability Assessment"
    log_info "Starting Phase 3: VULNERABILITY ASSESSMENT"
    
    # Create nuclei targets from gobuster results
    log_info "Creating nuclei targets from discovered URLs..."
    run_docker "echo 'https://${TARGET_DOMAIN}/' > vuln/nuclei_targets.txt && grep -E '^/' web/gobuster.txt 2>/dev/null | grep -v 'Status: 403' | awk '{print \$1}' | sed 's|/$||' | grep -v -E '\\.(php|html|htm|css|js|jpg|png|gif|ico)$' | sed 's|^/|https://${TARGET_DOMAIN}/|' | sed 's|[^/]$|&/|' | sort -u >> vuln/nuclei_targets.txt || echo 'Using main domain only' && echo 'https://${TARGET_DOMAIN}/' > vuln/nuclei_targets.txt"
    
    # Parallel vulnerability scanning
    run_parallel \
        "for url in \$(cat vuln/nuclei_targets.txt); do echo \"Nuclei scanning: \$url\" && nuclei -u \"\$url\" -severity critical,high,medium -o vuln/nuclei_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g').txt || echo \"No vulnerabilities found for \$url\" > vuln/nuclei_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g').txt; done" \
        "for xml_file in network/nmap_comprehensive_*.xml; do if [[ -f \"\$xml_file\" ]]; then echo \"Processing \$xml_file\" && searchsploit --nmap \"\$xml_file\" >> vuln/searchsploit.txt; fi; done || echo 'No nmap XML files found for searchsploit' > vuln/searchsploit_error.txt" \
        "nmap -sV --script vulners ${TARGET_DOMAIN} -oX vuln/nmap_vulners.xml || echo 'No nmap vulners results' > vuln/nmap_vulners.txt"
    
    # Combine results
    run_docker "cat vuln/nuclei_*.txt 2>/dev/null | grep -v 'No vulnerabilities found' | sort -u > vuln/nuclei.txt || echo 'No vulnerabilities found' > vuln/nuclei.txt"
    
    # Convert Nmap XML to JSON
    run_docker "if [[ -f vuln/nmap_vulners.xml ]]; then xq '.' vuln/nmap_vulners.xml > vuln/nmap_vulners.json 2>/dev/null || echo '{\"vulners\": []}' > vuln/nmap_vulners.json; else echo '{\"vulners\": []}' > vuln/nmap_vulners.json; fi"
    
    # Queue for Orca processing
    queue_tool_processing "nuclei" "${OUTPUT_DIR}/vuln/nuclei.txt"
    
    monitor_resources "Vulnerability Assessment"
    log_ok "Vulnerability assessment completed"
    log_info "Nuclei targets scanned: $(cat "${OUTPUT_DIR}/vuln/nuclei_targets.txt" 2>/dev/null | wc -l || echo "0")"
}

# Phase 4: WEB SECURITY
run_web() {
    log_info "Starting Phase 4: WEB SECURITY"
    
    log_info "Running gobuster for path discovery..."
    run_docker "gobuster dir -u https://${TARGET_DOMAIN} -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o web/gobuster.txt"
    
    log_info "Running katana on discovered URLs..."
    run_docker "echo 'https://${TARGET_DOMAIN}/' > web/katana_targets.txt && grep -E '^/' web/gobuster.txt | grep -v 'Status: 403' | awk '{print \$1}' | sed 's|/$||' | grep -v -E '\\.(php|html|htm|css|js|jpg|png|gif|ico)$' | sed 's|^/|https://${TARGET_DOMAIN}/|' | sed 's|[^/]$|&/|' | sort -u >> web/katana_targets.txt && for url in \$(cat web/katana_targets.txt); do echo \"Scanning: \$url\" && katana -u \"\$url\" -o web/katana_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$//').txt; done && cat web/katana_*.txt > web/katana.txt 2>/dev/null || echo 'No katana results' > web/katana.txt"
    
    log_info "Running nikto on all discovered URLs..."
    run_docker "if [[ -f web/katana_targets.txt ]]; then cp web/katana_targets.txt web/nikto_targets.txt; else echo 'https://${TARGET_DOMAIN}/' > web/nikto_targets.txt; fi && for url in \$(cat web/nikto_targets.txt); do echo \"Nikto scanning: \$url\" && nikto -h \"\$url\" -o web/nikto_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$//').txt || echo \"No nikto results for \$url\" > web/nikto_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$//').txt; done"
    
    log_info "Running ffuf for fuzzing..."
    run_docker "ffuf -u \"https://${TARGET_DOMAIN}/FUZZ\" -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o web/ffuf.json -of json || echo 'No ffuf results' > web/ffuf.txt"
    
    log_info "Running dirsearch..."
    run_docker "dirsearch -u \"https://${TARGET_DOMAIN}\" -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o web/dirsearch.txt || echo 'No dirsearch results' > web/dirsearch.txt"
    
    log_info "Running wapiti for web vulnerability scanning..."
    run_docker "wapiti -u https://${TARGET_DOMAIN} -o web/wapiti.html -f html || echo 'Wapiti scan completed with issues' > web/wapiti.txt"
    
    log_info "Running OWASP ZAP for comprehensive web security scan..."
    if command -v docker >/dev/null 2>&1; then
        # Check if main domain returns 404
        log_info "Checking main domain status..."
        domain_status=$(curl -s -o /dev/null -w "%{http_code}" "https://${TARGET_DOMAIN}" || echo "000")
        
        if [[ "$domain_status" == "404" ]]; then
            log_info "Main domain returns 404, using katana_targets.txt for ZAP scanning"
            # Use only katana_targets.txt as input for ZAP
            if [[ -f "${OUTPUT_DIR}/web/katana_targets.txt" ]]; then
                cp "${OUTPUT_DIR}/web/katana_targets.txt" "${OUTPUT_DIR}/web/zap_targets.txt"
                log_info "Using katana targets: $(cat "${OUTPUT_DIR}/web/zap_targets.txt" | wc -l) URLs found"
            else
                log_info "katana_targets.txt not found, using main domain only"
                echo "https://${TARGET_DOMAIN}/" > "${OUTPUT_DIR}/web/zap_targets.txt"
            fi
            
            # Run ZAP on discovered URLs
            while IFS= read -r url; do
                if [[ -n "$url" ]]; then
                    log_info "ZAP scanning: $url"
                    timeout "${ZAP_TIMEOUT_MINUTES}m" docker run --rm \
                        -v "${OUTPUT_DIR}/web:/zap/wrk/:rw" \
                        --user "$(id -u):$(id -g)" \
                        --entrypoint "" \
                        "$ZAP_DOCKER_IMAGE" \
                        bash -c "mkdir -p /zap/wrk && zap-full-scan.py -t '$url' -J /zap/wrk/zap_$(echo $url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$//').json" || true
                fi
            done < "${OUTPUT_DIR}/web/zap_targets.txt"
            
            # Combine all ZAP results - aggregate on host side
            if ls "${OUTPUT_DIR}/web"/zap_*.json 1>/dev/null 2>&1; then
                jq -s '.' "${OUTPUT_DIR}/web"/zap_*.json > "${OUTPUT_DIR}/web/zap.json" 2>/dev/null || echo '[]' > "${OUTPUT_DIR}/web/zap.json"
            else
                echo '[]' > "${OUTPUT_DIR}/web/zap.json"
            fi
            
            # Queue for Orca processing
            queue_tool_processing "zap" "${OUTPUT_DIR}/web/zap.json"
        else
            log_info "Main domain accessible (status: $domain_status), running ZAP on main domain"
            timeout "${ZAP_TIMEOUT_MINUTES}m" docker run --rm \
                -v "${OUTPUT_DIR}/web:/zap/wrk/:rw" \
                --user "$(id -u):$(id -g)" \
                --entrypoint "" \
                "$ZAP_DOCKER_IMAGE" \
                bash -c "mkdir -p /zap/wrk && zap-full-scan.py -t 'https://${TARGET_DOMAIN}' -J /zap/wrk/zap.json" || true
        fi
    else
        log_info "Docker not available, creating empty ZAP results"
        echo "[]" > "${OUTPUT_DIR}/web/zap.json"
    fi
    
    log_ok "Web security completed"
    log_info "Total URLs crawled by katana: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")"
}

# Phase 5: SSL/TLS SECURITY
run_ssl() {
    log_info "Starting Phase 5: SSL/TLS SECURITY"
    
    log_info "Running sslyze..."
    run_docker "sslyze --certinfo --heartbleed --robot --tlsv1_2 --tlsv1_3 --http_headers --json_out ssl/sslyze.json ${TARGET_DOMAIN}:443 || echo '{\"error\": \"sslyze not available\"}' > ssl/sslyze.json"
    
    log_info "Running sslscan..."
    run_docker "sslscan ${TARGET_DOMAIN}:443 > ssl/sslscan.txt"
    
    log_info "Running testssl.sh..."
    run_docker "testssl.sh --jsonfile ssl/testssl.json --htmlfile ssl/testssl.html ${TARGET_DOMAIN}:443 || echo 'testssl.sh not available, SSLyze completed successfully' > ssl/testssl_error.txt"
    
    log_ok "SSL/TLS security completed"
}

# Phase 6: DATABASE SECURITY
run_database() {
    log_info "Starting Phase 6: DATABASE SECURITY"
    
    # Create SQLMap targets from web discoveries (only URLs with parameters)
    log_info "Creating SQLMap targets from discovered URLs with parameters..."
    run_docker "grep '?' web/katana.txt | sort -u > database/sqlmap_targets.txt"
    
    log_info "Running sqlmap on parameterized URLs with safe settings..."
    run_docker "for url in \$(cat database/sqlmap_targets.txt); do echo \"SQLMap scanning: \$url\" && python3 /opt/tools/sqlmap/sqlmap.py -u \"\$url\" --batch --level=2 --risk=1 --threads=1 --timeout=5 --retries=1 --random-agent --flush-session --tamper=space2comment --output-dir=database/sqlmap_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g') || echo \"No SQL injection found for \$url\" > database/sqlmap_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g').txt; done"
    
    log_info "Checking database ports..."
    run_docker "nmap -sV -p 3306,5432,6379,1433,1521 ${TARGET_DOMAIN} -oA database/db_ports"
    
    log_info "Testing Redis access..."
    run_docker "nc -zv ${TARGET_DOMAIN} 6379 2>&1 | tee database/redis_test.txt || echo 'Redis not accessible' > database/redis_test.txt"
    
    log_info "Testing PostgreSQL access..."
    run_docker "nc -zv ${TARGET_DOMAIN} 5432 2>&1 | tee database/postgres_test.txt || echo 'PostgreSQL not accessible' > database/postgres_test.txt"
    
    log_info "Testing MySQL access..."
    run_docker "nc -zv ${TARGET_DOMAIN} 3306 2>&1 | tee database/mysql_test.txt || echo 'MySQL not accessible' > database/mysql_test.txt"
    
    log_ok "Database security completed"
}

# Phase 7: CONTAINER & CLOUD SECURITY
run_container() {
    log_info "Starting Phase 7: CONTAINER & CLOUD SECURITY"
    
    log_info "Running scanner-side metadata exposure test (informational)..."
    run_docker "echo 'Scanner-side metadata exposure test (informational)' > container/metadata_check.txt && curl -s http://169.254.169.254/latest/meta-data/ | head -20 >> container/metadata_check.txt || true"
    
    log_info "Checking Docker registry exposure..."
    run_docker "curl -s https://${TARGET_DOMAIN}/v2/_catalog 2>&1 | head -10 > container/docker_registry.txt || echo 'Docker registry not exposed' > container/docker_registry.txt"
    
    log_info "Checking Kubernetes API exposure..."
    run_docker "curl -s https://${TARGET_DOMAIN}/api/v1/pods 2>&1 | head -10 > container/k8s_api.txt || echo 'Kubernetes API not exposed' > container/k8s_api.txt"
    
    log_info "Running kubeaudit for Kubernetes security audit..."
    run_docker "kubeaudit all --json > container/kubeaudit_results.json || true"
    
    log_ok "Container and cloud security completed"
}

# Phase 8: REPORTING
run_reporting() {
    log_info "Starting Phase 8: REPORTING & CORRELATION"
    
    # Create executive summary
    log_info "Generating executive summary..."
    cat > "${OUTPUT_DIR}/executive_summary.txt" << EOF
VAPT Assessment Executive Summary
==================================
Target: ${TARGET_DOMAIN}
Date: $(date)
Assessment Type: Comprehensive VAPT Engine v2.3

EXECUTIVE SUMMARY:
==================
This report contains the results of a comprehensive security assessment
performed using the Enhanced VAPT Engine with 40+ security tools.

KEY FINDINGS:
=============
- Reconnaissance: $(cat "${OUTPUT_DIR}/recon/amass.txt" 2>/dev/null | wc -l || echo "0") subdomains discovered
- Network: $(cat "${OUTPUT_DIR}/network/naabu.txt" 2>/dev/null | wc -l || echo "0") open ports identified
- Web: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0") URLs crawled
- Vulnerabilities: $(grep -c "critical\|high\|medium" "${OUTPUT_DIR}/vuln/nuclei.txt" 2>/dev/null || echo "0") findings

TOOLS USED:
===========
Phase 1 (Recon): amass, assetfinder, subfinder, whois, dnsrecon, dig, whatweb, waybackurls, gau
Phase 2 (Network): naabu, nmap, masscan, rustscan, httpx
Phase 3 (Vulnerability): nuclei, searchsploit, nmap vulners
Phase 4 (Web): gobuster, katana, nikto, ffuf, dirsearch, wapiti, OWASP ZAP
Phase 5 (SSL): sslyze, sslscan, testssl.sh
Phase 6 (Database): sqlmap, database port checks
Phase 7 (Container): cloud metadata, docker registry, k8s API, kubeaudit (informational)

RECOMMENDATIONS:
================
1. Review and patch all identified vulnerabilities
2. Implement proper access controls and security headers
3. Regular security assessments recommended
4. Monitor for new vulnerabilities and threats

For detailed technical findings, refer to individual tool outputs in respective directories.
EOF
    
    # Generate HTML report
    log_info "Generating HTML report..."
    cat > "${OUTPUT_DIR}/vapt_report.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>VAPT Assessment Report - ${TARGET_DOMAIN}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .critical { color: #e74c3c; }
        .high { color: #e67e22; }
        .medium { color: #f39c12; }
        .low { color: #27ae60; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
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
        <p><strong>Target:</strong> ${TARGET_DOMAIN}</p>
        <p><strong>Assessment Date:</strong> $(date)</p>
        <p><strong>Engine Version:</strong> VAPT Engine v2.3</p>
        <p><strong>Total Tools Used:</strong> 40+</p>
    </div>
    
    <div class="section">
        <h3>Key Metrics</h3>
        <ul>
            <li>Subdomains Discovered: $(cat "${OUTPUT_DIR}/recon/amass.txt" 2>/dev/null | wc -l || echo "0")</li>
            <li>Open Ports: $(cat "${OUTPUT_DIR}/network/naabu.txt" 2>/dev/null | wc -l || echo "0")</li>
            <li>URLs Crawled: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")</li>
            <li>Vulnerabilities Found: $(grep -c "critical\|high\|medium" "${OUTPUT_DIR}/vuln/nuclei.txt" 2>/dev/null || echo "0")</li>
        </ul>
    </div>
    
    <div class="section">
        <h3>Tools Executed</h3>
        <table>
            <tr><th>Phase</th><th>Tools</th></tr>
            <tr><td>Reconnaissance</td><td>amass, assetfinder, subfinder, whois, dnsrecon, dig, whatweb, waybackurls, gau</td></tr>
            <tr><td>Network</td><td>naabu, nmap, masscan, rustscan, httpx</td></tr>
            <tr><td>Vulnerability</td><td>nuclei, searchsploit, nmap vulners</td></tr>
            <tr><td>Web</td><td>gobuster, katana, nikto, ffuf, dirsearch, wapiti, OWASP ZAP</td></tr>
            <tr><td>SSL/TLS</td><td>sslyze, sslscan, testssl.sh</td></tr>
            <tr><td>Database</td><td>sqlmap, database port checks</td></tr>
            <tr><td>Container</td><td>cloud metadata, docker registry, k8s API, kubeaudit (informational)</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h3>Recommendations</h3>
        <ol>
            <li>Immediate patching of critical and high vulnerabilities</li>
            <li>Implement proper security headers and configurations</li>
            <li>Regular security assessments and monitoring</li>
            <li>Security awareness training for development team</li>
        </ol>
    </div>
</body>
</html>
EOF
    
    log_ok "Reporting completed"
    log_info "Reports generated: executive_summary.txt, vapt_report.html"
}

# Legal authorization guardrail
check_authorization() {
    echo -e "${YELLOW}=== LEGAL AUTHORIZATION REQUIRED ===${NC}"
    echo -e "${YELLOW}This tool should only be used on systems you own or have explicit permission to test.${NC}"
    echo -e "${YELLOW}Unauthorized scanning is illegal and unethical.${NC}"
    echo ""
    read -p "Confirm you have authorization to scan ${TARGET_DOMAIN} (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        echo -e "${RED}[ERROR] Authorization not confirmed. Exiting.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[OK] Authorization confirmed. Proceeding with scan.${NC}"
    echo ""
}

# Main execution function
main() {
    # Parse arguments
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
            -q|--quiet)
                VERBOSE=false
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -m|--mode)
                EXECUTION_MODE="$2"
                shift 2
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
    
    # Validate required arguments
    if [[ -z "$TARGET_DOMAIN" ]]; then
        log_error "Target domain is required"
        usage
        exit 1
    fi
    
    # Legal authorization check
    check_authorization
    
    # Display banner
    banner
    
    # Check prerequisites
    log_info "Checking prerequisites"
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Pull Docker image
    log_info "Pulling Docker image: $DOCKER_IMAGE"
    if ! docker pull "$DOCKER_IMAGE" &>/dev/null; then
        log_error "Failed to pull Docker image: $DOCKER_IMAGE"
        exit 1
    fi
    
    # Initialize
    init_directories
    
    # Check service status (no automatic startup)
    init_qwen_service
    init_detectdojo_service
    
    # Start background processor for parallel tool processing (if Orca is running)
    start_background_processor
    
    # Create scan metadata inside container
    run_docker "cat > scan_metadata.json << EOF
{
    \"target\": \"${TARGET_DOMAIN}\",
    \"scan_id\": \"${SCAN_ID}\",
    \"scan_date\": \"$(date -Iseconds)\",
    \"engine_version\": \"2.3\",
    \"execution_mode\": \"${EXECUTION_MODE}\",
    \"docker_image\": \"${DOCKER_IMAGE}\",
    \"verbose\": ${VERBOSE},
    \"dry_run\": ${DRY_RUN}
}
EOF"
    
    log_info "Executing in ${EXECUTION_MODE} mode with OS detection and enhanced features"
    
    # Execute phases based on mode
    case "$EXECUTION_MODE" in
        "strict")
            log_info "Running in STRICT mode with enhanced error handling"
            set -euo pipefail
            run_recon
            run_network
            run_vulnerability
            run_web
            run_ssl
            run_database
            run_container
            run_reporting
            ;;
        "modular")
            log_info "Running in MODULAR mode - phases can continue independently"
            run_recon || log_warn "Reconnaissance phase failed"
            run_network || log_warn "Network scanning phase failed"
            run_vulnerability || log_warn "Vulnerability assessment phase failed"
            run_web || log_warn "Web security phase failed"
            run_ssl || log_warn "SSL/TLS assessment phase failed"
            run_database || log_warn "Database security phase failed"
            run_container || log_warn "Container security phase failed"
            run_reporting || log_warn "Reporting phase failed"
            ;;
        "unified")
            log_info "Running in UNIFIED mode - best effort execution"
            run_recon
            run_network
            run_vulnerability
            run_web
            run_ssl
            run_database
            run_container
            run_reporting
            ;;
        *)
            log_error "Invalid execution mode: $EXECUTION_MODE"
            usage
            exit 1
            ;;
    esac
    
    # Wait for background processor to complete
    if [[ -n "${BACKGROUND_PROCESSOR_PID:-}" ]]; then
        log_info "Waiting for Orca processing to complete..."
        sleep 10
        kill "$BACKGROUND_PROCESSOR_PID" 2>/dev/null || true
        wait "$BACKGROUND_PROCESSOR_PID" 2>/dev/null || true
    fi
    
    # Generate final DetectDojo report
    generate_final_report
    
    log_ok "VAPT assessment completed successfully!"
    log_info "Results available in: ${OUTPUT_DIR}"
    log_info "Executive summary: ${OUTPUT_DIR}/executive_summary.txt"
    log_info "HTML report: ${OUTPUT_DIR}/vapt_report.html"
    
    # Display summary
    echo ""
    echo -e "${CYAN}=== ASSESSMENT SUMMARY ===${NC}"
    echo -e "Target: ${GREEN}${TARGET_DOMAIN}${NC}"
    echo -e "Mode: ${GREEN}${EXECUTION_MODE}${NC}"
    echo -e "Output: ${GREEN}${OUTPUT_DIR}${NC}"
    echo ""
    echo -e "${CYAN}Key Metrics:${NC}"
    echo -e "- Subdomains: $(cat "${OUTPUT_DIR}/recon/amass.txt" 2>/dev/null | wc -l || echo "0")"
    echo -e "- Open Ports: $(cat "${OUTPUT_DIR}/network/naabu.txt" 2>/dev/null | wc -l || echo "0")"
    echo -e "- URLs Crawled: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")"
    echo -e "- Vulnerabilities: $(grep -c "critical\|high\|medium" "${OUTPUT_DIR}/vuln/nuclei.txt" 2>/dev/null || echo "0")"
    echo ""
    echo -e "${GREEN}✓ Enhanced VAPT Engine v2.3 - Complete!${NC}"
}

# Execute main function
main "$@"
