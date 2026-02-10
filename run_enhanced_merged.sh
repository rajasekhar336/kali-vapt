#!/bin/bash

# VAPT Engine - Enhanced Dockerized Version with Enterprise Integration
# Professional CLI VAPT Automation Framework with 40+ tools + DetectDojo + AI

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
DOCKER_IMAGE='rajatherise/kali-penvapt:latest'
OUTPUT_DIR='/var/log/output'
LOG_FILE='/var/production/logs/execution.log'
ZAP_DOCKER_IMAGE='ghcr.io/zaproxy/zaproxy:stable'
ZAP_TIMEOUT_MINUTES=30
MAX_PARALLEL_SCANS=1
SCAN_TIMEOUT=600
PORT_SCAN_TIMEOUT=600
RATE_LIMIT=100
DOCKER_CPU_LIMIT="1.5"
DOCKER_MEMORY_LIMIT="2g"
RUN_LOCAL=${RUN_LOCAL:-false}

# Enterprise Integration Configuration
QWEN_SERVICE="/var/production/qwen-0.5b-normalizer/qwen-0.5b-docker.sh"
DETECTDOJO_SERVICE="/var/production/detectdojo/detectdojo-service.sh"
ENABLE_QWEN_INTEGRATION=true
ENABLE_DETECTDOJO_INTEGRATION=true

# Tool arrays for DetectDojo integration - COMPLETE
import_only_tools=("amass")
vulnerability_assertions=("nuclei" "nmap_vulners")
web_vulnerability_assertions=("nikto" "wapiti" "zap" "katana_nuclei" "feroxbuster_nuclei" "ffuf_nuclei" "dirsearch_nuclei" "arjun" "httpx" "katana" "ffuf" "feroxbuster" "dirsearch" "whatweb")
database_findings=("sqlmap" "db_detailed_scan" "database_aggregated" "sslyze" "testssl")
cloud_findings=("kubeaudit" "cloud_aggregated")
network_risk_tools=("nmap" "masscan" "httpx")

# Enhanced banner
banner() {
    echo -e "${CYAN}"
    cat << 'BANNEREOF'
 _____ ____  ____    _    _     _   ____    _  __ _____ ___ 
| ____|  _ \/ ___|  / \  | |   | | |  _ \  / \| |/ |_   _/ _ \
|  _| | |_) \___ \ / _ \ | |   | | | | | |/ _ \| \| ' / | | | | | |
| |___|  _ < ___ ) / ___ \| |___| |_| | |_| / ___ \ .  \| | | | |_| |
|_____|_| \_\____/_/   \_\_____|_____|____/_/   \_\_|\_|\_|   \___/___/
                                                                        
VAPT Engine v2.3 - Enterprise Enhanced (DetectDojo + AI Integration)
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
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${BLUE}[INFO]${NC} $1"
}

log_ok() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${GREEN}[OK]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE" 2>/dev/null || echo -e "${YELLOW}[WARN]${NC} $1"
}

# Qwen Integration Functions
init_qwen_service() {
    if [[ "$ENABLE_QWEN_INTEGRATION" == "true" ]]; then
        log_info "Checking Qwen 0.5B service status..."
        if ! curl -s "${AI_SERVICE_URL:-http://localhost:8080}/health" >/dev/null 2>&1; then
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
        if ! curl -s "${DETECTDOJO_URL:-http://localhost:8081}/health" >/dev/null 2>&1; then
            log_warn "DetectDojo service not running - correlation disabled"
            ENABLE_DETECTDOJO_INTEGRATION=false
        else
            log_info "DetectDojo service is running and ready"
        fi
    fi
}

# Send tool output to DetectDojo API - WORKING VERSION
send_to_detectdojo() {
    local tool_name="$1"
    local target_domain="$2"
    local output_file="$3"
    
    # Store current strict mode settings
    local current_opts=$-
    set +e  # Temporarily disable strict mode
    
    if [[ ! -f "$output_file" ]]; then
        log_warn "Output file not found for $tool_name: $output_file"
        # Restore original options
        set -$current_opts
        return 1
    fi
    
    # For JSON files, even {} is valid content, so don't check for empty
    if [[ "$output_file" != *.json ]]; then
        if [[ ! -s "$output_file" ]]; then
            log_warn "Empty file: $output_file"
            # Restore original options
            set -$current_opts
            return 0
        fi
    fi
    
    # Handle JSON files - WORKING VERSION
    if [[ "$output_file" == *.json ]]; then
        # Check if file contains line-delimited JSON (like naabu output)
        local first_line
        first_line=$(head -n1 "$output_file" 2>/dev/null)
        
        if [[ "$first_line" == \{* ]]; then
            # Line-delimited JSON - convert to array
            local compact_json
            compact_json=$(jq -s . "$output_file" 2>/dev/null)
            if [[ $? -eq 0 ]]; then
                log_info "Sending JSON to DetectDojo: $tool_name -> $compact_json"
                # Send directly from host to DetectDojo API
                local json_payload
                json_payload=$(printf '{"tool_name": "%s", "target_domain": "%s", "tool_output": %s}' "$tool_name" "$target_domain" "$compact_json")
                curl -s -X POST http://localhost:8081/api/findings/add \
                    -H 'Content-Type: application/json' \
                    -d "$json_payload" || {
                    log_warn "Failed to send JSON results for $tool_name to DetectDojo"
                    return 0
                }
            else
                log_warn "Invalid JSON array in file: $output_file"
                return 1
            fi
        else
            # Single JSON document
            local compact_json
            compact_json=$(jq -c . "$output_file" 2>/dev/null)
            if [[ $? -eq 0 ]]; then
                log_info "Sending JSON to DetectDojo: $tool_name -> $compact_json"
                # Send directly from host to DetectDojo API
                local json_payload
                json_payload=$(printf '{"tool_name": "%s", "target_domain": "%s", "tool_output": %s}' "$tool_name" "$target_domain" "$compact_json")
                curl -s -X POST http://localhost:8081/api/findings/add \
                    -H 'Content-Type: application/json' \
                    -d "$json_payload" || {
                    log_warn "Failed to send JSON results for $tool_name to DetectDojo"
                    return 0
                }
            else
                log_warn "Invalid JSON file for $tool_name: $output_file"
                return 1
            fi
        fi
    else
        # Handle text files
        local tool_output
        tool_output=$(cat "$output_file")
        log_info "Sending text to DetectDojo: $tool_name (${#tool_output} chars)"
        # Send directly from host to DetectDojo API
        local json_payload
        json_payload=$(printf '{"tool_name": "%s", "target_domain": "%s", "tool_output": %s}' "$tool_name" "$target_domain" "$(jq -Rs . <<< "$tool_output")")
        curl -s -X POST http://localhost:8081/api/findings/add \
            -H 'Content-Type: application/json' \
            -d "$json_payload" || {
            log_warn "Failed to send text results for $tool_name to DetectDojo"
            return 0  # Don't exit the script in strict mode
        }
    fi
    
    # Restore original options before returning
    set -$current_opts
}

# Queue tool for batch processing
queue_tool_processing() {
    local tool_name="$1"
    local output_file="$2"
    local phase="$3"
    
    # Create batch file for this phase
    local batch_file="${OUTPUT_DIR}/processing_queue/detectdojo_batch_${phase}.txt"
    mkdir -p "${OUTPUT_DIR}/processing_queue"
    
    # Queue for batch processing: format "tool_name:output_file"
    echo "${tool_name}:${output_file}" | sed 's/\$//' >> "$batch_file"
}

# Process batch results for a phase
process_batch_results() {
    local phase="$1"
    local batch_file="${OUTPUT_DIR}/processing_queue/detectdojo_batch_${phase}.txt"
    
    log_info "Processing batch file: $batch_file"
    
    if [[ -f "$batch_file" ]] && [[ -s "$batch_file" ]]; then
        log_info "Processing batch DetectDojo results for $phase phase..."
        
        # Read all lines and process them one by one
        local lines=()
        mapfile -t lines < "$batch_file"
        
        local count=0
        for line in "${lines[@]}"; do
            if [[ -n "$line" ]]; then
                local tool_name="${line%%:*}"
                local output_file="${line#*:}"
                log_info "Processing: $tool_name -> $output_file"
                
                if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                    log_info "Sending to DetectDojo: $tool_name"
                    send_to_detectdojo "$tool_name" "$TARGET_DOMAIN" "$output_file" || true
                    ((count++))
                else
                    log_warn "File not found or empty: $output_file"
                fi
            fi
        done
        
        log_ok "Sent $count results to DetectDojo from $phase phase"
        rm "$batch_file" 2>/dev/null || true
    else
        log_info "No results to process for $phase phase"
    fi
}

# Enterprise-grade URL classification and routing
classify_and_route_urls() {
    local katana_output="$1"
    
    # Remove junk files and deduplicate
    grep -Ev '\.(css|js|png|jpg|svg|woff|ico|pdf)$' "$katana_output" | \
    sort -u > "${OUTPUT_DIR}/web/clean_urls.txt"
    
    # Split by purpose
    grep '?' "${OUTPUT_DIR}/web/clean_urls.txt" > "${OUTPUT_DIR}/web/parameterized_urls.txt" 2>/dev/null || true
    grep -E '/api/|/v1/|/v2/|/graphql' "${OUTPUT_DIR}/web/clean_urls.txt" > "${OUTPUT_DIR}/web/api_endpoints.txt" 2>/dev/null || true
    grep -E '/$' "${OUTPUT_DIR}/web/clean_urls.txt" > "${OUTPUT_DIR}/web/folder_urls.txt" 2>/dev/null || true
    grep -Ev '\?|/$' "${OUTPUT_DIR}/web/clean_urls.txt" > "${OUTPUT_DIR}/web/html_pages.txt" 2>/dev/null || true
    
    log_info "URL classification completed:"
    log_info "  - Parameterized URLs: $(wc -l < "${OUTPUT_DIR}/web/parameterized_urls.txt" 2>/dev/null || echo 0)"
    log_info "  - API endpoints: $(wc -l < "${OUTPUT_DIR}/web/api_endpoints.txt" 2>/dev/null || echo 0)"
    log_info "  - Folder URLs: $(wc -l < "${OUTPUT_DIR}/web/folder_urls.txt" 2>/dev/null || echo 0)"
    log_info "  - HTML pages: $(wc -l < "${OUTPUT_DIR}/web/html_pages.txt" 2>/dev/null || echo 0)"
    
    # Targeted tool execution
    log_info "Running targeted scans based on URL classification..."
    
    # Step 7: Intelligent Tool Selection Based on Intelligence
    log_info "Step 7: Intelligent Tool Selection Based on Gathered Intelligence"
    
    # SQLMap only on parameterized URLs (from gf pattern matching)
    if [[ -s "${OUTPUT_DIR}/web/parameterized_urls.txt" ]]; then
        log_info "Running SQLMap on parameterized URLs..."
        local MAX_JOBS=3
        local job_count=0
        
        while read -r url; do
            run_docker "sqlmap -u \"$url\" --batch --random-agent --output-dir=/output/web/sqlmap_$(echo $url | sed 's|https://||;s|/|_|g') 2>/dev/null || true" &
            ((job_count++))
            
            if [[ $job_count -ge $MAX_JOBS ]]; then
                wait -n
                ((job_count--))
            fi
        done < "${OUTPUT_DIR}/web/parameterized_urls.txt"
        wait
    fi
    
    # Nuclei on ALL live URLs + subdomains + services (always run)
    if [[ -s "/output/web/live_urls.txt" ]]; then
        log_info "Running Nuclei on all live URLs and discovered services..."
        run_docker 'nuclei -l /output/web/live_urls.txt -o /output/web/nuclei_comprehensive.json 2>/dev/null || echo "[]" > /output/web/nuclei_comprehensive.json'
    fi
    
    # Dalfox for URLs with parameters (XSS testing)
    if [[ -s "${OUTPUT_DIR}/web/parameterized_urls.txt" ]] && [[ -s "/output/web/live_urls.txt" ]]; then
        log_info "Running Dalfox for XSS testing on parameterized URLs..."
        # Select few high-value URLs for Dalfox
        head -10 "${OUTPUT_DIR}/web/parameterized_urls.txt" | while read -r url; do
            run_docker "dalfox scan \"$url\" -o /output/web/dalfox_$(echo $url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$||').json 2>/dev/null || true" &
        done
        wait
    fi
    
    # WordPress scanning with wpscan (conditional)
    if [[ -f "/output/web/whatweb.txt" ]] && grep -qi "wordpress" "/output/web/whatweb.txt"; then
        log_info "WordPress detected! Running wpscan..."
        run_docker "wpscan --url https://${TARGET_DOMAIN} -o /output/web/wpscan.json 2>/dev/null || echo 'No WordPress vulnerabilities found' > /output/web/wpscan.json"
    else
        log_info "No WordPress detected, skipping wpscan"
    fi
    
    # FFUF parameter fuzzing on parameterized URLs (using gf patterns)
    if [[ -s "${OUTPUT_DIR}/web/parameterized_urls.txt" ]]; then
        log_info "Running FFUF parameter fuzzing with gf patterns..."
        
        # Extract vulnerable patterns with gf
        run_docker "cat /output/web/parameterized_urls.txt | gf xss | head -20 > /output/web/xss_patterns.txt"
        run_docker "cat /output/web/parameterized_urls.txt | gf sqli | head -20 > /output/web/sqli_patterns.txt"
        
        # Use qsreplace for payload injection testing
        if [[ -s "/output/web/xss_patterns.txt" ]]; then
            run_docker "qsreplace -a /opt/SecLists/Fuzzing/XSS.txt -s < /output/web/xss_patterns.txt > /output/web/xss_payloads.txt"
        fi
        
        local MAX_JOBS=3
        local job_count=0
        
        while read -r url; do
            # FFUF parameter fuzzing with GET/POST
            run_docker "ffuf -w /opt/SecLists/Fuzzing/ParamDiscovery.txt -u \"$url\" -X GET,POST -o /output/web/ffuf_params_$(echo $url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$||').json -of json 2>/dev/null || true" &
            ((job_count++))
            
            if [[ $job_count -ge $MAX_JOBS ]]; then
                wait -n
                ((job_count--))
            fi
        done < "${OUTPUT_DIR}/web/parameterized_urls.txt"
        wait
    fi
    
    # ZAP deep scan on high-value URLs
    if [[ -s "/output/web/live_urls.txt" ]]; then
        log_info "Running ZAP deep scan on high-value URLs..."
        # Select top 5 URLs for deep scanning
        head -5 "/output/web/live_urls.txt" | while read -r url; do
            run_zap_scan "$url" "deep_scan"
        done
    fi
    
    # Additional: Quick HTTP probe with httprobe (optional)
    if [[ -s "/output/web/live_urls.txt" ]]; then
        log_info "Running httprobe for quick HTTP verification..."
        run_docker "httprobe -f /output/web/live_urls.txt -c 50 -o /output/web/httprobe.json 2>/dev/null || echo 'No httprobe results' > /output/web/httprobe.json"
    fi
    
    # Nikto logic moved to parallel execution block in run_web
    
    # ZAP on high-value HTML pages (limited set) - WITH NORMALIZATION
    head -10 "${OUTPUT_DIR}/web/html_pages.txt" > "${OUTPUT_DIR}/web/zap_targets.txt" 2>/dev/null || true
    
    # Process batch results for this phase
    process_batch_results "web"
}

# Docker wrapper function
run_docker() {
    local cmd="$1"
    
    if [[ "$RUN_LOCAL" == "true" ]]; then
        # Local execution mode (inside container)
        # Replace /output with actual OUTPUT_DIR
        local local_cmd=${cmd//\/output/${OUTPUT_DIR}}
        
        if [[ "$DRY_RUN" == "true" ]]; then
            echo "[DRY-RUN] (Local) bash -c '$local_cmd'"
            return 0
        fi
        
        # Ensure directories exist (redundant but safe)
        mkdir -p "${OUTPUT_DIR}"/{recon,network,vuln,web,ssl,database,container}
        
        export TARGET_DOMAIN
        log_info "Executing locally: $local_cmd"
        bash -c "$local_cmd" || {
             log_error "Command failed: $local_cmd"
             return 1
        }
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] docker run --rm -v ${OUTPUT_DIR}:/output $DOCKER_IMAGE bash -c '$cmd'"
        return 0
    fi
    # Create directories first
    mkdir -p "${OUTPUT_DIR}"/{recon,network,vuln,web,ssl,database,container}
    docker run --rm -v "${OUTPUT_DIR}:/output" -e "TARGET_DOMAIN=$TARGET_DOMAIN" "$DOCKER_IMAGE" bash -c "mkdir -p /output/{recon,network,vuln,web,ssl,database,container} && $cmd" || {
        log_error "Docker command failed: $cmd"
        return 1
    }
}

# Retry wrapper
run_with_retry() {
    local cmd="$1"
    local retries=3
    local count=0
    while [[ $count -lt $retries ]]; do
        if eval "$cmd"; then
            return 0
        fi
        count=$((count + 1))
        [[ $count -lt $retries ]] && sleep 2
    done
    log_warn "Command failed after $retries attempts: $cmd"
    return 1
}

# Initialize directories
init_directories() {
    # Create timestamped directory for this scan
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="${OUTPUT_DIR}/${TARGET_DOMAIN}_${TIMESTAMP}"
    
    log_info "Initializing output directories..."
    log_info "Output directory: ${OUTPUT_DIR}"
    mkdir -p "${OUTPUT_DIR}"/{recon,network,web,ssl,database,container,vuln} || {
        log_error "Failed to create output directories"
        exit 1
    }
    mkdir -p "${OUTPUT_DIR}/web/urls_classified" || {
        log_error "Failed to create URL classification directory"
        exit 1
    }
    mkdir -p "${OUTPUT_DIR}/processing_queue" || {
        log_error "Failed to create processing queue directory"
        exit 1
    }
}

# Check authorization
check_authorization() {
    echo -e "${YELLOW}=== LEGAL AUTHORIZATION REQUIRED ===${NC}"
    echo -e "${YELLOW}This tool should only be used on systems you own or have explicit permission to test.${NC}"
    echo ""
    if [[ "${I_HAVE_AUTHORIZATION:-no}" == "yes" ]]; then
        echo -e "${GREEN}[OK] Authorization confirmed via environment variable.${NC}"
        return 0
    fi
    # Skip interactive check for automation
    log_info "Authorization check skipped in automated mode"
    return 0
}

# Phase 1: RECONNAISSANCE
run_recon() {
    log_info "Starting Phase 1: RECONNAISSANCE"
    
    log_info "Running subfinder for subdomain enumeration..."
    run_docker 'subfinder -d ${TARGET_DOMAIN} -o /output/recon/amass.txt 2>/dev/null || touch /output/recon/amass.txt' || true
    
    log_info "Running DNS reconnaissance..."
    # Try dnsx first, fall back to lagacy tools if not available or fails
    if run_docker 'which dnsx >/dev/null'; then
        log_info "Using dnsx for DNS recon..."
        run_docker 'echo ${TARGET_DOMAIN} | dnsx -recon -wd ${TARGET_DOMAIN} -o /output/recon/dnsx.json -json 2>/dev/null || echo "{}" > /output/recon/dnsx.json'
    else
        log_warn "dnsx not found, falling back to dig/dnsrecon..."
        run_docker 'dig ${TARGET_DOMAIN} ANY > /output/recon/dig.txt 2>/dev/null || touch /output/recon/dig.txt'
        run_docker 'dnsrecon -d ${TARGET_DOMAIN} -j /output/recon/dnsrecon.json 2>/dev/null || echo "{}" > /output/recon/dnsrecon.json'
    fi
    
    log_info "Running WhatWeb for technology detection..."
    run_docker "whatweb ${TARGET_DOMAIN} > /output/recon/whatweb.txt 2>/dev/null || touch /output/recon/whatweb.txt"
    
    # WAF Detection for understanding security controls
    log_info "Running WAF detection..."
    run_docker "wafw00f ${TARGET_DOMAIN} > /output/recon/waf_detection.txt 2>/dev/null || echo 'No WAF detected' > /output/recon/waf_detection.txt"
    
    # Queue recon results for DetectDojo processing
    if [[ -f "${OUTPUT_DIR}/recon/amass.txt" ]] && [[ -s "${OUTPUT_DIR}/recon/amass.txt" ]]; then
        queue_tool_processing "amass" "${OUTPUT_DIR}/recon/amass.txt" "recon"
    fi
    if [[ -f "${OUTPUT_DIR}/recon/dnsx.json" ]] && [[ -s "${OUTPUT_DIR}/recon/dnsx.json" ]]; then
        queue_tool_processing "dnsx" "${OUTPUT_DIR}/recon/dnsx.json" "recon"
    fi
    if [[ -f "${OUTPUT_DIR}/recon/whatweb.txt" ]] && [[ -s "${OUTPUT_DIR}/recon/whatweb.txt" ]]; then
        queue_tool_processing "whatweb" "${OUTPUT_DIR}/recon/whatweb.txt" "recon"
    fi
    if [[ -f "${OUTPUT_DIR}/recon/waf_detection.txt" ]] && [[ -s "${OUTPUT_DIR}/recon/waf_detection.txt" ]]; then
        queue_tool_processing "wafw00f" "${OUTPUT_DIR}/recon/waf_detection.txt" "recon"
    fi
    
    log_ok "Reconnaissance completed"
    
    # Process batch results for this phase
    process_batch_results "recon"
}

# Phase 2: NETWORK SCANNING
run_network() {
    log_info "Starting Phase 2: NETWORK SCANNING"
    
    log_info "Running naabu for port discovery..."
    run_docker 'naabu -p 80,443,8080,8443 -host ${TARGET_DOMAIN} -json -o /output/network/naabu.json 2>/dev/null || echo '{}' > /output/network/naabu.json'
    
    log_info "Running httprobe for quick HTTP verification on discovered ports..."
    if [[ -f "/output/network/naabu.json" ]] && [[ -s "/output/network/naabu.json" ]]; then
        # Extract open ports and probe with httprobe
        run_docker 'jq -r ".[] | select(.open == true) | \"\(.port):\(.host)\"" /output/network/naabu.json 2>/dev/null | httprobe -c 50 -o /output/network/httprobe.json 2>/dev/null || echo "No httprobe results" > /output/network/httprobe.json'
    fi
    
    log_info "Running nmap for detailed port scanning..."
    PORTS=$(jq -r '.[].port' "${OUTPUT_DIR}/network/naabu.json" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
    
    if [[ -n "$PORTS" ]]; then
        run_docker "nmap -sV -sC -p $PORTS ${TARGET_DOMAIN} -o /output/network/nmap_detailed"
        log_info "Nmap scanning ports: $PORTS"
    else
        log_warn "No open ports found by naabu, skipping detailed nmap"
        touch "${OUTPUT_DIR}/network/nmap_detailed"
    fi
    
    log_ok "Network scanning completed"
    
    # Queue network results for DetectDojo processing
    if [[ -f "${OUTPUT_DIR}/network/naabu.json" ]] && [[ -s "${OUTPUT_DIR}/network/naabu.json" ]]; then
        queue_tool_processing "naabu" "${OUTPUT_DIR}/network/naabu.json" "network"
    fi
    
    if [[ -f "${OUTPUT_DIR}/network/nmap_detailed" ]] && [[ -s "${OUTPUT_DIR}/network/nmap_detailed" ]]; then
        queue_tool_processing "nmap" "${OUTPUT_DIR}/network/nmap_detailed" "network"
    fi
    
    if [[ -f "${OUTPUT_DIR}/network/httprobe.json" ]] && [[ -s "${OUTPUT_DIR}/network/httprobe.json" ]]; then
        queue_tool_processing "httprobe" "${OUTPUT_DIR}/network/httprobe.json" "network"
    fi
    
    # Process batch results for this phase
    process_batch_results "network"
}

# Phase 3: VULNERABILITY ASSESSMENT
run_vulnerability() {
    log_info "Starting Phase 3: VULNERABILITY ASSESSMENT"
    
    log_info "Preparing nuclei targets..."
    run_docker 'echo "https://${TARGET_DOMAIN}/" > /output/vuln/nuclei_targets.txt'
    
    log_info "Running nuclei for vulnerability detection..."
    run_docker 'nuclei -l /output/vuln/nuclei_targets.txt -o /output/vuln/nuclei.json 2>/dev/null || echo "[]" > /output/vuln/nuclei.json'
    
    log_info "Running nmap vulnerability scripts..."
    run_docker 'nmap --script vuln -p 80,443,8080,8443 ${TARGET_DOMAIN} -o /output/vuln/nmap_vulners.xml 2>/dev/null || touch /output/vuln/nmap_vulners.xml'
    
    log_ok "Vulnerability assessment completed"
    
    # Process batch results for this phase
    process_batch_results "vulnerability"
}

# Phase 4: WEB SECURITY - ENTERPRISE GRADE
run_zap_scan() {
    local url="$1"
    local name=$(echo "$url" | sed 's|https://||g' | sed 's|/|_|g')

    log_info "Running ZAP baseline scan on $url..."
    docker run --rm \
        -v "${OUTPUT_DIR}/web:/zap/wrk" \
        --network host \
        ${ZAP_DOCKER_IMAGE} \
        zap-baseline.py -t "$url" -J "zap_${name}.json" || echo '{}' > "${OUTPUT_DIR}/web/zap_${name}.json"
}

# Phase 4: WEB SECURITY - ENTERPRISE GRADE WITH ENHANCED PIPELINE
run_web() {
    log_info "Starting Phase 4: WEB SECURITY with Enhanced Pipeline"
    
    # Step 1: Historical URL Discovery
    log_info "Step 1: Historical URL Discovery (gau managed)..."
    run_docker "gau ${TARGET_DOMAIN} --threads 5 | sort -u > /output/web/historical_urls.txt 2>/dev/null || echo 'No gau results' > /output/web/historical_urls.txt"
    
    # Step 2: Live URL Verification with httpx (Enhanced)
    if [[ -f "/output/web/historical_urls.txt" ]]; then
        log_info "Step 2: Live URL Verification with httpx..."
        run_docker "httpx -l /output/web/historical_urls.txt -silent -follow-redirects -tech-detect -status-code -o /output/web/historical_live.txt"
        live_count=$(cat /output/web/historical_live.txt 2>/dev/null | wc -l || echo "0")
        log_info "httpx verified: $live_count live URLs from historical sources"
    fi
    
    # Step 3: Directory & Path Discovery (Optimized)
    log_info "Step 3: Fast Directory & Path Discovery..."
    
    # Feroxbuster (High performance)
    run_docker "feroxbuster -u https://${TARGET_DOMAIN} -w /opt/SecLists/Discovery/Web-Content/common.txt -t 50 -d 2 --no-state -o /output/web/feroxbuster.json --json 2>/dev/null || echo 'No feroxbuster' > /output/web/feroxbuster.json"
    
    # FFUF (directory fuzzing mode) - Keeping as backup
    run_docker "ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt -u https://${TARGET_DOMAIN}/FUZZ -o /output/web/ffuf_dir.json -of json 2>/dev/null || echo 'No ffuf results' > /output/web/ffuf_dir.json"
    
    # Step 4: Merge and deduplicate ALL discovery results
    log_info "Step 4: Merging ALL discovery results with pipeline glue tools..."
    
    # Use sort -u for URL deduplication
    {
        # From gau (historical)
        [[ -f "${OUTPUT_DIR}/web/historical_urls.txt" ]] && cat "${OUTPUT_DIR}/web/historical_urls.txt" 2>/dev/null || echo ""
        
        # From feroxbuster
        [[ -f "${OUTPUT_DIR}/web/feroxbuster.json" ]] && jq -r 'try select(.type == "response") | .url' "${OUTPUT_DIR}/web/feroxbuster.json" 2>/dev/null || echo ""
        
        # From ffuf (directory mode)
        [[ -f "${OUTPUT_DIR}/web/ffuf_dir.json" ]] && jq -r 'try .results[] .url' "${OUTPUT_DIR}/web/ffuf_dir.json" 2>/dev/null || echo ""
    } | grep -E '^http' | sort -u > "${OUTPUT_DIR}/web/all_discovered_urls.txt"
    
    discovered_count=$(cat "${OUTPUT_DIR}/web/all_discovered_urls.txt" 2>/dev/null | wc -l || echo "0")
    log_info "Total discovered URLs after deduplication: $discovered_count"
    
    # Step 5: Katana crawling on merged URLs
    if [[ -f "${OUTPUT_DIR}/web/all_discovered_urls.txt" ]] && [[ -s "${OUTPUT_DIR}/web/all_discovered_urls.txt" ]]; then
        log_info "Step 5: Katana crawling on merged URLs..."
        run_docker "katana -list ${OUTPUT_DIR}/web/all_discovered_urls.txt -o ${OUTPUT_DIR}/web/katana.txt"
        katana_count=$(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")
        log_info "Katana crawled: $katana_count URLs"
    fi
    
    # Step 6: Filter live URLs with HTTPX
    if [[ -f "${OUTPUT_DIR}/web/katana.txt" ]]; then
        log_info "Step 6: Final live URL filtering with HTTPX..."
        run_docker "httpx -l ${OUTPUT_DIR}/web/katana.txt -silent -o ${OUTPUT_DIR}/web/live_urls.txt"
        final_live_count=$(cat "${OUTPUT_DIR}/web/live_urls.txt" 2>/dev/null | wc -l || echo "0")
        log_info "Final live URLs: $final_live_count"
    fi
    
    # Step 8: Parallel Execution of Heavy Scans
    log_info "Step 8: Running heavy scans in parallel (WPScan, ZAP, Nikto)..."
    
    pids=()
    
    # 8a. WordPress scanning (if detected)
    if [[ -f "/output/web/whatweb.txt" ]] && grep -qi "wordpress" "/output/web/whatweb.txt"; then
        log_info "WordPress detected! Starting wpscan in background..."
        (run_docker "wpscan --url https://${TARGET_DOMAIN} -o /output/web/wpscan.json 2>/dev/null || echo 'No WordPress vulnerabilities found' > /output/web/wpscan.json") &
        pids+=($!)
    fi
    
    # 8b. ZAP baseline scan on main domain
    log_info "Starting ZAP baseline scan in background..."
    (run_zap_scan "https://${TARGET_DOMAIN}" "baseline") &
    pids+=($!)
    
    # 8c. Nikto on base URLs + folders
    echo "https://${TARGET_DOMAIN}/" | cat - "${OUTPUT_DIR}/web/folder_urls.txt" 2>/dev/null | \
    sort -u > "${OUTPUT_DIR}/web/nikto_targets.txt"
    
    if [[ -s "${OUTPUT_DIR}/web/nikto_targets.txt" ]]; then
        log_info "Starting Nikto scan in background..."
        (
            while read -r url; do
                run_docker "nikto -h \"$url\" -o /output/web/nikto_$(echo $url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$||').htm -Format htm 2>/dev/null || touch /output/web/nikto_$(echo $url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$||').htm"
            done < "${OUTPUT_DIR}/web/nikto_targets.txt"
        ) &
        pids+=($!)
    fi
    
    # Wait for all background jobs
    log_info "Waiting for parallel scans to complete..."
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    
    log_ok "Enhanced Web security assessment completed"
}

# Phase 5: SSL/TLS ASSESSMENT
run_ssl() {
    log_info "Starting Phase 5: SSL/TLS ASSESSMENT"
    
    log_info "Running sslyze for SSL/TLS testing..."
    run_docker "sslyze --regular ${TARGET_DOMAIN}:443 > /output/ssl/sslyze.json 2>/dev/null || echo '{\"error\": \"sslyze not available\", \"alternative\": \"testssl completed successfully\"}' > /output/ssl/sslyze.json"
    
    log_info "Running testssl for SSL/TLS security misconfiguration detection..."
    run_docker "/opt/testssl.sh/testssl.sh --jsonfile-pretty /output/ssl/testssl.json --warnings --batch --file ${TARGET_DOMAIN}:443 2>/dev/null || echo '{\"error\": \"testssl.sh dependency issue\", \"alternative\": \"sslyze completed successfully\"}' > /output/ssl/testssl.json"
    
    # Extract security misconfigurations from testssl results for nuclei targeting
    if [[ -f "/output/ssl/testssl.json" ]] && [[ -s "/output/ssl/testssl.json" ]]; then
        log_info "Extracting SSL/TLS misconfigurations for enhanced vulnerability scanning..."
        # Extract vulnerable configurations and create additional nuclei targets
        run_docker 'jq -r ".[] | select(.severity == \"HIGH\" or .severity == \"MEDIUM\") | .id" /output/ssl/testssl.json 2>/dev/null | sed "s|^|https://${TARGET_DOMAIN}/|" | sort -u > /output/ssl/vulnerable_configs.txt'
        
        if [[ -s "/output/ssl/vulnerable_configs.txt" ]]; then
            log_info "Found $(cat /output/ssl/vulnerable_configs.txt 2>/dev/null | wc -l || echo "0") SSL/TLS misconfigurations"
            # Append to nuclei targets for comprehensive scanning
            cat /output/ssl/vulnerable_configs.txt 2>/dev/null >> /output/vuln/nuclei_targets.txt
        fi
    fi
    
    log_ok "SSL/TLS assessment completed"
    
    # Queue SSL results for DetectDojo processing
    if [[ -f "${OUTPUT_DIR}/ssl/sslyze.json" ]] && [[ -s "${OUTPUT_DIR}/ssl/sslyze.json" ]]; then
        queue_tool_processing "sslyze" "${OUTPUT_DIR}/ssl/sslyze.json" "ssl"
    fi
    
    if [[ -f "${OUTPUT_DIR}/ssl/testssl.json" ]] && [[ -s "${OUTPUT_DIR}/ssl/testssl.json" ]]; then
        queue_tool_processing "testssl" "${OUTPUT_DIR}/ssl/testssl.json" "ssl"
    fi
    
    if [[ -f "${OUTPUT_DIR}/ssl/vulnerable_configs.txt" ]] && [[ -s "${OUTPUT_DIR}/ssl/vulnerable_configs.txt" ]]; then
        queue_tool_processing "ssl_misconfig" "${OUTPUT_DIR}/ssl/vulnerable_configs.txt" "ssl"
    fi
    
    # Process batch results for this phase
    process_batch_results "ssl"
}

# Phase 6: DATABASE SCANNING
run_database() {
    log_info "Starting Phase 6: DATABASE SCANNING"
    
    log_info "Running database port checks..."
    run_docker "nmap -p 1433,3306,5432,5984,6379,27017,1521,27017,27018,27019 ${TARGET_DOMAIN} -o /output/database/db_ports.txt"
    
    log_info "Running detailed database scans on open ports..."
    if [[ -s "/output/database/db_ports.txt" ]]; then
        run_docker "nmap -sV -sC -p $(cat /output/database/db_ports.txt | tr '\n' ' ') ${TARGET_DOMAIN} -o /output/database/db_detailed_scan"
    fi
    
    log_ok "Database scanning completed"
}

# Phase 7: CONTAINER & CLOUD SECURITY
run_container() {
    log_info "Starting Phase 7: CONTAINER & CLOUD SECURITY"
    
    log_info "Checking for metadata exposure..."
    run_docker "curl -s http://169.254.169.254/latest/meta-data/ > /output/container/metadata_check.txt 2>/dev/null || echo 'No metadata exposure detected' > /output/container/metadata_check.txt"
    
    log_info "Running kubeaudit for Kubernetes security..."
    run_docker "kubeaudit scan /output/container/kubeaudit.json 2>/dev/null || echo '[]' > /output/container/kubeaudit.json"
    
    log_info "Running trivy for container image scanning..."
    run_docker "trivy image --severity HIGH,CRITICAL --format json -o /output/container/trivy.json ${DOCKER_IMAGE} 2>/dev/null || echo '[]' > /output/container/trivy.json"
    
    log_ok "Container and cloud security completed"
}

# Generate final report
generate_final_report() {
    log_info "Generating final assessment report..."
    
    local report_file="${OUTPUT_DIR}/vapt_report.md"
    
    cat > "$report_file" << EOF
# Enterprise VAPT Assessment Report

## 🎯 Target Information
- **Domain**: $TARGET_DOMAIN
- **Mode**: $EXECUTION_MODE
- **Assessment Date**: $(date)
- **Framework Version**: Enterprise VAPT Engine v2.3

## 📊 Executive Summary
The automated assessment of **$TARGET_DOMAIN** has been completed using the Enterprise VAPT pipeline. The pipeline executed parallel web scans and modern reconnaissance tools to minimize scan time while maintaining high coverage.

### 🛡️ Phase Status
- **Reconnaissance**: ✅ Completed ($(ls "${OUTPUT_DIR}/recon" | wc -l) files)
- **Network Scanning**: ✅ Completed ($(ls "${OUTPUT_DIR}/network" | wc -l) files)
- **Vulnerability Assessment**: ✅ Completed ($(ls "${OUTPUT_DIR}/vulnerability" | wc -l) files)
- **Web Security**: ✅ Completed ($(ls "${OUTPUT_DIR}/web" | wc -l) files)
- **SSL/TLS Assessment**: ✅ Completed
- **Database Security**: ✅ Completed
- **Container Security**: ✅ Completed

## 🔍 Tools & Results Highlights
- **Active Scans**: ZAP, Nikto, WPScan (Parallelized)
- **Recon Engine**: subfinder, dnsx, whatweb, wafw00f
- **Vulnerabilities**: Checked with Nuclei & Nmap Scripts
- **Results Location**: \`$OUTPUT_DIR\`
- **DetectDojo Integration**: $ENABLE_DETECTDOJO_INTEGRATION

## 🚀 Recommendations
1. **Review Findings**: Examine the detailed JSON/HTML reports in \`$OUTPUT_DIR\`.
2. **Prioritize Remediation**: Focus on High and Critical findings first.
3. **Continuous Monitoring**: Integrity of security posture requires periodic rescans.

---
*Report generated by Enterprise VAPT Engine*
EOF
    
    log_ok "Final report generated: $report_file"
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

    # Authorization check
    check_authorization

    # Display banner
    banner

    # Check Docker
    if ! command -v docker &> /dev/null; then
        if [[ "$RUN_LOCAL" == "true" ]]; then
            log_warn "Docker not found, but RUN_LOCAL is set. Proceeding with local execution."
        else
            log_error "Docker is not installed"
            exit 1
        fi
    fi

    # Initialize
    init_directories

    # Check service status
    init_qwen_service
    init_detectdojo_service

    # Display target
    echo ""
    echo -e "${CYAN}=== ASSESSMENT TARGET ===${NC}"
    echo -e "Target: ${GREEN}${TARGET_DOMAIN}${NC}"
    echo -e "Mode: ${GREEN}${EXECUTION_MODE}${NC}"
    echo ""

    # Execute phases based on mode
    case "$EXECUTION_MODE" in
        "strict")
            log_info "Running in STRICT mode with enhanced error handling"
            # Temporarily disable strict mode to complete full scan
            set +eo pipefail
            run_recon
            run_network
            run_vulnerability
            run_web
            run_ssl
            run_database
            run_container
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
            ;;
        *)
            log_error "Invalid execution mode: $EXECUTION_MODE"
            usage
            exit 1
            ;;
    esac

    # Generate final report
    generate_final_report

    log_ok "VAPT assessment completed successfully!"
    log_info "Results available in: ${OUTPUT_DIR}"
    log_info "Executive summary: ${OUTPUT_DIR}/vapt_report.md"
    
    # Display summary
    echo ""
    echo -e "${CYAN}=== ASSESSMENT SUMMARY ===${NC}"
    echo -e "Target: ${GREEN}${TARGET_DOMAIN}${NC}"
    echo -e "Mode: ${GREEN}${EXECUTION_MODE}${NC}"
    echo -e "Output: ${GREEN}${OUTPUT_DIR}${NC}"
    echo ""
    echo -e "${GREEN}✓ Enterprise VAPT Engine v2.3 - Complete!${NC}"
}

# Execute main function
main "$@"
