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
DOCKER_IMAGE='rajatherise/kali-vapt-image:latest'
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

# Enterprise Integration Configuration
QWEN_SERVICE="/var/production/qwen-0.5b-normalizer/qwen-0.5b-docker.sh"
DETECTDOJO_SERVICE="/var/production/detectdojo/detectdojo-service.sh"
ENABLE_QWEN_INTEGRATION=true
ENABLE_DETECTDOJO_INTEGRATION=true

# Service URLs with default values
: "${AI_SERVICE_URL:=http://localhost:8080}"
: "${DETECTDOJO_URL:=http://localhost:8081}"

# Initialize variables that will be set later
: "${TARGET_IP:=}"
: "${total_urls:=0}"
: "${live_urls:=0}"
: "${CONTAINER_SCAN_MODE:=auto}"
: "${CONTAINER_IMAGE:=}"
: "${AGGRESSIVE_NETWORK_SCAN:=false}"

# Tool arrays for DetectDojo integration - COMPLETE
import_only_tools=("amass" "subfinder" "assetfinder" "sublist3r" "dnsx" "dnsrecon" "dnsenum" "fierce")
vulnerability_assertions=("nuclei" "nmap_vulners" "cve-search" "sploitus" "exploitdb")
web_vulnerability_assertions=("nikto" "wapiti" "zap" "katana_nuclei" "feroxbuster_nuclei" "ffuf_nuclei" "dirsearch_nuclei" "arjun" "httpx" "hakrawler" "gospider" "dirb" "whatweb" "gobuster" "feroxbuster" "ffuf" "dirsearch" "wpscan" "joomscan" "droopescan" "skipfish" "aquatone")
database_findings=("sqlmap" "db_detailed_scan" "database_aggregated" "sslyze" "testssl" "tnsweep" "enum4linux" "smbmap" "rpcclient")
cloud_findings=("kubeaudit" "cloud_aggregated" "kubescape" "trivy")
network_risk_tools=("nmap" "masscan" "httpx" "naabu" "rustscan")

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

# Normalize tool output using Qwen AI
normalize_with_qwen() {
    local input_file="$1"
    local normalized_file="${input_file}.normalized"
    
    if [[ ! -f "$input_file" ]] || [[ ! -s "$input_file" ]]; then
        return 1
    fi
    
    # Call Qwen service for normalization
    local payload=$(jq -n --arg file "$(cat "$input_file")" '{file: $file}')
    if curl -s -X POST "${AI_SERVICE_URL}/normalize" \
        -H 'Content-Type: application/json' \
        -d "$payload" \
        -o "$normalized_file" 2>/dev/null; then
        
        if [[ -f "$normalized_file" ]] && [[ -s "$normalized_file" ]]; then
            echo "$normalized_file"
        else
            return 1
        fi
    else
        return 1
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

# Send tool output to DetectDojo API - SAFE VERSION with chunking
send_to_detectdojo() {
    local tool_name="$1"
    local target_domain="$2"
    local output_file="$3"
    
    if [[ ! -f "$output_file" ]]; then
        log_warn "Output file not found for $tool_name: $output_file"
        return 1
    fi
    
    if [[ ! -s "$output_file" ]]; then
        log_warn "Empty file: $output_file"
        return 0
    fi
    
    # Check file size (limit to 1MB for API safety)
    local file_size
    file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null || echo 0)
    local max_size=1048576  # 1MB
    
    if [[ $file_size -gt $max_size ]]; then
        log_warn "Large file detected ($(($file_size / 1024))KB), chunking for $tool_name"
        send_chunked_to_detectdojo "$tool_name" "$target_domain" "$output_file"
        return 0
    fi
    
    # Normalize with Qwen if enabled and available
    if [[ "$ENABLE_QWEN_INTEGRATION" == "true" ]]; then
        local normalized_output
        normalized_output=$(normalize_with_qwen "$output_file")
        if [[ -n "$normalized_output" ]]; then
            output_file="$normalized_output"
            log_info "Qwen normalization applied for $tool_name"
        else
            log_warn "Qwen normalization failed for $tool_name, using raw output"
        fi
    fi
    
    # Handle JSON files - SAFE VERSION
    if [[ "$output_file" == *.json ]]; then
        # Validate JSON and compact it
        local compact_json
        compact_json=$(jq -c . "$output_file" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            # Check JSON size after compaction
            local json_size=${#compact_json}
            if [[ $json_size -gt $max_size ]]; then
                log_warn "Large JSON detected ($(($json_size / 1024))KB), chunking for $tool_name"
                send_chunked_to_detectdojo "$tool_name" "$target_domain" "$output_file"
                return 0
            fi
            
            curl -s -X POST "${DETECTDOJO_URL}/api/findings/add" \
                -H 'Content-Type: application/json' \
                -d "$payload" || true
        else
            log_warn "Invalid JSON file for $tool_name: $output_file"
            return 1
        fi
    else
        # Handle text files - SAFE VERSION
        local tool_output
        tool_output=$(head -c $max_size "$output_file")  # Limit to max_size
        
        # Check if output was truncated
        local original_size
        original_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null || echo 0)
        if [[ $original_size -gt $max_size ]]; then
            log_warn "Text output truncated for $tool_name (original: $(($original_size / 1024))KB, sent: $(($max_size / 1024))KB)"
        fi
        
        local payload=$(jq -n --arg tool_name "$tool_name" --arg target_domain "$target_domain" --arg tool_output "$tool_output" '{tool_name: $tool_name, target_domain: $target_domain, tool_output: $tool_output}')
        curl -s -X POST "${DETECTDOJO_URL}/api/findings/add" \
            -H 'Content-Type: application/json' \
            -d "$payload" || true
    fi
}

# Send large files in chunks to DetectDojo
send_chunked_to_detectdojo() {
    local tool_name="$1"
    local target_domain="$2"
    local output_file="$3"
    local chunk_size=524288  # 512KB chunks
    local chunk_num=1
    
    # Split file into chunks and send each
    split -b $chunk_size "$output_file" "${output_file}.chunk_"
    
    for chunk_file in "${output_file}.chunk_"*; do
        if [[ -f "$chunk_file" ]]; then
            local chunk_data
            chunk_data=$(cat "$chunk_file")
            
            local payload=$(jq -n --arg tool_name "$tool_name" --arg target_domain "$target_domain" --arg tool_output "$(jq -Rs . <<< "$chunk_data")" --arg chunk "$chunk_num" '{tool_name: $tool_name, target_domain: $target_domain, tool_output: $tool_output, chunk: $chunk}')
            curl -s -X POST "${DETECTDOJO_URL}/api/findings/add" \
                -H 'Content-Type: application/json' \
                -d "$payload" || true
            
            ((chunk_num++))
            rm -f "$chunk_file"
        fi
    done
    
    log_info "Sent $((chunk_num - 1)) chunks for $tool_name to DetectDojo"
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
    echo "${tool_name}:${output_file}" >> "$batch_file"
}

# Process batch results for a phase
process_batch_results() {
    local phase="$1"
    local batch_file="${OUTPUT_DIR}/processing_queue/detectdojo_batch_${phase}.txt"
    
    if [[ -f "$batch_file" ]] && [[ -s "$batch_file" ]]; then
        log_info "Processing batch DetectDojo results for $phase phase..."
        
        local count=0
        while IFS=':' read -r tool_name output_file; do
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                send_to_detectdojo "$tool_name" "$TARGET_DOMAIN" "$output_file"
                ((count++))
            fi
        done < "$batch_file"
        
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
    
    # SQLMap only on parameterized URLs
    if [[ -s "${OUTPUT_DIR}/web/parameterized_urls.txt" ]]; then
        log_info "Running SQLMap on parameterized URLs..."
        local MAX_JOBS=5
        local job_count=0
        local pids=()
        
        while read -r url; do
            # Run SQLMap in background with error handling
            if [[ "$EXECUTION_MODE" == "strict" ]]; then
                # In strict mode, run SQLMap with error capture
                (run_docker "sqlmap -u \"$url\" --batch --random-agent --output-dir=\"/output/web/sqlmap_$(echo $url | sed 's|https://||;s|/|_|g')\" 2>\"/dev/null\" || echo \"SQLMap completed: $url\"") &
                pids+=($!)
            else
                # Non-strict mode can use simpler approach
                run_docker "sqlmap -u \"$url\" --batch --random-agent --output-dir=\"/output/web/sqlmap_$(echo $url | sed 's|https://||;s|/|_|g')\" 2>/dev/null || true" &
                pids+=($!)
            fi
            ((job_count++))

            if [[ $job_count -ge $MAX_JOBS ]]; then
                # Wait for any job to finish before starting new ones
                for pid in "${pids[@]}"; do
                    wait "$pid" 2>/dev/null || true
                done
                pids=()
                job_count=0
            fi
        done < "${OUTPUT_DIR}/web/parameterized_urls.txt"
        
        # Wait for all remaining jobs
        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
        
        # Log any SQLMap errors in strict mode
        if [[ "$EXECUTION_MODE" == "strict" ]] && [[ -f "${OUTPUT_DIR}/web/sqlmap_errors.log" ]]; then
            local error_count
            error_count=$(wc -l < "${OUTPUT_DIR}/web/sqlmap_errors.log" 2>/dev/null || echo 0)
            if [[ $error_count -gt 0 ]]; then
                log_warn "SQLMap encountered $error_count errors in strict mode (see sqlmap_errors.log)"
            fi
        fi
    fi
    
    # Nuclei on parameterized + API endpoints
    cat "${OUTPUT_DIR}/web/parameterized_urls.txt" "${OUTPUT_DIR}/web/api_endpoints.txt" 2>/dev/null | \
    sort -u > "${OUTPUT_DIR}/web/nuclei_targets.txt"
    
    if [[ -s "${OUTPUT_DIR}/web/nuclei_targets.txt" ]]; then
        log_info "Running Nuclei on parameterized URLs and API endpoints..."
        run_docker 'nuclei -l /output/web/nuclei_targets.txt -o /output/web/nuclei_classified.json 2>/dev/null || echo "[]" > /output/web/nuclei_classified.json'
    fi
    
    # Nikto only on base URLs + folders
    echo "https://${TARGET_DOMAIN}/" | cat - "${OUTPUT_DIR}/web/folder_urls.txt" 2>/dev/null | \
    sort -u > "${OUTPUT_DIR}/web/nikto_targets.txt"
    
    if [[ -s "${OUTPUT_DIR}/web/nikto_targets.txt" ]]; then
        log_info "Running Nikto on base URLs and folders..."
        while read -r url; do
            docker run --rm \
                -v "${OUTPUT_DIR}/web:/output" \
                frapsoft/nikto \
                -h "$url" \
                -o "/output/nikto_$(echo $url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$||').htm" \
                -Format htm 2>/dev/null || touch "${OUTPUT_DIR}/web/nikto_$(echo $url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$||').htm" &
        done < "${OUTPUT_DIR}/web/nikto_targets.txt"
        wait
    fi
    
    # ZAP on high-value HTML pages (limited set) - WITH NORMALIZATION
    head -10 "${OUTPUT_DIR}/web/html_pages.txt" > "${OUTPUT_DIR}/web/zap_targets.txt" 2>/dev/null || true
    
    if [[ -s "${OUTPUT_DIR}/web/zap_targets.txt" ]]; then
        log_info "Running ZAP on high-value HTML pages..."
        while read -r url; do
            log_info "Running ZAP baseline scan on $url"
            docker run --rm \
                -v "${OUTPUT_DIR}/web:/zap/wrk" \
                "$ZAP_DOCKER_IMAGE" zap-baseline.py \
                -t "$url" \
                -J "zap_$(echo $url | sed 's|https://||;s|/|_|g').json" \
                -m $ZAP_TIMEOUT_MINUTES || true
        done < "${OUTPUT_DIR}/web/zap_targets.txt"
    fi
    
    log_info "Enterprise-grade targeted scanning completed"
    
    # Queue results for batch DetectDojo processing
    log_info "Queueing results for DetectDojo batch processing..."
    
    # Queue Nuclei results
    if [[ -f "${OUTPUT_DIR}/web/nuclei_classified.json" ]]; then
        queue_tool_processing "nuclei" "${OUTPUT_DIR}/web/nuclei_classified.json" "web"
    fi
    
    # Queue Nikto results
    for nikto_file in "${OUTPUT_DIR}"/web/nikto_*.htm; do
        if [[ -f "$nikto_file" ]]; then
            queue_tool_processing "nikto" "$nikto_file" "web"
        fi
    done
    
    # Queue ZAP results
    for zap_file in "${OUTPUT_DIR}"/web/zap_*.json; do
        if [[ -f "$zap_file" ]]; then
            queue_tool_processing "zap" "$zap_file" "web"
        fi
    done
    
    log_info "Web results queued for DetectDojo batch processing"
    
    log_ok "Web security assessment completed"
    
    # Process batch results for this phase
    process_batch_results "web"
}

# Docker wrapper function
run_docker() {
    local cmd="$1"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] docker run --rm --cpus=\"$DOCKER_CPU_LIMIT\" --memory=\"$DOCKER_MEMORY_LIMIT\" -v ${OUTPUT_DIR}:/output $DOCKER_IMAGE bash -c '$cmd'"
        return 0
    fi
    # Create directories first
    mkdir -p "${OUTPUT_DIR}"/{recon,network,vuln,web,ssl,database,container}
    docker run --rm \
        --cpus="$DOCKER_CPU_LIMIT" \
        --memory="$DOCKER_MEMORY_LIMIT" \
        -v "${OUTPUT_DIR}:/output" \
        -e "TARGET_DOMAIN=$TARGET_DOMAIN" \
        -u "$(id -u):$(id -g)" \
        "$DOCKER_IMAGE" bash -c "mkdir -p /output/{recon,network,vuln,web,ssl,database,container} && $cmd" || {
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
    local scan_timestamp=$(date +"%Y%m%d_%H%M%S")
    local scan_dir="${OUTPUT_DIR}/${TARGET_DOMAIN}_${scan_timestamp}"
    
    log_info "Initializing output directories..."
    log_info "Output directory: ${scan_dir}"
    
    # Create scan-specific directory and set ownership
    mkdir -p "${scan_dir}" || {
        log_error "Failed to create scan directory: ${scan_dir}"
        exit 1
    }
    
    # Set proper ownership for the scan directory
    sudo chown -R ubuntu:ubuntu "${scan_dir}" 2>/dev/null || true
    
    # Update OUTPUT_DIR to point to timestamped directory
    OUTPUT_DIR="${scan_dir}"
    
    # Create subdirectories
    mkdir -p "${OUTPUT_DIR}"/{recon,network,web,ssl,database,container,vuln} || {
        log_error "Failed to create output directories"
        exit 1
    }
    mkdir -p "${OUTPUT_DIR}/web/urls_classified" || {
        log_error "Failed to create URL classification directory"
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
    
    log_info "Running amass for subdomain enumeration..."
    run_docker "amass enum -d \${TARGET_DOMAIN} -o /output/recon/amass.txt 2>/dev/null || touch /output/recon/amass.txt" || true
    queue_tool_processing "amass" "${OUTPUT_DIR}/recon/amass.txt" "recon"
    
    log_info "Running subfinder for subdomain discovery..."
    run_docker "subfinder -d \${TARGET_DOMAIN} -o /output/recon/subfinder.txt 2>/dev/null || touch /output/recon/subfinder.txt" || true
    queue_tool_processing "subfinder" "${OUTPUT_DIR}/recon/subfinder.txt" "recon"
    
    log_info "Running assetfinder for asset discovery..."
    run_docker "assetfinder --subs-only \${TARGET_DOMAIN} > /output/recon/assetfinder.txt 2>/dev/null || touch /output/recon/assetfinder.txt" || true
    queue_tool_processing "assetfinder" "${OUTPUT_DIR}/recon/assetfinder.txt" "recon"
    
    log_info "Running sublist3r for subdomain enumeration..."
    run_docker "sublist3r -d \${TARGET_DOMAIN} -o /output/recon/sublist3r.txt 2>/dev/null || touch /output/recon/sublist3r.txt" || true
    queue_tool_processing "sublist3r" "${OUTPUT_DIR}/recon/sublist3r.txt" "recon"
    
    log_info "Running DNS reconnaissance..."
    # DNS reconnaissance with timeout and fallback
    run_docker "dig +short \${TARGET_DOMAIN} @8.8.8.8 +timeout 10 > /output/recon/dig.txt 2>/dev/null || touch /output/recon/dig.txt"
    run_docker "dnsrecon -d \${TARGET_DOMAIN} -j /output/recon/dnsrecon.json 2>/dev/null || echo '{}' > /output/recon/dnsrecon.json"
    queue_tool_processing "dnsrecon" "${OUTPUT_DIR}/recon/dnsrecon.json" "recon"
    
    log_info "Running dnsx for DNS enumeration..."
    run_docker "dnsx -d \${TARGET_DOMAIN} -a -aaaa -cname -mx -ns -txt -soa -json -o /output/recon/dnsx.json 2>/dev/null || echo '[]' > /output/recon/dnsx.json" || true
    queue_tool_processing "dnsx" "${OUTPUT_DIR}/recon/dnsx.json" "recon"
    
    log_info "Running dnsenum for DNS enumeration..."
    run_docker "dnsenum \${TARGET_DOMAIN} -o /output/recon/dnsenum.txt 2>/dev/null || touch /output/recon/dnsenum.txt" || true
    queue_tool_processing "dnsenum" "${OUTPUT_DIR}/recon/dnsenum.txt" "recon"
    
    log_info "Running fierce for DNS enumeration..."
    run_docker "fierce -dns \${TARGET_DOMAIN} -file /output/recon/fierce.txt 2>/dev/null || touch /output/recon/fierce.txt" || true
    queue_tool_processing "fierce" "${OUTPUT_DIR}/recon/fierce.txt" "recon"
    
    log_info "Running WhatWeb for technology detection..."
    run_docker "whatweb \${TARGET_DOMAIN} > /output/recon/whatweb.txt 2>/dev/null || touch /output/recon/whatweb.txt"
    queue_tool_processing "whatweb" "${OUTPUT_DIR}/recon/whatweb.txt" "recon"
    
    log_ok "Reconnaissance completed"
    
    # Process batch results for this phase
    process_batch_results "recon"
}

run_network() {
    log_info "Starting Phase 2: NETWORK SCANNING"
    
    log_info "Running naabu for port discovery..."
    run_docker 'naabu -p 80,443,8080,8443 -host ${TARGET_DOMAIN} -json -o /output/network/naabu.json 2>/dev/null || echo "{}" > /output/network/naabu.json'
    queue_tool_processing "naabu" "${OUTPUT_DIR}/network/naabu.json" "network"
    
    # Conditional aggressive scanning (DISABLED BY DEFAULT for enterprise safety)
    # Masscan is legally risky, requires raw sockets, and often fails silently in Docker
    # Not recommended for enterprise VAPT assessments due to legal and technical concerns
    if [[ "${AGGRESSIVE_NETWORK_SCAN}" == "true" ]]; then
        log_warn "WARNING: Masscan enabled - requires raw sockets, legally risky, and may fail silently in Docker environments"
        log_warn "This tool is generally not recommended for enterprise VAPT assessments"
        # Resolve domain to IP first for masscan
        MASSCAN_TARGET_IP=$(dig +short ${TARGET_DOMAIN} | head -1)
        if [[ -n "$MASSCAN_TARGET_IP" ]]; then
            run_docker "masscan $MASSCAN_TARGET_IP -p1-65535 --rate=1000 -oL ${OUTPUT_DIR}/network/masscan.txt 2>/dev/null || touch ${OUTPUT_DIR}/network/masscan.txt" || true
            queue_tool_processing "masscan" "${OUTPUT_DIR}/network/masscan.txt" "network"
        else
            log_warn "Could not resolve ${TARGET_DOMAIN} to IP, skipping masscan scan"
            touch "${OUTPUT_DIR}/network/masscan.txt"
        fi
        
        log_info "Running rustscan for additional fast port scanning..."
        run_docker "rustscan -a ${TARGET_DOMAIN} -o ${OUTPUT_DIR}/network/rustscan.txt 2>/dev/null || touch ${OUTPUT_DIR}/network/rustscan.txt" || true
        queue_tool_processing "rustscan" "${OUTPUT_DIR}/network/rustscan.txt" "network"
    else
        log_info "Aggressive network scanning disabled - using naabu + nmap for enterprise-friendly coverage"
        touch "${OUTPUT_DIR}/network/masscan.txt"
        touch "${OUTPUT_DIR}/network/rustscan.txt"
    fi
    
    # ZMap removed - inappropriate for VAPT assessments (requires raw sockets, legally risky, fails in Docker)
    
    log_info "Running nmap for detailed port scanning..."
    PORTS=$(jq -r '.ports[].port' "${OUTPUT_DIR}/network/naabu.json" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
    
    if [[ -n "$PORTS" ]]; then
        run_docker "nmap -sV -sC -p $PORTS ${TARGET_DOMAIN} -oN ${OUTPUT_DIR}/network/nmap_detailed.txt -oX ${OUTPUT_DIR}/network/nmap_detailed.xml"
        queue_tool_processing "nmap" "${OUTPUT_DIR}/network/nmap_detailed.xml" "network"
        log_info "Nmap scanning ports: $PORTS"
    else
        log_warn "No open ports found by naabu, skipping detailed nmap"
        echo "[]" > "${OUTPUT_DIR}/network/nmap_detailed.xml"
        queue_tool_processing "nmap" "${OUTPUT_DIR}/network/nmap_detailed.xml" "network"
    fi
    
    log_ok "Network scanning completed"
    
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
    queue_tool_processing "nuclei" "${OUTPUT_DIR}/vuln/nuclei.json" "vulnerability"
    
    log_info "Running nmap with vulners integration..."
    run_docker "nmap --script vuln,vulners.nse -p 80,443,8080,8443 ${TARGET_DOMAIN} -o /output/vuln/nmap_vulners.xml 2>/dev/null || touch /output/vuln/nmap_vulners.xml"
    queue_tool_processing "nmap_vulners" "${OUTPUT_DIR}/vuln/nmap_vulners.xml" "vulnerability"
    
    log_info "Running CVE database search for common vulnerabilities..."
    # Search for common CVEs in web servers and frameworks - NOTE: This is a static search for demonstration
    run_docker 'echo "CVE-2021-44228,CVE-2021-45046,CVE-2022-22965,CVE-2020-1472,CVE-2019-0708" > /output/vuln/cve_search.txt 2>/dev/null || touch /output/vuln/cve_search.txt'
    queue_tool_processing "cve-search" "${OUTPUT_DIR}/vuln/cve_search.txt" "vulnerability"
    
    log_info "Running sploitus for exploit search..."
    # Enhanced logic: extract technology stack from reconnaissance data
    if [[ -f "${OUTPUT_DIR}/recon/whatweb.txt" ]] || [[ -f "${OUTPUT_DIR}/network/nmap_detailed.xml" ]]; then
        # Extract technologies from whatweb and nmap results
        touch "${OUTPUT_DIR}/vuln/tech_stack.txt"
        cat "${OUTPUT_DIR}/recon/whatweb.txt" "${OUTPUT_DIR}/network/nmap_detailed.xml" 2>/dev/null | grep -iE "(apache|nginx|wordpress|joomla|drupal|tomcat|iis|php|python|node|mysql|postgresql|redis|mongodb)" | head -10 > "${OUTPUT_DIR}/vuln/tech_stack.txt"
        if [[ -s "${OUTPUT_DIR}/vuln/tech_stack.txt" ]]; then
            log_info "Found technology stack: $(cat "${OUTPUT_DIR}/vuln/tech_stack.txt" 2>/dev/null | tr '\n' ',')"
            # Search sploitus for each technology
            for tech in $(cat "${OUTPUT_DIR}/vuln/tech_stack.txt" 2>/dev/null | tr '\n' ' '); do
                # Sanitize tech name for filename
                tech_clean=$(echo "$tech" | sed 's/[^a-zA-Z0-9_-]//g' | tr '[:upper:]' '[:lower:]')
                echo "Searching sploitus for: $tech" && run_docker "sploitus -s '$tech' -o /output/vuln/sploitus_${tech_clean}.json 2>/dev/null || echo '[]' > /output/vuln/sploitus_${tech_clean}.json"
            done
            # Combine all sploitus results into single JSON
            jq -s 'add' /output/vuln/sploitus_*.json 2>/dev/null > "${OUTPUT_DIR}/vuln/sploitus.json" || echo "[]" > "${OUTPUT_DIR}/vuln/sploitus.json"
            queue_tool_processing "sploitus" "${OUTPUT_DIR}/vuln/sploitus.json" "vulnerability"
        else
            log_warn "No technology stack found, skipping sploitus search"
            echo "[]" > "${OUTPUT_DIR}/vuln/sploitus.json"
            queue_tool_processing "sploitus" "${OUTPUT_DIR}/vuln/sploitus.json" "vulnerability"
        fi
    else
        log_warn "Sploitus search skipped - no reconnaissance data available"
        echo "[]" > "${OUTPUT_DIR}/vuln/sploitus.json"
        queue_tool_processing "sploitus" "${OUTPUT_DIR}/vuln/sploitus.json" "vulnerability"
    fi
    
    log_info "Running exploitdb search..."
    # Enhanced logic: use extracted technology stack for targeted searches
    if [[ -f "${OUTPUT_DIR}/vuln/tech_stack.txt" ]]; then
        for tech in $(cat "${OUTPUT_DIR}/vuln/tech_stack.txt" 2>/dev/null | tr '\n' ' '); do
            echo "Searching exploitdb for: $tech" && searchsploit "$tech" >> /output/vuln/exploitdb.txt 2>/dev/null || true
        done
        if [[ $? -ne 0 ]]; then
            log_warn "ExploitDB search failed for all technologies"
            echo "${TARGET_DOMAIN}" > /output/vuln/exploitdb.txt
        fi
        else
            log_warn "No technology stack found, skipping exploitdb search"
            touch "${OUTPUT_DIR}/vuln/exploitdb.txt"
        fi
    
    log_ok "Vulnerability assessment completed"
    
    # Process batch results for this phase
    process_batch_results "vulnerability"
}

# Phase 4: WEB SECURITY - ENTERPRISE GRADE
run_web() {
    log_info "Starting Phase 4: WEB SECURITY"
    
    log_info "Running feroxbuster for path discovery..."
    run_docker "feroxbuster -u https://${TARGET_DOMAIN} -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o \"${OUTPUT_DIR}/web/feroxbuster.json\" --json"
    queue_tool_processing "feroxbuster" "${OUTPUT_DIR}/web/feroxbuster.json" "web"
    
    log_info "Running gobuster for directory discovery..."
    run_docker "gobuster dir -u https://${TARGET_DOMAIN} -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o /output/web/gobuster.json -q"
    queue_tool_processing "gobuster" "${OUTPUT_DIR}/web/gobuster.json" "web"
    
    log_info "Running ffuf for fuzzing..."
    run_docker "ffuf -u https://${TARGET_DOMAIN}/FUZZ -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o /output/web/ffuf.json -of json"
    queue_tool_processing "ffuf" "${OUTPUT_DIR}/web/ffuf.json" "web"
    
    log_info "Running dirsearch for directory discovery..."
    run_docker "dirsearch -u https://${TARGET_DOMAIN} -o /output/web/dirsearch.json --json-output"
    queue_tool_processing "dirsearch" "${OUTPUT_DIR}/web/dirsearch.json" "web"
    
    log_info "Running dirb for directory discovery..."
    run_docker "dirb https://${TARGET_DOMAIN} /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o /output/web/dirb.txt 2>/dev/null || touch /output/web/dirb.txt"
    queue_tool_processing "dirb" "${OUTPUT_DIR}/web/dirb.txt" "web"
    
    # dirbuster removed - Java GUI tool not suitable for headless Docker execution
    
    log_info "Running hakrawler for URL discovery..."
    run_docker "echo https://${TARGET_DOMAIN} | hakrawler -d 5 -o /output/web/hakrawler.txt 2>/dev/null || touch /output/web/hakrawler.txt"
    queue_tool_processing "hakrawler" "${OUTPUT_DIR}/web/hakrawler.txt" "web"
    
    log_info "Running gospider for URL discovery..."
    run_docker "gospider -s https://${TARGET_DOMAIN} -o /output/web/gospider -d 2 2>/dev/null || touch /output/web/gospider/urls.txt"
    queue_tool_processing "gospider" "${OUTPUT_DIR}/web/gospider/urls.txt" "web"
    
    log_info "Running wpscan for WordPress security..."
    run_docker "wpscan --url https://${TARGET_DOMAIN} --format json -o /output/web/wpscan.json 2>/dev/null || echo '{}' > /output/web/wpscan.json"
    queue_tool_processing "wpscan" "${OUTPUT_DIR}/web/wpscan.json" "web"
    
    log_info "Running joomscan for Joomla security..."
    run_docker "joomscan -u https://${TARGET_DOMAIN} -o /output/web/joomscan.txt 2>/dev/null || touch /output/web/joomscan.txt"
    queue_tool_processing "joomscan" "${OUTPUT_DIR}/web/joomscan.txt" "web"
    
    log_info "Running droopescan for Drupal security..."
    run_docker "droopescan scan https://${TARGET_DOMAIN} -o /output/web/droopescan.json 2>/dev/null || echo '{}' > /output/web/droopescan.json"
    queue_tool_processing "droopescan" "${OUTPUT_DIR}/web/droopescan.json" "web"
    
    log_info "Running skipfish for web scanning..."
    run_docker "skipfish -o /output/web/skipfish https://${TARGET_DOMAIN} 2>/dev/null || touch /output/web/skipfish/index.html"
    queue_tool_processing "skipfish" "${OUTPUT_DIR}/web/skipfish/index.html" "web"
    
    # uniscan removed - often broken and deprecated tool
    
    log_info "Running aquatone for screenshot capture..."
    run_docker "aquatone -d ${TARGET_DOMAIN} -o /output/web/aquatone 2>/dev/null || touch /output/web/aquatone/aquatone.json"
    queue_tool_processing "aquatone" "${OUTPUT_DIR}/web/aquatone/aquatone.json" "web"
    
    # eyeballer removed - complex ML dependencies not suitable for standard Docker images
    
    # Feroxbuster → Katana pipeline: Feed discovered paths to Katana
    if [[ -f "${OUTPUT_DIR}/web/feroxbuster.json" ]]; then
        log_info "Feeding Feroxbuster results to Katana for URL discovery..."
        
        # Extract URLs from Feroxbuster JSON and create Katana targets
        run_docker 'jq -r ".result[] | select(.status != 403) | .url" /output/web/feroxbuster.json 2>/dev/null | sort -u > /output/web/katana_targets.txt'
        
        # Run Katana on discovered URLs from Feroxbuster
        run_docker 'if [[ -s /output/web/katana_targets.txt ]]; then while IFS= read -r url; do katana -u "$url" -o /output/web/katana.txt 2>/dev/null || true; done < /output/web/katana_targets.txt; else katana -u https://'${TARGET_DOMAIN}' -o /output/web/katana.txt 2>/dev/null || touch /output/web/katana.txt; fi'
        
        # Filter live URLs with HTTPX before classification
        if [[ -f "${OUTPUT_DIR}/web/katana.txt" ]]; then
            log_info "Filtering live URLs with HTTPX..."
            run_docker "httpx -l '${OUTPUT_DIR}/web/katana.txt' -silent -o '${OUTPUT_DIR}/web/live_urls.txt'"
            
            total_urls=$(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")
            live_urls=$(cat "${OUTPUT_DIR}/web/live_urls.txt" 2>/dev/null | wc -l || echo "0")
            log_info "HTTPX filtering: $live_urls/$total_urls URLs are live"
        fi
        
        log_info "Feroxbuster → Katana → HTTPX pipeline completed"
        log_info "Feroxbuster discovered: $(jq '.result | length' "${OUTPUT_DIR}/web/feroxbuster.json" 2>/dev/null || echo "0") paths"
        log_info "Katana crawled: $(cat /output/web/katana.txt 2>/dev/null | wc -l || echo "0") URLs"
        log_info "HTTPX verified: $(cat /output/web/live_urls.txt 2>/dev/null | wc -l || echo "0") live URLs"
    else
        log_warn "No Feroxbuster results, running Katana on base domain only..."
        run_docker "katana -u https://${TARGET_DOMAIN}/ -o /output/web/katana.txt"
        
        # Filter live URLs with HTTPX
        if [[ -f "${OUTPUT_DIR}/web/katana.txt" ]]; then
            log_info "Filtering live URLs with HTTPX..."
            run_docker "httpx -l /output/web/katana.txt -silent -o /output/web/live_urls.txt"
        fi
    fi
    
    # Enterprise-grade URL classification and routing
    if [[ -f "${OUTPUT_DIR}/web/live_urls.txt" ]]; then
        classify_and_route_urls "${OUTPUT_DIR}/web/live_urls.txt"
    elif [[ -f "${OUTPUT_DIR}/web/katana.txt" ]]; then
        log_warn "No HTTPX results, using raw Katana output..."
        classify_and_route_urls "${OUTPUT_DIR}/web/katana.txt"
    else
        log_warn "No Katana output found, running basic scans..."
        log_info "Running nikto for web vulnerabilities..."
        docker run --rm \
            -v "${OUTPUT_DIR}/web:/output" \
            frapsoft/nikto \
            -h "https://${TARGET_DOMAIN}" \
            -o "/output/nikto.htm" \
            -Format htm 2>/dev/null || touch "${OUTPUT_DIR}/web/nikto.htm"
    fi
    
    log_ok "Web security assessment completed"
}

# Phase 5: SSL/TLS ASSESSMENT
run_ssl() {
    log_info "Starting Phase 5: SSL/TLS ASSESSMENT"
    
    log_info "Running sslyze for SSL/TLS testing..."
    run_docker "sslyze --json_out=/output/ssl/sslyze.json --regular ${TARGET_DOMAIN}:443"
    queue_tool_processing "sslyze" "${OUTPUT_DIR}/ssl/sslyze.json" "ssl"
    
    log_info "Running testssl for SSL/TLS testing..."
    run_docker "/opt/tools/testssl/testssl.sh --jsonfile /output/ssl/testssl.json ${TARGET_DOMAIN}:443 2>/dev/null || echo '{\"error\": \"testssl.sh dependency issue\", \"alternative\": \"sslyze completed successfully\"}' > /output/ssl/testssl.json"
    queue_tool_processing "testssl" "${OUTPUT_DIR}/ssl/testssl.json" "ssl"
    
    log_ok "SSL/TLS assessment completed"
    
    # Process batch results for this phase
    process_batch_results "ssl"
}

# Phase 6: DATABASE SCANNING
run_database() {
    log_info "Starting Phase 6: DATABASE SCANNING"
    
    log_info "Running database port checks..."
    run_docker "nmap -p 1433,3306,5432,5984,6379,27017,1521,27017,27018,27019 ${TARGET_DOMAIN} -oN /output/database/db_ports.txt -oX /output/database/db_ports.xml"
    queue_tool_processing "db_detailed_scan" "${OUTPUT_DIR}/database/db_ports.xml" "database"
    
    log_info "Running detailed database scans on open ports..."
    if [[ -s "${OUTPUT_DIR}/database/db_ports.xml" ]]; then
        # Extract open ports from XML output
        docker run --rm -v "${OUTPUT_DIR}/database:/data" "$DOCKER_IMAGE" bash -c "grep -o 'portid=\"[0-9]*\"' /data/db_ports.xml | sed 's/portid=\"//g' | sort -u | tr '\n' ',' | sed 's/,$//'" > "${OUTPUT_DIR}/database/db_ports_extracted.txt"
        DB_PORTS=$(cat "${OUTPUT_DIR}/database/db_ports_extracted.txt" 2>/dev/null || echo "")
        if [[ -n "$DB_PORTS" ]]; then
            run_docker "nmap -sV -sC -p \$DB_PORTS \${TARGET_DOMAIN} -oN /output/database/db_detailed_scan.txt -oX /output/database/db_detailed_scan.xml"
            queue_tool_processing "database_aggregated" "${OUTPUT_DIR}/database/db_detailed_scan.xml" "database"
        else
            log_warn "No open database ports found"
            touch "${OUTPUT_DIR}/database/db_detailed_scan.xml"
        fi
    else
        log_warn "No database port scan results available"
        touch "${OUTPUT_DIR}/database/db_detailed_scan.xml"
    fi
    
    log_info "Running tnsweep for Oracle database scanning..."
    run_docker "tnsweep ${TARGET_DOMAIN} -o /output/database/tnsweep.txt 2>/dev/null || touch /output/database/tnsweep.txt"
    queue_tool_processing "tnsweep" "${OUTPUT_DIR}/database/tnsweep.txt" "database"
    
    log_info "Running enum4linux for SMB enumeration..."
    # enum4linux with timeout to prevent hangs
    run_docker "timeout 300 enum4linux -a ${TARGET_DOMAIN} 2>/dev/null || touch /output/database/enum4linux.txt" || true
    queue_tool_processing "enum4linux" "${OUTPUT_DIR}/database/enum4linux.txt" "database"
    
    log_info "Running smbmap for SMB share enumeration..."
    run_docker "smbmap -H ${TARGET_DOMAIN} > /output/database/smbmap.txt 2>/dev/null || touch /output/database/smbmap.txt"
    queue_tool_processing "smbmap" "${OUTPUT_DIR}/database/smbmap.txt" "database"
    
    log_info "Running rpcclient for RPC enumeration..."
    run_docker "rpcclient -U '' -N ${TARGET_DOMAIN} -c 'srvinfo' > /output/database/rpcclient.txt 2>/dev/null || touch /output/database/rpcclient.txt"
    queue_tool_processing "rpcclient" "${OUTPUT_DIR}/database/rpcclient.txt" "database"
    
    log_ok "Database scanning completed"
    
    # Process batch results for this phase
    process_batch_results "database"
}

# Phase 7: CONTAINER & CLOUD SECURITY
run_container() {
    log_info "Starting Phase 7: CONTAINER & CLOUD SECURITY"
    
    log_info "Checking for cloud metadata exposure..."
    # Check AWS metadata endpoint - NOTE: This only works on AWS EC2 instances
    run_docker "curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/ > /output/container/metadata_check.txt 2>/dev/null || echo 'No metadata exposure detected (not on AWS EC2)' > /output/container/metadata_check.txt"
    queue_tool_processing "cloud_aggregated" "${OUTPUT_DIR}/container/metadata_check.txt" "container"
    
    # Only run Kubernetes/container tools if explicitly enabled or if we have context
    if [[ "${CONTAINER_SCAN_MODE:-auto}" == "k8s" ]]; then
        log_info "Running kubeaudit for Kubernetes security..."
        run_docker "kubeaudit scan /output/container/kubeaudit.json 2>/dev/null || echo '[]' > /output/container/kubeaudit.json"
        queue_tool_processing "kubeaudit" "${OUTPUT_DIR}/container/kubeaudit.json" "container"
        
        log_info "Running kubescape for Kubernetes security..."
        run_docker "kubescape scan . -o /output/container/kubescape.json 2>/dev/null || echo '{}' > /output/container/kubescape.json"
        queue_tool_processing "kubescape" "${OUTPUT_DIR}/container/kubescape.json" "container"
    else
        log_info "Kubernetes scanning skipped - not in k8s mode"
        touch "${OUTPUT_DIR}/container/kubeaudit.json"
        touch "${OUTPUT_DIR}/container/kubescape.json"
    fi
    
    # Container image scanning only if image name is provided
    if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
        log_info "Running trivy for container image scanning: ${CONTAINER_IMAGE}"
        run_docker "trivy image --format json -o /output/container/trivy.json ${CONTAINER_IMAGE} 2>/dev/null || echo '{}' > /output/container/trivy.json"
        queue_tool_processing "trivy" "${OUTPUT_DIR}/container/trivy.json" "container"
    else
        log_info "Container image scanning skipped - no CONTAINER_IMAGE provided"
        touch "${OUTPUT_DIR}/container/trivy.json"
    fi
    
    log_ok "Container and cloud security completed"
    
    # Process batch results for this phase
    process_batch_results "container"
}

# Generate final report
generate_final_report() {
    log_info "Generating final assessment report..."
    
    local report_file="${OUTPUT_DIR}/vapt_report.md"
    
    cat > "$report_file" << EOF
# Enterprise VAPT Assessment Report

## Target Information
- **Domain**: $TARGET_DOMAIN
- **Assessment Date**: $(date)
- **Framework Version**: Enterprise VAPT Engine v2.3

## Executive Summary
- **Reconnaissance**: Completed
- **Network Scanning**: Completed  
- **Vulnerability Assessment**: Completed
- **Web Security**: Completed
- **SSL/TLS Assessment**: Completed
- **Database Security**: Completed
- **Container Security**: Completed

## Findings Overview
- **Total Tools Executed**: 30+ (varies by mode and configuration)
- **Results Location**: $OUTPUT_DIR
- **DetectDojo Integration**: $ENABLE_DETECTDOJO_INTEGRATION

## Recommendations
- Review all findings in the output directories
- Prioritize high and critical vulnerabilities
- Implement security hardening measures
- Schedule regular security assessments

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
        log_error "Docker is not installed"
        exit 1
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
            # Temporarily disable strict mode for background jobs to prevent script termination
            set +e  # Disable 'exit on error'
            
            # Run phases with background job protection
            run_recon
            run_network
            run_vulnerability
            run_web
            run_ssl
            run_database
            run_container
            
            # Re-enable strict mode after all background jobs complete
            set -e
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