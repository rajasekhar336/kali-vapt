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
        if ! curl -s "${DETECTDOJO_URL:-http://localhost:8081}" >/dev/null 2>&1; then
            log_warn "DetectDojo service not running - correlation disabled"
            ENABLE_DETECTDOJO_INTEGRATION=false
        else
            log_info "DetectDojo service is running and ready"
        fi
    fi
}

# Simple rule-based normalization for basic tools
normalize_basic_tool() {
    local tool_name="$1"
    local output_file="$2"
    
    case "$tool_name" in
        "amass")
            # Amass already outputs JSON, just validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "whatweb")
            # WhatWeb already outputs JSON, just validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "assetfinder"|"subfinder")
            # Normalize subdomain lists to JSON
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                jq -R -s 'split("\n") | map(select(length > 0)) | map({domain: .})' "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "naabu")
            # Naabu now outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "httpx")
            # HTTPX now outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "masscan")
            # Masscan now outputs XML, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '<nmaprun></nmaprun>'
            else
                echo '<nmaprun></nmaprun>'
            fi
            ;;
        "whois")
            # Normalize whois to structured JSON
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                jq -n --arg whois "$(cat "$output_file")' '{"whois_data": $whois}' 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "nuclei")
            # Nuclei now outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "nmap_vulners")
            # Nmap vulners outputs XML, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '<nmaprun></nmaprun>'
            else
                echo '<nmaprun></nmaprun>'
            fi
            ;;
        "nikto")
            # Nikto now outputs XML, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '<niktoscan></niktoscan>'
            else
                echo '<niktoscan></niktoscan>'
            fi
            ;;
        "gobuster")
            # Gobuster now outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "ffuf")
            # FFUF now outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "dirsearch")
            # Dirsearch now outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "wapiti")
            # Wapiti now outputs XML, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '<wapiti></wapiti>'
            else
                echo '<wapiti></wapiti>'
            fi
            ;;
        "zap")
            # ZAP outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "sqlmap")
            # SQLMap now outputs XML (log.xml), validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '<sqlmap></sqlmap>'
            else
                echo '<sqlmap></sqlmap>'
            fi
            ;;
        "kubeaudit")
            # Kubeaudit now outputs JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        "sslyze"|"testssl")
            # SSL tools output JSON, validate and pass through
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                cat "$output_file" 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
        *)
            # Default: just wrap raw output
            if [[ -f "$output_file" ]] && [[ -s "$output_file" ]]; then
                jq -n --arg raw "$(cat "$output_file")' '{"raw_output": $raw}' 2>/dev/null || echo '{"findings": []}'
            else
                echo '{"findings": []}'
            fi
            ;;
    esac
}

# Process tool output with AI and DetectDojo
process_tool_output() {
    local tool_name="$1"
    local output_file="$2"
    
    if [[ ! -f "$output_file" ]] || [[ ! -s "$output_file" ]]; then
        return 0
    fi
    
    # Skip processing for input-only tools (subdomains/URLs are inputs, not findings)
    local input_only_tools=("assetfinder" "subfinder" "whois" "waybackurls" "gau")
    
    if [[ " ${input_only_tools[@]} " =~ " ${tool_name} " ]]; then
        log_info "Skipping $tool_name - treated as input data, not findings"
        return 0
    fi
    
    # Skip processing for port scanners that feed to nmap (treated as inputs)
    local port_scanner_inputs=("naabu" "rustscan")
    
    if [[ " ${port_scanner_inputs[@]} " =~ " ${tool_name} " ]]; then
        log_info "Skipping $tool_name - port scanner results fed to nmap pipeline"
        return 0
    fi
    
    # Import directly to DetectDojo (network risk tools - no AI processing)
    local network_risk_tools=("nmap" "masscan" "httpx")
    
    # Check if this is a nmap/masscan/httpx tool (including dynamic names)
    if [[ "$tool_name" =~ ^nmap_ ]] || [[ "$tool_name" =~ ^masscan_ ]] || [[ "$tool_name" =~ ^httpx ]] || [[ " ${network_risk_tools[@]} " =~ " ${tool_name} " ]]; then
        if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
            log_info "Importing $tool_name network data directly to DetectDojo (network risk)..."
            local normalized_output
            normalized_output=$(normalize_basic_tool "$tool_name" "$output_file")
            
            echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        fi
        return 0
    fi
    
    # Import directly to DetectDojo (no AI processing)
    local import_only_tools=("amass")
    
    if [[ " ${import_only_tools[@]} " =~ " ${tool_name} " ]] && [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
        log_info "Importing $tool_name data directly to DetectDojo (no AI processing)..."
        local normalized_output
        normalized_output=$(normalize_basic_tool "$tool_name" "$output_file")
        
        echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        return 0
    fi
    
    # Import vulnerability assertions directly to DetectDojo (no AI processing)
    local vulnerability_assertions=("nuclei" "nmap_vulners")
    
    # Check if this is a vulnerability assertion tool (including dynamic names)
    if [[ " ${vulnerability_assertions[@]} " =~ " ${tool_name} " ]] || [[ "$tool_name" =~ ^nmap_.*_vulners$ ]]; then
        if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
            log_info "Importing $tool_name vulnerability assertions directly to DetectDojo..."
            local normalized_output
            normalized_output=$(normalize_basic_tool "$tool_name" "$output_file")
            
            echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        fi
        return 0
    fi
    
    # Skip processing for web discovery tools that feed to nuclei (paths are inputs, not findings)
    local web_discovery_inputs=("katana" "gobuster" "ffuf" "dirsearch")
    
    if [[ " ${web_discovery_inputs[@]} " =~ " ${tool_name} " ]]; then
        log_info "Skipping $tool_name - web discovery paths fed to nuclei for validation"
        return 0
    fi
    
    # Import web vulnerability assertions directly to DetectDojo (no AI processing)
    local web_vulnerability_assertions=("nikto" "wapiti" "zap")
    
    # Check if this is a web vulnerability assertion tool (including dynamic names)
    if [[ " ${web_vulnerability_assertions[@]} " =~ " ${tool_name} " ]] || [[ "$tool_name" =~ ^katana_nuclei$ ]] || [[ "$tool_name" =~ ^gobuster_nuclei$ ]] || [[ "$tool_name" =~ ^ffuf_nuclei$ ]] || [[ "$tool_name" =~ ^dirsearch_nuclei$ ]]; then
        if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
            log_info "Importing $tool_name web vulnerability assertions directly to DetectDojo..."
            local normalized_output
            normalized_output=$(normalize_basic_tool "$tool_name" "$output_file")
            
            echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        fi
        return 0
    fi
    
    # Skip processing for database connectivity tests (aggregated separately)
    local database_connectivity_tests=("redis_test" "postgres_test" "mysql_test")
    
    if [[ " ${database_connectivity_tests[@]} " =~ " ${tool_name} " ]]; then
        log_info "Skipping $tool_name - database connectivity test aggregated separately"
        return 0
    fi
    
    # Import database findings directly to DetectDojo (no AI processing)
    local database_findings=("sqlmap" "db_detailed_scan" "database_aggregated")
    
    # Check if this is a database finding tool
    if [[ " ${database_findings[@]} " =~ " ${tool_name} " ]]; then
        if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
            log_info "Importing $tool_name database findings directly to DetectDojo..."
            local normalized_output
            normalized_output=$(normalize_basic_tool "$tool_name" "$output_file")
            
            echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        fi
        return 0
    fi
    # Skip processing for cloud/container exposure tests (aggregated separately)
    local cloud_exposure_tests=("metadata_check" "docker_registry" "k8s_api")
    
    if [[ " ${cloud_exposure_tests[@]} " =~ " ${tool_name} " ]]; then
        log_info "Skipping $tool_name - cloud/container exposure test aggregated separately"
        return 0
    fi
    
    # Import cloud/container findings directly to DetectDojo (no AI processing)
    local cloud_findings=("kubeaudit" "cloud_aggregated")
    
    # Check if this is a cloud/container finding tool
    if [[ " ${cloud_findings[@]} " =~ " ${tool_name} " ]]; then
        if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
            log_info "Importing $tool_name cloud/container findings directly to DetectDojo..."
            local normalized_output
            normalized_output=$(normalize_basic_tool "$tool_name" "$output_file")
            
            echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        fi
        return 0
    fi
    local ai_tools=()
    
    # Check if tool needs AI processing
    if [[ " ${ai_tools[@]} " =~ " ${tool_name} " ]] && [[ "$ENABLE_QWEN_INTEGRATION" == "true" ]]; then
        log_info "Processing $tool_name output with AI for severity and remediation..."
        
        # Send to Qwen for normalization and remediation
        local normalized_output
        normalized_output=$(curl -s -X POST "http://localhost:8080/normalize" \
            -H "Content-Type: application/json" \
            -d "{
                \"tool_name\": \"$tool_name\",
                \"tool_output\": \"$(cat "$output_file" | head -c 1000)\",
                \"target_domain\": \"$TARGET_DOMAIN\"
            }" 2>/dev/null || echo "")
        
        if [[ -n "$normalized_output" ]] && [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
            # Send AI-processed output to DetectDojo
            log_info "Sending AI-processed $tool_name findings to DetectDojo..."
            echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        fi
    else
        # Normalize with basic rules then send to DetectDojo
        if [[ "$ENABLE_DETECTDOJO_INTEGRATION" == "true" ]]; then
            log_info "Normalizing $tool_name output with basic rules..."
            local normalized_output
            normalized_output=$(normalize_basic_tool "$tool_name" "$output_file")
            
            log_info "Sending normalized $tool_name findings to DetectDojo..."
            echo "$normalized_output" | "$DETECTDOJO_SERVICE" send "$tool_name" "$TARGET_DOMAIN" >/dev/null 2>&1 || true
        fi
    fi
}

# Feed large network outputs back into scanning pipeline
feed_network_inputs_to_pipeline() {
    log_info "Checking for large network outputs to feed back into scanning pipeline..."
    
    # Check naabu output (many open ports)
    if [[ -f "${OUTPUT_DIR}/network/naabu.json" ]]; then
        local port_count
        port_count=$(run_docker "jq '. | length' network/naabu.json 2>/dev/null || echo '0'" 2>/dev/null || echo "0")
        if [[ "$port_count" -gt 50 ]]; then
            log_info "Feeding $port_count open ports from naabu to nmap for detailed scanning..."
            
            # Extract unique hosts from naabu JSON and feed to nmap
            run_docker "jq -r '.[].host' network/naabu.json 2>/dev/null | sort -u > network/naabu_hosts.txt 2>/dev/null || true" 2>/dev/null || true
            
            if [[ -f "${OUTPUT_DIR}/network/naabu_hosts.txt" ]]; then
                while read -r host; do
                    if [[ -n "$host" ]]; then
                        run_docker "jq -r \"select(.host == \\\"$host\\\") | .port\" network/naabu.json 2>/dev/null | tr '\n' ',' | sed 's/,$//' > network/naabu_ports_${host//./_}.txt 2>/dev/null || true" 2>/dev/null || true
                        if [[ -f "${OUTPUT_DIR}/network/naabu_ports_${host//./_}.txt" ]] && [[ -s "${OUTPUT_DIR}/network/naabu_ports_${host//./_}.txt" ]]; then
                            run_docker "nmap -sV -sC -oA network/naabu_nmap_${host//./_} -p \$(cat network/naabu_ports_${host//./_}.txt) $host || true" 2>/dev/null || true
                        fi
                    fi
                done < "${OUTPUT_DIR}/network/naabu_hosts.txt"
                
                # Queue the new nmap results
                for xml_file in "${OUTPUT_DIR}"/network/naabu_nmap_*.xml; do
                    if [[ -f "$xml_file" ]]; then
                        local host=$(basename "$xml_file" .xml | sed 's/naabu_nmap_//g' | sed 's/_/./g')
                        queue_tool_processing "naabu_nmap_$host" "$xml_file"
                    fi
                done
            fi
        fi
    fi
    
    # Check rustscan output (many open ports)
    if [[ -f "${OUTPUT_DIR}/network/rustscan.xml" ]]; then
        # Count open ports from rustscan XML
        local port_count
        port_count=$(run_docker "xq '.nmaprun.host.ports.port | length' network/rustscan.xml 2>/dev/null || echo '0'" 2>/dev/null || echo "0")
        if [[ "$port_count" -gt 50 ]]; then
            log_info "Feeding $port_count open ports from rustscan to nmap for detailed scanning..."
            
            # Extract hosts from rustscan XML and feed to nmap
            run_docker "xq -r '.nmaprun.host.address.\"@addr\"' network/rustscan.xml 2>/dev/null | sort -u > network/rustscan_hosts.txt 2>/dev/null || true" 2>/dev/null || true
            
            if [[ -f "${OUTPUT_DIR}/network/rustscan_hosts.txt" ]]; then
                while read -r host; do
                    if [[ -n "$host" ]]; then
                        run_docker "xq -r '.nmaprun.host.ports.port[].\"@portid\"' network/rustscan.xml 2>/dev/null | tr '\n' ',' | sed 's/,$//' > network/rustscan_ports_${host//./_}.txt 2>/dev/null || true" 2>/dev/null || true
                        if [[ -f "${OUTPUT_DIR}/network/rustscan_ports_${host//./_}.txt" ]] && [[ -s "${OUTPUT_DIR}/network/rustscan_ports_${host//./_}.txt" ]]; then
                            run_docker "nmap -sV -sC -oA network/rustscan_nmap_${host//./_} -p \$(cat network/rustscan_ports_${host//./_}.txt) $host || true" 2>/dev/null || true
                        fi
                    fi
                done < "${OUTPUT_DIR}/network/rustscan_hosts.txt"
                
                # Queue the new nmap results
                for xml_file in "${OUTPUT_DIR}"/network/rustscan_nmap_*.xml; do
                    if [[ -f "$xml_file" ]]; then
                        local host=$(basename "$xml_file" .xml | sed 's/rustscan_nmap_//g' | sed 's/_/./g')
                        queue_tool_processing "rustscan_nmap_$host" "$xml_file"
                    fi
                done
            fi
        fi
    fi
}

# Feed large outputs back into scanning pipeline
feed_inputs_to_pipeline() {
    log_info "Checking for large outputs to feed back into scanning pipeline..."
    
    # Check subfinder output (100+ subdomains)
    if [[ -f "${OUTPUT_DIR}/recon/subfinder.txt" ]]; then
        local subdomain_count
        subdomain_count=$(wc -l < "${OUTPUT_DIR}/recon/subfinder.txt" 2>/dev/null || echo "0")
        if [[ "$subdomain_count" -gt 100 ]]; then
            log_info "Feeding $subdomain_count subdomains from subfinder to httpx and nuclei..."
            
            # Feed to httpx for HTTP probing
            run_docker "cat recon/subfinder.txt | httpx -o recon/subfinder_httpx.txt -silent -status-code -title -tech-detect -follow-redirects || true" 2>/dev/null || true
            
            # Feed to nuclei for vulnerability scanning
            run_docker "cat recon/subfinder.txt | nuclei -o recon/subfinder_nuclei.txt -silent || true" 2>/dev/null || true
            
            # Queue the new results for processing
            queue_tool_processing "subfinder_httpx" "${OUTPUT_DIR}/recon/subfinder_httpx.txt"
            queue_tool_processing "subfinder_nuclei" "${OUTPUT_DIR}/recon/subfinder_nuclei.txt"
        fi
    fi
    
    # Check waybackurls output (1000+ URLs)
    if [[ -f "${OUTPUT_DIR}/recon/waybackurls.txt" ]]; then
        local url_count
        url_count=$(wc -l < "${OUTPUT_DIR}/recon/waybackurls.txt" 2>/dev/null || echo "0")
        if [[ "$url_count" -gt 1000 ]]; then
            log_info "Feeding $url_count URLs from waybackurls to nuclei..."
            
            # Feed to nuclei for vulnerability scanning
            run_docker "cat recon/waybackurls.txt | nuclei -o recon/waybackurls_nuclei.txt -silent || true" 2>/dev/null || true
            
            # Queue the new results for processing
            queue_tool_processing "waybackurls_nuclei" "${OUTPUT_DIR}/recon/waybackurls_nuclei.txt"
        fi
    fi
    
    # Check gau output (1000+ URLs)
    if [[ -f "${OUTPUT_DIR}/recon/gau.txt" ]]; then
        local url_count
        url_count=$(wc -l < "${OUTPUT_DIR}/recon/gau.txt" 2>/dev/null || echo "0")
        if [[ "$url_count" -gt 1000 ]]; then
            log_info "Feeding $url_count URLs from gau to nuclei..."
            
            # Feed to nuclei for vulnerability scanning
            run_docker "cat recon/gau.txt | nuclei -o recon/gau_nuclei.txt -silent || true" 2>/dev/null || true
            
            # Queue the new results for processing
            queue_tool_processing "gau_nuclei" "${OUTPUT_DIR}/recon/gau_nuclei.txt"
        fi
    fi
    
    # Check assetfinder output (50+ subdomains)
    if [[ -f "${OUTPUT_DIR}/recon/assetfinder.txt" ]]; then
        local subdomain_count
        subdomain_count=$(wc -l < "${OUTPUT_DIR}/recon/assetfinder.txt" 2>/dev/null || echo "0")
        if [[ "$subdomain_count" -gt 50 ]]; then
            log_info "Found $subdomain_count subdomains from assetfinder (large dataset, ignoring as per rule)"
        fi
    fi
}

# Feed large web discovery outputs back to nuclei for validation
feed_web_inputs_to_pipeline() {
    log_info "Checking for large web discovery outputs to feed back to nuclei for validation..."
    
    # Check katana output (20+ folders)
    if [[ -f "${OUTPUT_DIR}/web/katana.txt" ]]; then
        local folder_count
        folder_count=$(wc -l < "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null || echo "0")
        if [[ "$folder_count" -gt 20 ]]; then
            log_info "Feeding $folder_count URLs from katana to nuclei for vulnerability validation..."
            
            # Feed to nuclei for vulnerability scanning
            run_docker "cat web/katana.txt | nuclei -o web/katana_nuclei.txt -silent || true" 2>/dev/null || true
            
            # Queue the new results for processing
            queue_tool_processing "katana_nuclei" "${OUTPUT_DIR}/web/katana_nuclei.txt"
        fi
    fi
    
    # Check gobuster output (50+ paths)
    if [[ -f "${OUTPUT_DIR}/web/gobuster.json" ]]; then
        local path_count
        path_count=$(jq '.result | length' "${OUTPUT_DIR}/web/gobuster.json" 2>/dev/null || echo "0")
        if [[ "$path_count" -gt 50 ]]; then
            log_info "Feeding $path_count paths from gobuster to nuclei for vulnerability validation..."
            
            # Extract full URLs and feed to nuclei
            run_docker "jq -r '.result[].url' web/gobuster.json 2>/dev/null | nuclei -o web/gobuster_nuclei.txt -silent || true" 2>/dev/null || true
            
            # Queue the new results for processing
            queue_tool_processing "gobuster_nuclei" "${OUTPUT_DIR}/web/gobuster_nuclei.txt"
        fi
    fi
    
    # Check ffuf output (50+ hits)
    if [[ -f "${OUTPUT_DIR}/web/ffuf.json" ]]; then
        local hit_count
        hit_count=$(run_docker "jq '.results | length' web/ffuf.json 2>/dev/null || echo '0'" 2>/dev/null || echo "0")
        if [[ "$hit_count" -gt 50 ]]; then
            log_info "Feeding $hit_count hits from ffuf to nuclei for vulnerability validation..."
            
            # Extract URLs from ffuf JSON and feed to nuclei
            run_docker "jq -r '.results[].url' web/ffuf.json 2>/dev/null | nuclei -o web/ffuf_nuclei.txt -silent || true" 2>/dev/null || true
            
            # Queue the new results for processing
            queue_tool_processing "ffuf_nuclei" "${OUTPUT_DIR}/web/ffuf_nuclei.txt"
        fi
    fi
    
    # Check dirsearch output (50+ paths)
    if [[ -f "${OUTPUT_DIR}/web/dirsearch.json" ]]; then
        local path_count
        path_count=$(jq '.results | length' "${OUTPUT_DIR}/web/dirsearch.json" 2>/dev/null || echo "0")
        if [[ "$path_count" -gt 50 ]]; then
            log_info "Feeding $path_count paths from dirsearch to nuclei for vulnerability validation..."
            
            # Extract URLs and feed to nuclei
            run_docker "jq -r '.results[].path' web/dirsearch.json 2>/dev/null | sed 's|^|https://${TARGET_DOMAIN}|' | nuclei -o web/dirsearch_nuclei.txt -silent || true" 2>/dev/null || true
            
            # Queue the new results for processing
            queue_tool_processing "dirsearch_nuclei" "${OUTPUT_DIR}/web/dirsearch_nuclei.txt"
        fi
    fi
}

# Feed database port discoveries back to nmap for detailed scanning
feed_database_inputs_to_pipeline() {
    log_info "Checking database port discoveries to feed back to nmap for detailed scanning..."
    
    # Check db_ports output (any database ports found)
    if [[ -f "${OUTPUT_DIR}/database/db_ports.nmap" ]]; then
        local db_port_count
        db_port_count=$(run_docker "xq '.nmaprun.host.ports.port[] | select(.service.\"@name\" | test(\"mysql|postgres|redis|mongodb|oracle|mssql\")) | .portid' database/db_ports.nmap 2>/dev/null | wc -l || echo '0'" 2>/dev/null || echo "0")
        if [[ "$db_port_count" -gt 0 ]]; then
            log_info "Feeding $db_port_count database ports from db_ports to nmap for detailed scanning..."
            
            # Extract database ports and feed to nmap for detailed scanning
            run_docker "xq -r '.nmaprun.host.ports.port[] | select(.service.\"@name\" | test(\"mysql|postgres|redis|mongodb|oracle|mssql\")) | .portid' database/db_ports.nmap 2>/dev/null | tr '\n' ',' | sed 's/,$//' > database/db_port_list.txt 2>/dev/null || true" 2>/dev/null || true
            
            if [[ -f "${OUTPUT_DIR}/database/db_port_list.txt" ]] && [[ -s "${OUTPUT_DIR}/database/db_port_list.txt" ]]; then
                run_docker "nmap -sV -sC -p \$(cat database/db_port_list.txt) ${TARGET_DOMAIN} -oA database/db_detailed_scan || true" 2>/dev/null || true
                
                # Queue the detailed scan results
                queue_tool_processing "db_detailed_scan" "${OUTPUT_DIR}/database/db_detailed_scan.xml"
            fi
        fi
    fi
}

# Aggregate database connectivity tests into single findings
aggregate_database_findings() {
    log_info "Aggregating database connectivity tests into single findings..."
    
    # Create aggregated database findings
    local redis_accessible="false"
    local postgres_accessible="false" 
    local mysql_accessible="false"
    
    # Check Redis connectivity
    if [[ -f "${OUTPUT_DIR}/database/redis_test.txt" ]]; then
        if grep -q "Connection successful\|Connected to" "${OUTPUT_DIR}/database/redis_test.txt" 2>/dev/null; then
            redis_accessible="true"
        fi
    fi
    
    # Check PostgreSQL connectivity
    if [[ -f "${OUTPUT_DIR}/database/postgres_test.txt" ]]; then
        if grep -q "Connection successful\|Connected to\|postgresql" "${OUTPUT_DIR}/database/postgres_test.txt" 2>/dev/null; then
            postgres_accessible="true"
        fi
    fi
    
    # Check MySQL connectivity
    if [[ -f "${OUTPUT_DIR}/database/mysql_test.txt" ]]; then
        if grep -q "Connection successful\|Connected to\|mysql" "${OUTPUT_DIR}/database/mysql_test.txt" 2>/dev/null; then
            mysql_accessible="true"
        fi
    fi
    
    # Create aggregated findings JSON
    run_docker "cat > database/aggregated_findings.json << 'EOF'
{
  \"timestamp\": \"$(date -Iseconds)\",
  \"target_domain\": \"${TARGET_DOMAIN}\",
  \"database_exposures\": {
    \"redis_accessible\": $redis_accessible,
    \"postgres_accessible\": $postgres_accessible,
    \"mysql_accessible\": $mysql_accessible
  },
  \"summary\": {
    \"total_databases_tested\": 3,
    \"accessible_databases\": $((redis_accessible == "true" || postgres_accessible == "true" || mysql_accessible == "true" ? 1 : 0)),
    \"exposure_risk\": \"$((redis_accessible == "true" || postgres_accessible == "true" || mysql_accessible == "true" && echo "HIGH" || echo "LOW"))\"
  }
}
EOF" 2>/dev/null || true
    
    # Queue the aggregated findings
    queue_tool_processing "database_aggregated" "${OUTPUT_DIR}/database/aggregated_findings.json"
}

# Aggregate cloud/container exposure tests into single high-value finding
aggregate_cloud_findings() {
    log_info "Aggregating cloud/container exposure tests into single high-value finding..."
    
    # Create aggregated cloud findings
    local metadata_exposed="false"
    local docker_registry_exposed="false"
    local k8s_api_exposed="false"
    
    # Check metadata exposure
    if [[ -f "${OUTPUT_DIR}/container/metadata_check.txt" ]]; then
        if grep -q -v "Scanner-side\|informational" "${OUTPUT_DIR}/container/metadata_check.txt" 2>/dev/null && [[ -s "${OUTPUT_DIR}/container/metadata_check.txt" ]]; then
            metadata_exposed="true"
        fi
    fi
    
    # Check Docker registry exposure
    if [[ -f "${OUTPUT_DIR}/container/docker_registry.txt" ]]; then
        if grep -q "accessible\|open\|exposed" "${OUTPUT_DIR}/container/docker_registry.txt" 2>/dev/null; then
            docker_registry_exposed="true"
        fi
    fi
    
    # Check Kubernetes API exposure
    if [[ -f "${OUTPUT_DIR}/container/k8s_api.txt" ]]; then
        if grep -q "accessible\|open\|exposed\|200 OK\|unauthorized" "${OUTPUT_DIR}/container/k8s_api.txt" 2>/dev/null; then
            k8s_api_exposed="true"
        fi
    fi
    
    # Create aggregated cloud findings JSON
    run_docker "cat > container/aggregated_cloud_findings.json << 'EOF'
{
  \"timestamp\": \"$(date -Iseconds)\",
  \"target_domain\": \"${TARGET_DOMAIN}\",
  \"cloud_exposures\": {
    \"metadata_exposed\": $metadata_exposed,
    \"docker_registry_exposed\": $docker_registry_exposed,
    \"k8s_api_exposed\": $k8s_api_exposed
  },
  \"summary\": {
    \"total_cloud_services_tested\": 3,
    \"exposed_services\": $((metadata_exposed == "true" || docker_registry_exposed == "true" || k8s_api_exposed == "true" ? 1 : 0)),
    \"exposure_risk\": \"$((metadata_exposed == "true" || docker_registry_exposed == "true" || k8s_api_exposed == "true" && echo "HIGH" || echo "LOW"))\",
    \"finding_type\": \"cloud_container_exposure\"
  }
}
EOF" 2>/dev/null || true
    
    # Queue the aggregated findings
    queue_tool_processing "cloud_aggregated" "${OUTPUT_DIR}/container/aggregated_cloud_findings.json"
}

# Create summary files for tools that generate multiple outputs
create_summary_files() {
    local phase="$1"
    
    case "$phase" in
        "web")
            # Create nikto summary from multiple nikto XML files
            if ls "${OUTPUT_DIR}/web"/nikto_*.xml 1>/dev/null 2>&1; then
                # Combine XML files using xq
                run_docker "xq -s 'map(select(.niktoscan)) | add' web/nikto_*.xml 2>/dev/null > web/nikto_summary.xml || echo '<niktoscan></niktoscan>' > web/nikto_summary.xml" 2>/dev/null || true
            else
                echo '<niktoscan></niktoscan>' > "${OUTPUT_DIR}/web/nikto_summary.xml"
            fi
            ;;
        "database")
            # Create sqlmap summary from multiple sqlmap log.xml files
            if ls "${OUTPUT_DIR}"/database/sqlmap_*/log.xml 1>/dev/null 2>&1; then
                # Combine XML files using xq
                run_docker "xq -s 'map(select(.sqlmap)) | add' database/sqlmap_*/log.xml 2>/dev/null > database/sqlmap_summary.xml || echo '<sqlmap></sqlmap>' > database/sqlmap_summary.xml" 2>/dev/null || true
            else
                echo '<sqlmap></sqlmap>' > "${OUTPUT_DIR}/database/sqlmap_summary.xml"
            fi
            ;;
    esac
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
    
    # Always queue for processing - AI vs Direct DetectDojo will be decided in process_tool_output
    if [[ -f "$output_file" ]]; then
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
    chmod 755 "$OUTPUT_DIR" 2>/dev/null || true
    
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
    SCAN_ID="${SCAN_ID:-${TARGET_DOMAIN}_${SCAN_DATE}}"
    
    OUTPUT_BASE="/var/log/output"
    OUTPUT_DIR="${OUTPUT_DIR:-${OUTPUT_BASE}/${SCAN_ID}}"
    LOG_FILE="${OUTPUT_DIR}/execution.log"
    
    # Create base output directory with fallback
    if ! mkdir -p "$OUTPUT_BASE" 2>/dev/null; then
        # Try with if user permission fails
        mkdir -p "$OUTPUT_BASE" 2>/dev/null || {
            # Fallback to user directory
            OUTPUT_BASE="$HOME/vapt_output"
            mkdir -p "$OUTPUT_BASE"
            log_warn "Using alternative output directory: $OUTPUT_BASE"
            OUTPUT_DIR="${OUTPUT_BASE}/${SCAN_ID}"
        }
    fi
    
    # Create scan-specific directory with permissions
    if ! mkdir -p "$OUTPUT_DIR" 2>/dev/null; then
        mkdir -p "$OUTPUT_DIR" 2>/dev/null || {
            log_error "Failed to create output directory: $OUTPUT_DIR"
            exit 1
        }
    fi
    
    # Ensure proper permissions and ownership
    chown -R "$(id -u):$(id -g)" "$OUTPUT_DIR" 2>/dev/null || true
    chmod 755 "$OUTPUT_DIR" 2>/dev/null || chmod 755 "$OUTPUT_DIR" 2>/dev/null || true
    
    # Create processing queue directory
    mkdir -p "${OUTPUT_DIR}/processing_queue" 2>/dev/null || mkdir -p "${OUTPUT_DIR}/processing_queue" 2>/dev/null || true
    chmod 755 "${OUTPUT_DIR}/processing_queue" 2>/dev/null || chmod 755 "${OUTPUT_DIR}/processing_queue" 2>/dev/null || true
    
    # Create scan subdirectories
    for dir in recon network vuln web ssl database container reports; do
        mkdir -p "${OUTPUT_DIR}/${dir}" 2>/dev/null || mkdir -p "${OUTPUT_DIR}/${dir}" 2>/dev/null || true
        chown "$(id -u):$(id -g)" "${OUTPUT_DIR}/${dir}" 2>/dev/null || true
    done
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    
    log_ok "Directories initialized"
    log_info "Output directory: $OUTPUT_DIR"
}

# Phase 1: RECONNAISSANCE (Optimized)
run_recon() {
    log_info "Starting Phase 1: RECONNAISSANCE"
    
    # Parallel subdomain discovery
    run_parallel \
        "timeout 300 amass enum -d ${TARGET_DOMAIN} -json recon/amass.json || echo '${TARGET_DOMAIN}' > recon/amass.txt" \
        "assetfinder ${TARGET_DOMAIN} | tee recon/assetfinder.txt" \
        "subfinder -d ${TARGET_DOMAIN} -o recon/subfinder.txt || echo '${TARGET_DOMAIN}' > recon/subfinder.txt"
    
    # Parallel information gathering
    run_parallel \
        "whois ${TARGET_DOMAIN} > recon/whois.txt || echo 'Whois information not available' > recon/whois.txt" \
        "dnsrecon -d ${TARGET_DOMAIN} -j recon/dnsrecon.json" \
        "dig ${TARGET_DOMAIN} A AAAA MX TXT NS > recon/dig.txt || echo 'Dig failed' > recon/dig_error.txt" \
        "whatweb -a 3 --log-json=recon/whatweb.json https://${TARGET_DOMAIN} || echo 'WhatWeb scan failed' > recon/whatweb_error.txt"
    
    # Parallel URL discovery
    run_parallel \
        "waybackurls ${TARGET_DOMAIN} > recon/waybackurls.txt" \
        "gau ${TARGET_DOMAIN} > recon/gau.txt"
    
    # Fallback logic
    run_docker "if [[ ! -s recon/amass.json ]]; then echo '[{\"name\": \"${TARGET_DOMAIN}\", \"domain\": \"${TARGET_DOMAIN}\"}]' > recon/amass.json; fi"
    run_docker "if [[ ! -s recon/subfinder.txt ]]; then echo '${TARGET_DOMAIN}' > recon/subfinder.txt; fi"
    
    # Feed large outputs back into scanning pipeline
    feed_inputs_to_pipeline
    
    # Queue reconnaissance tools for processing (skip input-only tools)
    queue_tool_processing "amass" "${OUTPUT_DIR}/recon/amass.json"
    queue_tool_processing "whatweb" "${OUTPUT_DIR}/recon/whatweb.json"
    queue_tool_processing "dnsrecon" "${OUTPUT_DIR}/recon/dnsrecon.json"
    queue_tool_processing "dig" "${OUTPUT_DIR}/recon/dig.txt"
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
    log_info "Running naabu for port discovery with JSON output for DefectDojo compatibility"
    run_docker "timeout ${PORT_SCAN_TIMEOUT} naabu -list targets.txt -p 1-65535 -json -o network/naabu.json || echo 'Naabu scan failed' > network/naabu_error.txt"
    
    # Fast port scanning with XML output for DefectDojo compatibility
    run_docker "rustscan -a ${TARGET_DOMAIN} -r 1-65535 --ulimit 5000 -- -sV -oX network/rustscan.xml"
    
    # Service discovery with JSON output for DefectDojo compatibility
    run_with_retry "jq -r '.host + \":\" + (.port|tostring)' network/naabu.json 2>/dev/null | httpx -json -o network/httpx.json || true"
    
    # Individual IP scanning with enhanced error handling (serialized)
    run_docker "for ip in \$(jq -r '.[] | select(.type==\"A\") | .address' recon/dnsrecon.json 2>/dev/null || echo ''); do if [[ -n \"\$ip\" ]]; then echo \"Scanning IP: \$ip\" && timeout ${SCAN_TIMEOUT} nmap -sS -sV -O --script vulners \$ip -oA network/nmap_comprehensive_\${ip//./_} 2>/dev/null || timeout ${SCAN_TIMEOUT} nmap -sS -sV --script vulners \$ip -oA network/nmap_comprehensive_\${ip//./_} 2>/dev/null || timeout ${SCAN_TIMEOUT} nmap -sV --script vulners \$ip -oA network/nmap_comprehensive_\${ip//./_} || echo \"Nmap scan failed for \$ip\" > network/nmap_error_\${ip//./_}.txt; else echo \"No IPs found for nmap scanning\" > network/nmap_error.txt; fi; done"
    
    # Masscan with XML output for DefectDojo compatibility
    if [[ "$masscan_enabled" == "true" ]]; then
        run_docker "masscan ${TARGET_DOMAIN} -p1-65535 --rate=1000 -oX network/masscan_${TARGET_DOMAIN}.xml || echo 'Masscan failed' > network/masscan_error.xml"
    fi
    
    # Feed large network outputs back into scanning pipeline
    feed_network_inputs_to_pipeline
    
    # Queue network tools for processing (skip port scanner inputs, import network risk tools)
    queue_tool_processing "httpx" "${OUTPUT_DIR}/network/httpx.json"
    
    # Queue nmap results for each IP (network risk - direct import)
    for xml_file in "${OUTPUT_DIR}"/network/nmap_comprehensive_*.xml; do
        if [[ -f "$xml_file" ]]; then
            local ip=$(basename "$xml_file" .xml | sed 's/nmap_comprehensive_//g' | sed 's/_/./g')
            queue_tool_processing "nmap_$ip" "$xml_file"
        fi
    done
    
    # Queue masscan results if available (network risk - direct import)
    for xml_file in "${OUTPUT_DIR}"/network/masscan_*.xml; do
        if [[ -f "$xml_file" ]]; then
            local ip=$(basename "$xml_file" .xml | sed 's/masscan_//g' | sed 's/_/./g')
            queue_tool_processing "masscan_$ip" "$xml_file"
        fi
    done
    
    monitor_resources "Network Scanning"
    log_ok "Network scanning completed"
}

# Phase 3: VULNERABILITY ASSESSMENT (Optimized)
run_vulnerability() {
    track_progress 8 3 "Vulnerability Assessment"
    log_info "Starting Phase 3: VULNERABILITY ASSESSMENT"
    
    # Create nuclei targets from gobuster results
    log_info "Creating nuclei targets from discovered URLs..."
    run_docker "echo 'https://${TARGET_DOMAIN}/' > vuln/nuclei_targets.txt && jq -r '.result[] | select(.status != 403) | .url' web/gobuster.json 2>/dev/null | sed 's|/$||' | grep -v -E '\\.(php|html|htm|css|js|jpg|png|gif|ico)$' | sed 's|^/|https://${TARGET_DOMAIN}/|' | sed 's|[^/]$|&/|' | sort -u >> vuln/nuclei_targets.txt || echo 'Using main domain only' && echo 'https://${TARGET_DOMAIN}/' > vuln/nuclei_targets.txt"
    
    # Parallel vulnerability scanning with DefectDojo-compatible formats
    run_parallel \
        "for url in \$(cat vuln/nuclei_targets.txt); do echo \"Nuclei scanning: \$url\" && nuclei -u \"\$url\" -severity critical,high,medium -json -o vuln/nuclei_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g').json || echo \"No vulnerabilities found for \$url\" > vuln/nuclei_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g').json; done" \
        "nmap -sV --script vulners ${TARGET_DOMAIN} -oX vuln/nmap_vulners.xml || echo 'No nmap vulners results' > vuln/nmap_vulners.txt"
    
    # Combine JSON results from nuclei
    run_docker "jq -s 'flatten | group_by(.templateID) | map(select(length > 0) | .[0])' vuln/nuclei_*.json 2>/dev/null > vuln/nuclei.json || echo '[]' > vuln/nuclei.json"
    
    # Queue vulnerability tools for processing (skip exploit database, import assertions)
    queue_tool_processing "nuclei" "${OUTPUT_DIR}/vuln/nuclei.json"
    queue_tool_processing "nmap_vulners" "${OUTPUT_DIR}/vuln/nmap_vulners.xml"
    
    monitor_resources "Vulnerability Assessment"
    log_ok "Vulnerability assessment completed"
    log_info "Nuclei targets scanned: $(cat "${OUTPUT_DIR}/vuln/nuclei_targets.txt" 2>/dev/null | wc -l || echo "0")"
}

# Phase 4: WEB SECURITY
run_web() {
    log_info "Starting Phase 4: WEB SECURITY"
    
    log_info "Running gobuster for path discovery with JSON output for DefectDojo compatibility..."
    run_docker "gobuster dir -u https://${TARGET_DOMAIN} -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o web/gobuster.json -f json"
    
    log_info "Running katana on discovered URLs..."
    run_docker "echo 'https://${TARGET_DOMAIN}/' > web/katana_targets.txt && jq -r '.result[] | select(.status != 403) | .url' web/gobuster.json 2>/dev/null | sed 's|/$||' | grep -v -E '\\.(php|html|htm|css|js|jpg|png|gif|ico)$' | sed 's|^/|https://${TARGET_DOMAIN}/|' | sed 's|[^/]$|&/|' | sort -u >> web/katana_targets.txt && for url in \$(cat web/katana_targets.txt); do echo \"Scanning: \$url\" && katana -u \"\$url\" -o web/katana_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$//').txt; done && cat web/katana_*.txt > web/katana.txt 2>/dev/null || echo 'No katana results' > web/katana.txt"
    
    log_info "Running nikto on all discovered URLs with XML output for DefectDojo compatibility..."
    run_docker "if [[ -f web/katana_targets.txt ]]; then cp web/katana_targets.txt web/nikto_targets.txt; else echo 'https://${TARGET_DOMAIN}/' > web/nikto_targets.txt; fi && for url in \$(cat web/nikto_targets.txt); do echo \"Nikto scanning: \$url\" && nikto -h \"\$url\" -o web/nikto_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$//').xml -Format xml || echo \"No nikto results for \$url\" > web/nikto_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g' | sed 's|/$//').xml; done"
    
    log_info "Running ffuf for fuzzing..."
    run_docker "ffuf -u \"https://${TARGET_DOMAIN}/FUZZ\" -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt -o web/ffuf.json -of json || echo 'No ffuf results' > web/ffuf.txt"
    
    log_info "Running dirsearch with JSON output for DefectDojo compatibility..."
    run_docker "dirsearch -u \"https://${TARGET_DOMAIN}\" -w /opt/wordlists/SecLists/Discovery/Web-Content/common.txt --format=json -o web/dirsearch.json || echo 'No dirsearch results' > web/dirsearch.txt"
    
    log_info "Running wapiti for web vulnerability scanning with XML output for DefectDojo compatibility..."
    run_docker "wapiti -u https://${TARGET_DOMAIN} -o web/wapiti.xml -f xml || echo 'Wapiti scan completed with issues' > web/wapiti.txt"
    
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
    
    # Feed database port discoveries back to nmap for detailed scanning
feed_database_inputs_to_pipeline() {
    log_info "Checking database port discoveries to feed back to nmap for detailed scanning..."
    
    # Check db_ports output (any database ports found)
    if [[ -f "${OUTPUT_DIR}/database/db_ports.nmap" ]]; then
        local db_port_count
        db_port_count=$(run_docker "xq '.nmaprun.host.ports.port[] | select(.service.\"@name\" | test(\"mysql|postgres|redis|mongodb|oracle|mssql\")) | .portid' database/db_ports.nmap 2>/dev/null | wc -l || echo '0'" 2>/dev/null || echo "0")
        if [[ "$db_port_count" -gt 0 ]]; then
            log_info "Feeding $db_port_count database ports from db_ports to nmap for detailed scanning..."
            
            # Extract database ports and feed to nmap for detailed scanning
            run_docker "xq -r '.nmaprun.host.ports.port[] | select(.service.\"@name\" | test(\"mysql|postgres|redis|mongodb|oracle|mssql\")) | .portid' database/db_ports.nmap 2>/dev/null | tr '\n' ',' | sed 's/,$//' > database/db_port_list.txt 2>/dev/null || true" 2>/dev/null || true
            
            if [[ -f "${OUTPUT_DIR}/database/db_port_list.txt" ]] && [[ -s "${OUTPUT_DIR}/database/db_port_list.txt" ]]; then
                run_docker "nmap -sV -sC -p \$(cat database/db_port_list.txt) ${TARGET_DOMAIN} -oA database/db_detailed_scan || true" 2>/dev/null || true
                
                # Queue the detailed scan results
                queue_tool_processing "db_detailed_scan" "${OUTPUT_DIR}/database/db_detailed_scan.xml"
            fi
        fi
    fi
    queue_tool_processing "nikto" "${OUTPUT_DIR}/web/nikto_summary.xml"
    queue_tool_processing "wapiti" "${OUTPUT_DIR}/web/wapiti.xml"
    queue_tool_processing "zap" "${OUTPUT_DIR}/web/zap.json"
    
    log_ok "Web security completed"
    log_info "Total URLs crawled by katana: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")"
}

# Phase 5: SSL/TLS SECURITY
run_ssl() {
    log_info "Starting Phase 5: SSL/TLS SECURITY"
    
    log_info "Running sslyze with JSON output for DefectDojo compatibility..."
    run_docker "sslyze --certinfo --heartbleed --robot --tlsv1_2 --tlsv1_3 --http_headers --json_out ssl/sslyze.json ${TARGET_DOMAIN}:443 || echo '{\"error\": \"sslyze not available\"}' > ssl/sslyze.json"
    
    log_info "Running testssl.sh with JSON output for DefectDojo compatibility..."
    run_docker "testssl.sh --jsonfile ssl/testssl.json ${TARGET_DOMAIN}:443 || echo 'testssl.sh not available, SSLyze completed successfully' > ssl/testssl_error.txt"
    
    # Queue SSL/TLS tools for processing (DefectDojo-compatible formats)
    queue_tool_processing "sslyze" "${OUTPUT_DIR}/ssl/sslyze.json"
    queue_tool_processing "testssl" "${OUTPUT_DIR}/ssl/testssl.json"
    
    log_ok "SSL/TLS security completed"
}

# Phase 6: DATABASE SECURITY
run_database() {
    log_info "Starting Phase 6: DATABASE SECURITY"
    
    # Create SQLMap targets from web discoveries (only URLs with parameters)
    log_info "Creating SQLMap targets from discovered URLs with parameters..."
    run_docker "grep '?' web/katana.txt | sort -u > database/sqlmap_targets.txt"
    
    log_info "Running sqlmap on parameterized URLs with XML output for DefectDojo compatibility..."
    run_docker "for url in \$(cat database/sqlmap_targets.txt); do echo \"SQLMap scanning: \$url\" && python3 /opt/tools/sqlmap/sqlmap.py -u \"\$url\" --batch --level=2 --risk=1 --threads=1 --timeout=5 --retries=1 --random-agent --flush-session --tamper=space2comment --xml --output-dir=database/sqlmap_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g') || echo \"No SQL injection found for \$url\" > database/sqlmap_\$(echo \$url | sed 's|https://||g' | sed 's|/|_|g').txt; done"
    
    log_info "Checking database ports..."
    run_docker "nmap -sV -p 3306,5432,6379,1433,1521 ${TARGET_DOMAIN} -oA database/db_ports"
    
    log_info "Testing Redis access..."
    run_docker "nc -zv ${TARGET_DOMAIN} 6379 2>&1 | tee database/redis_test.txt || echo 'Redis not accessible' > database/redis_test.txt"
    
    log_info "Testing PostgreSQL access..."
    run_docker "nc -zv ${TARGET_DOMAIN} 5432 2>&1 | tee database/postgres_test.txt || echo 'PostgreSQL not accessible' > database/postgres_test.txt"
    
    log_info "Testing MySQL access..."
    run_docker "nc -zv ${TARGET_DOMAIN} 3306 2>&1 | tee database/mysql_test.txt || echo 'MySQL not accessible' > database/mysql_test.txt"
    
    # Create summary files for processing
    create_summary_files "database"
    
    # Feed database port discoveries back to nmap for detailed scanning
    feed_database_inputs_to_pipeline
    
    # Aggregate database connectivity tests into single findings
    aggregate_database_findings
    
    # Queue database security tools for processing (skip connectivity tests, import findings)
    queue_tool_processing "sqlmap" "${OUTPUT_DIR}/database/sqlmap_summary.xml"
    
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
    
    log_info "Running kubeaudit for Kubernetes security audit with JSON output for DefectDojo compatibility..."
    run_docker "kubeaudit all -f container/kubeaudit.json || true"
    
    # Aggregate cloud/container exposure tests into single high-value finding
    aggregate_cloud_findings
    
    # Queue container & cloud tools for processing (skip exposure tests, import findings)
    queue_tool_processing "kubeaudit" "${OUTPUT_DIR}/container/kubeaudit.json"
    
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
- Network: $(jq '. | length' "${OUTPUT_DIR}/network/naabu.json" 2>/dev/null || echo "0") open ports identified
- Web: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0") URLs crawled
- Vulnerabilities: $(jq '[.[] | select(.severity == "critical" or .severity == "high" or .severity == "medium")] | length' "${OUTPUT_DIR}/vuln/nuclei.json" 2>/dev/null || echo "0") findings

TOOLS USED:
===========
Phase 1 (Recon): amass, assetfinder, subfinder, whois, dnsrecon, dig, whatweb, waybackurls, gau
Phase 2 (Network): naabu, nmap, masscan, rustscan, httpx
Phase 3 (Vulnerability): nuclei, nmap vulners
Phase 4 (Web): gobuster, katana, nikto, ffuf, dirsearch, wapiti, OWASP ZAP
Phase 5 (SSL): sslyze, testssl.sh
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
            <li>Open Ports: $(jq '. | length' "${OUTPUT_DIR}/network/naabu.json" 2>/dev/null || echo "0")</li>
            <li>URLs Crawled: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")</li>
            <li>Vulnerabilities Found: $(jq '[.[] | select(.severity == "critical" or .severity == "high" or .severity == "medium")] | length' "${OUTPUT_DIR}/vuln/nuclei.json" 2>/dev/null || echo "0")</li>
        </ul>
    </div>
    
    <div class="section">
        <h3>Tools Executed</h3>
        <table>
            <tr><th>Phase</th><th>Tools</th></tr>
            <tr><td>Reconnaissance</td><td>amass, assetfinder, subfinder, whois, dnsrecon, dig, whatweb, waybackurls, gau</td></tr>
            <tr><td>Network</td><td>naabu, nmap, masscan, rustscan, httpx</td></tr>
            <tr><td>Vulnerability</td><td>nuclei, nmap vulners</td></tr>
            <tr><td>Web</td><td>gobuster, katana, nikto, ffuf, dirsearch, wapiti, OWASP ZAP</td></tr>
            <tr><td>SSL/TLS</td><td>sslyze, testssl.sh</td></tr>
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
    if [[ "${I_HAVE_AUTHORIZATION:-no}" == "yes" ]]; then
        echo -e "${GREEN}[OK] Authorization confirmed via environment variable.${NC}"
        return 0
    fi
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
    echo -e "- Open Ports: $(jq '. | length' "${OUTPUT_DIR}/network/naabu.json" 2>/dev/null || echo "0")"
    echo -e "- URLs Crawled: $(cat "${OUTPUT_DIR}/web/katana.txt" 2>/dev/null | wc -l || echo "0")"
    echo -e "- Vulnerabilities: $(jq '[.[] | select(.severity == "critical" or .severity == "high" or .severity == "medium")] | length' "${OUTPUT_DIR}/vuln/nuclei.json" 2>/dev/null || echo "0")"
    echo ""
    echo -e "${GREEN}✓ Enhanced VAPT Engine v2.3 - Complete!${NC}"
}

# Execute main function
main "$@"
