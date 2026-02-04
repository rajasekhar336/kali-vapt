#!/bin/bash

# Kali VAPT Framework - Quick Start Script
# One-command setup and execution for run_enhanced.sh

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
TARGET_DOMAIN=""
VERBOSE=false
MODE="strict"

# Banner
banner() {
    echo -e "${CYAN}"
    cat << 'BANNEREOF'
 _____ ____  ____    _    _     _   ____    _  __ _____ ___ 
| ____|  _ \/ ___|  / \  | |   | | |  _ \  / \| |/ |_   _/ _ \
|  _| | |_) \___ \ / _ \ | |   | | | | | |/ _ \| \| ' / | | | | | |
| |___|  _ < ___ ) / ___ \| |___| |_| | |_| / ___ \ .  \| | | | |_| |
|_____|_| \_\____/_/   \_\_____|_____|____/_/   \_\_|\_|\_|   \___/___/
                                                                        
Kali VAPT Framework - Quick Start for Enhanced Engine
BANNEREOF
    echo -e "${NC}"
}

# Usage
usage() {
    echo "Usage: $0 <target_domain> [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help"
    echo "  -v, --verbose    Verbose output"
    echo "  -m, --mode MODE  Execution mode: strict, modular, unified (default: strict)"
    echo ""
    echo "This script sets up AI services and runs the main VAPT framework (run_enhanced.sh)"
    echo ""
    echo "Examples:"
    echo "  $0 example.com"
    echo "  $0 example.com --verbose"
    echo "  $0 example.com --mode modular"
}

# Logging
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon not running. Please start Docker service."
        exit 1
    fi
    
    log_info "Prerequisites check passed ✓"
}

# Setup AI services (optional but recommended)
setup_ai_services() {
    log_info "Setting up AI services for enhanced vulnerability analysis..."
    
    # Create necessary directories
    mkdir -p logs output
    
    # Ensure scripts are executable
    chmod +x *.sh */*.sh
    
    # Start Qwen AI service
    if [[ -d "qwen-0.5b-normalizer" ]]; then
        log_info "Starting Qwen 0.5B AI normalization service..."
        cd qwen-0.5b-normalizer
        if ./qwen-0.5b-docker.sh start; then
            log_info "Qwen AI service started ✓"
        else
            log_warn "Qwen AI service failed to start - continuing without AI normalization"
        fi
        cd ..
    else
        log_warn "Qwen AI service directory not found - continuing without AI"
    fi
    
    # Start DetectDojo service
    if [[ -d "detectdojo" ]]; then
        log_info "Starting DetectDojo correlation service..."
        cd detectdojo
        if ./detectdojo-service.sh start; then
            log_info "DetectDojo service started ✓"
        else
            log_warn "DetectDojo service failed to start - continuing without correlation"
        fi
        cd ..
    else
        log_warn "DetectDojo service directory not found - continuing without correlation"
    fi
    
    # Wait for services to initialize
    log_info "Waiting for AI services to initialize..."
    sleep 5
}

# Run main VAPT assessment
run_assessment() {
    log_info "Starting Enhanced VAPT assessment for: ${TARGET_DOMAIN}"
    
    local cmd="./run_enhanced.sh ${TARGET_DOMAIN}"
    
    if [[ "$VERBOSE" == true ]]; then
        cmd="${cmd} --verbose"
    fi
    
    if [[ "$MODE" != "strict" ]]; then
        cmd="${cmd} --mode ${MODE}"
    fi
    
    log_info "Executing: ${cmd}"
    log_info "This will run 8 assessment phases with 40+ security tools"
    
    eval "$cmd"
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
            -m|--mode)
                MODE="$2"
                shift 2
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
    
    banner
    check_prerequisites
    setup_ai_services
    run_assessment
    
    log_info "Enhanced VAPT assessment completed!"
    log_info "Results available in: /var/log/output/${TARGET_DOMAIN}_$(date +%Y%m%d)/"
    log_info "HTML report: /var/log/output/${TARGET_DOMAIN}_$(date +%Y%m%d)/vapt_report.html"
    log_info "Executive summary: /var/log/output/${TARGET_DOMAIN}_$(date +%Y%m%d)/executive_summary.txt"
}

main "$@"
