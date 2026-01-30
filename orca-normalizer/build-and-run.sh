#!/bin/bash

# Production Orca-Mini-3B Docker Build and Run Script
# Full offline Docker template for 2GB RAM + swap

set -euo pipefail

# Configuration
IMAGE_NAME="orca-normalizer:production"
CONTAINER_NAME="orca-normalizer-prod"
HOST_PORT="8080"
CONTAINER_PORT="8080"
MEMORY_LIMIT="2g"
CPU_LIMIT="1.0"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check system resources
check_resources() {
    log_info "Checking system resources..."
    
    # Check memory
    total_mem=$(free -g | awk '/^Mem:/{print $2}')
    available_mem=$(free -g | awk '/^Mem:/{print $7}')
    
    log_info "Total Memory: ${total_mem}GB"
    log_info "Available Memory: ${available_mem}GB"
    
    # Check swap
    swap_total=$(free -g | awk '/^Swap:/{print $2}')
    log_info "Swap Memory: ${swap_total}GB"
    
    if [[ $((total_mem + swap_total)) -lt 3 ]]; then
        log_warn "Recommended: 3GB+ total memory (RAM + swap)"
        log_warn "Current: $((total_mem + swap_total))GB"
    else
        log_info "Memory requirements met ✓"
    fi
    
    # Check disk space
    disk_available=$(df -BG . | awk 'NR==2{print $4}' | sed 's/G//')
    log_info "Available Disk Space: ${disk_available}GB"
    
    if [[ $disk_available -lt 5 ]]; then
        log_warn "Recommended: 5GB+ disk space for model and containers"
    else
        log_info "Disk space requirements met ✓"
    fi
}

# Build Docker image
build_image() {
    log_info "Building production Orca-Mini-3B image..."
    
    # Check if Dockerfile exists
    if [[ ! -f "Dockerfile" ]]; then
        log_error "Dockerfile not found"
        exit 1
    fi
    
    # Build image
    docker build -f Dockerfile -t "$IMAGE_NAME" . || {
        log_error "Failed to build Docker image"
        exit 1
    }
    
    log_info "Docker image built successfully ✓"
}

# Stop existing container
stop_container() {
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        log_info "Stopping existing container: $CONTAINER_NAME"
        docker stop "$CONTAINER_NAME" || true
        docker rm "$CONTAINER_NAME" || true
    fi
}

# Run container
run_container() {
    log_info "Starting production Orca-Mini-3B container..."
    
    # Create volume directories
    mkdir -p ./output ./logs
    
    # Run container with resource limits
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p "${HOST_PORT}:${CONTAINER_PORT}" \
        --cpus="$CPU_LIMIT" \
        --memory="$MEMORY_LIMIT" \
        --memory-swap="$MEMORY_LIMIT" \
        -v "$(pwd)/output:/app/output" \
        -v "$(pwd)/logs:/app/logs" \
        --restart unless-stopped \
        "$IMAGE_NAME" || {
        log_error "Failed to start container"
        exit 1
    }
    
    log_info "Container started successfully ✓"
}

# Wait for service to be ready
wait_for_service() {
    log_info "Waiting for Orca service to be ready..."
    
    for i in {1..60}; do
        if curl -s "http://localhost:${HOST_PORT}/health" >/dev/null 2>&1; then
            log_info "Orca service is ready! ✓"
            return 0
        fi
        echo -n "."
        sleep 2
    done
    
    log_error "Service failed to start within timeout"
    return 1
}

# Test service
test_service() {
    log_info "Testing Orca service..."
    
    # Test health endpoint
    health_response=$(curl -s "http://localhost:${HOST_PORT}/health")
    if echo "$health_response" | jq -e '.status' >/dev/null 2>&1; then
        log_info "Health check passed ✓"
    else
        log_error "Health check failed"
        return 1
    fi
    
    # Test normalization endpoint
    test_payload='{
        "tool_name": "nuclei",
        "tool_output": "[critical] SQL injection found at /login?id=1",
        "target_domain": "example.com"
    }'
    
    norm_response=$(curl -s -X POST "http://localhost:${HOST_PORT}/normalize" \
        -H "Content-Type: application/json" \
        -d "$test_payload")
    
    if echo "$norm_response" | jq -e '.success' >/dev/null 2>&1; then
        log_info "Normalization test passed ✓"
        finding_count=$(echo "$norm_response" | jq -r '.count // 0')
        log_info "Processed $finding_count findings"
    else
        log_error "Normalization test failed"
        return 1
    fi
    
    log_info "All tests passed ✓"
}

# Show status
show_status() {
    log_info "Service Status:"
    echo "Container: $CONTAINER_NAME"
    echo "Image: $IMAGE_NAME"
    echo "Port: localhost:$HOST_PORT"
    echo ""
    
    # Container status
    if docker ps -q -f name="$CONTAINER_NAME" | grep -q .; then
        log_info "Container: Running ✓"
        docker ps -f name="$CONTAINER_NAME"
    else
        log_warn "Container: Not running"
    fi
    
    echo ""
    log_info "Service URLs:"
    echo "  Health: http://localhost:$HOST_PORT/health"
    echo "  Normalize: http://localhost:$HOST_PORT/normalize"
    echo "  Status: http://localhost:$HOST_PORT/status"
    
    echo ""
    log_info "Usage Example:"
    echo "curl -X POST http://localhost:$HOST_PORT/normalize \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -d '{\"tool_name\":\"nuclei\",\"tool_output\":\"[high] XSS found\",\"target_domain\":\"example.com\"}'"
}

# Main function
main() {
    case "${1:-build}" in
        build)
            check_resources
            build_image
            ;;
        run)
            stop_container
            run_container
            wait_for_service
            test_service
            show_status
            ;;
        deploy)
            check_resources
            build_image
            stop_container
            run_container
            wait_for_service
            test_service
            show_status
            ;;
        stop)
            stop_container
            log_info "Service stopped"
            ;;
        status)
            show_status
            ;;
        test)
            test_service
            ;;
        logs)
            docker logs -f "$CONTAINER_NAME"
            ;;
        *)
            echo "Production Orca-Mini-3B Docker Manager"
            echo ""
            echo "Usage: $0 {build|run|deploy|stop|status|test|logs}"
            echo ""
            echo "Commands:"
            echo "  build     Build Docker image"
            echo "  run       Run container (image must exist)"
            echo "  deploy    Build and run (full deployment)"
            echo "  stop      Stop container"
            echo "  status    Show service status"
            echo "  test      Test service endpoints"
            echo "  logs      Show container logs"
            echo ""
            echo "Examples:"
            echo "  $0 deploy    # Full deployment"
            echo "  $0 status    # Check status"
            echo "  $0 test      # Test service"
            exit 1
            ;;
    esac
}

# Execute main function
main "$@"
