#!/bin/bash

# Qwen 0.5B Service Docker Manager
# All Docker operations in one place

set -euo pipefail

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

# Docker operations
start() {
    log_info "Starting Qwen 0.5B service with Docker Compose..."
    docker compose up -d
    log_info "Waiting for service to be ready..."
    sleep 5
    
    if curl -s http://localhost:8080/health >/dev/null 2>&1; then
        log_info "Qwen 0.5B service is ready! ✓"
    else
        log_error "Service failed to start"
        return 1
    fi
}

stop() {
    log_info "Stopping Qwen 0.5B service..."
    docker compose down
    log_info "Service stopped"
}

restart() {
    log_info "Restarting Qwen 0.5B service..."
    docker compose restart
    sleep 3
    log_info "Service restarted"
}

logs() {
    docker compose logs -f
}

status() {
    log_info "Qwen 0.5B Service Status:"
    docker compose ps
    
    if curl -s http://localhost:8080/health >/dev/null 2>&1; then
        log_info "Health: ✓ Running"
        curl -s http://localhost:8080/status | jq . 2>/dev/null || echo "Status endpoint available"
    else
        log_warn "Health: ✗ Not responding"
    fi
}

test() {
    log_info "Testing Orca service..."
    
    # Test health
    if curl -s http://localhost:8080/health >/dev/null 2>&1; then
        log_info "Health check passed ✓"
    else
        log_error "Health check failed"
        return 1
    fi
    
    # Test normalization
    test_payload='{"tool_name":"zap","tool_output":"[critical] SQL injection at /login","target_domain":"example.com"}'
    
    response=$(curl -s -X POST "http://localhost:8080/normalize" \
        -H "Content-Type: application/json" \
        -d "$test_payload")
    
    if echo "$response" | jq -e '.success' >/dev/null 2>&1; then
        log_info "Normalization test passed ✓"
        count=$(echo "$response" | jq -r '.count // 0')
        log_info "Processed $count findings"
    else
        log_error "Normalization test failed"
        return 1
    fi
    
    log_info "All tests passed ✓"
}

# Main function
case "${1:-start}" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    test)
        test
        ;;
    logs)
        logs
        ;;
    *)
        echo "Orca Docker Manager"
        echo ""
        echo "Usage: $0 {start|stop|restart|status|test|logs}"
        echo ""
        echo "Commands:"
        echo "  start    Build and start service"
        echo "  stop     Stop service"
        echo "  restart  Restart service"
        echo "  status   Show service status"
        echo "  test     Test service endpoints"
        echo "  logs     Show service logs"
        echo ""
        echo "Examples:"
        echo "  $0 start     # Start the service"
        echo "  $0 status    # Check status"
        echo "  $0 test      # Test functionality"
        exit 1
        ;;
esac
