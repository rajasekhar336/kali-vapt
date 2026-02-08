FROM ghcr.io/zaproxy/zaproxy:stable

# Install additional tools
RUN apt-get update && apt-get install -y \
    curl \
    jq \
    python3 \
    python3-pip

# Create working directory
WORKDIR /zap

# Expose ZAP port
EXPOSE 8080

# Default command
CMD ["zap.sh", "-daemon", "-host", "0.0.0.0", "-port", "8080", "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.port=8080"]
