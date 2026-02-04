FROM python:3.9-slim

# Install system dependencies including Ollama
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    jq \
    git \
    zstd \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

# Install Python dependencies
RUN pip install --no-cache-dir \
    flask \
    requests \
    psutil

# Create app directories
WORKDIR /app
RUN mkdir -p /app/models /app/prompts /app/output /app/logs

# Copy configuration files
COPY schema.json /app/
COPY prompts/ /app/prompts/
COPY orca-service.py /app/
COPY remediation_rules.py /app/
COPY vulnerability_classifier.py /app/

# Create startup script that starts Ollama and our service
RUN echo '#!/bin/bash\n\
echo "Starting Ollama service..."\n\
ollama serve &\n\
sleep 5\n\
echo "Checking for Qwen 0.5B model..."\n\
if ollama list | grep -q "qwen:0.5b"; then\n\
    echo "✓ Qwen 0.5B model already available"\n\
else\n\
    echo "📥 Downloading Qwen 0.5B model (500MB - one-time download)..."\n\
    ollama pull qwen:0.5b\n\
    echo "✓ Model download completed"\n\
fi\n\
echo "Starting Qwen 0.5B AI Service..."\n\
echo "Memory info:"\n\
free -h\n\
echo "Starting Flask API..."\n\
python /app/orca-service.py\n\
' > /app/start.sh && chmod +x /app/start.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8080 11434

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV OLLAMA_HOST=0.0.0.0
ENV MODEL_PATH=/app/models
ENV MAX_MEMORY=1800
ENV TOKEN_LIMIT=512

# Start service
CMD ["/app/start.sh"]
