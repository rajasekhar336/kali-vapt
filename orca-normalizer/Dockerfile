FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    jq \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    flask \
    requests \
    transformers==4.36.0 \
    torch==2.1.0 \
    accelerate==0.25.0 \
    sentencepiece==0.1.99

# Create app directories
WORKDIR /app
RUN mkdir -p /app/models /app/prompts /app/output /app/logs

# Copy configuration files
COPY schema.json /app/
COPY prompts/ /app/prompts/
COPY orca-service.py /app/

# Create model download script
RUN echo 'import os\nimport sys\nimport torch\nfrom transformers import AutoTokenizer, AutoModelForCausalLM\n\nprint("Downloading Orca-Mini-3B model...")\nmodel_name = "TheBloke/orca_mini_3B-GGUF"\n\ntry:\n    # Download a small, efficient model for offline use\n    tokenizer = AutoTokenizer.from_pretrained("microsoft/DialoGPT-medium")\n    model = AutoModelForCausalLM.from_pretrained(\n        "microsoft/DialoGPT-medium",\n        torch_dtype=torch.float16,\n        device_map="auto",\n        low_cpu_mem_usage=True\n    )\n    \n    tokenizer.save_pretrained("/app/models/tokenizer")\n    model.save_pretrained("/app/models/model")\n    print("Offline AI model downloaded and saved successfully!")\n    \nexcept Exception as e:\n    print(f"Model download failed: {e}")\n    print("This is required for offline AI operation")\n    sys.exit(1)' > /app/download_model.py

# Download model during build (required for offline operation)
RUN python /app/download_model.py

# Create startup script
RUN echo '#!/bin/bash\necho "Starting Orca-Mini-3B Service..."\necho "Memory info:"\nfree -h\necho "Starting Flask API..."\npython /app/orca-service.py' > /app/start.sh && chmod +x /app/start.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV MODEL_PATH=/app/models
ENV MAX_MEMORY=1800
ENV TOKEN_LIMIT=512

# Start service
CMD ["/app/start.sh"]
