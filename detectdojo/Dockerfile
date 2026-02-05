FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir flask requests

# Create app directories
WORKDIR /app
RUN mkdir -p /app/logs

# Copy application files
COPY app.py /app/
COPY requirements.txt /app/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Expose port
EXPOSE 8081

# Environment variables
ENV NORMALIZER_URL=http://127.0.0.1:8080
ENV PYTHONUNBUFFERED=1

# Start Flask app
CMD ["python", "/app/app.py"]
