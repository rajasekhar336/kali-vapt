FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVIRONMENTS=/app/.venv \
    POETRY_CACHE_DIR=/root/.cache/pypoetry

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    docker.io \
    curl \
    uuid-runtime \
    && rm -rf /var/lib/apt/lists/*

# Create appuser with docker group access
RUN groupadd -r -f docker && useradd -m -u 1001 appuser && \
    usermod -aG docker appuser || true

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads /app/reports

# Set permissions
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Start command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
