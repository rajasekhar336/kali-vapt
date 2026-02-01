#!/bin/bash

# Production Deployment Script for VAPT Web UI
set -e

echo "🚀 DEPLOYING VAPT PRODUCTION SYSTEM"

# Environment variables
export COMPOSE_PROJECT_NAME="vapt-prod"
export COMPOSE_FILE="docker-compose.production.yml"

# Create environment file if not exists
if [ ! -f .env ]; then
    echo "📝 Creating .env file with secure defaults..."
    cat > .env << EOF
# Database Configuration
DB_PASSWORD=vapt_secure_db_password_$(date +%s)

# Redis Configuration  
REDIS_PASSWORD=vapt_secure_redis_password_$(date +%s)

# Application Configuration
SECRET_KEY=vapt_secret_key_$(openssl rand -hex 32)

# Monitoring
GRAFANA_PASSWORD=vapt_grafana_admin_$(date +%s)

# SSL Configuration (replace with your certificates)
SSL_CERT_PATH=./nginx/ssl/cert.pem
SSL_KEY_PATH=./nginx/ssl/key.pem
EOF
fi

# Load environment variables
source .env

echo "🔧 Creating SSL directory..."
mkdir -p nginx/ssl

# Generate self-signed certificate for testing (replace with real certificates in production)
if [ ! -f nginx/ssl/cert.pem ]; then
    echo "🔐 Generating self-signed SSL certificate..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/key.pem \
        -out nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
fi

echo "🏗️ Building production images..."
docker-compose -f $COMPOSE_FILE build --no-cache

echo "🗄️ Initializing database..."
docker-compose -f $COMPOSE_FILE up -d vapt-db vapt-redis

echo "⏳ Waiting for database to be ready..."
sleep 30

echo "🚀 Starting all services..."
docker-compose -f $COMPOSE_FILE up -d

echo "⏳ Waiting for services to be healthy..."
sleep 60

echo "🔍 Checking service health..."
docker-compose -f $COMPOSE_FILE ps

echo "📊 Access URLs:"
echo "🌐 Frontend: https://localhost"
echo "🔧 Backend API: https://localhost/api"
echo "📈 Grafana: http://localhost:3001 (admin: $GRAFANA_PASSWORD)"
echo "📊 Prometheus: http://localhost:9090"
echo "📚 API Docs: https://localhost/docs"

echo "🎉 VAPT Production System deployed successfully!"
echo ""
echo "📋 Next Steps:"
echo "1. Replace self-signed SSL certificates with real certificates"
echo "2. Update passwords in .env file"
echo "3. Configure monitoring alerts in Grafana"
echo "4. Set up backup strategies for database"
echo "5. Configure CI/CD pipeline for automated deployments"

# Health check
echo "🔍 Final health check..."
if curl -f http://localhost/api/health > /dev/null 2>&1; then
    echo "✅ Backend API is healthy"
else
    echo "❌ Backend API health check failed"
fi

if curl -f http://localhost > /dev/null 2>&1; then
    echo "✅ Frontend is healthy"
else
    echo "❌ Frontend health check failed"
fi

echo "🎊 Deployment complete!"
