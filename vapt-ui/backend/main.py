from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import asyncpg
import redis.asyncio as redis
import json
import uuid
import asyncio
import aiohttp
import logging
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import docker
from celery import Celery

# Production logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Celery configuration
celery_app = Celery(
    'vapt_production',
    broker='redis://vapt-redis:6379/0',
    backend='redis://vapt-redis:6379/0'
)

# Database connection pool
class Database:
    def __init__(self):
        self.pool = None
    
    async def init(self):
        self.pool = await asyncpg.create_pool(
            'postgresql://vapt_user:vapt_secure_password@vapt-db:5432/vapt_platform',
            min_size=5,
            max_size=20,
            command_timeout=60
        )
    
    async def close(self):
        if self.pool:
            await self.pool.close()

db = Database()

# Redis connection
class RedisClient:
    def __init__(self):
        self.client = None
    
    async def init(self):
        self.client = redis.Redis.from_url('redis://vapt-redis:6379/1')
    
    async def close(self):
        if self.client:
            await self.client.close()

redis_client = RedisClient()

# Docker client (lazy initialization)
docker_client = None

def get_docker_client():
    global docker_client
    if docker_client is None:
        docker_client = docker.from_env()
    return docker_client

# Pydantic models
class ScanRequest(BaseModel):
    target_domain: str = Field(..., pattern=r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    scan_type: str = Field(default='full', pattern=r'^(full|quick|custom)$')
    tools: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = None

class ScanResponse(BaseModel):
    scan_id: str
    target_domain: str
    status: str
    message: str

class Vulnerability(BaseModel):
    id: str
    tool_name: str
    title: str
    severity: str
    issue_type: str
    endpoint: Optional[str]
    description: str
    cvss_score: Optional[float]
    cve_id: Optional[str]
    created_at: datetime

class RemediationRequest(BaseModel):
    vulnerability_id: str

class ReportRequest(BaseModel):
    scan_id: str
    format: str = Field(default='pdf', pattern=r'^(pdf|docx|json|csv)$')
    include_remediation: bool = True

# Security
security = HTTPBearer(auto_error=False)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Implement JWT validation here
    return {"user_id": "demo_user", "role": "admin"}

# Application lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await db.init()
    await redis_client.init()
    logger.info("Production VAPT API started successfully")
    
    yield
    
    # Shutdown
    await db.close()
    await redis_client.close()
    logger.info("Production VAPT API stopped")

# FastAPI app
app = FastAPI(
    title="VAPT Production API",
    description="Production-ready Vulnerability Assessment and Penetration Testing API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://vapt.yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check
@app.get("/api/health", tags=["Health"])
async def health_check():
    """Comprehensive health check for all services"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": await check_database_health(),
            "redis": await check_redis_health(),
            "ai_service": await check_ai_health(),
            "docker": await check_docker_health()
        }
    }
    
    # Check if any service is unhealthy
    if any(service != "healthy" for service in health_status["services"].values()):
        health_status["status"] = "degraded"
    
    return health_status

async def check_database_health():
    try:
        async with db.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        return "healthy"
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return "unhealthy"

async def check_redis_health():
    try:
        await redis_client.client.ping()
        return "healthy"
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return "unhealthy"

async def check_ai_health():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('http://qwen-0.5b-normalizer-prod:8080/health', timeout=5) as response:
                return "healthy" if response.status == 200 else "unhealthy"
    except Exception as e:
        logger.error(f"AI service health check failed: {e}")
        return "unhealthy"

async def check_docker_health():
    try:
        client = get_docker_client()
        client.ping()
        return "healthy"
    except Exception as e:
        logger.error(f"Docker health check failed: {e}")
        return "unhealthy"

# Scan management
@app.post("/api/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
):
    """Create and start a new VAPT scan"""
    scan_id = str(uuid.uuid4())
    
    # Validate domain
    if not await validate_domain(scan_request.target_domain):
        raise HTTPException(status_code=400, detail="Invalid target domain")
    
    # Insert scan into database
    async with db.pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO scans (id, target_domain, scan_type, status, config, created_by)
            VALUES ($1, $2, $3, $4, $5, $6)
        """, scan_id, scan_request.target_domain, scan_request.scan_type, 
            'pending', json.dumps(scan_request.dict()), current_user["user_id"])
    
    # Start background scan
    background_tasks.add_task(execute_scan_background, scan_id, scan_request.dict())
    
    logger.info(f"Scan {scan_id} started for {scan_request.target_domain} by {current_user['user_id']}")
    
    return ScanResponse(
        scan_id=scan_id,
        target_domain=scan_request.target_domain,
        status="pending",
        message="Scan started successfully"
    )

@app.get("/api/scans", tags=["Scans"])
async def list_scans(
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    """List scans with pagination and filtering"""
    async with db.pool.acquire() as conn:
        query = """
            SELECT id, target_domain, scan_type, status, started_at, completed_at, created_by
            FROM scans
            WHERE created_by = $1
        """
        params = [current_user["user_id"]]
        
        if status:
            query += " AND status = $2"
            params.append(status)
        
        query += " ORDER BY started_at DESC LIMIT $%s OFFSET $%s"
        params.extend([limit, offset])
        
        # Adjust parameter placeholders for asyncpg
        param_placeholders = []
        for i, param in enumerate(params, 1):
            param_placeholders.append(f"${i}")
        
        query = query.replace("$%s", param_placeholders[-2]).replace("$%s", param_placeholders[-1])
        
        rows = await conn.fetch(query, *params)
        
        scans = []
        for row in rows:
            scans.append({
                "id": row["id"],
                "target_domain": row["target_domain"],
                "scan_type": row["scan_type"],
                "status": row["status"],
                "started_at": row["started_at"].isoformat(),
                "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
                "created_by": row["created_by"]
            })
        
        return {"scans": scans}

@app.get("/api/scans/{scan_id}/vulnerabilities", tags=["Vulnerabilities"])
async def get_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = Query(None),
    tool: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    """Get vulnerabilities for a specific scan"""
    async with db.pool.acquire() as conn:
        # Verify scan ownership
        scan = await conn.fetchval(
            "SELECT created_by FROM scans WHERE id = $1", scan_id
        )
        if not scan or scan != current_user["user_id"]:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        query = """
            SELECT id, tool_name, title, severity, issue_type, endpoint,
                   description, cvss_score, cve_id, created_at
            FROM vulnerabilities
            WHERE scan_id = $1
        """
        params = [scan_id]
        
        if severity:
            query += " AND severity = $2"
            params.append(severity)
        
        if tool:
            query += " AND tool_name = $%s"
            params.append(tool)
        
        query += " ORDER BY severity DESC, created_at DESC"
        
        rows = await conn.fetch(query, *params)
        
        vulnerabilities = []
        for row in rows:
            vulnerabilities.append({
                "id": row["id"],
                "tool_name": row["tool_name"],
                "title": row["title"],
                "severity": row["severity"],
                "issue_type": row["issue_type"],
                "endpoint": row["endpoint"],
                "description": row["description"],
                "cvss_score": float(row["cvss_score"]) if row["cvss_score"] else None,
                "cve_id": row["cve_id"],
                "created_at": row["created_at"].isoformat(),
                "has_remediation": await redis_client.client.exists(f"remediation:{row['id']}")
            })
        
        return {"vulnerabilities": vulnerabilities}

@app.get("/api/vulnerabilities/{vuln_id}/remediation", tags=["AI"])
async def get_remediation(
    vuln_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get AI-powered remediation for a vulnerability"""
    # Check cache first
    cache_key = f"remediation:{vuln_id}"
    cached = await redis_client.client.get(cache_key)
    
    if cached:
        return json.loads(cached)
    
    # Get vulnerability details
    async with db.pool.acquire() as conn:
        vuln = await conn.fetchrow("""
            SELECT v.tool_name, v.title, v.severity, v.description, v.raw_output, v.endpoint,
                   s.target_domain, s.created_by
            FROM vulnerabilities v
            JOIN scans s ON v.scan_id = s.id
            WHERE v.id = $1
        """, vuln_id)
    
    if not vuln or vuln["created_by"] != current_user["user_id"]:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # Call AI service
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                'http://qwen-0.5b-normalizer-prod:8080/normalize',
                json={
                    'tool_name': vuln["tool_name"],
                    'tool_output': vuln["raw_output"] or vuln["description"],
                    'target_domain': vuln["target_domain"]
                },
                timeout=30
            ) as response:
                if response.status == 200:
                    ai_result = await response.json()
                    
                    # Cache for 1 hour
                    await redis_client.client.setex(
                        cache_key, 3600, json.dumps(ai_result)
                    )
                    
                    return ai_result
                else:
                    raise HTTPException(status_code=503, detail="AI service unavailable")
    
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="AI service timeout")
    except Exception as e:
        logger.error(f"AI service error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Background tasks
async def execute_scan_background(scan_id: str, scan_config: dict):
    """Execute VAPT scan in background"""
    async with db.pool.acquire() as conn:
        await conn.execute(
            "UPDATE scans SET status = 'running', started_at = NOW() WHERE id = $1",
            scan_id
        )
    
    try:
        # Execute tools using Docker containers
        target_domain = scan_config["target_domain"]
        
        # This would integrate with your existing run_enhanced.sh
        # For now, simulate the scan
        await asyncio.sleep(30)  # Simulate scan time
        
        # Update scan status
        async with db.pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status = 'completed', completed_at = NOW() WHERE id = $1",
                scan_id
            )
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        async with db.pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status = 'failed' WHERE id = $1",
                scan_id
            )

async def validate_domain(domain: str) -> bool:
    """Validate target domain"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{domain}", timeout=5) as response:
                return True
    except:
        return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=4,
        access_log=True
    )
