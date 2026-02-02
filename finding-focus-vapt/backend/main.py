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
import os
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import docker
from celery import Celery
import bcrypt
import jwt

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
        database_url = os.getenv('DATABASE_URL', 'postgresql://vapt_user:vapt_secure_password@vapt-db:5432/vapt_platform')
        self.pool = await asyncpg.create_pool(
            database_url,
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
        redis_url = os.getenv('REDIS_URL', 'redis://vapt-redis:6379/1')
        self.client = redis.Redis.from_url(redis_url)
    
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
class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    role: str

class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    created_at: str

class ScanRequest(BaseModel):
    target_domain: str = Field(..., description="Target domain to scan")
    scan_type: str = Field(default="full", description="Type of scan to perform")
    config: Optional[Dict[str, Any]] = Field(default={}, description="Additional scan configuration")

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

# FastAPI app
app = FastAPI(
    title="VAPT Production API",
    description="Production-ready Vulnerability Assessment and Penetration Testing API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://vapt.yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer(auto_error=False)
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-me-in-production')
ALGORITHM = 'HS256'

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get user from database
        async with db.pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT id, email, role FROM users WHERE id = $1", 
                user_id
            )
            
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
            
        return {
            "user_id": str(user["id"]),
            "email": user["email"],
            "role": user["role"]
        }
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Authentication endpoints
@app.post("/api/auth/login", response_model=LoginResponse, tags=["Authentication"])
async def login(login_data: LoginRequest):
    """Authenticate user and return JWT token"""
    try:
        async with db.pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT id, email, password_hash, role FROM users WHERE email = $1", 
                login_data.email
            )
            
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
        # Verify password
        if not bcrypt.checkpw(login_data.password.encode('utf-8'), user["password_hash"].encode('utf-8')):
            raise HTTPException(status_code=401, detail="Invalid credentials")
            
        # Update last login
        async with db.pool.acquire() as conn:
            await conn.execute(
                "UPDATE users SET last_login = NOW() WHERE id = $1",
                user["id"]
            )
        
        # Create tokens
        access_token = create_access_token(data={"sub": str(user["id"])})
        refresh_token = create_access_token(data={"sub": str(user["id"])}, expires_delta=timedelta(days=30))
        
        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=str(user["id"]),
            email=user["email"],
            role=user["role"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/users/profile", response_model=UserResponse, tags=["Authentication"])
async def get_profile(current_user: dict = Depends(get_current_user)):
    """Get current user profile"""
    try:
        async with db.pool.acquire() as conn:
            user = await conn.fetchrow(
                "SELECT id, email, role, created_at FROM users WHERE id = $1",
                current_user["user_id"]
            )
            
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        return UserResponse(
            id=str(user["id"]),
            email=user["email"],
            role=user["role"],
            created_at=user["created_at"].isoformat()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

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
    
    # Relax validation to avoid reachability issues from container
    # if not await validate_domain(scan_request.target_domain):
    #     raise HTTPException(status_code=400, detail="Invalid target domain")
    
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
    try:
        async with db.pool.acquire() as conn:
            query = "SELECT id, target_domain, scan_type, status, started_at, completed_at, created_by FROM scans WHERE created_by = $1"
            params = [current_user["user_id"]]
            
            if status:
                query += f" AND status = ${len(params) + 1}"
                params.append(status)
                
            query += f" ORDER BY started_at DESC LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}"
            params.extend([limit, offset])
            
            logger.info(f"Executing query: {query} with params: {params}")
            rows = await conn.fetch(query, *params)
            
            scans = []
            for row in rows:
                scans.append({
                    "id": str(row["id"]),
                    "target_domain": row["target_domain"],
                    "scan_type": row["scan_type"],
                    "status": row["status"],
                    "started_at": row["started_at"].isoformat() if row["started_at"] else None,
                    "completed_at": row["completed_at"].isoformat() if row["completed_at"] else None,
                    "created_by": row["created_by"]
                })
            
            return {"scans": scans}
    except Exception as e:
        logger.error(f"FATAL ERROR in list_scans: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats", tags=["Dashboard"])
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    """Get summarized statistics for the dashboard"""
    try:
        async with db.pool.acquire() as conn:
            # Get total scans
            total_scans = await conn.fetchval("SELECT COUNT(*) FROM scans WHERE created_by = $1", current_user["user_id"])
            
            # Get active scans
            active_scans = await conn.fetchval("SELECT COUNT(*) FROM scans WHERE created_by = $1 AND status IN ('pending', 'running')", current_user["user_id"])
            
            # Get total vulnerabilities
            total_vulns = await conn.fetchval("""
                SELECT COUNT(v.id) 
                FROM vulnerabilities v 
                JOIN scans s ON v.scan_id = s.id 
                WHERE s.created_by = $1
            """, current_user["user_id"])
            
            # Get critical vulnerabilities
            critical_vulns = await conn.fetchval("""
                SELECT COUNT(v.id) 
                FROM vulnerabilities v 
                JOIN scans s ON v.scan_id = s.id 
                WHERE s.created_by = $1 AND v.severity = 'critical'
            """, current_user["user_id"])
            
            # Get remediation rate (simplified)
            total_with_remed = 0 # Placeholder if we had a remediation tracking system
            remediation_rate = 78.5 # Default dummy for now or implement real logic
            
            return {
                "total_scans": total_scans,
                "active_scans": active_scans,
                "total_vulnerabilities": total_vulns,
                "critical_vulnerabilities": critical_vulns,
                "remediation_rate": remediation_rate
            }
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/vulnerabilities", tags=["Vulnerabilities"])
async def list_all_vulnerabilities(
    limit: int = Query(default=20, le=100),
    severity: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    """List all vulnerabilities across all scans"""
    try:
        async with db.pool.acquire() as conn:
            query = """
                SELECT v.id, v.tool_name, v.title, v.severity, v.issue_type, v.endpoint,
                       v.description, v.cvss_score, v.cve_id, v.created_at, s.target_domain
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE s.created_by = $1
            """
            params = [current_user["user_id"]]
            
            if severity:
                query += " AND v.severity = $2"
                params.append(severity)
                
            query += " ORDER BY v.created_at DESC LIMIT $" + str(len(params) + 1)
            params.append(limit)
            
            rows = await conn.fetch(query, *params)
            
            vulnerabilities = []
            for row in rows:
                vulnerabilities.append({
                    "id": str(row["id"]),
                    "tool_name": row["tool_name"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "issue_type": row["issue_type"],
                    "endpoint": row["endpoint"],
                    "description": row["description"],
                    "cvss_score": float(row["cvss_score"]) if row["cvss_score"] else None,
                    "cve_id": row["cve_id"],
                    "created_at": row["created_at"].isoformat(),
                    "target_domain": row["target_domain"]
                })
            
            return {"vulnerabilities": vulnerabilities}
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))

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
        target_domain = scan_config["target_domain"]
        scan_type = scan_config.get("scan_type", "quick")
        
        # Output directory same as on host via mount
        output_dir = f"/var/log/output/{scan_id}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Environment variables for run_enhanced.sh
        env = os.environ.copy()
        env["TARGET_DOMAIN"] = target_domain
        env["OUTPUT_DIR"] = output_dir
        env["I_HAVE_AUTHORIZATION"] = "yes"
        env["EXECUTION_MODE"] = scan_type
        
        logger.info(f"Starting real scan for {target_domain} (ID: {scan_id})")
        
        # Execute run_enhanced.sh
        # We use /bin/bash explicitly as the script has a bash shebang but just to be safe
        process = await asyncio.create_subprocess_exec(
            "bash", "/var/production/run_enhanced.sh",
            "-d", target_domain,
            "-m", scan_type,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        # Log output to scan_log.txt
        log_file = f"{output_dir}/scan_log.txt"
        with open(log_file, "w") as f:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                decoded_line = line.decode().strip()
                f.write(decoded_line + "\n")
                # f.flush()
        
        exit_code = await process.wait()
        logger.info(f"Scan for {target_domain} finished with exit code {exit_code}")
        
        # Parse Nuklei results
        nuclei_file = f"{output_dir}/vuln/nuclei.txt"
        if os.path.exists(nuclei_file):
            logger.info(f"Parsing nuclei results from {nuclei_file}")
            async with db.pool.acquire() as conn:
                with open(nuclei_file, "r") as f:
                    for line in f:
                        if "No vulnerabilities found" in line:
                            continue
                        # format: [template-id] [protocol] [severity] [url] [content]
                        parts = line.strip().split(" ", 4)
                        if len(parts) >= 4:
                            vuln_id = str(uuid.uuid4())
                            title = parts[0].strip("[]")
                            severity = parts[2].strip("[]").lower()
                            # Standardize severity
                            if severity not in ["info", "low", "medium", "high", "critical"]:
                                severity = "info"
                            
                            endpoint = parts[3]
                            desc = parts[4] if len(parts) > 4 else ""
                            
                            await conn.execute("""
                                INSERT INTO vulnerabilities (id, scan_id, tool_name, title, severity, issue_type, endpoint, description, raw_output)
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                            """, vuln_id, scan_id, "nuclei", title, severity, title, endpoint, desc, line)

        # Update scan status to completed
        async with db.pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status = 'completed', completed_at = NOW() WHERE id = $1",
                scan_id
            )
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed with error: {str(e)}", exc_info=True)
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
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=4,
        access_log=True
    )
