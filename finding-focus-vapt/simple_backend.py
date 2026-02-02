from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import json
from datetime import datetime

app = FastAPI(title="VAPT Test API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": "simulated",
            "redis": "simulated", 
            "ai_service": await check_ai_health()
        }
    }

async def check_ai_health():
    try:
        response = requests.get("http://localhost:8080/health", timeout=5)
        return "healthy" if response.status_code == 200 else "unhealthy"
    except:
        return "unhealthy"

@app.post("/api/scans")
async def create_scan(scan_data: dict):
    return {
        "scan_id": "test-scan-123",
        "target_domain": scan_data.get("target_domain"),
        "status": "pending",
        "message": "Test scan started successfully"
    }

@app.get("/api/scans")
async def list_scans():
    return {
        "scans": [
            {
                "id": "test-scan-123",
                "target_domain": "example.com",
                "scan_type": "full",
                "status": "completed",
                "started_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat()
            }
        ]
    }

@app.get("/api/scans/test-scan-123/vulnerabilities")
async def get_vulnerabilities():
    return {
        "vulnerabilities": [
            {
                "id": "vuln-1",
                "tool_name": "nuclei",
                "title": "Content Security Policy Violation",
                "severity": "medium",
                "issue_type": "csp_violation",
                "endpoint": "https://example.com/",
                "description": "CSP allows unsafe inline scripts",
                "cvss_score": 5.4,
                "cve_id": None,
                "created_at": datetime.utcnow().isoformat(),
                "has_remediation": False
            },
            {
                "id": "vuln-2", 
                "tool_name": "nikto",
                "title": "Missing X-Frame-Options Header",
                "severity": "low",
                "issue_type": "security_headers_missing",
                "endpoint": "https://example.com/",
                "description": "The anti-clickjacking X-Frame-Options header is not present",
                "cvss_score": 2.1,
                "cve_id": None,
                "created_at": datetime.utcnow().isoformat(),
                "has_remediation": False
            }
        ]
    }

@app.get("/api/vulnerabilities/{vuln_id}/remediation")
async def get_remediation(vuln_id: str):
    # Call AI service for remediation
    try:
        response = requests.post(
            "http://localhost:8080/normalize",
            json={
                "tool_name": "nuclei",
                "tool_output": "CSP violation found at https://example.com/",
                "target_domain": "example.com"
            },
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "findings": [{
                    "title": "Remediation Unavailable",
                    "remediation": "AI service temporarily unavailable. Please check CSP headers and remove unsafe-inline directives.",
                    "severity": "medium",
                    "confidence": "low"
                }]
            }
    except Exception as e:
        return {
            "findings": [{
                "title": "Remediation Error", 
                "remediation": f"Error contacting AI service: {str(e)}. Manual remediation recommended.",
                "severity": "medium",
                "confidence": "low"
            }]
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
