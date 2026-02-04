VAPT Framework Integration Guide

Architecture
============

The VAPT framework now follows this end-to-end flow:

1. run_enhanced.sh (VAPT Engine)
   ├─ Runs 40+ security tools
   └─ Outputs raw tool results to log directory

2. send_to_detectdojo() (in run_enhanced.sh)
   ├─ Sends each tool's raw output to DetectDojo via REST API
   └─ POST to http://detectdojo:8081/api/findings/add

3. DetectDojo (port 8081)
   ├─ Receives raw tool outputs
   ├─ Calls qwen-0.5b-normalizer (port 8080) for AI processing
   │  ├─ Normalizes findings (title, severity, description)
   │  ├─ Generates remediation steps
   │  └─ Adds confidence scores
   ├─ Deduplicates findings (removes duplicates across tools)
   ├─ Correlates findings (groups by severity, endpoint)
   ├─ Calculates overall security score (0-100)
   └─ Exposes REST API and HTML reports

4. Qwen 0.5B Model (port 8080)
   ├─ Runs Ollama (port 11434)
   └─ Returns normalized findings with remediation

Data Flow Example
=================

Tool: nuclei
Raw output: [{"id":"cve-2021-44228", "template":"log4j-rce"}]
                    ↓
DetectDojo /api/findings/add (POST)
                    ↓
Qwen Normalizer (detects: Log4j RCE, severity: critical)
                    ↓
DetectDojo stores:
{
  "title": "Log4j Remote Code Execution",
  "severity": "critical",
  "tool": "nuclei",
  "description": "Log4j RCE vulnerability allows remote code execution",
  "remediation": "Upgrade Log4j to 2.17.0 or later..."
}

REST API Endpoints
==================

POST /api/findings/add
  - Body: { tool_name, target_domain, tool_output }
  - Sends raw output to normalizer and stores result
  - Returns: { success, assessment_id, total_findings }

GET /api/findings/<assessment_id>
  - Returns: Deduplicated findings, grouped by severity
  - Includes: title, severity, description, remediation, tool, endpoint

GET /api/report/<assessment_id>
  - Returns: JSON report with security score, summary, top issues

GET /api/report/<assessment_id>/html
  - Returns: HTML report with formatted findings table and details

GET /api/assessments
  - Returns: List of all assessments with scores

Environment Variables (docker-compose)
======================================

qwen-0.5b-normalizer:
  - OLLAMA_URL: http://ollama:11434 (or http://127.0.0.1:11434 for local dev)

detectdojo:
  - NORMALIZER_URL: http://qwen-0.5b-normalizer:8080
  - DETECTDOJO_URL: (accessible at http://localhost:8081)

run_enhanced.sh:
  - DETECTDOJO_URL: http://localhost:8081
  - AI_SERVICE_URL: http://localhost:8080 (for health checks, not used now)

Testing the Integration Locally
================================

1. Start services:
   docker-compose up -d

2. Check health:
   curl http://localhost:8081/health
   curl http://localhost:8080/health

3. Send a test finding:
   curl -X POST http://localhost:8081/api/findings/add \
     -H "Content-Type: application/json" \
     -d '{
       "tool_name": "test",
       "target_domain": "example.com",
       "tool_output": "SQL injection in parameter id: SELECT * FROM users WHERE id = 1 OR 1=1"
     }'

4. Retrieve assessment:
   curl http://localhost:8081/api/assessments | jq .
   
   # Get the assessment_id from the response, then:
   curl http://localhost:8081/api/report/assessment_example_com_20260204/html > report.html

Troubleshooting
===============

**DetectDojo can't connect to normalizer:**
- Ensure qwen-0.5b-normalizer container is running: docker ps
- Check logs: docker logs qwen-0.5b-normalizer-prod
- Verify NORMALIZER_URL in detectdojo env vars

**Findings not showing up:**
- Check DetectDojo logs: docker logs detectdojo-server
- Verify tool_output is not empty in POST request
- Ensure normalizer is responsive: curl http://localhost:8080/health

**Security score is 0:**
- Check if findings were successfully normalized
- Verify severity field is correctly set (critical|high|medium|low|info)
- Use GET /api/findings/<assessment_id> to inspect findings

Next Steps
==========

1. Integrate with web UI (React/Vue) to display findings in real-time
2. Add authentication to DetectDojo API (API keys or OAuth)
3. Add database backend (PostgreSQL/MongoDB) for persistent storage
4. Add webhook notifications when critical findings are discovered
5. Add automatic remediation suggestions based on remediation field
6. Add CIS benchmark scoring and compliance reports
