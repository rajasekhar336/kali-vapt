Deployment recommendations for Kali VAPT (with DetectDojo Orchestrator)

Overview
--------
The VAPT framework now uses DetectDojo as the central orchestrator:

1. `run_enhanced.sh` → Runs 40+ security tools → produces raw outputs
2. `send_to_detectdojo.sh` → Posts tool outputs to DetectDojo (port 8081)
3. DetectDojo → Calls normalizer (port 8080) for AI processing → stores findings
4. DetectDojo → Deduplicates, correlates, scores findings → exposes REST API + HTML reports

This flow ensures all findings are normalized and scored consistently through the AI model.

Key Components
--------------
- **run_enhanced.sh** (port N/A): Orchestrates security tools
- **qwen-0.5b-normalizer** (port 8080): AI vulnerability normalization service
- **detectdojo** (port 8081): Findings orchestrator and reporting

Recommended docker-compose snippet
----------------------------------
Example to run all services together (adjust to your environment):

```yaml
version: '3.8'

services:
  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    restart: unless-stopped
    ports:
      - "11434:11434"
    volumes:
      - ollama_data:/root/.ollama
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:11434/api/tags"]
      interval: 30s
      timeout: 10s
      retries: 5

  qwen-0.5b-normalizer:
    build:
      context: ./qwen-0.5b-normalizer
    environment:
      - OLLAMA_URL=http://ollama:11434
    depends_on:
      - ollama
    ports:
      - "8080:8080"
    restart: unless-stopped

  detectdojo:
    build:
      context: ./detectdojo
    ports:
      - "8081:8081"
    environment:
      - NORMALIZER_URL=http://qwen-0.5b-normalizer:8080
    depends_on:
      - qwen-0.5b-normalizer
    restart: unless-stopped

volumes:
  ollama_data:
    driver: local
```

DetectDojo REST API
-------------------
- **GET /health** → Service health
- **POST /api/findings/add** → Add raw tool output (DetectDojo will normalize via Qwen)
- **GET /api/findings/<assessment_id>** → Get deduplicated findings
- **GET /api/report/<assessment_id>** → Get security report (JSON)
- **GET /api/report/<assessment_id>/html** → Get HTML report
- **GET /api/assessments** → List all assessments

Example: Send nuclei findings
```bash
curl -X POST http://localhost:8081/api/findings/add \
  -H "Content-Type: application/json" \
  -d '{
    "tool_name": "nuclei",
    "target_domain": "example.com",
    "tool_output": "[raw nuclei JSON output here]"
  }'
```

Example: Get security report
```bash
curl http://localhost:8081/api/report/assessment_example_com_20260204 | jq .
```

Example: Get HTML report
```bash
curl http://localhost:8081/api/report/assessment_example_com_20260204/html > report.html
```

Using send_to_detectdojo.sh helper
----------------------------------
From `run_enhanced.sh`, you can send tool outputs easily:

```bash
./send_to_detectdojo.sh nuclei example.com ./logs/nuclei_findings.json
./send_to_detectdojo.sh sqlmap example.com ./logs/sqlmap_findings.json
```

Security checklist for production
---------------------------------
- Run containers as non-root users where possible.
- Use network segmentation: place AI services on an internal network; only expose required ports.
- Apply resource limits (CPU, memory) to AI and normalization services.
- Configure log rotation and avoid persisting raw sensitive outputs long-term.
- Enable TLS for exposed HTTP endpoints (use reverse proxy or ingress controller).
- Add monitoring and alerting for high memory or CPU usage.
- Secure the DetectDojo API with authentication (API key or OAuth).

Model and installer verification
--------------------------------
- Verify Ollama installer checksums before executing in production.
- Prefer vendor-provided packages or pinned container images.

Operational notes
-----------------
- For large model downloads, pull and cache model artifacts in a controlled build pipeline.
- Back up assessment data and model volumes securely.
- Keep an inventory of container images and check for CVEs using image scanners.
- Monitor DetectDojo and normalizer service logs for failures.


