Kali VAPT — Security Hardening Report

Summary of changes applied
--------------------------
- Patched `qwen-0.5b-normalizer/orca-service.py`:
  - Added missing imports for `vulnerability_classifier` and `remediation_rules`.
  - Added a robust `_extract_json_from_ai_response()` helper to parse AI JSON safely.
  - Added `validate_against_schema()` to validate AI outputs against `schema.json` using `jsonschema`.
  - Changed `load_model()` to fallback to mock mode instead of exiting when Ollama is unavailable.

- Added `qwen-0.5b-normalizer/requirements.txt` (pinned deps), unit tests, and lint/security deps (`flake8`, `bandit`).
- Added CI workflow `.github/workflows/ci.yml` to run tests, flake8, and Bandit.
- Added secret scanning workflow `.github/workflows/secret-scan.yml` using TruffleHog action.
- Added `.pre-commit-config.yaml` including detect-secrets and flake8 hooks.
- Hardening in top-level `Dockerfile` and `qwen-0.5b-normalizer/Dockerfile` to avoid piping remote scripts directly and to not start Ollama within the normalizer container.
- Commented out `docker.sock` mount in `docker-compose.yml` and recommended running Ollama as a separate service.

Outstanding recommendations (prioritized)
----------------------------------------
1. Replace any remaining `curl | sh` patterns with downloaded, verified installers or container images.
2. Add JSON schema file that fully specifies expected fields and types for AI outputs (expand `schema.json`).
3. Add unit tests for `remediation_rules.py` and more extensive tests for `orca-service.py` endpoints (mock Ollama API).
4. Add image scanning to CI (e.g., GitHub Actions with Trivy) and enforce scanning on PRs.
5. Introduce secret management (Vault or cloud provider secret managers) and avoid environment secrets in CI logs.
6. Consider moving to Kubernetes or an orchestrator where you can enforce resource limits and network policies.

Suggested next steps to deploy securely
--------------------------------------
- Create a deployment pipeline that builds images, runs tests, scans images, and only then deploys to production.
- Run the `qwen-0.5b-normalizer` behind an authenticated proxy and ensure Ollama API is accessible only from internal networks.
- Add runtime monitoring and alerting for high memory/CPU and failed health checks.

If you want, I can now:
- Expand `schema.json` to a strict JSON Schema for validation.
- Add unit tests and mocks for `orca-service.py` endpoints.
- Add image scanning CI step (Trivy) and a pre-commit secrets baseline.

Which of these should I implement next? 
