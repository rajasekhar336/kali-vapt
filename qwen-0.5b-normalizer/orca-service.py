#!/usr/bin/env python3
"""
Production Qwen 0.5B Normalization Service
- Two-step LLM processing: Normalization -> Remediation
- API endpoint (Flask)
- Prompts folder
- Output folder  
- Model preload and safe memory handling
"""

import os
import sys
import json
import logging
import psutil
import requests
from flask import Flask, request, jsonify
from datetime import datetime
import re

# Local imports (rule-based helpers)
from vulnerability_classifier import classify_vulnerability
from remediation_rules import get_detailed_remediation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/qwen-service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Global variables
model = None
tokenizer = None
use_mock_ai = True

# Memory monitoring
def check_memory_usage():
    """Check memory usage and log warnings"""
    memory = psutil.virtual_memory()
    logger.info(f"Memory usage: {memory.percent}% ({memory.used/1024/1024/1024:.1f}GB/{memory.total/1024/1024/1024:.1f}GB)")
    
    if memory.percent > 85:
        logger.warning(f"High memory usage: {memory.percent}%")
    
    return memory.percent

def load_model():
    """Connect to Ollama service"""
    global model, tokenizer, use_mock_ai
    
    logger.info("Connecting to Ollama service...")
    
    # Wait for Ollama to be ready
    import time
    max_retries = 30
    for i in range(max_retries):
        try:
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                logger.info("Ollama service is ready ✓")
                use_mock_ai = False
                model = "ollama"
                tokenizer = None
                return
        except:
            logger.info(f"Waiting for Ollama... ({i+1}/{max_retries})")
            time.sleep(2)
    
    logger.error("Failed to connect to Ollama service; falling back to mock mode")
    # Do not exit the process; continue in degraded/mock mode so the service remains available.
    use_mock_ai = True
    model = None
    tokenizer = None
    return

def load_schema():
    """Load JSON schema"""
    try:
        with open('/app/schema.json', 'r') as f:
            raw = json.load(f)
            # Convert permissive schema file into a jsonschema-compatible schema
            # If the file contains a simple template, create a basic validation schema
            if isinstance(raw, dict) and any('|' in str(v) for v in raw.values()):
                properties = {}
                for k, v in raw.items():
                    properties[k] = {"type": "string"}
                return {"type": "object", "properties": properties}
            return raw
    except Exception as e:
        logger.error(f"Schema loading error: {e}")
        return {}


def validate_against_schema(data):
    """Validate parsed AI output against schema.json using jsonschema."""
    try:
        from jsonschema import validate, ValidationError
    except Exception:
        logger.debug("jsonschema not available; skipping validation")
        return True

    schema = load_schema()
    if not schema:
        return True

    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        logger.warning(f"AI output failed schema validation: {e}")
        return False


def _extract_json_from_ai_response(ai_response):
    """Attempt to robustly extract a JSON object from an AI text response.

    Tries fenced ```json blocks first, then finds the first balanced JSON object.
    Returns parsed JSON (dict) or None on failure.
    """
    if not ai_response:
        return None

    # Try fenced ```json blocks
    m = re.search(r"```json\s*(\{.*?\})\s*```", ai_response, re.S)
    if m:
        candidate = m.group(1)
    else:
        # Fallback: find first balanced JSON object by scanning braces
        start = ai_response.find('{')
        if start == -1:
            return None
        depth = 0
        end = None
        for i in range(start, len(ai_response)):
            if ai_response[i] == '{':
                depth += 1
            elif ai_response[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        if end is None:
            return None
        candidate = ai_response[start:end]

    # Clean candidate and attempt parse
    candidate = candidate.strip().strip('`')
    try:
        return json.loads(candidate)
    except Exception as e:
        logger.debug(f"Failed to parse extracted JSON: {e}")
        return None

def normalize_finding(tool_name, tool_output, target_domain):
    """Step 1: Normalize raw tool output using rule-based classification"""
    try:
        logger.info(f"Classifying {tool_name} finding using rules...")
        
        # Use rule-based classifier instead of AI
        normalized = classify_vulnerability(tool_name, tool_output, target_domain)
        
        if normalized:
            logger.info(f"Successfully classified: {normalized.get('issue_type', 'unknown')}")
            return normalized
        else:
            logger.warning("Rule-based classification failed")
            return None
            
    except Exception as e:
        logger.error(f"Classification error: {e}")
        return None

def generate_remediation(normalized_finding):
    """Step 2: Generate remediation for normalized finding"""
    try:
        # Load remediation prompt
        with open('/app/prompts/remediation_prompt.txt', 'r') as f:
            prompt_template = f.read()
        
        finding_json = json.dumps(normalized_finding, indent=2)
        prompt = prompt_template.replace("{{FINDING}}", finding_json)
        
        logger.info(f"Generating remediation for {normalized_finding.get('issue_type', 'unknown')}...")
        
        response = requests.post("http://localhost:11434/api/generate", 
                                   json={
                                       "model": "qwen:0.5b",
                                       "prompt": prompt,
                                       "stream": False
                                   }, timeout=60)
        
        if response.status_code != 200:
            logger.error(f"Remediation API error: {response.status_code}")
            return "Remediation not available due to processing error."
        
        ai_response = response.json().get("response", "")
        
        ai_response = ai_response
        result = _extract_json_from_ai_response(ai_response)
        if result and validate_against_schema(result):
            remediation = result.get("remediation", "Generic remediation: Apply security best practices.")
            logger.info("Successfully generated remediation")
            return remediation
        elif result:
            logger.warning("Parsed AI JSON but it failed schema validation; ignoring AI remediation")

        # Fallback: try to extract a remediation line from plain text
        lines = ai_response.splitlines()
        for line in lines:
            if 'remediation' in line.lower() and ':' in line:
                return line.split(':', 1)[1].strip().strip('"')

        return "Remediation: Follow security best practices for this vulnerability type."
        
    except Exception as e:
        logger.error(f"Remediation generation error: {e}")
        return "Remediation: Consult security documentation for proper fix."

def process_with_one_step_ai(tool_name, tool_output, target_domain):
    """One-step AI processing: normalization + remediation together"""
    findings = []
    
    try:
        # Load one-step prompt
        with open('/app/prompts/one_step_prompt.txt', 'r') as f:
            prompt_template = f.read()
        
        prompt = prompt_template.replace("{{TOOL}}", tool_name)\
                               .replace("{{TARGET}}", target_domain)\
                               .replace("{{RAW}}", tool_output[:2000])  # Limit input
        
        logger.info(f"Processing {tool_name} with one-step AI...")
        
        response = requests.post("http://localhost:11434/api/generate", 
                                   json={
                                       "model": "qwen:0.5b",
                                       "prompt": prompt,
                                       "stream": False
                                   }, timeout=120)
        
        if response.status_code != 200:
            logger.error(f"One-step AI API error: {response.status_code}")
            return findings
        
        ai_response = response.json().get("response", "")
        result = _extract_json_from_ai_response(ai_response)
        if result and validate_against_schema(result):
            final_finding = {
                "title": result.get("issue", "Unknown Issue"),
                "severity": result.get("severity", "medium"),
                "cve": "",
                "tool": tool_name,
                "target": target_domain,
                "endpoint": result.get("url", ""),
                "description": result.get("description", ""),
                "remediation": result.get("remediation", "Follow security best practices."),
                "confidence": "medium",
                "cvss": "",
                "references": f"https://owasp.org/www-project-top-ten/{result.get('issue_type', result.get('issue__type', 'other'))}",
                "raw_output": tool_output
            }

            findings.append(final_finding)
            logger.info(f"Successfully processed with one-step AI: {result.get('issue_type', 'unknown')}")
        elif result:
            logger.warning("AI returned JSON but it failed schema validation; skipping")
        
    except Exception as e:
        logger.error(f"One-step AI processing error: {e}")
    
    return findings

def process_with_simple_ai(tool_name, tool_output, target_domain):
    """Simple single-step AI processing for better Qwen 0.5B results"""
    findings = []
    
    try:
        # Load simple prompt
        with open('/app/prompts/simple_prompt.txt', 'r') as f:
            prompt_template = f.read()
        
        prompt = prompt_template.replace("{{TOOL}}", tool_name)\
                               .replace("{{TARGET}}", target_domain)\
                               .replace("{{RAW}}", tool_output[:1500])  # Limit input
        
        logger.info(f"Processing {tool_name} with simple AI...")
        
        response = requests.post("http://localhost:11434/api/generate", 
                                   json={
                                       "model": "qwen:0.5b",
                                       "prompt": prompt,
                                       "stream": False
                                   }, timeout=45)
        
        if response.status_code != 200:
            logger.error(f"Simple AI API error: {response.status_code}")
            return findings
        
        ai_response = response.json().get("response", "")
        result = _extract_json_from_ai_response(ai_response)
        if result and validate_against_schema(result):
            final_finding = {
                "title": result.get("issue", "Unknown Issue"),
                "severity": result.get("severity", "medium"),
                "cve": "",
                "tool": tool_name,
                "target": target_domain,
                "endpoint": result.get("url", ""),
                "description": result.get("description", ""),
                "remediation": result.get("remediation", "Follow security best practices."),
                "confidence": "medium",
                "cvss": "",
                "references": "",
                "raw_output": tool_output
            }

            findings.append(final_finding)
            logger.info(f"Successfully processed with simple AI: {result.get('issue_type', 'unknown')}")
        elif result:
            logger.warning("AI returned JSON but it failed schema validation; skipping")
        
    except Exception as e:
        logger.error(f"Simple AI processing error: {e}")
    
    return findings

# API Endpoints
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    memory_percent = check_memory_usage()
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "memory_usage": f"{memory_percent}%",
        "model_loaded": True,
        "service": "qwen-0.5b-normalizer",
        "mode": "two_step_ai"
    })

@app.route('/normalize', methods=['POST'])
def normalize_output():
    """Main normalization endpoint using two-step flow"""
    try:
        # Check memory
        check_memory_usage()
        
        # Get request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        tool_name = data.get('tool_name', 'unknown')
        tool_output = data.get('tool_output', '')
        target_domain = data.get('target_domain', 'unknown')
        
        if not tool_output:
            return jsonify({"error": "No tool_output provided"}), 400
        
        logger.info(f"Processing {tool_name} output for {target_domain}")
        
        # Process using one-step AI (AI handles both normalization and remediation)
        findings = process_with_one_step_ai(tool_name, tool_output, target_domain)
        
        # Create output data
        output_data = {
            "tool_name": tool_name,
            "target_domain": target_domain,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "processing_method": "qwen_one_step_ai"
        }
        
        # Save to VAPT output directory only
        import glob
        vapt_dirs = glob.glob("/var/log/output/*_*/")
        if vapt_dirs:
            latest_vapt_dir = max(vapt_dirs, key=os.path.getctime)
            vapt_file = f"{latest_vapt_dir}/qwen_{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                with open(vapt_file, 'w') as f:
                    json.dump(output_data, f, indent=2)
                logger.info(f"Saved to VAPT directory: {vapt_file}")
                output_file = vapt_file
            except Exception as e:
                logger.error(f"Could not save to VAPT directory: {e}")
                return jsonify({"error": "Failed to save output"}), 500
        else:
            # Fallback to /var/log/qwen-0.5b if no VAPT directory exists
            os.makedirs('/var/log/qwen-0.5b', exist_ok=True)
            output_file = f"/var/log/qwen-0.5b/{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            logger.info(f"Saved to fallback directory: {output_file}")
        
        logger.info(f"Processed {len(findings)} findings, saved to {output_file}")
        
        return jsonify({
            "success": True,
            "count": len(findings),
            "findings": findings,
            "processing_method": "qwen_one_step_ai",
            "message": f"Processed {len(findings)} findings"
        })
        
    except Exception as e:
        logger.error(f"Normalization error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    """Status endpoint"""
    memory = psutil.virtual_memory()
    
    return jsonify({
        "service": "qwen-0.5b-normalizer",
        "status": "running",
        "memory_usage": f"{memory.percent}%",
        "memory_available": f"{memory.available/1024/1024/1024:.1f}GB",
        "model_loaded": True,
        "processing_method": "qwen_one_step_ai",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    logger.info("Starting Qwen 0.5B One-Step AI Service (Normalization + Remediation)...")
    
    # Create directories
    os.makedirs('/app/logs', exist_ok=True)
    os.makedirs('/app/output', exist_ok=True)
    
    # Load model
    load_model()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=8080, debug=False)
