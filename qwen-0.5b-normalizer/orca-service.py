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
    
    logger.error("Failed to connect to Ollama service")
    sys.exit(1)

def load_schema():
    """Load JSON schema"""
    try:
        with open('/app/schema.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Schema loading error: {e}")
        return {}

def normalize_finding(tool_name, tool_output, target_domain):
    """Step 1: Normalize raw tool output to clean JSON"""
    try:
        # Load normalization prompt
        with open('/app/prompts/normalization_prompt.txt', 'r') as f:
            prompt_template = f.read()
        
        prompt = prompt_template.replace("{{TOOL}}", tool_name)\
                               .replace("{{TARGET}}", target_domain)\
                               .replace("{{RAW}}", tool_output[:2000])  # Limit input size
        
        logger.info(f"Normalizing {tool_name} finding...")
        
        response = requests.post("http://localhost:11434/api/generate", 
                                   json={
                                       "model": "qwen:0.5b",
                                       "prompt": prompt,
                                       "stream": False
                                   }, timeout=30)
        
        if response.status_code != 200:
            logger.error(f"Normalization API error: {response.status_code}")
            return None
        
        ai_response = response.json().get("response", "")
        
        # Extract JSON from response
        try:
            # Find JSON in the response
            start_idx = ai_response.find('{')
            end_idx = ai_response.rfind('}') + 1
            if start_idx != -1 and end_idx != -1:
                json_str = ai_response[start_idx:end_idx]
                normalized = json.loads(json_str)
                logger.info(f"Successfully normalized finding: {normalized.get('issue_type', 'unknown')}")
                return normalized
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in normalization: {e}")
            logger.debug(f"AI response: {ai_response}")
        
        return None
        
    except Exception as e:
        logger.error(f"Normalization error: {e}")
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
                                   }, timeout=30)
        
        if response.status_code != 200:
            logger.error(f"Remediation API error: {response.status_code}")
            return "Remediation not available due to processing error."
        
        ai_response = response.json().get("response", "")
        
        # Extract JSON from response
        try:
            start_idx = ai_response.find('{')
            end_idx = ai_response.rfind('}') + 1
            if start_idx != -1 and end_idx != -1:
                json_str = ai_response[start_idx:end_idx]
                result = json.loads(json_str)
                remediation = result.get("remediation", "Generic remediation: Apply security best practices.")
                logger.info(f"Successfully generated remediation")
                return remediation
        except json.JSONDecodeError:
            # Fallback: extract text if JSON parsing fails
            lines = ai_response.split('\n')
            for line in lines:
                if 'remediation' in line.lower() and ':' in line:
                    return line.split(':', 1)[1].strip().strip('"')
        
        return "Remediation: Follow security best practices for this vulnerability type."
        
    except Exception as e:
        logger.error(f"Remediation generation error: {e}")
        return "Remediation: Consult security documentation for proper fix."

def process_with_two_step_flow(tool_name, tool_output, target_domain):
    """Process tool output using two-step LLM flow"""
    findings = []
    
    try:
        # Step 1: Normalize the finding
        normalized = normalize_finding(tool_name, tool_output, target_domain)
        if not normalized:
            logger.warning(f"Failed to normalize {tool_name} output")
            return findings
        
        # Step 2: Generate remediation
        remediation = generate_remediation(normalized)
        
        # Combine into final finding
        final_finding = {
            "title": normalized.get("issue", "Unknown Issue"),
            "severity": normalized.get("severity", "medium"),
            "cve": "",  # Can be added later
            "tool": normalized.get("tool", tool_name),
            "target": normalized.get("target", target_domain),
            "endpoint": normalized.get("url", ""),
            "description": normalized.get("description", ""),
            "remediation": remediation,
            "confidence": normalized.get("confidence", "medium"),
            "cvss": "",  # Can be calculated later
            "references": "",  # Can be added based on issue_type
            "raw_output": tool_output
        }
        
        findings.append(final_finding)
        logger.info(f"Successfully processed {tool_name} finding with two-step flow")
        
    except Exception as e:
        logger.error(f"Two-step processing error: {e}")
    
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
        
        # Process using two-step flow
        findings = process_with_two_step_flow(tool_name, tool_output, target_domain)
        
        # Create output data
        output_data = {
            "tool_name": tool_name,
            "target_domain": target_domain,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "processing_method": "qwen_two_step_ai"
        }
        
        # Save to file (both locations)
        output_file = f"/app/output/{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        # Also save to VAPT output directory if exists
        import glob
        vapt_dirs = glob.glob("/var/log/output/*_*/")
        if vapt_dirs:
            latest_vapt_dir = max(vapt_dirs, key=os.path.getctime)
            vapt_file = f"{latest_vapt_dir}/qwen_{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                with open(vapt_file, 'w') as f:
                    json.dump(output_data, f, indent=2)
                logger.info(f"Also saved to VAPT directory: {vapt_file}")
            except Exception as e:
                logger.warning(f"Could not save to VAPT directory: {e}")
        
        logger.info(f"Processed {len(findings)} findings, saved to {output_file}")
        
        return jsonify({
            "success": True,
            "count": len(findings),
            "findings": findings,
            "processing_method": "qwen_two_step_ai",
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
        "processing_method": "qwen_two_step_ai",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    logger.info("Starting Qwen 0.5B Two-Step Normalization Service...")
    
    # Create directories
    os.makedirs('/app/logs', exist_ok=True)
    os.makedirs('/app/output', exist_ok=True)
    
    # Load model
    load_model()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=8080, debug=False)
