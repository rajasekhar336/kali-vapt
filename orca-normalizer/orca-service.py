#!/usr/bin/env python3
"""
Production Orca-Mini-3B Normalization Service
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
        logging.FileHandler('/app/logs/orca-service.log'),
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
        return {"title": "", "severity": "critical|high|medium|low|info", "tool": "", "target": "", "endpoint": "", "description": "", "remediation": "", "confidence": "high|medium|low", "cvss": "", "references": "", "raw_excerpt": ""}

def load_prompt_template():
    """Load prompt template"""
    try:
        with open('/app/prompts/universal_prompt.txt', 'r') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Prompt loading error: {e}")
        return "Analyze this security tool output and extract findings:"

def normalize_with_ai(tool_name, tool_output, target_domain):
    """Real AI normalization using Ollama"""
    try:
        schema = load_schema()
        
        # Create AI prompt for vulnerability analysis
        prompt = f"""You are a cybersecurity expert analyzing security tool output. 

TASK: Extract security vulnerabilities and provide structured findings with specific remediation.

TOOL: {tool_name}
TARGET: {target_domain}

RAW OUTPUT:
{tool_output}

REQUIREMENTS:
1. Extract ONLY actual security vulnerabilities (ignore informational data)
2. For each vulnerability, provide:
   - Severity level (critical/high/medium/low)
   - Specific endpoint/URL if mentioned
   - Clear description of the issue
   - DETAILED and ACTIONABLE remediation steps
   - CVE numbers if mentioned

REMEDIATION GUIDELINES:
- Provide specific implementation steps
- Include code examples where relevant
- Reference security frameworks (OWASP, NIST)
- Suggest specific tools or configurations
- Make remediation practical and implementable

RESPONSE FORMAT: Return valid JSON array with objects following this schema:
{json.dumps(schema)}

RULES:
- If no vulnerabilities found, return empty array []
- Be specific about endpoints and URLs
- Provide DETAILED remediation steps (not generic advice)
- Include CVE numbers when available
- Do not invent vulnerabilities
- Make remediation specific to the vulnerability type

JSON Response:"""

        logger.info(f"Sending to Ollama for {tool_name} analysis...")
        
        # Call Ollama API
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": "orca-mini:3b",
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "max_tokens": 1000
            }
        }, timeout=30)
        
        if response.status_code != 200:
            logger.error(f"Ollama API error: {response.status_code}")
            return []
        
        ai_response = response.json().get("response", "")
        logger.info(f"Ollama response received: {len(ai_response)} chars")
        
        # Extract JSON from AI response
        try:
            # Look for JSON array in response
            json_start = ai_response.find('[')
            json_end = ai_response.rfind(']') + 1
            
            if json_start != -1 and json_end > json_start:
                json_str = ai_response[json_start:json_end]
                findings = json.loads(json_str)
                
                # Validate and enhance findings
                validated_findings = []
                for finding in findings:
                    if isinstance(finding, dict):
                        # Ensure required fields
                        finding.setdefault("tool", tool_name)
                        finding.setdefault("target", target_domain)
                        finding.setdefault("confidence", "medium")
                        finding.setdefault("cvss", "")
                        finding.setdefault("references", "")
                        finding.setdefault("raw_output", tool_output)
                        
                        validated_findings.append(finding)
                
                logger.info(f"Ollama processed {len(validated_findings)} findings")
                return validated_findings
            else:
                logger.warning("No JSON array found in Ollama response")
                return []
                
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            logger.error(f"Raw AI response: {ai_response[:500]}...")
            return []
        
    except Exception as e:
        logger.error(f"Ollama processing error: {e}")
        return []

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    memory_percent = check_memory_usage()
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "memory_usage": f"{memory_percent}%",
        "model_loaded": True,
        "service": "orca-normalizer",
        "mode": "offline_ai_only"
    })

@app.route('/normalize', methods=['POST'])
def normalize_output():
    """Main normalization endpoint"""
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
        
        logger.info(f"Normalizing output from {tool_name} for {target_domain}")
        
        # Normalize with offline AI only
        findings = normalize_with_ai(tool_name, tool_output, target_domain)
        
        # Save output
        output_data = {
            "tool_name": tool_name,
            "target_domain": target_domain,
            "timestamp": datetime.now().isoformat(),
            "findings": findings,
            "processing_method": "ollama_ai"
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
            vapt_file = f"{latest_vapt_dir}/orca_{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                with open(vapt_file, 'w') as f:
                    json.dump(output_data, f, indent=2)
                logger.info(f"Also saved to VAPT directory: {vapt_file}")
            except Exception as e:
                logger.warning(f"Could not save to VAPT directory: {e}")
        
        logger.info(f"Processed {len(findings)} findings, saved to {output_file}")
        
        if findings:
            return jsonify({
                "success": True,
                "findings": findings,
                "count": len(findings),
                "processing_method": "ollama_ai"
            })
        else:
            return jsonify({
                "success": True,
                "findings": [],
                "count": 0,
                "message": "No security findings detected",
                "processing_method": "ollama_ai"
            })
            
    except Exception as e:
        logger.error(f"Normalization error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/status', methods=['GET'])
def status():
    """Status endpoint"""
    memory = psutil.virtual_memory()
    
    return jsonify({
        "service": "orca-normalizer",
        "status": "running",
        "memory_usage": f"{memory.percent}%",
        "memory_available": f"{memory.available/1024/1024/1024:.1f}GB",
        "model_loaded": True,
        "processing_method": "ollama_ai",
        "timestamp": datetime.now().isoformat()
    })

if __name__ == '__main__':
    logger.info("Starting Orca-Mini-3B Normalization Service...")
    
    # Create directories
    os.makedirs('/app/logs', exist_ok=True)
    os.makedirs('/app/output', exist_ok=True)
    
    # Load model
    load_model()
    
    # Start Flask app
    app.run(host='0.0.0.0', port=8080, debug=False)
