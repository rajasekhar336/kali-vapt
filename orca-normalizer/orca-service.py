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
    """Load AI model - fail if not available"""
    global model, tokenizer, use_mock_ai
    
    try:
        # Check if model files exist
        if not os.path.exists('/app/models/model') or not os.path.exists('/app/models/tokenizer'):
            logger.error("Model files not found - please build with model download")
            sys.exit(1)
        
        logger.info("Loading offline AI model...")
        
        # Check available memory
        memory = psutil.virtual_memory()
        available_gb = memory.available / 1024 / 1024 / 1024
        
        if available_gb < 1.5:
            logger.error(f"Insufficient memory: {available_gb:.1f}GB (required: 1.5GB+)")
            sys.exit(1)
        
        # Load model
        from transformers import AutoTokenizer, AutoModelForCausalLM
        import torch
        
        tokenizer = AutoTokenizer.from_pretrained('/app/models/tokenizer')
        model = AutoModelForCausalLM.from_pretrained(
            '/app/models/model',
            torch_dtype=torch.float16,
            device_map='auto',
            low_cpu_mem_usage=True
        )
        
        use_mock_ai = False
        logger.info("Offline AI model loaded successfully ✓")
        
    except Exception as e:
        logger.error(f"Failed to load AI model: {e}")
        logger.error("Please ensure model is properly downloaded and sufficient memory is available")
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
    """Pure AI normalization using loaded model"""
    try:
        schema = load_schema()
        prompt_template = load_prompt_template()
        
        prompt = f"""
{prompt_template}

Tool: {tool_name}
Target: {target_domain}
Raw Output: {tool_output[:1000]}

Schema: {json.dumps(schema)}

Output JSON:
"""
        
        # Generate response
        inputs = tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True)
        outputs = model.generate(
            inputs.input_ids,
            max_new_tokens=256,
            temperature=0.1,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
        
        response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Extract JSON from response
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start != -1 and json_end > json_start:
                json_str = response[json_start:json_end]
                finding = json.loads(json_str)
                return [finding]
        except Exception as e:
            logger.error(f"JSON extraction error: {e}")
        
        logger.warning("No valid JSON extracted from AI response")
        return []
        
    except Exception as e:
        logger.error(f"AI normalization error: {e}")
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
            "processing_method": "offline_ai"
        }
        
        # Save to file
        output_file = f"/app/output/{tool_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Processed {len(findings)} findings, saved to {output_file}")
        
        if findings:
            return jsonify({
                "success": True,
                "findings": findings,
                "count": len(findings),
                "processing_method": "offline_ai"
            })
        else:
            return jsonify({
                "success": True,
                "findings": [],
                "count": 0,
                "message": "No security findings detected",
                "processing_method": "offline_ai"
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
        "processing_method": "offline_ai_only",
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
