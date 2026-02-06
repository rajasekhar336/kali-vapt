#!/usr/bin/env python3

"""

DetectDojo Vulnerability Orchestration Service

- Receives raw tool outputs from VAPT assessment

- Sends to normalizer (Qwen) for AI processing

- Correlates and deduplicates findings

- Calculates security score and generates reports

"""



import os

import json

import logging

import requests

from flask import Flask, request, jsonify

from datetime import datetime

from collections import defaultdict

import hashlib



# Configure logging

logging.basicConfig(

    level=logging.INFO,

    format='%(asctime)s - %(levelname)s - %(message)s',

    handlers=[

        logging.FileHandler('/app/logs/detectdojo.log'),

        logging.StreamHandler()

    ]

)

logger = logging.getLogger(__name__)



app = Flask(__name__)



# Global state

FINDINGS_DB = {}  # {assessment_id: {target: str, findings: [], created_at: str}}

NORMALIZER_URL = os.getenv('NORMALIZER_URL', 'http://127.0.0.1:8080')



# ============ Helpers ============



def get_assessment_id(target_domain):

    """Generate or retrieve assessment ID for target"""

    safe_target = target_domain.replace('.', '_').replace(':', '_')

    return f"assessment_{safe_target}_{datetime.now().strftime('%Y%m%d')}"



def get_or_create_assessment(target_domain):

    """Get or create assessment record"""

    assessment_id = get_assessment_id(target_domain)

    if assessment_id not in FINDINGS_DB:

        FINDINGS_DB[assessment_id] = {

            "target": target_domain,

            "findings": [],

            "created_at": datetime.now().isoformat(),

            "updated_at": datetime.now().isoformat()

        }

    return assessment_id, FINDINGS_DB[assessment_id]



def normalize_tool_output(tool_name, tool_output, target_domain):

    """Send raw output to normalizer service and get normalized finding"""

    try:

        response = requests.post(

            f"{NORMALIZER_URL}/normalize",

            json={

                "tool_name": tool_name,

                "tool_output": tool_output,

                "target_domain": target_domain

            },

            timeout=120

        )

        

        if response.status_code == 200:

            data = response.json()

            findings = data.get("findings", [])

            logger.info(f"Normalized {tool_name}: {len(findings)} findings")

            return findings

        else:

            logger.error(f"Normalizer returned {response.status_code}")

            return []

    except Exception as e:

        logger.error(f"Error calling normalizer: {e}")

        return []



def deduplicate_findings(findings):

    """Remove duplicate findings based on title, severity, endpoint"""

    seen = {}

    unique = []

    

    for finding in findings:

        # Create hash key from title + severity + endpoint

        key_str = f"{finding.get('title', '')}|{finding.get('severity', '')}|{finding.get('endpoint', '')}"

        key = hashlib.md5(key_str.encode()).hexdigest()

        

        if key not in seen:

            seen[key] = finding

            unique.append(finding)

        else:

            # Merge: keep higher confidence/more details

            if finding.get('confidence') == 'high' and seen[key].get('confidence') != 'high':

                seen[key] = finding

                unique[-1] = finding

    

    return unique



def calculate_security_score(findings):

    """Calculate overall security score (0-100) based on findings"""

    if not findings:

        return 100

    

    severity_weights = {

        "critical": 40,

        "high": 20,

        "medium": 10,

        "low": 5,

        "info": 1

    }

    

    total_points = 0

    for finding in findings:

        severity = finding.get('severity', 'medium').lower()

        total_points += severity_weights.get(severity, 5)

    

    # Score = 100 - capped points (max 100 deduction)

    score = max(0, 100 - min(total_points, 100))

    return score



def group_findings_by_severity(findings):

    """Group findings by severity level"""

    grouped = defaultdict(list)

    for finding in findings:

        severity = finding.get('severity', 'medium').lower()

        grouped[severity].append(finding)

    return dict(grouped)



# ============ REST Endpoints ============



@app.route('/health', methods=['GET'])

def health():

    """Health check endpoint"""

    return jsonify({

        "status": "healthy",

        "service": "detectdojo",

        "timestamp": datetime.now().isoformat(),

        "normalizer_url": NORMALIZER_URL

    })



@app.route('/api/findings/add', methods=['POST'])

def add_findings():

    """Receive raw tool outputs and normalize them"""

    try:

        data = request.get_json()

        if not data:

            return jsonify({"error": "No JSON data provided"}), 400

        

        tool_name = data.get('tool_name', 'unknown')

        tool_output = data.get('tool_output', '')

        target_domain = data.get('target_domain', 'unknown')

        

        if not tool_output:

            return jsonify({"error": "No tool_output provided"}), 400

        

        logger.info(f"Received {tool_name} output for {target_domain}")

        

        # Get or create assessment

        assessment_id, assessment = get_or_create_assessment(target_domain)

        

        # Send to normalizer

        normalized = normalize_tool_output(tool_name, tool_output, target_domain)

        

        # Add to assessment

        for finding in normalized:

            finding['tool'] = tool_name

            finding['added_at'] = datetime.now().isoformat()

            assessment['findings'].append(finding)

        

        # Update timestamp

        assessment['updated_at'] = datetime.now().isoformat()

        

        logger.info(f"Assessment {assessment_id} now has {len(assessment['findings'])} total findings")

        

        return jsonify({

            "success": True,

            "assessment_id": assessment_id,

            "normalized_count": len(normalized),

            "total_findings": len(assessment['findings'])

        })

    

    except Exception as e:

        logger.error(f"Error adding findings: {e}")

        return jsonify({"error": str(e)}), 500



@app.route('/api/findings/<assessment_id>', methods=['GET'])

def get_findings(assessment_id):

    """Get findings for an assessment"""

    if assessment_id not in FINDINGS_DB:

        return jsonify({"error": "Assessment not found"}), 404

    

    assessment = FINDINGS_DB[assessment_id]

    

    # Deduplicate

    unique_findings = deduplicate_findings(assessment['findings'])

    

    # Group by severity

    grouped = group_findings_by_severity(unique_findings)

    

    return jsonify({

        "assessment_id": assessment_id,

        "target": assessment['target'],

        "created_at": assessment['created_at'],

        "updated_at": assessment['updated_at'],

        "findings": unique_findings,

        "grouped_by_severity": grouped,

        "total_findings": len(unique_findings),

        "by_severity": {k: len(v) for k, v in grouped.items()}

    })



@app.route('/api/report/<assessment_id>', methods=['GET'])

def get_report(assessment_id):

    """Generate comprehensive security report"""

    if assessment_id not in FINDINGS_DB:

        return jsonify({"error": "Assessment not found"}), 404

    

    assessment = FINDINGS_DB[assessment_id]

    unique_findings = deduplicate_findings(assessment['findings'])

    grouped = group_findings_by_severity(unique_findings)

    security_score = calculate_security_score(unique_findings)

    

    # Build report

    report = {

        "assessment_id": assessment_id,

        "target": assessment['target'],

        "created_at": assessment['created_at'],

        "updated_at": assessment['updated_at'],

        "security_score": security_score,

        "rating": "CRITICAL" if security_score < 40 else "HIGH" if security_score < 60 else "MEDIUM" if security_score < 80 else "LOW",

        "summary": {

            "total_findings": len(unique_findings),

            "critical": len(grouped.get('critical', [])),

            "high": len(grouped.get('high', [])),

            "medium": len(grouped.get('medium', [])),

            "low": len(grouped.get('low', [])),

            "info": len(grouped.get('info', []))

        },

        "findings": unique_findings,

        "findings_by_severity": grouped,

        "top_issues": [

            f["title"] for f in sorted(unique_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get('severity', 'medium'), 5))[:10]

        ]

    }

    

    return jsonify(report)



@app.route('/api/assessments', methods=['GET'])

def list_assessments():

    """List all assessments"""

    assessments = []

    for assessment_id, data in FINDINGS_DB.items():

        unique_findings = deduplicate_findings(data['findings'])

        assessments.append({

            "assessment_id": assessment_id,

            "target": data['target'],

            "created_at": data['created_at'],

            "updated_at": data['updated_at'],

            "findings_count": len(unique_findings),

            "security_score": calculate_security_score(unique_findings)

        })

    

    return jsonify({

        "assessments": assessments,

        "total": len(assessments)

    })



@app.route('/api/report/<assessment_id>/html', methods=['GET'])

def get_report_html(assessment_id):

    """Generate HTML report"""

    if assessment_id not in FINDINGS_DB:

        return "Assessment not found", 404

    

    assessment = FINDINGS_DB[assessment_id]

    unique_findings = deduplicate_findings(assessment['findings'])

    grouped = group_findings_by_severity(unique_findings)

    security_score = calculate_security_score(unique_findings)

    rating = "CRITICAL" if security_score < 40 else "HIGH" if security_score < 60 else "MEDIUM" if security_score < 80 else "LOW"

    

    # Build HTML

    html = f"""

    <!DOCTYPE html>

    <html>

    <head>

        <title>VAPT Report - {assessment['target']}</title>

        <style>

            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}

            .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}

            .score-box {{ font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }}

            .score-critical {{ color: #e74c3c; }}

            .score-high {{ color: #e67e22; }}

            .score-medium {{ color: #f39c12; }}

            .score-low {{ color: #27ae60; }}

            .section {{ background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}

            table {{ width: 100%; border-collapse: collapse; }}

            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}

            th {{ background: #ecf0f1; font-weight: bold; }}

            .critical {{ background: #fadbd8; }}

            .high {{ background: #fdebd0; }}

            .medium {{ background: #fef5e7; }}

            .low {{ background: #eafaf1; }}

            .info {{ background: #ebf5fb; }}

        </style>

    </head>

    <body>

        <div class="header">

            <h1>VAPT Assessment Report</h1>

            <p><strong>Target:</strong> {assessment['target']}</p>

            <p><strong>Date:</strong> {assessment['created_at']}</p>

        </div>

        

        <div class="section">

            <h2>Security Score</h2>

            <div class="score-box score-{rating.lower()}">

                {security_score}/100 - {rating}

            </div>

        </div>

        

        <div class="section">

            <h2>Summary</h2>

            <table>

                <tr>

                    <th>Severity</th>

                    <th>Count</th>

                </tr>

                <tr class="critical">

                    <td>Critical</td>

                    <td>{len(grouped.get('critical', []))}</td>

                </tr>

                <tr class="high">

                    <td>High</td>

                    <td>{len(grouped.get('high', []))}</td>

                </tr>

                <tr class="medium">

                    <td>Medium</td>

                    <td>{len(grouped.get('medium', []))}</td>

                </tr>

                <tr class="low">

                    <td>Low</td>

                    <td>{len(grouped.get('low', []))}</td>

                </tr>

                <tr class="info">

                    <td>Info</td>

                    <td>{len(grouped.get('info', []))}</td>

                </tr>

            </table>

        </div>

        

        <div class="section">

            <h2>Findings ({len(unique_findings)} total)</h2>

            <table>

                <tr>

                    <th>Severity</th>

                    <th>Title</th>

                    <th>Tool</th>

                    <th>Endpoint</th>

                </tr>

    """

    

    for finding in sorted(unique_findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get('severity', 'medium'), 5)):

        severity = finding.get('severity', 'medium').lower()

        html += f"""

                <tr class="{severity}">

                    <td><strong>{severity.upper()}</strong></td>

                    <td>{finding.get('title', 'Unknown')}</td>

                    <td>{finding.get('tool', 'unknown')}</td>

                    <td>{finding.get('endpoint', '-')}</td>

                </tr>

        """

    

    html += """

            </table>

        </div>

        

        <div class="section">

            <h2>Detailed Findings</h2>

    """

    

    for finding in unique_findings:

        severity = finding.get('severity', 'medium').lower()

        html += f"""

            <div class="section" style="border-left: 4px solid #{'e74c3c' if severity == 'critical' else 'e67e22' if severity == 'high' else 'f39c12' if severity == 'medium' else '27ae60'};">

                <h3>{finding.get('title', 'Unknown')}</h3>

                <p><strong>Severity:</strong> {severity.upper()}</p>

                <p><strong>Tool:</strong> {finding.get('tool', 'unknown')}</p>

                <p><strong>Endpoint:</strong> {finding.get('endpoint', '-')}</p>

                <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>

                <p><strong>Remediation:</strong></p>

                <pre>{finding.get('remediation', 'N/A')}</pre>

            </div>

        """

    

    html += """

        </div>

    </body>

    </html>

    """

    

    return html, 200, {'Content-Type': 'text/html'}



if __name__ == '__main__':

    logger.info("Starting DetectDojo Orchestration Service...")

    

    # Create directories

    os.makedirs('/app/logs', exist_ok=True)

    

    # Start Flask app

    app.run(host='0.0.0.0', port=8081, debug=False)

