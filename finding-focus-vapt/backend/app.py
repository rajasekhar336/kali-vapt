from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import redis
import json
import uuid
import docker
import os
from datetime import datetime, timedelta
import threading
from celery import Celery

app = Flask(__name__)
CORS(app)

# Configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://vapt_user:vapt_secure_password@localhost:5432/vapt_platform')
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379')
AI_SERVICE_URL = os.getenv('AI_SERVICE_URL', 'http://localhost:8080')

# Celery configuration
celery = Celery('vapt_backend', broker=REDIS_URL, backend=REDIS_URL)

# Database connection
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

# Redis connection
redis_client = redis.from_url(REDIS_URL)

# Docker client
docker_client = docker.from_env()

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'services': {
            'database': check_database(),
            'redis': check_redis(),
            'ai_service': check_ai_service()
        }
    })

def check_database():
    try:
        conn = get_db_connection()
        conn.close()
        return 'healthy'
    except:
        return 'unhealthy'

def check_redis():
    try:
        redis_client.ping()
        return 'healthy'
    except:
        return 'unhealthy'

def check_ai_service():
    try:
        import requests
        response = requests.get(f"{AI_SERVICE_URL}/health", timeout=5)
        return 'healthy' if response.status_code == 200 else 'unhealthy'
    except:
        return 'unhealthy'

@app.route('/api/scans', methods=['POST'])
def create_scan():
    data = request.get_json()
    target_domain = data.get('target_domain')
    scan_type = data.get('scan_type', 'full')
    
    if not target_domain:
        return jsonify({'error': 'Target domain is required'}), 400
    
    scan_id = str(uuid.uuid4())
    
    # Insert scan into database
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO scans (id, target_domain, scan_type, status, config)
        VALUES (%s, %s, %s, %s, %s)
    """, (scan_id, target_domain, scan_type, 'pending', json.dumps(data)))
    
    conn.commit()
    conn.close()
    
    # Start background scan
    execute_scan.delay(scan_id, target_domain, scan_type, data)
    
    return jsonify({
        'scan_id': scan_id,
        'target_domain': target_domain,
        'status': 'pending',
        'message': 'Scan started successfully'
    })

@app.route('/api/scans', methods=['GET'])
def list_scans():
    limit = request.args.get('limit', 20)
    offset = request.args.get('offset', 0)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, target_domain, scan_type, status, started_at, completed_at
        FROM scans
        ORDER BY started_at DESC
        LIMIT %s OFFSET %s
    """, (limit, offset))
    
    scans = []
    for row in cursor.fetchall():
        scans.append({
            'id': row[0],
            'target_domain': row[1],
            'scan_type': row[2],
            'status': row[3],
            'started_at': row[4].isoformat(),
            'completed_at': row[5].isoformat() if row[5] else None
        })
    
    conn.close()
    
    return jsonify({'scans': scans})

@app.route('/api/scans/<scan_id>/vulnerabilities', methods=['GET'])
def get_vulnerabilities(scan_id):
    severity_filter = request.args.get('severity')
    tool_filter = request.args.get('tool')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT id, tool_name, title, severity, issue_type, endpoint, 
               description, raw_output, cvss_score, cve_id, created_at
        FROM vulnerabilities
        WHERE scan_id = %s
    """
    params = [scan_id]
    
    if severity_filter:
        query += " AND severity = %s"
        params.append(severity_filter)
    
    if tool_filter:
        query += " AND tool_name = %s"
        params.append(tool_filter)
    
    query += " ORDER BY severity_order DESC, created_at"
    
    cursor.execute(query, params)
    
    vulnerabilities = []
    for row in cursor.fetchall():
        vulnerabilities.append({
            'id': row[0],
            'tool_name': row[1],
            'title': row[2],
            'severity': row[3],
            'issue_type': row[4],
            'endpoint': row[5],
            'description': row[6],
            'raw_output': row[7],
            'cvss_score': float(row[8]) if row[8] else None,
            'cve_id': row[9],
            'created_at': row[10].isoformat(),
            'has_remediation': False  # Will be updated when AI is called
        })
    
    conn.close()
    
    return jsonify({'vulnerabilities': vulnerabilities})

@app.route('/api/vulnerabilities/<vuln_id>/remediation', methods=['GET'])
def get_remediation(vuln_id):
    # Check cache first
    cache_key = f"remediation:{vuln_id}"
    cached = redis_client.get(cache_key)
    
    if cached:
        return jsonify(json.loads(cached))
    
    # Get vulnerability details
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT tool_name, title, severity, description, raw_output, endpoint
        FROM vulnerabilities
        WHERE id = %s
    """, (vuln_id,))
    
    vuln = cursor.fetchone()
    conn.close()
    
    if not vuln:
        return jsonify({'error': 'Vulnerability not found'}), 404
    
    # Call AI service
    import requests
    try:
        response = requests.post(f"{AI_SERVICE_URL}/normalize", 
            json={
                'tool_name': vuln[0],
                'tool_output': vuln[4],
                'target_domain': vuln[5] or 'unknown'
            },
            timeout=30
        )
        
        if response.status_code == 200:
            ai_result = response.json()
            
            # Cache the result
            redis_client.setex(cache_key, 3600, json.dumps(ai_result))
            
            return jsonify(ai_result)
        else:
            return jsonify({'error': 'AI service unavailable'}), 503
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scans/<scan_id>/reports', methods=['POST'])
def generate_report(scan_id):
    report_format = request.get_json().get('format', 'pdf')
    
    # Generate report in background
    report_id = str(uuid.uuid4())
    generate_report.delay(scan_id, report_id, report_format)
    
    return jsonify({
        'report_id': report_id,
        'status': 'generating',
        'message': 'Report generation started'
    })

@celery.task
def execute_scan(scan_id, target_domain, scan_type, config):
    """Background task to execute VAPT scan"""
    # Update scan status
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE scans 
        SET status = 'running', started_at = NOW()
        WHERE id = %s
    """, (scan_id,))
    
    conn.commit()
    
    try:
        # Execute tools using existing run_enhanced.sh logic
        # This would integrate with your existing scanning infrastructure
        
        # For now, simulate scan completion
        cursor.execute("""
            UPDATE scans 
            SET status = 'completed', completed_at = NOW()
            WHERE id = %s
        """, (scan_id,))
        
        conn.commit()
        
    except Exception as e:
        cursor.execute("""
            UPDATE scans 
            SET status = 'failed'
            WHERE id = %s
        """, (scan_id,))
        
        conn.commit()
    
    conn.close()

@celery.task
def generate_report(scan_id, report_id, report_format):
    """Background task to generate reports"""
    # Generate report with AI remediation included
    # Implementation would use report generation libraries
    
    pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
