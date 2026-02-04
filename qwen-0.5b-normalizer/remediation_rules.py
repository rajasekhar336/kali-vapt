#!/usr/bin/env python3
"""
Rule-based remediation system for Qwen 0.5B
Provides detailed, specific remediation steps based on vulnerability type
"""

def get_detailed_remediation(issue_type, issue_title, url, description):
    """Get detailed remediation based on vulnerability type"""
    
    remediation_rules = {
        "csp_violation": {
            "title": "Content Security Policy Violation",
            "remediation": """1. Implement strict Content Security Policy: script-src 'self'; object-src 'none'; base-uri 'self'.
2. Remove 'unsafe-inline' from all CSP directives.
3. Use nonce-based or hash-based CSP for specific scripts: script-src 'self' 'nonce-{random}'.
4. Add report-uri or report-to directive for CSP violation monitoring.
5. Test CSP implementation using https://csp-evaluator.withgoogle.com/
6. Monitor CSP reports for 30 days to ensure no legitimate functionality is blocked.
7. Consider implementing CSP in report-only mode first to test impact.""",
            "code_examples": {
                "nginx": "add_header Content-Security-Policy \"script-src 'self'; object-src 'none'; base-uri 'self';\";",
                "apache": "Header always set Content-Security-Policy \"script-src 'self'; object-src 'none'; base-uri 'self';\"",
                "html": "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'; object-src 'none';\">"
            }
        },
        
        "security_headers_missing": {
            "title": "Security Headers Missing",
            "remediation": """1. Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.
2. Add X-Content-Type-Options: nosniff to prevent MIME-sniffing attacks.
3. Add Strict-Transport-Security: max-age=31536000; includeSubDomains for HTTPS enforcement.
4. Add Referrer-Policy: strict-origin-when-cross-origin.
5. Add Permissions-Policy header to control feature access.
6. Add Content-Security-Policy as above if not already present.
7. Test headers using https://securityheaders.com/""",
            "code_examples": {
                "nginx": "add_header X-Frame-Options DENY;\nadd_header X-Content-Type-Options nosniff;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\";",
                "apache": "Header always set X-Frame-Options DENY\nHeader always set X-Content-Type-Options nosniff\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
            }
        },
        
        "xss_reflected": {
            "title": "Cross Site Scripting (Reflected)",
            "remediation": """1. Implement input validation on all user inputs using allow-list approach.
2. Use output encoding with libraries like OWASP ESAPI or framework-specific encoding.
3. Set Content-Security-Policy header to prevent inline script execution.
4. Use parameterized queries for database operations.
5. Implement HTTP-only and Secure flags on cookies.
6. Use framework-provided XSS protection (e.g., express-validator, Django forms).
7. Test with XSS payloads: <script>alert('XSS')</script>, \"onerror=\"alert(1)""",
            "code_examples": {
                "javascript": "const escapeHtml = (unsafe) => unsafe.replace(/[&<>"']/g, (m) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', \"'\": '&#39;'}[m]));",
                "python": "import html\ndef escape_html(text): return html.escape(text, quote=True)",
                "php": "$escaped = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');"
            }
        },
        
        "sql_injection": {
            "title": "SQL Injection",
            "remediation": """1. Replace all dynamic SQL queries with parameterized queries/prepared statements.
2. Use ORM frameworks that provide built-in SQL injection protection.
3. Implement input validation and sanitization for all user inputs.
4. Apply principle of least privilege to database accounts.
5. Use stored procedures with parameter binding where appropriate.
6. Implement web application firewall (WAF) rules for SQL injection patterns.
7. Regularly scan for SQL injection vulnerabilities using automated tools.""",
            "code_examples": {
                "python": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                "java": "PreparedStatement stmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); stmt.setInt(1, userId);",
                "php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id'); $stmt->execute(['id' => $userId]);"
            }
        },
        
        "hidden_file": {
            "title": "Hidden File Exposure",
            "remediation": """1. Remove .git, .svn, .env, and other sensitive files from web root.
2. Configure web server to deny access to hidden files and directories.
3. Use .htaccess (Apache) or location blocks (Nginx) to block access patterns.
4. Implement proper .gitignore files to prevent sensitive files in repositories.
5. Move configuration files outside web root directory.
6. Regularly scan for exposed sensitive files using automated tools.
7. Implement file integrity monitoring for critical directories.""",
            "code_examples": {
                "apache": "<FilesMatch '^\\.'>\n    Require all denied\n</FilesMatch>\n<FilesMatch '\\.(git|svn|env|config)$'>\n    Require all denied\n</FilesMatch>",
                "nginx": "location ~ /\\. { deny all; }\nlocation ~ \\.(git|svn|env|config)$ { deny all; }"
            }
        },
        
        "information_disclosure": {
            "title": "Information Disclosure",
            "remediation": """1. Remove or obscure server signatures and version information.
2. Disable detailed error messages in production environments.
3. Implement generic error pages that don't reveal system information.
4. Remove debug endpoints and administrative interfaces from production.
5. Configure web servers to hide server headers.
6. Implement proper logging without exposing sensitive information.
7. Regularly audit application for information leakage points.""",
            "code_examples": {
                "nginx": "server_tokens off;\nmore_clear_headers Server;\nmore_clear_headers X-Powered-By;",
                "apache": "ServerTokens Prod\nServerSignature Off\nHeader unset Server\nHeader unset X-Powered-By"
            }
        }
    }
    
    # Get the specific remediation rule
    rule = remediation_rules.get(issue_type, remediation_rules.get("security_headers_missing"))
    
    if rule:
        remediation = f"{rule['remediation']}\n\nReferences:\n- OWASP Top 10: https://owasp.org/www-project-top-ten/\n- NIST Cybersecurity Framework\n- CWE-{issue_type.upper()}: {rule['title']}"
        
        # Add code examples if available
        if "code_examples" in rule:
            remediation += "\n\nImplementation Examples:\n"
            for tech, code in rule["code_examples"].items():
                remediation += f"\n{tech}:\n{code}\n"
    else:
        remediation = "1. Follow OWASP security best practices\n2. Implement proper input validation and output encoding\n3. Use framework-provided security features\n4. Regular security testing and code reviews\n5. Keep dependencies updated\n6. Implement defense-in-depth security measures\n\nReferences:\n- OWASP Application Security Verification Standard\n- NIST Cybersecurity Framework\n- SANS Top 25 Coding Errors"
    
    return remediation

# Test function
if __name__ == "__main__":
    print(get_detailed_remediation("csp_violation", "CSP Violation", "https://example.com", "CSP allows unsafe-inline"))
