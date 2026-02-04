# Complete VAPT Framework Tools List

## 🎯 **Total Tools: 40+ Security Tools**

---

## **🔍 Phase 1: Reconnaissance (9 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **amass** | Subdomain enumeration | Rule-Based |
| **assetfinder** | Asset discovery | Rule-Based |
| **subfinder** | Subdomain discovery | Rule-Based |
| **whois** | Domain information | Rule-Based |
| **dnsrecon** | DNS reconnaissance | Rule-Based |
| **dig** | DNS queries | Rule-Based |
| **whatweb** | Web technology identification | Rule-Based |
| **waybackurls** | URL discovery from archives | Rule-Based |
| **gau** | Get All URLs | Rule-Based |

---

## **🌐 Phase 2: Network Scanning (6+ tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **naabu** | Fast port scanner | Rule-Based |
| **rustscan** | Ultra-fast port scanning | Rule-Based |
| **httpx** | HTTP probe | Rule-Based |
| **nmap*** | Comprehensive network mapping (per IP) | Rule-Based |
| **masscan*** | Fast port discovery (per IP) | Rule-Based |

---

## **🛡️ Phase 3: Vulnerability Assessment (3 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **nuclei** | Vulnerability scanner with templates | **AI Processing** |
| **searchsploit** | Exploit database search | **AI Processing** |
| **nmap_vulners** | Nmap vulners script for CVE detection | **AI Processing** |

---

## **🌍 Phase 4: Web Security (7 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **gobuster** | Directory/file brute-force | Rule-Based |
| **katana** | Web crawler | Rule-Based |
| **nikto** | Web server vulnerability scanner | **AI Processing** |
| **ffuf** | Fast web fuzzer | Rule-Based |
| **dirsearch** | Directory scanner | Rule-Based |
| **wapiti** | Web application vulnerability scanner | Rule-Based |
| **OWASP ZAP** | Comprehensive web security testing | **AI Processing** |

---

## **🔒 Phase 5: SSL/TLS Security (3 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **sslyze** | SSL/TLS configuration analyzer | Rule-Based |
| **sslscan** | SSL configuration scanner | Rule-Based |
| **testssl.sh** | Comprehensive SSL testing | Rule-Based |

---

## **🗄️ Phase 6: Database Security (5 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **sqlmap** | SQL injection detection and exploitation | **AI Processing** |
| **db_ports** | Database port scanning | Rule-Based |
| **redis_test** | Redis connectivity test | Rule-Based |
| **postgres_test** | PostgreSQL connectivity test | Rule-Based |
| **mysql_test** | MySQL connectivity test | Rule-Based |

---

## **🐳 Phase 7: Container & Cloud Security (4 tools)**
| Tool | Purpose | Processing |
|------|---------|------------|
| **metadata_check** | Cloud metadata exposure test | Rule-Based |
| **docker_registry** | Docker registry exposure test | Rule-Based |
| **k8s_api** | Kubernetes API exposure test | Rule-Based |
| **kubeaudit** | Kubernetes security audit | Rule-Based |

---

## **📊 Processing Summary**

### **🤖 AI-Processed Tools (6 tools)**
Need contextual analysis, severity assignment, and remediation:
- `nuclei`, `nikto`, `zap`, `sqlmap`, `nmap_vulners`, `searchsploit`

### **🔄 Rule-Based Normalization (34+ tools)**
Basic JSON structure conversion:
- All reconnaissance tools (9)
- Network scanning tools (6+)
- SSL/TLS tools (3)
- Database connectivity tests (4)
- Container/cloud tools (4)
- Web discovery tools (4)

---

## **🚀 Execution Flow**

```bash
./run_enhanced.sh example.com --verbose

# All 40+ tools execute → Processing queue → 
# 6 tools → AI → DetectDojo (with severity/remediation)
# 34+ tools → Rule-based → DetectDojo (structured format)
# Final comprehensive report
```

---

## **📈 Tool Categories by Count**

| Category | Tool Count | Processing Type |
|----------|------------|-----------------|
| Reconnaissance | 9 | Rule-Based |
| Network | 6+ | Rule-Based |
| Vulnerability | 3 | AI Processing |
| Web Security | 7 | 1 AI + 6 Rule-Based |
| SSL/TLS | 3 | Rule-Based |
| Database | 5 | 1 AI + 4 Rule-Based |
| Container/Cloud | 4 | Rule-Based |
| **TOTAL** | **40+** | **6 AI + 34+ Rule-Based** |

---

## **🎯 Output Structure**

```
/var/log/output/<domain>_<date>/
├── recon/           # 9 tool outputs
├── network/         # 6+ tool outputs (nmap/masscan per IP)
├── vuln/            # 3 tool outputs
├── web/             # 7 tool outputs
├── ssl/             # 3 tool outputs
├── database/        # 5 tool outputs
├── container/       # 4 tool outputs
├── reports/         # AI + DetectDojo reports
└── processing_queue/ # Background processing
```
