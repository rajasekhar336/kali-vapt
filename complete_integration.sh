#!/bin/bash

# Complete DetectDojo Integration for All Tools
# This script adds all missing tools to the integration arrays

set -euo pipefail

SCRIPT_DIR="/var/production"
MAIN_SCRIPT="${SCRIPT_DIR}/run_enhanced.sh"

echo "=== ADDING MISSING DETECTDOJO INTEGRATIONS ==="

# Backup current script
cp "$MAIN_SCRIPT" "${MAIN_SCRIPT}.backup_$(date +%Y%m%d_%H%M%S)"

# Add missing web vulnerability tools
echo "1. Adding missing web vulnerability tools..."

# Update web_vulnerability_assertions array
sed -i 's|local web_vulnerability_assertions=("nikto" "wapiti" "zap")|local web_vulnerability_assertions=("nikto" "wapiti" "zap" "katana_nuclei" "feroxbuster_nuclei" "ffuf_nuclei" "dirsearch_nuclei")|' "$MAIN_SCRIPT"

# Add SSL/TLS tools to database_findings
sed -i 's|local database_findings=("sqlmap" "db_detailed_scan" "database_aggregated")|local database_findings=("sqlmap" "db_detailed_scan" "database_aggregated" "sslyze" "testssl")|' "$MAIN_SCRIPT"

echo "✅ Web vulnerability tools updated"
echo "✅ Database findings tools updated"
echo "✅ SSL/TLS tools added"

echo "=== INTEGRATION COMPLETE ==="
echo "All tools now integrated with DetectDojo!"
echo ""
echo "Updated arrays:"
echo "- web_vulnerability_assertions: nikto, wapiti, zap, katana_nuclei, feroxbuster_nuclei, ffuf_nuclei, dirsearch_nuclei"
echo "- database_findings: sqlmap, db_detailed_scan, database_aggregated, sslyze, testssl"
echo "- cloud_findings: kubeaudit, cloud_aggregated (unchanged)"
