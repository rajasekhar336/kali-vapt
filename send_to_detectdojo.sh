#!/bin/bash
# Helper: Send tool output to DetectDojo for normalization and correlation

set -euo pipefail

DETECTDOJO_URL="${DETECTDOJO_URL:-http://localhost:8081}"
TOOL_NAME="$1"
TARGET_DOMAIN="$2"
TOOL_OUTPUT_FILE="$3"

if [[ ! -f "$TOOL_OUTPUT_FILE" ]]; then
    echo "[ERROR] File not found: $TOOL_OUTPUT_FILE" >&2
    exit 1
fi

TOOL_OUTPUT=$(cat "$TOOL_OUTPUT_FILE")

# Send to DetectDojo
echo "[INFO] Sending $TOOL_NAME findings to DetectDojo..."
curl -X POST "$DETECTDOJO_URL/api/findings/add" \
    -H "Content-Type: application/json" \
    -d @- << EOF
{
  "tool_name": "$TOOL_NAME",
  "target_domain": "$TARGET_DOMAIN",
  "tool_output": $(jq -Rs . <<< "$TOOL_OUTPUT")
}
EOF

echo ""
echo "[INFO] Successfully sent to DetectDojo"
