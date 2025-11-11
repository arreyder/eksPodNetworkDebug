#!/usr/bin/env bash
# Update investigation document with new diagnostic data
# Usage: ./sgfp_update_investigation.sh <investigation-file> <bundle-dir> [--status healthy|unhealthy]

set -euo pipefail

INV_FILE="${1:?usage: sgfp_update_investigation.sh <investigation-file> <bundle-dir> [--status healthy|unhealthy]}"
BUNDLE_DIR="${2:?usage: sgfp_update_investigation.sh <investigation-file> <bundle-dir> [--status healthy|unhealthy]}"
STATUS="${3:-}"

if [ "$1" = "--status" ] && [ -n "${2:-}" ]; then
  STATUS="$2"
  INV_FILE="${3:?usage: sgfp_update_investigation.sh <investigation-file> <bundle-dir> [--status healthy|unhealthy]}"
  BUNDLE_DIR="${4:?usage: sgfp_update_investigation.sh <investigation-file> <bundle-dir> [--status healthy|unhealthy]}"
fi

if [ ! -f "$INV_FILE" ]; then
  echo "[ERROR] Investigation file not found: $INV_FILE" >&2
  exit 1
fi

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "[ERROR] Bundle directory not found: $BUNDLE_DIR" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] jq is required" >&2
  exit 1
fi

log() { printf "[INV-UPDATE] %s\n" "$*"; }

log "Updating investigation document"
log "File: $INV_FILE"
log "Bundle: $BUNDLE_DIR"
[ -n "$STATUS" ] && log "Status: $STATUS"

# Find pod directory
POD_DIR=$(find "$BUNDLE_DIR" -type d -name "pod_*" | head -1)
if [ -z "$POD_DIR" ]; then
  echo "[ERROR] Could not find pod directory in bundle" >&2
  exit 1
fi

POD_NAME=$(basename "$POD_DIR" | sed 's/^pod_//')
POD_IP=$(grep "^POD_IP=" "$POD_DIR/pod_ip.txt" 2>/dev/null | cut -d= -f2- || echo "unknown")

# Extract key data points
log "Extracting key diagnostic data..."

# Get normalized data if available
NORMALIZED_DATA=""
if [ -f "$BUNDLE_DIR/../healthy-pods"/*/normalized.json ] || [ -f "baselines"/*/healthy-pods/*/normalized.json ]; then
  # Try to find normalized data
  NORM_FILE=$(find "baselines" -name "normalized.json" -path "*/$(basename "$BUNDLE_DIR")/*" 2>/dev/null | head -1 || echo "")
  [ -z "$NORM_FILE" ] && NORM_FILE=$(./sgfp_extract_normalized.sh "$BUNDLE_DIR" 2>/dev/null | tee /tmp/norm_tmp.json && echo "/tmp/norm_tmp.json" || echo "")
  if [ -n "$NORM_FILE" ] && [ -f "$NORM_FILE" ]; then
    NORMALIZED_DATA=$(cat "$NORM_FILE")
  fi
fi

# Get ENI readiness
ENI_READY="unknown"
if [ -f "$POD_DIR/pod_eni_readiness.txt" ]; then
  ENI_READY=$(grep "^ReadyForTraffic=" "$POD_DIR/pod_eni_readiness.txt" 2>/dev/null | cut -d= -f2- || echo "unknown")
fi

# Get network namespace completeness
NODE_DIR=$(find "$BUNDLE_DIR" -type d -name "node_*" | head -1)
NETNS_COMPLETE="unknown"
if [ -n "$NODE_DIR" ] && [ -f "$NODE_DIR/node_netns_details.json" ] && [ -n "$POD_IP" ] && [ "$POD_IP" != "unknown" ]; then
  NETNS_COMPLETE=$(jq -r --arg ip "$POD_IP" '.[] | select(.ips.ipv4[]? == $ip) | .completeness // {}' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "{}")
  if [ "$NETNS_COMPLETE" != "{}" ] && [ "$NETNS_COMPLETE" != "null" ]; then
    ETH0_STATE=$(echo "$NETNS_COMPLETE" | jq -r '.eth0_state // "unknown"' 2>/dev/null || echo "unknown")
    ROUTE_COUNT=$(echo "$NETNS_COMPLETE" | jq -r '.route_count // 0' 2>/dev/null || echo "0")
    DEFAULT_ROUTE=$(echo "$NETNS_COMPLETE" | jq -r '.default_route // ""' 2>/dev/null || echo "")
    NETNS_COMPLETE="eth0=$ETH0_STATE, routes=$ROUTE_COUNT, default_route=$([ -n "$DEFAULT_ROUTE" ] && echo "present" || echo "missing")"
  fi
fi

# Get pod phase and ready status
POD_PHASE="unknown"
POD_READY="unknown"
if [ -f "$POD_DIR/pod_full.json" ]; then
  POD_PHASE=$(jq -r '.status.phase // "unknown"' "$POD_DIR/pod_full.json" 2>/dev/null || echo "unknown")
  POD_READY=$(jq -r '([.status.conditions[]? | select(.type == "Ready") | .status == "True"] | first) // false' "$POD_DIR/pod_full.json" 2>/dev/null || echo "unknown")
fi

# Get security group count
SG_COUNT="unknown"
if [ -f "$POD_DIR/pod_branch_eni_sgs.txt" ]; then
  SG_COUNT=$(wc -l < "$POD_DIR/pod_branch_eni_sgs.txt" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
fi

# Create timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DATE=$(date -u +"%Y-%m-%d")

# Generate report entry
REPORT_ENTRY=$(cat <<EOF
### Report: $POD_NAME

**Date**: \`$DATE\`  
**Pod**: \`$POD_NAME\`  
**Status**: \`${STATUS:-unknown}\`  
**Key Findings**:
- Pod Phase: \`$POD_PHASE\`
- Pod Ready: \`$POD_READY\`
- ENI Ready: \`$ENI_READY\`
- Network Namespace: \`$NETNS_COMPLETE\`
- Security Groups: \`$SG_COUNT\`

**Relevant Data Points**:
- Pod IP: \`$POD_IP\`
- ENI Readiness: \`$ENI_READY\`
- Network Namespace Completeness: \`$NETNS_COMPLETE\`

**Link**: \`$BUNDLE_DIR\`

---

EOF
)

log "Generated report entry for: $POD_NAME"

# Append to investigation document
{
  echo ""
  echo "$REPORT_ENTRY"
} >> "$INV_FILE"

# Update last updated timestamp
sed -i "s/^\*\*Last Updated\*\*:.*/\*\*Last Updated\*\*: \`$TIMESTAMP\`/" "$INV_FILE" 2>/dev/null || true

log "Investigation document updated: $INV_FILE"
log "Added report entry for pod: $POD_NAME"

