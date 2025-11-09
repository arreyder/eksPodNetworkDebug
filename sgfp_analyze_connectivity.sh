#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:?Usage: sgfp_analyze_connectivity.sh <sgfp_bundle_dir>}"

if [ ! -d "$BUNDLE" ]; then
  echo "[ANALYZE] ERROR: Bundle directory does not exist: $BUNDLE" >&2
  exit 1
fi

echo "[ANALYZE] Analyzing connectivity issues for bundle: $BUNDLE"
POD_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'pod_*' | head -n1 || true)
NODE_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'node_*' | head -n1 || true)
AWS_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'aws_*' | head -n1 || true)

if [ -z "$POD_DIR" ] || [ ! -d "$POD_DIR" ]; then
  echo "[ANALYZE] ERROR: Pod directory not found in bundle: $BUNDLE" >&2
  exit 1
fi

issues=0
warnings=0

echo ""
echo "=== ENI Attachment Analysis ==="

# Check ENI attachment status
# Note: Branch ENIs attached to trunk don't have Attachment.Status, they use ParentNetworkInterfaceId
if [ -s "$POD_DIR/pod_eni_attachment_status.txt" ]; then
  ATTACH_STATUS=$(cat "$POD_DIR/pod_eni_attachment_status.txt" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
  if [ "$ATTACH_STATUS" = "attached" ]; then
    echo "[OK] ENI attachment status: attached"
  elif [ "$ATTACH_STATUS" = "attaching" ]; then
    echo "[ISSUE] ENI attachment status: attaching (may indicate attachment in progress or stuck)"
    issues=$((issues+1))
  elif [ "$ATTACH_STATUS" = "unknown" ]; then
    # For branch ENIs, check if they're attached via trunk (ParentNetworkInterfaceId)
    if [ -s "$POD_DIR/pod_parent_trunk_eni.txt" ]; then
      PARENT_ENI=$(cat "$POD_DIR/pod_parent_trunk_eni.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
      if [ -n "$PARENT_ENI" ] && [ "$PARENT_ENI" != "null" ] && [ "$PARENT_ENI" != "" ]; then
        echo "[OK] ENI attached to trunk: $PARENT_ENI (branch ENI, no Attachment.Status field)"
      else
        echo "[WARN] ENI attachment status unknown (branch ENI without parent trunk reference)"
        warnings=$((warnings+1))
      fi
    else
      echo "[WARN] ENI attachment status unknown (no attachment info available)"
      warnings=$((warnings+1))
    fi
  else
    echo "[ISSUE] ENI attachment status: $ATTACH_STATUS (unexpected state)"
    issues=$((issues+1))
  fi
fi

# Check ENI status
if [ -s "$POD_DIR/pod_eni_status.txt" ]; then
  ENI_STATUS=$(cat "$POD_DIR/pod_eni_status.txt" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
  if [ "$ENI_STATUS" = "in-use" ]; then
    echo "[OK] ENI status: in-use"
  else
    echo "[WARN] ENI status: $ENI_STATUS (expected: in-use)"
    warnings=$((warnings+1))
  fi
fi

# Analyze timing: pod creation vs ENI attachment
if [ -s "$POD_DIR/pod_timing.txt" ] && [ -s "$POD_DIR/pod_eni_attach_time.txt" ]; then
  POD_CREATED=$(grep "^CREATED=" "$POD_DIR/pod_timing.txt" 2>/dev/null | cut -d= -f2- || echo "")
  ENI_ATTACHED=$(cat "$POD_DIR/pod_eni_attach_time.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
  
  if [ -n "$POD_CREATED" ] && [ -n "$ENI_ATTACHED" ] && [ "$POD_CREATED" != "unknown" ] && [ "$ENI_ATTACHED" != "unknown" ]; then
    # Convert to epoch and calculate difference (requires GNU date or fallback)
    if date --version >/dev/null 2>&1; then
      # GNU date
      POD_EPOCH=$(date -d "$POD_CREATED" +%s 2>/dev/null || echo "0")
      ENI_EPOCH=$(date -d "$ENI_ATTACHED" +%s 2>/dev/null || echo "0")
    else
      # BSD date or fallback
      POD_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$POD_CREATED" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "$POD_CREATED" +%s 2>/dev/null || echo "0")
      ENI_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$ENI_ATTACHED" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "$ENI_ATTACHED" +%s 2>/dev/null || echo "0")
    fi
    
    if [ "$POD_EPOCH" != "0" ] && [ "$ENI_EPOCH" != "0" ]; then
      DIFF=$((ENI_EPOCH - POD_EPOCH))
      if [ "$DIFF" -lt 0 ]; then
        echo "[WARN] ENI attached before pod creation (timing anomaly)"
        warnings=$((warnings+1))
      elif [ "$DIFF" -gt 300 ]; then
        echo "[ISSUE] ENI attachment delay: ${DIFF}s (>5min, may indicate attachment issues)"
        issues=$((issues+1))
      else
        echo "[OK] ENI attachment timing: ${DIFF}s after pod creation"
      fi
    fi
  fi
fi

echo ""
echo "=== IPAMD State Analysis ==="

# Check IPAMD warm pool and branch ENI limits
if [ -s "$POD_DIR/ipamd_pool.json" ]; then
  WARM_IPS=$(jq -r '.warmIPTarget // 0' "$POD_DIR/ipamd_pool.json" 2>/dev/null || echo "0")
  WARM_ENIS=$(jq -r '.warmIPTarget // 0' "$POD_DIR/ipamd_pool.json" 2>/dev/null || echo "0")
  if [ "$WARM_IPS" != "0" ] || [ "$WARM_ENIS" != "0" ]; then
    echo "[INFO] IPAMD warm pool: IPs=$WARM_IPS, ENIs=$WARM_ENIS"
  fi
fi

# Check branch ENI limits on trunk
# Note: Branch ENIs attached to trunks don't show ParentNetworkInterfaceId in describe-network-interfaces
# We need to use IPAMD introspection or count by node/trunk association
if [ -n "$AWS_DIR" ] && [ -s "$AWS_DIR/trunk_eni.json" ]; then
  TRUNK_ID=$(jq -r '.NetworkInterfaces[0].NetworkInterfaceId // empty' "$AWS_DIR/trunk_eni.json" 2>/dev/null || echo "")
  if [ -n "$TRUNK_ID" ] && [ "$TRUNK_ID" != "null" ]; then
    # Try to get branch ENI count from IPAMD introspection
    if [ -s "$POD_DIR/ipamd_introspection.json" ]; then
      # IPAMD introspection shows ENIs with trunk association
      BRANCH_COUNT=$(jq -r "[.[] | select(.TrunkENI == \"$TRUNK_ID\" or .trunkENI == \"$TRUNK_ID\")] | length" "$POD_DIR/ipamd_introspection.json" 2>/dev/null || echo "0")
      if [ "$BRANCH_COUNT" = "0" ]; then
        # Try alternative structure
        BRANCH_COUNT=$(jq -r "[.[] | select(.trunkENI == \"$TRUNK_ID\")] | length" "$POD_DIR/ipamd_introspection.json" 2>/dev/null || echo "0")
      fi
      if [ "$BRANCH_COUNT" != "0" ]; then
        echo "[INFO] Branch ENIs on trunk (from IPAMD): $BRANCH_COUNT"
        # Typical limit is 50 branch ENIs per trunk
        if [ "$BRANCH_COUNT" -gt 45 ]; then
          echo "[WARN] Branch ENI count approaching limit (typical limit: 50)"
          warnings=$((warnings+1))
        fi
      else
        echo "[INFO] Branch ENI count: Unable to determine from IPAMD (may need to check VPC-wide scan)"
      fi
    else
      echo "[INFO] Branch ENI count: IPAMD data not available"
    fi
  fi
fi

echo ""
echo "=== Subnet IP Availability ==="

# Check subnet IP availability
if [ -n "$AWS_DIR" ] && [ -s "$AWS_DIR/subnets.json" ]; then
  LOW_IP_SUBNETS=$(jq -r '.[] | select(.[1] < 10) | "\(.[0]): \(.[1]) IPs available (CIDR: \(.[2]))"' "$AWS_DIR/subnets.json" 2>/dev/null || true)
  if [ -n "$LOW_IP_SUBNETS" ]; then
    echo "[ISSUE] Subnets with low IP availability (<10 IPs):"
    echo "$LOW_IP_SUBNETS" | sed 's/^/  - /'
    issues=$((issues+1))
  else
    echo "[OK] All subnets have adequate IP availability"
  fi
fi

echo ""
echo "=== Pod Events Analysis ==="

# Check for network-related events
if [ -s "$POD_DIR/pod_events.txt" ]; then
  EVENT_COUNT=$(wc -l < "$POD_DIR/pod_events.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$EVENT_COUNT" -gt 0 ]; then
    NETWORK_EVENTS=$(grep -iE "(network|eni|attach|security.?group|failed|error|timeout|not.*ready|pending)" "$POD_DIR/pod_events.txt" 2>/dev/null || true)
    if [ -n "$NETWORK_EVENTS" ]; then
      echo "[ISSUE] Network-related events found:"
      echo "$NETWORK_EVENTS" | head -10 | sed 's/^/  - /'
      issues=$((issues+1))
    else
      echo "[OK] No network-related events found ($EVENT_COUNT total events)"
    fi
  else
    echo "[OK] No pod events found"
  fi
else
  echo "[INFO] Pod events not available"
fi

echo ""
echo "=== CNI Logs Analysis ==="

# Check aws-node logs for errors
if [ -s "$POD_DIR/aws_node_errors.log" ]; then
  # Count non-empty lines (exclude whitespace-only lines)
  ERROR_COUNT=$(grep -v '^[[:space:]]*$' "$POD_DIR/aws_node_errors.log" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$ERROR_COUNT" -gt 0 ]; then
    echo "[ISSUE] Found $ERROR_COUNT error/warning lines in aws-node logs"
    echo "[INFO] Recent errors (last 5):"
    grep -v '^[[:space:]]*$' "$POD_DIR/aws_node_errors.log" 2>/dev/null | tail -5 | sed 's/^/  - /'
    issues=$((issues+1))
  else
    echo "[OK] No errors found in aws-node logs"
  fi
else
  echo "[INFO] aws-node error logs not available"
fi

# Check node-level CNI logs (from /var/log/aws-routed-eni/)
if [ -n "$NODE_DIR" ] && [ -d "$NODE_DIR/cni_logs" ]; then
  echo ""
  echo "=== Node CNI Logs Analysis ==="
  CNI_ERRORS_FOUND=0
  
  for ERROR_FILE in "$NODE_DIR/cni_logs"/*.errors; do
    if [ -f "$ERROR_FILE" ] && [ -s "$ERROR_FILE" ]; then
      LOG_NAME=$(basename "$ERROR_FILE" .errors)
      ERROR_COUNT=$(wc -l < "$ERROR_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
      if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "[ISSUE] Found $ERROR_COUNT error/warning lines in $LOG_NAME"
        echo "[INFO] Recent errors (last 3):"
        tail -3 "$ERROR_FILE" | sed 's/^/  - /'
        CNI_ERRORS_FOUND=$((CNI_ERRORS_FOUND + 1))
        issues=$((issues+1))
      fi
    fi
  done
  
  if [ "$CNI_ERRORS_FOUND" -eq 0 ]; then
    echo "[OK] No errors found in node CNI logs"
  fi
else
  echo "[INFO] Node CNI logs not available (node diagnostics may not have been collected on the node)"
fi

echo ""
echo "=== Readiness Gate Timing ==="

# Check SG-for-Pods readiness gate timing
if [ -s "$POD_DIR/pod_conditions.json" ]; then
  READINESS_TIME=$(jq -r '.[] | select(.type=="PodReadyToStartContainers") | .lastTransitionTime // empty' "$POD_DIR/pod_conditions.json" 2>/dev/null || echo "")
  if [ -n "$READINESS_TIME" ] && [ "$READINESS_TIME" != "null" ] && [ -s "$POD_DIR/pod_timing.txt" ]; then
    POD_CREATED=$(grep "^CREATED=" "$POD_DIR/pod_timing.txt" 2>/dev/null | cut -d= -f2- || echo "")
    if [ -n "$POD_CREATED" ] && [ "$POD_CREATED" != "unknown" ]; then
      if date --version >/dev/null 2>&1; then
        POD_EPOCH=$(date -d "$POD_CREATED" +%s 2>/dev/null || echo "0")
        READY_EPOCH=$(date -d "$READINESS_TIME" +%s 2>/dev/null || echo "0")
      else
        POD_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$POD_CREATED" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "$POD_CREATED" +%s 2>/dev/null || echo "0")
        READY_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$READINESS_TIME" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "$READINESS_TIME" +%s 2>/dev/null || echo "0")
      fi
      if [ "$POD_EPOCH" != "0" ] && [ "$READY_EPOCH" != "0" ]; then
        DIFF=$((READY_EPOCH - POD_EPOCH))
        if [ "$DIFF" -gt 60 ]; then
          echo "[ISSUE] Readiness gate took ${DIFF}s (>1min, may indicate ENI attachment delay)"
          issues=$((issues+1))
        else
          echo "[OK] Readiness gate timing: ${DIFF}s"
        fi
      fi
    fi
  fi
fi

echo ""
echo "=== Summary ==="
echo "[ANALYZE] Issues found: $issues"
echo "[ANALYZE] Warnings: $warnings"

if [ "$issues" -gt 0 ] || [ "$warnings" -gt 0 ]; then
  echo ""
  echo "[ANALYZE] Recommendations:"
  [ "$issues" -gt 0 ] && echo "  - Review ENI attachment status and timing"
  [ "$warnings" -gt 0 ] && echo "  - Check branch ENI limits and subnet IP availability"
  echo "  - Review aws-node logs for detailed error messages"
  echo "  - Consider increasing warm pool size if IPs are low"
  echo "  - Check for API throttling in CloudTrail events"
fi

