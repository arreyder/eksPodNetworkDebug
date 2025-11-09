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

# Get pod IP for analysis
POD_IP=$(grep "^POD_IP=" "$POD_DIR/pod_ip.txt" 2>/dev/null | cut -d= -f2- || echo "unknown")

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
echo "=== Network Namespace Analysis ==="

# Check for stuck/orphaned network namespaces
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_netns_details.json" ]; then
  if jq -e 'length > 0' "$NODE_DIR/node_netns_details.json" >/dev/null 2>&1; then
    NETNS_COUNT=$(jq -r 'length' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "0")
    echo "[INFO] Found $NETNS_COUNT network namespace(s) on node"
    
    # Check for namespaces with no interfaces (potential leaks)
    # Note: Some namespaces might show 0 interfaces if they're in cleanup or we can't access them properly
    # Only flag as issue if we have a significant number or if they're old
    EMPTY_NS=$(jq -r '[.[] | select(.interface_count == 0)] | length' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "0")
    if [ "$EMPTY_NS" != "0" ]; then
      # Check if any empty namespaces are old (more than 1 hour old) - these are more likely to be leaks
      CURRENT_TIME=$(date +%s 2>/dev/null || echo "0")
      if [ "$CURRENT_TIME" != "0" ]; then
        OLD_EMPTY_NS=$(jq -r --arg now "$CURRENT_TIME" '[.[] | select(.interface_count == 0 and (($now | tonumber) - .mtime) > 3600)] | length' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "0")
        
        if [ "$OLD_EMPTY_NS" != "0" ] && [ "$OLD_EMPTY_NS" != "null" ] && [ "$OLD_EMPTY_NS" != "" ]; then
          echo "[ISSUE] Found $OLD_EMPTY_NS network namespace(s) with no interfaces and older than 1 hour (likely leaks)"
          jq -r --arg now "$CURRENT_TIME" '.[] | select(.interface_count == 0 and (($now | tonumber) - .mtime) > 3600) | "  - \(.name) (age: \(($now | tonumber) - .mtime)s)"' "$NODE_DIR/node_netns_details.json" 2>/dev/null || true
          issues=$((issues+1))
        elif [ "$EMPTY_NS" -gt 10 ]; then
          # If we have many empty namespaces, flag it as a potential issue
          echo "[WARN] Found $EMPTY_NS network namespace(s) with no interfaces (may be in cleanup or detection issue)"
          warnings=$((warnings+1))
        else
          echo "[INFO] Found $EMPTY_NS network namespace(s) with no interfaces (may be in cleanup)"
        fi
      else
        # Can't determine age, just report count
        if [ "$EMPTY_NS" -gt 10 ]; then
          echo "[WARN] Found $EMPTY_NS network namespace(s) with no interfaces (may be in cleanup or detection issue)"
          warnings=$((warnings+1))
        else
          echo "[INFO] Found $EMPTY_NS network namespace(s) with no interfaces (may be in cleanup)"
        fi
      fi
    fi
    
    # Get pod UID and try to match against network namespace
    # AWS VPC CNI uses container ID (sandbox ID) for namespace names, not pod UID directly
    POD_UID=$(grep "^UID=" "$POD_DIR/pod_timing.txt" 2>/dev/null | cut -d= -f2- || echo "")
    
    # Try to get container ID from pod status (infra container)
    POD_CONTAINER_ID=""
    if [ -s "$POD_DIR/pod_full.json" ]; then
      # Try multiple methods to get container ID:
      # 1. Look for infra/pause container in containerStatuses
      POD_CONTAINER_ID=$(jq -r '.status.containerStatuses[]? | select(.name | test("POD|infra|pause")) | .containerID // empty' "$POD_DIR/pod_full.json" 2>/dev/null | head -1 || echo "")
      
      # 2. If not found, try initContainers (some setups use init containers)
      if [ -z "$POD_CONTAINER_ID" ] || [ "$POD_CONTAINER_ID" = "null" ] || [ "$POD_CONTAINER_ID" = "" ]; then
        POD_CONTAINER_ID=$(jq -r '.status.initContainerStatuses[]? | select(.name | test("POD|infra|pause")) | .containerID // empty' "$POD_DIR/pod_full.json" 2>/dev/null | head -1 || echo "")
      fi
      
      # 3. If still not found, get the first container's ID (fallback)
      if [ -z "$POD_CONTAINER_ID" ] || [ "$POD_CONTAINER_ID" = "null" ] || [ "$POD_CONTAINER_ID" = "" ]; then
        POD_CONTAINER_ID=$(jq -r '.status.containerStatuses[0]? | .containerID // empty' "$POD_DIR/pod_full.json" 2>/dev/null | head -1 || echo "")
      fi
      
      # Remove container runtime prefix (e.g., "containerd://" or "docker://")
      if [ -n "$POD_CONTAINER_ID" ] && [ "$POD_CONTAINER_ID" != "null" ] && [ "$POD_CONTAINER_ID" != "" ]; then
        POD_CONTAINER_ID=$(echo "$POD_CONTAINER_ID" | sed 's|^[^:]*://||' || echo "$POD_CONTAINER_ID")
      fi
    fi
    
    POD_NS_FOUND=0
    POD_NS_NAME=""
    POD_NS_MTIME="0"
    
    # AWS VPC CNI network namespaces are typically named with "cni-" prefix followed by container ID hash
    # The format is usually: cni-<hash> where hash is derived from container ID
    # Try matching by container ID first (most reliable)
    if [ -n "$POD_CONTAINER_ID" ] && [ "$POD_CONTAINER_ID" != "null" ] && [ "$POD_CONTAINER_ID" != "" ]; then
      # Container IDs are usually 64-character hashes (sha256)
      # AWS CNI may use a hash of the container ID, so try multiple approaches:
      # 1. Try matching last 12 characters (common short ID format)
      CONTAINER_ID_SHORT=$(echo "$POD_CONTAINER_ID" | tail -c 13 | head -c 12 || echo "$POD_CONTAINER_ID")
      POD_NS_NAME=$(jq -r --arg cid "$CONTAINER_ID_SHORT" '.[] | select(.name | contains($cid)) | .name' "$NODE_DIR/node_netns_details.json" 2>/dev/null | head -1 || echo "")
      
      # 2. If not found, try matching any part of the container ID (CNI may hash it differently)
      if [ -z "$POD_NS_NAME" ]; then
        # Try matching first 12 characters
        CONTAINER_ID_FIRST=$(echo "$POD_CONTAINER_ID" | head -c 12 || echo "")
        POD_NS_NAME=$(jq -r --arg cid "$CONTAINER_ID_FIRST" '.[] | select(.name | contains($cid)) | .name' "$NODE_DIR/node_netns_details.json" 2>/dev/null | head -1 || echo "")
      fi
      
      # 3. Try full container ID match (unlikely but possible)
      if [ -z "$POD_NS_NAME" ]; then
        POD_NS_NAME=$(jq -r --arg cid "$POD_CONTAINER_ID" '.[] | select(.name | contains($cid)) | .name' "$NODE_DIR/node_netns_details.json" 2>/dev/null | head -1 || echo "")
      fi
      
      # 4. If still not found, the namespace name might be a hash of the container ID
      # In that case, we can't match it directly, but we can note that we tried
      if [ -z "$POD_NS_NAME" ] && [ -n "$POD_CONTAINER_ID" ]; then
        # Debug: log that we have container ID but couldn't match
        echo "[INFO] Container ID found: ${POD_CONTAINER_ID:0:12}... (but namespace not matched - may use hashed format)"
      fi
    fi
    
    # Fallback: try matching by pod UID (less reliable for AWS CNI)
    if [ -z "$POD_NS_NAME" ] && [ -n "$POD_UID" ]; then
      # Try exact UID match
      POD_NS_NAME=$(jq -r --arg uid "$POD_UID" '.[] | select(.name == $uid) | .name' "$NODE_DIR/node_netns_details.json" 2>/dev/null | head -1 || echo "")
      if [ -z "$POD_NS_NAME" ]; then
        # Try partial match (UID might be part of namespace name)
        POD_NS_NAME=$(jq -r --arg uid "$POD_UID" '.[] | select(.name | contains($uid)) | .name' "$NODE_DIR/node_netns_details.json" 2>/dev/null | head -1 || echo "")
      fi
    fi
    
    if [ -n "$POD_NS_NAME" ]; then
      POD_NS_FOUND=1
      POD_NS_MTIME=$(jq -r --arg name "$POD_NS_NAME" '.[] | select(.name == $name) | .mtime' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "0")
    fi
    
    if [ "$POD_NS_FOUND" = "0" ]; then
      echo "[WARN] Pod network namespace not found (pod may not have network setup yet or namespace name doesn't match UID)"
      warnings=$((warnings+1))
    else
      echo "[OK] Pod network namespace found: $POD_NS_NAME"
      # Get namespace creation time and compare to pod creation
      POD_CREATED=$(grep "^CREATED=" "$POD_DIR/pod_timing.txt" 2>/dev/null | cut -d= -f2- || echo "")
      if [ -n "$POD_CREATED" ] && [ "$POD_CREATED" != "unknown" ] && [ "$POD_NS_MTIME" != "0" ]; then
        # Convert pod creation time to epoch (handle both GNU and BSD date)
        if date --version >/dev/null 2>&1; then
          POD_CREATED_EPOCH=$(date -d "$POD_CREATED" +%s 2>/dev/null || echo "0")
        else
          POD_CREATED_EPOCH=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$POD_CREATED" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%S" "$POD_CREATED" +%s 2>/dev/null || echo "0")
        fi
        if [ "$POD_CREATED_EPOCH" != "0" ] && [ "$POD_NS_MTIME" != "0" ]; then
          NS_DELAY=$((POD_NS_MTIME - POD_CREATED_EPOCH))
          if [ "$NS_DELAY" -lt 0 ]; then
            echo "[WARN] Network namespace created before pod (timing anomaly)"
            warnings=$((warnings+1))
          elif [ "$NS_DELAY" -gt 60 ]; then
            echo "[ISSUE] Network namespace creation delay: ${NS_DELAY}s after pod creation (>60s)"
            issues=$((issues+1))
          else
            echo "[OK] Network namespace created ${NS_DELAY}s after pod creation"
          fi
        fi
      fi
    fi
  fi
else
  echo "[INFO] Network namespace details not available"
fi

# IP address conflict detection
if [ -n "$NODE_DIR" ] && [ -f "$NODE_DIR/node_duplicate_ips.txt" ]; then
  # Check if file has non-whitespace content
  if [ -s "$NODE_DIR/node_duplicate_ips.txt" ] && grep -q '[^[:space:]]' "$NODE_DIR/node_duplicate_ips.txt" 2>/dev/null; then
    echo ""
    echo "[ISSUE] IP address conflicts detected:"
    grep '[^[:space:]]' "$NODE_DIR/node_duplicate_ips.txt" | sed 's/^/  - /'
    issues=$((issues+1))
  else
    echo "[OK] No IP address conflicts detected"
  fi
fi

# DNS resolution check
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_dns_tests.txt" ]; then
  echo ""
  echo "=== DNS Resolution ==="
  # Check for actual failures (not the expected metadata service failure)
  K8S_DNS_FAILED=$(grep -A 5 "kubernetes.default.svc.cluster.local" "$NODE_DIR/node_dns_tests.txt" 2>/dev/null | grep -qi "FAILED" && echo "1" || echo "0")
  if [ "$K8S_DNS_FAILED" = "1" ]; then
    echo "[ISSUE] Kubernetes DNS resolution failed"
    grep -A 5 "kubernetes.default.svc.cluster.local" "$NODE_DIR/node_dns_tests.txt" | grep -E "(FAILED|error|timeout|NXDOMAIN)" | head -3 | sed 's/^/  - /'
    issues=$((issues+1))
  else
    echo "[OK] Kubernetes DNS resolution working"
  fi
  # Note: metadata service DNS failure is expected and not an issue
fi

# Resource exhaustion checks
if [ -n "$NODE_DIR" ]; then
  echo ""
  echo "=== Resource Exhaustion ==="
  
  # File descriptors
  if [ -s "$NODE_DIR/node_file_descriptors.txt" ]; then
    ALLOCATED=$(awk '{print $1}' "$NODE_DIR/node_file_descriptors.txt" 2>/dev/null || echo "0")
    MAX=$(awk '{print $3}' "$NODE_DIR/node_file_descriptors.txt" 2>/dev/null || echo "0")
    if [ "$MAX" != "0" ] && [ "$ALLOCATED" != "0" ]; then
      USAGE_PCT=$((ALLOCATED * 100 / MAX))
      if [ "$USAGE_PCT" -gt 80 ]; then
        echo "[ISSUE] File descriptor usage high: $ALLOCATED / $MAX (~$USAGE_PCT%)"
        issues=$((issues+1))
      else
        echo "[OK] File descriptor usage: $ALLOCATED / $MAX (~$USAGE_PCT%)"
      fi
    fi
  fi
  
  # Memory pressure
  if [ -s "$NODE_DIR/node_memory_info.txt" ]; then
    MEM_AVAILABLE=$(grep "^MemAvailable:" "$NODE_DIR/node_memory_info.txt" 2>/dev/null | awk '{print $2}' || echo "0")
    MEM_TOTAL=$(grep "^MemTotal:" "$NODE_DIR/node_memory_info.txt" 2>/dev/null | awk '{print $2}' || echo "0")
    if [ "$MEM_TOTAL" != "0" ] && [ "$MEM_AVAILABLE" != "0" ]; then
      MEM_USAGE_PCT=$(((MEM_TOTAL - MEM_AVAILABLE) * 100 / MEM_TOTAL))
      if [ "$MEM_USAGE_PCT" -gt 90 ]; then
        echo "[ISSUE] Memory usage high: ~$MEM_USAGE_PCT%"
        issues=$((issues+1))
      else
        echo "[OK] Memory usage: ~$MEM_USAGE_PCT%"
      fi
    fi
  fi
fi

# Network interface state check
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_interfaces_state.txt" ]; then
  echo ""
  echo "=== Network Interface State ==="
  DOWN_COUNT=$(grep -E "state DOWN" "$NODE_DIR/node_interfaces_state.txt" 2>/dev/null | grep -v " lo:" | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$DOWN_COUNT" -gt 0 ]; then
    echo "[ISSUE] Found $DOWN_COUNT interface(s) in DOWN state (excluding lo):"
    grep -E "state DOWN" "$NODE_DIR/node_interfaces_state.txt" | grep -v " lo:" | head -10 | sed 's/^/  - /'
    issues=$((issues+1))
  else
    echo "[OK] No interfaces in unexpected DOWN state"
  fi
fi

# MTU mismatch / fragmentation check
if [ -n "$NODE_DIR" ]; then
  echo ""
  echo "=== MTU Configuration ==="
  
  MTU_ISSUES=0
  MTU_TMP=$(mktemp)
  
  # Extract MTU values from node interfaces (excluding loopback)
  if [ -s "$NODE_DIR/node_interface_ip_stats.txt" ]; then
    # Extract MTU from ip -s link output, excluding loopback interfaces
    # Format: "1: lo: <...> mtu 65536 ..." or "5: eth0: <...> mtu 1500 ..."
    grep -E "^[0-9]+:" "$NODE_DIR/node_interface_ip_stats.txt" 2>/dev/null | grep -v " lo:" | grep -oE "mtu [0-9]+" | sed 's/mtu //' | sort -u > "$MTU_TMP" || true
    
    if [ -s "$MTU_TMP" ]; then
      MTU_COUNT=$(wc -l < "$MTU_TMP" | tr -d '[:space:]' || echo "0")
      MTU_VALUES=$(cat "$MTU_TMP" | tr '\n' ',' | sed 's/,$//')
      
      if [ "$MTU_COUNT" -gt 1 ]; then
        echo "[WARN] Multiple MTU values found on node interfaces (excluding loopback): $MTU_VALUES"
        warnings=$((warnings+1))
        MTU_ISSUES=1
        
        # Show which interfaces have which MTU (excluding loopback)
        echo "[INFO] Interface MTU breakdown:"
        grep -E "^[0-9]+:" "$NODE_DIR/node_interface_ip_stats.txt" 2>/dev/null | grep -v " lo:" | grep -oE "^[0-9]+:[^:]+:.*mtu [0-9]+" | sed 's/^/  - /' | head -10
      else
        MTU_VALUE=$(cat "$MTU_TMP" | head -1 | tr -d '[:space:]' || echo "")
        if [ -n "$MTU_VALUE" ]; then
          if [ "$MTU_VALUE" = "1500" ]; then
            echo "[OK] Standard MTU (1500) on all non-loopback interfaces"
          elif [ "$MTU_VALUE" = "9001" ]; then
            echo "[OK] Jumbo frames enabled (MTU 9001) on all non-loopback interfaces"
          elif [ "$MTU_VALUE" -lt 1500 ]; then
            echo "[WARN] Unusually low MTU ($MTU_VALUE) - may cause fragmentation issues"
            warnings=$((warnings+1))
            MTU_ISSUES=1
          elif [ "$MTU_VALUE" -gt 9001 ]; then
            echo "[WARN] Unusually high MTU ($MTU_VALUE) - may not be supported by network"
            warnings=$((warnings+1))
            MTU_ISSUES=1
          else
            echo "[INFO] MTU: $MTU_VALUE on all non-loopback interfaces"
          fi
        fi
      fi
    fi
  fi
  
  # Check pod interface MTU if available
  if [ -s "$POD_DIR/pod_interface_stats.txt" ] && ! grep -qi "not available\|command failed" "$POD_DIR/pod_interface_stats.txt" 2>/dev/null; then
    POD_MTU_TMP=$(mktemp)
    grep -oE "mtu [0-9]+" "$POD_DIR/pod_interface_stats.txt" 2>/dev/null | sed 's/mtu //' | sort -u > "$POD_MTU_TMP" || true
    
    if [ -s "$POD_MTU_TMP" ]; then
      POD_MTU=$(cat "$POD_MTU_TMP" | head -1 | tr -d '[:space:]' || echo "")
      if [ -n "$POD_MTU" ] && [ -s "$MTU_TMP" ]; then
        NODE_MTU=$(cat "$MTU_TMP" | head -1 | tr -d '[:space:]' || echo "")
        if [ -n "$NODE_MTU" ] && [ "$POD_MTU" != "$NODE_MTU" ]; then
          echo "[ISSUE] MTU mismatch: pod interface ($POD_MTU) != node interface ($NODE_MTU) - may cause fragmentation"
          issues=$((issues+1))
          MTU_ISSUES=1
        fi
      fi
    fi
    rm -f "$POD_MTU_TMP" 2>/dev/null || true
  fi
  
  # Check for fragmentation hints in kernel logs
  if [ -s "$NODE_DIR/node_dmesg_network.txt" ]; then
    FRAG_HINTS=$(grep -iE "fragmentation needed|frag.*drop|mtu.*exceed" "$NODE_DIR/node_dmesg_network.txt" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    if [ "$FRAG_HINTS" != "0" ] && [ "$FRAG_HINTS" -gt 0 ]; then
      echo "[ISSUE] Found $FRAG_HINTS fragmentation-related message(s) in kernel logs"
      grep -iE "fragmentation needed|frag.*drop|mtu.*exceed" "$NODE_DIR/node_dmesg_network.txt" 2>/dev/null | head -3 | sed 's/^/  - /'
      issues=$((issues+1))
      MTU_ISSUES=1
    fi
  fi
  
  if [ "$MTU_ISSUES" -eq 0 ]; then
    echo "[OK] No MTU configuration issues detected"
  fi
  
  rm -f "$MTU_TMP" 2>/dev/null || true
fi

# kube-proxy iptables analysis
if [ -n "$NODE_DIR" ]; then
  echo ""
  echo "=== kube-proxy iptables Analysis ==="
  
  KUBE_PROXY_ISSUES=0
  NODE_IPTABLES_FILTER="${NODE_DIR}/node_iptables_filter.txt"
  NODE_IPTABLES_NAT="${NODE_DIR}/node_iptables_nat.txt"
  
  if [ -s "$NODE_IPTABLES_FILTER" ] || [ -s "$NODE_IPTABLES_NAT" ]; then
    # Check for kube-proxy chains
    KUBE_SERVICES_FILTER=$(grep -c "^Chain KUBE-SERVICES" "$NODE_IPTABLES_FILTER" 2>/dev/null | tr -d '[:space:]' || echo "0")
    KUBE_SERVICES_NAT=$(grep -c "^Chain KUBE-SERVICES" "$NODE_IPTABLES_NAT" 2>/dev/null | tr -d '[:space:]' || echo "0")
    KUBE_NODEPORTS=$(grep -c "^Chain KUBE-NODEPORTS" "$NODE_IPTABLES_FILTER" 2>/dev/null | tr -d '[:space:]' || echo "0")
    KUBE_MARK_MASQ=$(grep -c "^Chain KUBE-MARK-MASQ" "$NODE_IPTABLES_NAT" 2>/dev/null | tr -d '[:space:]' || echo "0")
    
    # Check for IPVS mode (would have KUBE-IPVS chains or no kube-proxy chains)
    KUBE_IPVS=$(grep -c "^Chain KUBE-IPVS" "$NODE_IPTABLES_FILTER" 2>/dev/null | tr -d '[:space:]' || echo "0")
    
    if [ "$KUBE_IPVS" -gt 0 ]; then
      echo "[INFO] kube-proxy running in IPVS mode (KUBE-IPVS chains detected)"
    elif [ "$KUBE_SERVICES_NAT" -gt 0 ] || [ "$KUBE_SERVICES_FILTER" -gt 0 ]; then
      echo "[OK] kube-proxy running in iptables mode"
      
      # Check if chains are being used (have packet counts > 0)
      # Packet counts may have K/M suffixes (e.g., "2668K" = 2,668,000)
      if [ -s "$NODE_IPTABLES_NAT" ]; then
        # Check for any KUBE-SERVICES rules with packet counts (lines starting with numbers, possibly with K/M)
        KUBE_SERVICES_RULES=$(grep "KUBE-SERVICES" "$NODE_IPTABLES_NAT" 2>/dev/null | grep -E "^[[:space:]]*[0-9]+[KM]?" | wc -l | tr -d '[:space:]' || echo "0")
        if [ -n "$KUBE_SERVICES_RULES" ] && [ "$KUBE_SERVICES_RULES" != "0" ] && [ "$KUBE_SERVICES_RULES" -gt 0 ] 2>/dev/null; then
          # Get a sample packet count for display
          SAMPLE_PKTS=$(grep "KUBE-SERVICES" "$NODE_IPTABLES_NAT" 2>/dev/null | grep -E "^[[:space:]]*[0-9]+[KM]?" | head -1 | awk '{print $1}' || echo "0")
          echo "[OK] KUBE-SERVICES chain active ($KUBE_SERVICES_RULES rule(s) with traffic, sample: $SAMPLE_PKTS packets)"
        else
          echo "[WARN] KUBE-SERVICES chain has no packet counts (may indicate kube-proxy not processing traffic)"
          warnings=$((warnings+1))
          KUBE_PROXY_ISSUES=1
        fi
      fi
      
      if [ "$KUBE_NODEPORTS" -gt 0 ]; then
        echo "[OK] KUBE-NODEPORTS chain present"
      fi
      
      if [ "$KUBE_MARK_MASQ" -gt 0 ]; then
        KUBE_MARK_MASQ_REFS=$(grep "^Chain KUBE-MARK-MASQ" "$NODE_IPTABLES_NAT" 2>/dev/null | grep -oE "\([0-9]+ references\)" | grep -oE "[0-9]+" | head -1 || echo "0")
        echo "[OK] KUBE-MARK-MASQ chain present ($KUBE_MARK_MASQ_REFS references)"
      fi
      
      # Check for masquerade rules (required for service traffic)
      MASQ_RULES=$(grep -iE "MASQUERADE|KUBE-MARK-MASQ" "$NODE_IPTABLES_NAT" 2>/dev/null | grep -E "^[[:space:]]+[0-9]+" | wc -l | tr -d '[:space:]' || echo "0")
      if [ "$MASQ_RULES" -gt 0 ]; then
        echo "[OK] Found $MASQ_RULES masquerade rule(s) (required for service traffic)"
      else
        echo "[WARN] No masquerade rules found - service traffic may not work correctly"
        warnings=$((warnings+1))
        KUBE_PROXY_ISSUES=1
      fi
      
      # Check for pod-specific service rules (we already check this in report, but summarize here)
      if [ -n "$POD_IP" ] && [ "$POD_IP" != "unknown" ]; then
        POD_SERVICE_RULES=$(grep -i "$POD_IP" "$NODE_IPTABLES_NAT" 2>/dev/null | grep -E "^[[:space:]]+[0-9]+" | wc -l | tr -d '[:space:]' || echo "0")
        if [ "$POD_SERVICE_RULES" -gt 0 ]; then
          echo "[OK] Found $POD_SERVICE_RULES iptables rule(s) for pod IP $POD_IP (service rules present)"
        else
          echo "[INFO] No iptables service rules found for pod IP $POD_IP (pod may not be part of a service)"
        fi
      fi
    else
      echo "[WARN] kube-proxy chains not found - kube-proxy may not be running or using different mode"
      warnings=$((warnings+1))
      KUBE_PROXY_ISSUES=1
    fi
  else
    echo "[INFO] iptables rules not available for kube-proxy analysis"
  fi
  
  if [ "$KUBE_PROXY_ISSUES" -eq 0 ]; then
    echo "[OK] No kube-proxy iptables issues detected"
  fi
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
echo "=== CloudTrail API Diagnostics ==="

# Try to find API diagnostics directory (same parent as bundle)
API_DIAG_DIR=""
if [ -d "$(dirname "$BUNDLE")" ]; then
  API_DIAG_DIR=$(ls -dt "$(dirname "$BUNDLE")"/sgfp_api_diag_* 2>/dev/null | head -1 || echo "")
fi

if [ -n "$API_DIAG_DIR" ] && [ -d "$API_DIAG_DIR" ]; then
  # Check for real errors/throttles
  ERROR_COUNT=0
  if [ -f "$API_DIAG_DIR/eni_errors.tsv" ]; then
    ERROR_COUNT=$(wc -l < "$API_DIAG_DIR/eni_errors.tsv" 2>/dev/null | tr -d '[:space:]' || echo "0")
  fi
  
  if [ "$ERROR_COUNT" -gt 0 ]; then
    echo "[ISSUE] Found $ERROR_COUNT real error/throttle event(s) in CloudTrail"
    echo "[INFO] Recent errors/throttles (last 5):"
    head -5 "$API_DIAG_DIR/eni_errors.tsv" | awk -F'\t' '{printf "  - %s: %s (%s)\n", $2, $5, $6}' 2>/dev/null || true
    issues=$((issues+1))
  else
    echo "[OK] No real errors/throttles found in CloudTrail"
  fi
  
  # Show throttle summary by action
  if [ -s "$API_DIAG_DIR/throttle_by_action.txt" ]; then
    THROTTLE_COUNT=$(wc -l < "$API_DIAG_DIR/throttle_by_action.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$THROTTLE_COUNT" -gt 0 ]; then
      echo "[INFO] Throttles by action:"
      head -5 "$API_DIAG_DIR/throttle_by_action.txt" | sed 's/^/  - /'
    fi
  fi
  
  # Show API calls by user/caller
  if [ -s "$API_DIAG_DIR/calls_by_user.txt" ]; then
    USER_COUNT=$(wc -l < "$API_DIAG_DIR/calls_by_user.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$USER_COUNT" -gt 0 ]; then
      echo "[INFO] API calls by user/caller:"
      head -10 "$API_DIAG_DIR/calls_by_user.txt" | sed 's/^/  - /'
    fi
  fi
  
  # Show summary stats
  if [ -s "$API_DIAG_DIR/flat_events.json" ]; then
    TOTAL_EVENTS=$(jq -r 'length' "$API_DIAG_DIR/flat_events.json" 2>/dev/null || echo "0")
    DRYRUN_COUNT=$(wc -l < "$API_DIAG_DIR/eni_dryruns.tsv" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$TOTAL_EVENTS" != "0" ]; then
      echo "[INFO] Total ENI API events analyzed: $TOTAL_EVENTS (dry-runs: $DRYRUN_COUNT)"
    fi
  fi
else
  echo "[INFO] CloudTrail API diagnostics not available (run with --skip-api to skip, or provide --api-dir)"
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
  if [ -n "$API_DIAG_DIR" ] && [ -d "$API_DIAG_DIR" ] && [ -s "$API_DIAG_DIR/eni_errors.tsv" ]; then
    ERROR_COUNT=$(wc -l < "$API_DIAG_DIR/eni_errors.tsv" 2>/dev/null | tr -d '[:space:]' || echo "0")
    [ "$ERROR_COUNT" -gt 0 ] && echo "  - Review CloudTrail API throttles/errors (see API diagnostics)"
  fi
fi

