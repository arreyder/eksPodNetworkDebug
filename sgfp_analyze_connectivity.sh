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
echo "=== ENI / Instance Limits Analysis ==="

# Function to get ENI/IP limits for instance type
# Based on AWS EC2 documentation: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html
get_instance_limits() {
  local instance_type="$1"
  case "$instance_type" in
    # Small instances
    t3.nano|t3.micro|t3.small|t3.medium|t4g.nano|t4g.micro|t4g.small|t4g.medium)
      echo "3 4"  # 3 ENIs, 4 IPs per ENI
      ;;
    # Medium instances
    t3.large|t3.xlarge|t4g.large|t4g.xlarge|m5.large|m5.xlarge|m5d.large|m5d.xlarge|c5.large|c5.xlarge|c5d.large|c5d.xlarge|r5.large|r5.xlarge|r5d.large|r5d.xlarge|m6i.large|m6i.xlarge|c6i.large|c6i.xlarge|r6i.large|r6i.xlarge)
      echo "3 10"  # 3 ENIs, 10 IPs per ENI
      ;;
    # Large instances (2xlarge, 4xlarge)
    t3.2xlarge|t4g.2xlarge|m5.2xlarge|m5.4xlarge|m5d.2xlarge|m5d.4xlarge|c5.2xlarge|c5.4xlarge|c5d.2xlarge|c5d.4xlarge|r5.2xlarge|r5.4xlarge|r5d.2xlarge|r5d.4xlarge|m6i.2xlarge|m6i.4xlarge|c6i.2xlarge|c6i.4xlarge|r6i.2xlarge|r6i.4xlarge|m7i.2xlarge|m7i.4xlarge|c7i.2xlarge|c7i.4xlarge|r7i.2xlarge|r7i.4xlarge)
      echo "4 15"  # 4 ENIs, 15 IPs per ENI
      ;;
    # Graviton2/Graviton3 2xlarge, 4xlarge
    m6g.2xlarge|m6g.4xlarge|c6g.2xlarge|c6g.4xlarge|r6g.2xlarge|r6g.4xlarge|m7g.2xlarge|m7g.4xlarge|c7g.2xlarge|c7g.4xlarge|r7g.2xlarge|r7g.4xlarge|m8g.2xlarge|m8g.4xlarge|c8g.2xlarge|c8g.4xlarge|r8g.2xlarge|r8g.4xlarge)
      echo "4 15"  # 4 ENIs, 15 IPs per ENI
      ;;
    # Graviton2/Graviton3 with d (NVMe) suffix
    m6gd.2xlarge|m6gd.4xlarge|c6gd.2xlarge|c6gd.4xlarge|r6gd.2xlarge|r6gd.4xlarge|m7gd.2xlarge|m7gd.4xlarge|c7gd.2xlarge|c7gd.4xlarge|r7gd.2xlarge|r7gd.4xlarge|m8gd.2xlarge|m8gd.4xlarge|c8gd.2xlarge|c8gd.4xlarge|r8gd.2xlarge|r8gd.4xlarge)
      echo "4 15"  # 4 ENIs, 15 IPs per ENI
      ;;
    # Very large instances (8xlarge+)
    m5.8xlarge|m5.12xlarge|m5.16xlarge|m5.24xlarge|m5d.8xlarge|m5d.12xlarge|m5d.16xlarge|m5d.24xlarge|c5.9xlarge|c5.12xlarge|c5.18xlarge|c5.24xlarge|c5d.9xlarge|c5d.12xlarge|c5d.18xlarge|c5d.24xlarge|r5.8xlarge|r5.12xlarge|r5.16xlarge|r5.24xlarge|r5d.8xlarge|r5d.12xlarge|r5d.16xlarge|r5d.24xlarge|m6i.8xlarge|m6i.12xlarge|m6i.16xlarge|m6i.24xlarge|m6i.32xlarge|c6i.8xlarge|c6i.12xlarge|c6i.16xlarge|c6i.24xlarge|c6i.32xlarge|r6i.8xlarge|r6i.12xlarge|r6i.16xlarge|r6i.24xlarge|r6i.32xlarge|m7i.8xlarge|m7i.12xlarge|m7i.16xlarge|m7i.24xlarge|m7i.32xlarge|c7i.8xlarge|c7i.12xlarge|c7i.16xlarge|c7i.24xlarge|c7i.32xlarge|r7i.8xlarge|r7i.12xlarge|r7i.16xlarge|r7i.24xlarge|r7i.32xlarge)
      echo "8 30"  # 8 ENIs, 30 IPs per ENI
      ;;
    # Graviton2/Graviton3 8xlarge+
    m6g.8xlarge|m6g.12xlarge|m6g.16xlarge|m6g.metal|c6g.8xlarge|c6g.12xlarge|c6g.16xlarge|c6g.metal|r6g.8xlarge|r6g.12xlarge|r6g.16xlarge|r6g.metal|m7g.8xlarge|m7g.12xlarge|m7g.16xlarge|m7g.metal|c7g.8xlarge|c7g.12xlarge|c7g.16xlarge|c7g.metal|r7g.8xlarge|r7g.12xlarge|r7g.16xlarge|r7g.metal|m8g.8xlarge|m8g.12xlarge|m8g.16xlarge|m8g.metal|c8g.8xlarge|c8g.12xlarge|c8g.16xlarge|c8g.metal|r8g.8xlarge|r8g.12xlarge|r8g.16xlarge|r8g.metal)
      echo "8 30"  # 8 ENIs, 30 IPs per ENI
      ;;
    # Graviton2/Graviton3 with d (NVMe) suffix 8xlarge+
    m6gd.8xlarge|m6gd.12xlarge|m6gd.16xlarge|m6gd.metal|c6gd.8xlarge|c6gd.12xlarge|c6gd.16xlarge|c6gd.metal|r6gd.8xlarge|r6gd.12xlarge|r6gd.16xlarge|r6gd.metal|m7gd.8xlarge|m7gd.12xlarge|m7gd.16xlarge|m7gd.metal|c7gd.8xlarge|c7gd.12xlarge|c7gd.16xlarge|c7gd.metal|r7gd.8xlarge|r7gd.12xlarge|r7gd.16xlarge|r7gd.metal|m8gd.8xlarge|m8gd.12xlarge|m8gd.16xlarge|m8gd.metal|c8gd.8xlarge|c8gd.12xlarge|c8gd.16xlarge|c8gd.metal|r8gd.8xlarge|r8gd.12xlarge|r8gd.16xlarge|r8gd.metal)
      echo "8 30"  # 8 ENIs, 30 IPs per ENI
      ;;
    # Metal instances
    m5.metal|m5d.metal|c5.metal|c5d.metal|r5.metal|r5d.metal|m6i.metal|c6i.metal|r6i.metal|m7i.metal|c7i.metal|r7i.metal)
      echo "15 50"  # 15 ENIs, 50 IPs per ENI
      ;;
    *)
      # Default for unknown types - use conservative values (common for 2xlarge instances)
      echo "4 10"
      ;;
  esac
}

ENI_LIMITS_ISSUES=0
if [ -n "$AWS_DIR" ]; then
  INSTANCE_TYPE_FILE="$AWS_DIR/node_instance_type.txt"
  INSTANCE_ENIS_FILE="$AWS_DIR/all_instance_enis.json"
  TRUNK_ENI_FILE="$AWS_DIR/trunk_eni_id.txt"
  BRANCH_ENIS_FILE="$AWS_DIR/_all_branch_enis_in_vpc.json"
  
  if [ -s "$INSTANCE_TYPE_FILE" ]; then
    INSTANCE_TYPE=$(cat "$INSTANCE_TYPE_FILE" 2>/dev/null | tr -d '[:space:]' || echo "unknown")
    
    if [ "$INSTANCE_TYPE" != "unknown" ] && [ -n "$INSTANCE_TYPE" ]; then
      echo "[INFO] Instance type: $INSTANCE_TYPE"
      
      # Get limits for this instance type
      LIMITS=$(get_instance_limits "$INSTANCE_TYPE")
      MAX_ENIS=$(echo "$LIMITS" | awk '{print $1}')
      MAX_IPS_PER_ENI=$(echo "$LIMITS" | awk '{print $2}')
      
      if [ -n "$MAX_ENIS" ] && [ "$MAX_ENIS" != "0" ]; then
        echo "[INFO] Instance limits: $MAX_ENIS ENI(s), $MAX_IPS_PER_ENI IP(s) per ENI"
        
        # Count current ENIs on instance
        if [ -s "$INSTANCE_ENIS_FILE" ]; then
          CURRENT_ENIS=$(jq -r 'length' "$INSTANCE_ENIS_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
          echo "[INFO] Current ENIs on instance: $CURRENT_ENIS / $MAX_ENIS"
          
          # Check if approaching ENI limit
          if [ "$CURRENT_ENIS" -ge "$MAX_ENIS" ]; then
            echo "[ISSUE] Instance at ENI limit: $CURRENT_ENIS / $MAX_ENIS - cannot attach more ENIs"
            issues=$((issues+1))
            ENI_LIMITS_ISSUES=1
          elif [ "$CURRENT_ENIS" -ge $((MAX_ENIS - 1)) ]; then
            echo "[WARN] Instance approaching ENI limit: $CURRENT_ENIS / $MAX_ENIS (1 remaining)"
            warnings=$((warnings+1))
            ENI_LIMITS_ISSUES=1
          elif [ "$CURRENT_ENIS" -ge $((MAX_ENIS * 80 / 100)) ]; then
            echo "[WARN] Instance ENI usage high: $CURRENT_ENIS / $MAX_ENIS (~$((CURRENT_ENIS * 100 / MAX_ENIS))%)"
            warnings=$((warnings+1))
            ENI_LIMITS_ISSUES=1
          fi
        fi
        
        # Check branch ENI count if using trunking
        if [ -s "$TRUNK_ENI_FILE" ]; then
          TRUNK_ENI_ID=$(cat "$TRUNK_ENI_FILE" 2>/dev/null | tr -d '[:space:]' || echo "")
          if [ -n "$TRUNK_ENI_ID" ] && [ "$TRUNK_ENI_ID" != "null" ] && [ "$TRUNK_ENI_ID" != "" ]; then
            # Count branch ENIs attached to this trunk
            if [ -s "$BRANCH_ENIS_FILE" ]; then
              BRANCH_ENIS_ON_TRUNK=$(jq -r --arg trunk "$TRUNK_ENI_ID" '[.[] | select(.Attachment == $trunk)] | length' "$BRANCH_ENIS_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
              MAX_BRANCH_ENIS=50  # Trunk ENI limit
              
              if [ -n "$BRANCH_ENIS_ON_TRUNK" ] && [ "$BRANCH_ENIS_ON_TRUNK" != "0" ]; then
                echo "[INFO] Branch ENIs on trunk: $BRANCH_ENIS_ON_TRUNK / $MAX_BRANCH_ENIS"
                
                if [ "$BRANCH_ENIS_ON_TRUNK" -ge "$MAX_BRANCH_ENIS" ]; then
                  echo "[ISSUE] Trunk ENI at branch ENI limit: $BRANCH_ENIS_ON_TRUNK / $MAX_BRANCH_ENIS - cannot attach more pod ENIs"
                  issues=$((issues+1))
                  ENI_LIMITS_ISSUES=1
                elif [ "$BRANCH_ENIS_ON_TRUNK" -ge 45 ]; then
                  echo "[WARN] Trunk ENI approaching branch ENI limit: $BRANCH_ENIS_ON_TRUNK / $MAX_BRANCH_ENIS (approaching 50 limit)"
                  warnings=$((warnings+1))
                  ENI_LIMITS_ISSUES=1
                fi
              fi
            fi
          fi
        fi
        
        # Calculate max pods (approximate)
        # Formula: (ENIs * (IPs per ENI - 1)) + 2 (for host network pods)
        MAX_PODS=$((MAX_ENIS * (MAX_IPS_PER_ENI - 1) + 2))
        echo "[INFO] Estimated max pods (without trunking): ~$MAX_PODS"
        
        if [ "$ENI_LIMITS_ISSUES" -eq 0 ]; then
          echo "[OK] No ENI/instance limit issues detected"
        else
          echo "[INFO] Recommendation: Consider using larger instance types or ENI trunking if limits are reached"
        fi
      else
        echo "[INFO] Instance type limits not available for: $INSTANCE_TYPE"
      fi
    else
      echo "[INFO] Instance type not available"
    fi
  else
    echo "[INFO] Instance type information not available"
  fi
else
  echo "[INFO] AWS diagnostics not available for ENI limits analysis"
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
echo "=== Subnet IP Availability / IP Exhaustion Analysis ==="

IP_EXHAUSTION_ISSUES=0

# Check subnet IP availability
if [ -n "$AWS_DIR" ] && [ -s "$AWS_DIR/subnets.json" ]; then
  LOW_IP_SUBNETS=$(jq -r '.[] | select(.[1] < 10) | "\(.[0]): \(.[1]) IPs available (CIDR: \(.[2]))"' "$AWS_DIR/subnets.json" 2>/dev/null || true)
  if [ -n "$LOW_IP_SUBNETS" ]; then
    echo "[ISSUE] Subnets with low IP availability (<10 IPs):"
    echo "$LOW_IP_SUBNETS" | sed 's/^/  - /'
    issues=$((issues+1))
    IP_EXHAUSTION_ISSUES=1
  else
    echo "[OK] All subnets have adequate IP availability"
  fi
fi

# Check for pods stuck in Pending state
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_pending_pods.json" ]; then
  PENDING_COUNT=$(jq -r '.items | length' "$NODE_DIR/node_pending_pods.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$PENDING_COUNT" != "0" ] && [ "$PENDING_COUNT" -gt 0 ]; then
    echo "[INFO] Found $PENDING_COUNT pod(s) in Pending state"
    
    # Check pending pods for IP-related reasons
    PENDING_IP_RELATED=0
    PENDING_PODS_LIST=""
    NP_INDEX=0
    while [ "$NP_INDEX" -lt "$PENDING_COUNT" ]; do
      POD_NAME=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].metadata.name // "unknown"' "$NODE_DIR/node_pending_pods.json" 2>/dev/null || echo "unknown")
      POD_NS=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].metadata.namespace // "default"' "$NODE_DIR/node_pending_pods.json" 2>/dev/null || echo "default")
      POD_UID=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].metadata.uid // ""' "$NODE_DIR/node_pending_pods.json" 2>/dev/null || echo "")
      
      # Check pod conditions for IP-related reasons
      POD_CONDITIONS=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].status.conditions // []' "$NODE_DIR/node_pending_pods.json" 2>/dev/null || echo "[]")
      POD_SCHEDULED=$(echo "$POD_CONDITIONS" | jq -r '.[]? | select(.type == "PodScheduled") | .reason // ""' 2>/dev/null || echo "")
      POD_INITIALIZED=$(echo "$POD_CONDITIONS" | jq -r '.[]? | select(.type == "Initialized") | .reason // ""' 2>/dev/null || echo "")
      
      # Check for IP-related pending reasons
      if echo "$POD_SCHEDULED" | grep -qiE "(insufficient|ip|eni|network|resource)" || \
         echo "$POD_INITIALIZED" | grep -qiE "(ip|eni|network|resource)"; then
        PENDING_IP_RELATED=$((PENDING_IP_RELATED + 1))
        if [ -z "$PENDING_PODS_LIST" ]; then
          PENDING_PODS_LIST="$POD_NS/$POD_NAME"
        else
          PENDING_PODS_LIST="$PENDING_PODS_LIST, $POD_NS/$POD_NAME"
        fi
      fi
      
      NP_INDEX=$((NP_INDEX + 1))
    done
    
    if [ "$PENDING_IP_RELATED" -gt 0 ]; then
      echo "[ISSUE] Found $PENDING_IP_RELATED pod(s) in Pending state with IP-related reasons: $PENDING_PODS_LIST"
      issues=$((issues+1))
      IP_EXHAUSTION_ISSUES=1
    elif [ "$PENDING_COUNT" -gt 5 ]; then
      # If many pending pods, warn even if not explicitly IP-related
      echo "[WARN] Found $PENDING_COUNT pod(s) in Pending state (may indicate IP exhaustion or other resource issues)"
      warnings=$((warnings+1))
      IP_EXHAUSTION_ISSUES=1
    fi
  fi
fi

# Check CNI logs for IP allocation failures
if [ -n "$NODE_DIR" ] && [ -d "$NODE_DIR/cni_logs" ]; then
  IP_ALLOCATION_ERRORS=0
  
  # Check ipamd.log for IP allocation errors
  if [ -s "$NODE_DIR/cni_logs/ipamd.log" ]; then
    IPAMD_IP_ERRORS=$(grep -iE "(unable.*allocate|failed.*allocate|no.*ip.*available|ip.*exhaust|insufficient.*ip|cannot.*allocate.*ip|allocation.*failed)" "$NODE_DIR/cni_logs/ipamd.log" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    if [ "$IPAMD_IP_ERRORS" != "0" ] && [ "$IPAMD_IP_ERRORS" -gt 0 ]; then
      IP_ALLOCATION_ERRORS=$((IP_ALLOCATION_ERRORS + IPAMD_IP_ERRORS))
      echo "[ISSUE] Found $IPAMD_IP_ERRORS IP allocation error(s) in ipamd.log"
      grep -iE "(unable.*allocate|failed.*allocate|no.*ip.*available|ip.*exhaust|insufficient.*ip|cannot.*allocate.*ip|allocation.*failed)" "$NODE_DIR/cni_logs/ipamd.log" 2>/dev/null | head -5 | sed 's/^/  - /'
      issues=$((issues+1))
      IP_EXHAUSTION_ISSUES=1
    fi
  fi
  
  # Check plugin.log for IP allocation errors
  if [ -s "$NODE_DIR/cni_logs/plugin.log" ]; then
    PLUGIN_IP_ERRORS=$(grep -iE "(unable.*allocate|failed.*allocate|no.*ip.*available|ip.*exhaust|insufficient.*ip|cannot.*allocate.*ip|allocation.*failed|failed.*get.*ip)" "$NODE_DIR/cni_logs/plugin.log" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    if [ "$PLUGIN_IP_ERRORS" != "0" ] && [ "$PLUGIN_IP_ERRORS" -gt 0 ]; then
      IP_ALLOCATION_ERRORS=$((IP_ALLOCATION_ERRORS + PLUGIN_IP_ERRORS))
      echo "[ISSUE] Found $PLUGIN_IP_ERRORS IP allocation error(s) in plugin.log"
      grep -iE "(unable.*allocate|failed.*allocate|no.*ip.*available|ip.*exhaust|insufficient.*ip|cannot.*allocate.*ip|allocation.*failed|failed.*get.*ip)" "$NODE_DIR/cni_logs/plugin.log" 2>/dev/null | head -5 | sed 's/^/  - /'
      issues=$((issues+1))
      IP_EXHAUSTION_ISSUES=1
    fi
  fi
  
  if [ "$IP_ALLOCATION_ERRORS" -eq 0 ]; then
    echo "[OK] No IP allocation errors found in CNI logs"
  fi
fi

# Correlate: if low IPs AND pending pods AND IP errors, this is likely IP exhaustion
if [ "$IP_EXHAUSTION_ISSUES" -eq 1 ]; then
  echo "[INFO] Recommendation: Check subnet IP availability, consider enlarging subnets, using prefix delegation, or reducing warm IP pool size"
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

# DNS / CoreDNS / NodeLocal DNSCache analysis
if [ -n "$NODE_DIR" ]; then
  echo ""
  echo "=== DNS / CoreDNS / NodeLocal DNSCache Analysis ==="
  
  DNS_ISSUES=0
  
  # Check DNS resolution
  if [ -s "$NODE_DIR/node_dns_tests.txt" ]; then
    K8S_DNS_FAILED=$(grep -A 5 "kubernetes.default.svc.cluster.local" "$NODE_DIR/node_dns_tests.txt" 2>/dev/null | grep -qi "FAILED" && echo "1" || echo "0")
    if [ "$K8S_DNS_FAILED" = "1" ]; then
      echo "[ISSUE] Kubernetes DNS resolution failed"
      grep -A 5 "kubernetes.default.svc.cluster.local" "$NODE_DIR/node_dns_tests.txt" | grep -E "(FAILED|error|timeout|NXDOMAIN)" | head -3 | sed 's/^/  - /'
      issues=$((issues+1))
      DNS_ISSUES=1
    else
      echo "[OK] Kubernetes DNS resolution working"
    fi
    # Note: metadata service DNS failure is expected and not an issue
  fi
  
  # Check CoreDNS pods
  if [ -s "$NODE_DIR/node_coredns_pods.json" ]; then
    COREDNS_COUNT=$(jq -r '.items | length' "$NODE_DIR/node_coredns_pods.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$COREDNS_COUNT" = "0" ]; then
      echo "[ISSUE] No CoreDNS pods found - DNS will not work"
      issues=$((issues+1))
      DNS_ISSUES=1
    else
      echo "[INFO] Found $COREDNS_COUNT CoreDNS pod(s)"
      
      # Check CoreDNS pod status
      COREDNS_READY=0
      COREDNS_NOT_READY=0
      NP_INDEX=0
      while [ "$NP_INDEX" -lt "$COREDNS_COUNT" ]; do
        POD_STATUS=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].status.phase // "Unknown"' "$NODE_DIR/node_coredns_pods.json" 2>/dev/null || echo "Unknown")
        POD_NAME=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].metadata.name // "unknown"' "$NODE_DIR/node_coredns_pods.json" 2>/dev/null || echo "unknown")
        READY_COUNT=$(jq -r --argjson idx "$NP_INDEX" '[.items[$idx].status.containerStatuses[]? | select(.ready == true)] | length' "$NODE_DIR/node_coredns_pods.json" 2>/dev/null || echo "0")
        TOTAL_CONTAINERS=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].status.containerStatuses | length' "$NODE_DIR/node_coredns_pods.json" 2>/dev/null || echo "0")
        
        if [ "$POD_STATUS" = "Running" ] && [ "$READY_COUNT" = "$TOTAL_CONTAINERS" ] && [ "$TOTAL_CONTAINERS" != "0" ]; then
          COREDNS_READY=$((COREDNS_READY + 1))
        else
          COREDNS_NOT_READY=$((COREDNS_NOT_READY + 1))
          echo "[WARN] CoreDNS pod '$POD_NAME' not ready (status: $POD_STATUS, ready: $READY_COUNT/$TOTAL_CONTAINERS)"
          warnings=$((warnings+1))
          DNS_ISSUES=1
        fi
        NP_INDEX=$((NP_INDEX + 1))
      done
      
      if [ "$COREDNS_READY" -gt 0 ]; then
        echo "[OK] $COREDNS_READY CoreDNS pod(s) ready"
      fi
      
      # Check if CoreDNS is scaled appropriately (at least 2 for HA)
      if [ "$COREDNS_COUNT" -lt 2 ]; then
        echo "[WARN] Only $COREDNS_COUNT CoreDNS pod(s) - consider scaling to 2+ for high availability"
        warnings=$((warnings+1))
        DNS_ISSUES=1
      fi
    fi
  fi
  
  # Check NodeLocal DNSCache
  if [ -s "$NODE_DIR/node_nodelocal_dns_pods.json" ]; then
    NODELOCAL_COUNT=$(jq -r '.items | length' "$NODE_DIR/node_nodelocal_dns_pods.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$NODELOCAL_COUNT" = "0" ]; then
      echo "[INFO] NodeLocal DNSCache not enabled (optional - improves DNS latency and reduces CoreDNS load)"
    else
      echo "[INFO] Found $NODELOCAL_COUNT NodeLocal DNSCache pod(s)"
      
      # Check NodeLocal DNSCache pod status on this node
      NODE_NAME=$(grep "^NODE=" "$POD_DIR/node_name.txt" 2>/dev/null | cut -d= -f2- || echo "")
      NODELOCAL_ON_NODE=0
      NODELOCAL_READY=0
      if [ -n "$NODE_NAME" ]; then
        NP_INDEX=0
        while [ "$NP_INDEX" -lt "$NODELOCAL_COUNT" ]; do
          POD_NODE=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].spec.nodeName // ""' "$NODE_DIR/node_nodelocal_dns_pods.json" 2>/dev/null || echo "")
          POD_NAME=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].metadata.name // "unknown"' "$NODE_DIR/node_nodelocal_dns_pods.json" 2>/dev/null || echo "unknown")
          POD_STATUS=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].status.phase // "Unknown"' "$NODE_DIR/node_nodelocal_dns_pods.json" 2>/dev/null || echo "Unknown")
          READY_COUNT=$(jq -r --argjson idx "$NP_INDEX" '[.items[$idx].status.containerStatuses[]? | select(.ready == true)] | length' "$NODE_DIR/node_nodelocal_dns_pods.json" 2>/dev/null || echo "0")
          TOTAL_CONTAINERS=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx].status.containerStatuses | length' "$NODE_DIR/node_nodelocal_dns_pods.json" 2>/dev/null || echo "0")
          
          if [ "$POD_NODE" = "$NODE_NAME" ]; then
            NODELOCAL_ON_NODE=$((NODELOCAL_ON_NODE + 1))
            if [ "$POD_STATUS" = "Running" ] && [ "$READY_COUNT" = "$TOTAL_CONTAINERS" ] && [ "$TOTAL_CONTAINERS" != "0" ]; then
              NODELOCAL_READY=$((NODELOCAL_READY + 1))
              echo "[OK] NodeLocal DNSCache pod '$POD_NAME' ready on this node"
            else
              echo "[WARN] NodeLocal DNSCache pod '$POD_NAME' on this node not ready (status: $POD_STATUS, ready: $READY_COUNT/$TOTAL_CONTAINERS)"
              warnings=$((warnings+1))
              DNS_ISSUES=1
            fi
          fi
          NP_INDEX=$((NP_INDEX + 1))
        done
        
        if [ "$NODELOCAL_ON_NODE" -eq 0 ]; then
          echo "[WARN] No NodeLocal DNSCache pod found on this node (may be using CoreDNS directly)"
          warnings=$((warnings+1))
          DNS_ISSUES=1
        fi
      fi
    fi
  fi
  
  # Check DNS service endpoints
  if [ -s "$NODE_DIR/node_dns_endpoints.json" ]; then
    ENDPOINT_COUNT=$(jq -r '.subsets[0].addresses | length' "$NODE_DIR/node_dns_endpoints.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$ENDPOINT_COUNT" = "0" ]; then
      echo "[ISSUE] DNS service has no endpoints - DNS will not work"
      issues=$((issues+1))
      DNS_ISSUES=1
    else
      echo "[OK] DNS service has $ENDPOINT_COUNT endpoint(s)"
    fi
  fi
  
  # Check DNS service IP
  if [ -s "$NODE_DIR/node_dns_service.json" ]; then
    DNS_SERVICE_IP=$(jq -r '.spec.clusterIP // ""' "$NODE_DIR/node_dns_service.json" 2>/dev/null || echo "")
    if [ -n "$DNS_SERVICE_IP" ] && [ "$DNS_SERVICE_IP" != "null" ] && [ "$DNS_SERVICE_IP" != "" ]; then
      echo "[INFO] DNS service IP: $DNS_SERVICE_IP"
    fi
  fi
  
  # Check NodeLocal DNSCache service IP (if exists)
  if [ -s "$NODE_DIR/node_nodelocal_dns_service.json" ] && ! jq -e '.kind == null' "$NODE_DIR/node_nodelocal_dns_service.json" >/dev/null 2>&1; then
    NODELOCAL_SERVICE_IP=$(jq -r '.spec.clusterIP // ""' "$NODE_DIR/node_nodelocal_dns_service.json" 2>/dev/null || echo "")
    if [ -n "$NODELOCAL_SERVICE_IP" ] && [ "$NODELOCAL_SERVICE_IP" != "null" ] && [ "$NODELOCAL_SERVICE_IP" != "" ]; then
      echo "[INFO] NodeLocal DNSCache service IP: $NODELOCAL_SERVICE_IP"
    fi
  fi
  
  if [ "$DNS_ISSUES" -eq 0 ]; then
    echo "[OK] No DNS/CoreDNS/NodeLocal DNSCache issues detected"
  fi
fi

# AMI / CNI / Kernel Drift Analysis
if [ -n "$NODE_DIR" ]; then
  echo ""
  echo "=== AMI / CNI / Kernel Drift Analysis ==="
  
  VERSION_ISSUES=0
  
  # Check Kubernetes version
  if [ -s "$NODE_DIR/node_k8s_version.txt" ]; then
    K8S_VERSION=$(cat "$NODE_DIR/node_k8s_version.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$K8S_VERSION" ] && [ "$K8S_VERSION" != "" ]; then
      echo "[INFO] Kubernetes version: $K8S_VERSION"
      # Extract major.minor version
      K8S_MAJOR_MINOR=$(echo "$K8S_VERSION" | sed -E 's/v?([0-9]+\.[0-9]+).*/\1/' || echo "")
      if [ -n "$K8S_MAJOR_MINOR" ]; then
        # Check if version is very old (e.g., < 1.20)
        K8S_MAJOR=$(echo "$K8S_MAJOR_MINOR" | cut -d. -f1)
        K8S_MINOR=$(echo "$K8S_MAJOR_MINOR" | cut -d. -f2)
        if [ "$K8S_MAJOR" -lt 1 ] || ([ "$K8S_MAJOR" -eq 1 ] && [ "$K8S_MINOR" -lt 20 ]); then
          echo "[WARN] Kubernetes version $K8S_VERSION is quite old (EKS typically uses 1.20+)"
          warnings=$((warnings+1))
          VERSION_ISSUES=1
        fi
      fi
    fi
  fi
  
  # Check OS image (AMI)
  if [ -s "$NODE_DIR/node_os_image.txt" ]; then
    OS_IMAGE=$(cat "$NODE_DIR/node_os_image.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$OS_IMAGE" ] && [ "$OS_IMAGE" != "" ]; then
      echo "[INFO] OS image: $OS_IMAGE"
      # Check if it's an EKS-optimized AMI
      # EKS-optimized AMIs typically contain "eks" or are Amazon Linux 2023 (which is used for EKS)
      if echo "$OS_IMAGE" | grep -qiE "eks|amazon.*linux.*eks|amazon.*linux.*2023"; then
        echo "[OK] EKS-optimized AMI detected"
      else
        echo "[WARN] Non-EKS-optimized AMI detected: $OS_IMAGE (may cause compatibility issues)"
        warnings=$((warnings+1))
        VERSION_ISSUES=1
      fi
    fi
  fi
  
  # Check kernel version
  if [ -s "$NODE_DIR/node_kernel_version.txt" ]; then
    KERNEL_VERSION=$(cat "$NODE_DIR/node_kernel_version.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$KERNEL_VERSION" ] && [ "$KERNEL_VERSION" != "" ]; then
      echo "[INFO] Kernel version: $KERNEL_VERSION"
      # Extract major.minor version
      KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1 || echo "0")
      KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2 || echo "0")
      # Check if kernel is very old (e.g., < 5.4)
      if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
        echo "[WARN] Kernel version $KERNEL_VERSION is quite old (EKS typically uses 5.4+)"
        warnings=$((warnings+1))
        VERSION_ISSUES=1
      fi
    fi
  fi
  
  # Check aws-node version
  if [ -s "$NODE_DIR/node_aws_node_version.txt" ]; then
    AWS_NODE_VERSION=$(cat "$NODE_DIR/node_aws_node_version.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$AWS_NODE_VERSION" ] && [ "$AWS_NODE_VERSION" != "" ]; then
      echo "[INFO] aws-node version: $AWS_NODE_VERSION"
      # Check if version is very old (e.g., < 1.10)
      # Strip 'v' prefix if present
      AWS_NODE_VERSION_CLEAN=$(echo "$AWS_NODE_VERSION" | sed 's/^v//' || echo "$AWS_NODE_VERSION")
      AWS_NODE_MAJOR=$(echo "$AWS_NODE_VERSION_CLEAN" | cut -d. -f1 2>/dev/null || echo "0")
      AWS_NODE_MINOR=$(echo "$AWS_NODE_VERSION_CLEAN" | cut -d. -f2 2>/dev/null || echo "0")
      # Only do numeric comparison if we have valid numbers
      if [ "$AWS_NODE_MAJOR" != "0" ] && [ -n "$AWS_NODE_MAJOR" ] && [ "$AWS_NODE_MAJOR" -ge 0 ] 2>/dev/null; then
        if [ "$AWS_NODE_MAJOR" -lt 1 ] || ([ "$AWS_NODE_MAJOR" -eq 1 ] && [ "$AWS_NODE_MINOR" -lt 10 ] 2>/dev/null); then
          echo "[WARN] aws-node version $AWS_NODE_VERSION is quite old (consider upgrading)"
          warnings=$((warnings+1))
          VERSION_ISSUES=1
        fi
      fi
    fi
  elif [ -s "$NODE_DIR/node_aws_node_image.txt" ]; then
    AWS_NODE_IMAGE=$(cat "$NODE_DIR/node_aws_node_image.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$AWS_NODE_IMAGE" ] && [ "$AWS_NODE_IMAGE" != "" ]; then
      echo "[INFO] aws-node image: $AWS_NODE_IMAGE"
    fi
  fi
  
  # Check kube-proxy version
  if [ -s "$NODE_DIR/node_kube_proxy_version.txt" ]; then
    KUBE_PROXY_VERSION=$(cat "$NODE_DIR/node_kube_proxy_version.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$KUBE_PROXY_VERSION" ] && [ "$KUBE_PROXY_VERSION" != "" ]; then
      echo "[INFO] kube-proxy version: $KUBE_PROXY_VERSION"
      # Check if kube-proxy version matches Kubernetes version
      if [ -s "$NODE_DIR/node_k8s_version.txt" ]; then
        K8S_VERSION=$(cat "$NODE_DIR/node_k8s_version.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
        K8S_MAJOR_MINOR=$(echo "$K8S_VERSION" | sed -E 's/v?([0-9]+\.[0-9]+).*/\1/' || echo "")
        KUBE_PROXY_MAJOR_MINOR=$(echo "$KUBE_PROXY_VERSION" | sed -E 's/v?([0-9]+\.[0-9]+).*/\1/' || echo "")
        if [ -n "$K8S_MAJOR_MINOR" ] && [ -n "$KUBE_PROXY_MAJOR_MINOR" ] && [ "$K8S_MAJOR_MINOR" != "$KUBE_PROXY_MAJOR_MINOR" ]; then
          echo "[ISSUE] kube-proxy version ($KUBE_PROXY_VERSION) does not match Kubernetes version ($K8S_VERSION) - version mismatch may cause issues"
          issues=$((issues+1))
          VERSION_ISSUES=1
        else
          echo "[OK] kube-proxy version matches Kubernetes version"
        fi
      fi
    fi
  elif [ -s "$NODE_DIR/node_kube_proxy_image.txt" ]; then
    KUBE_PROXY_IMAGE=$(cat "$NODE_DIR/node_kube_proxy_image.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$KUBE_PROXY_IMAGE" ] && [ "$KUBE_PROXY_IMAGE" != "" ]; then
      echo "[INFO] kube-proxy image: $KUBE_PROXY_IMAGE"
    fi
  fi
  
  # Check container runtime version
  if [ -s "$NODE_DIR/node_container_runtime_version.txt" ]; then
    CONTAINERD_VERSION=$(cat "$NODE_DIR/node_container_runtime_version.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$CONTAINERD_VERSION" ] && [ "$CONTAINERD_VERSION" != "" ]; then
      echo "[INFO] Container runtime: $CONTAINERD_VERSION"
    fi
  fi
  
  if [ "$VERSION_ISSUES" -eq 0 ]; then
    echo "[OK] No version drift issues detected"
  else
    echo "[INFO] Recommendation: Ensure all components use compatible versions, use EKS-optimized AMIs, and keep components up to date"
  fi
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

# Route table drift analysis
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_routes_all.txt" ]; then
  echo ""
  echo "=== Route Table Analysis ==="
  
  ROUTE_ISSUES=0
  ROUTES_FILE="$NODE_DIR/node_routes_all.txt"
  
  # Check for default route (0.0.0.0/0)
  DEFAULT_ROUTE=$(grep -E "^default|^0\.0\.0\.0/0" "$ROUTES_FILE" 2>/dev/null | head -1 || echo "")
  if [ -z "$DEFAULT_ROUTE" ]; then
    echo "[ISSUE] Default route (0.0.0.0/0) not found - node may not have internet/VPC connectivity"
    issues=$((issues+1))
    ROUTE_ISSUES=1
  else
    echo "[OK] Default route present: $DEFAULT_ROUTE"
  fi
  
  # Check for VPC subnet routes (if we have subnet info)
  if [ -n "$AWS_DIR" ] && [ -s "$AWS_DIR/subnets.json" ]; then
    # Extract subnet CIDRs from AWS data
    SUBNET_CIDRS=$(jq -r '.[] | .[2]' "$AWS_DIR/subnets.json" 2>/dev/null | grep -v "^null$" | grep -v "^$" || true)
    
    if [ -n "$SUBNET_CIDRS" ]; then
      SUBNET_ROUTE_ISSUES=0
      MISSING_SUBNET_ROUTES=""
      while IFS= read -r SUBNET_CIDR; do
        [ -z "$SUBNET_CIDR" ] && continue
        # Check if route exists for this subnet (exact match or covers it)
        # Route format: "10.4.192.0/18 dev eth0" or "10.4.192.0/18 via 10.4.192.1 dev eth0"
        ROUTE_FOUND=$(grep -E "^${SUBNET_CIDR}|^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+.*dev" "$ROUTES_FILE" 2>/dev/null | grep -E "${SUBNET_CIDR}" | head -1 || echo "")
        
        if [ -z "$ROUTE_FOUND" ]; then
          # Check if any route covers this subnet (broader route)
          # Extract network portion for comparison
          SUBNET_NETWORK=$(echo "$SUBNET_CIDR" | cut -d'/' -f1)
          # Check if default route or broader route exists (simplified check)
          if [ -z "$DEFAULT_ROUTE" ]; then
            if [ -z "$MISSING_SUBNET_ROUTES" ]; then
              MISSING_SUBNET_ROUTES="$SUBNET_CIDR"
            else
              MISSING_SUBNET_ROUTES="$MISSING_SUBNET_ROUTES, $SUBNET_CIDR"
            fi
            SUBNET_ROUTE_ISSUES=1
          fi
        fi
      done <<< "$SUBNET_CIDRS"
      
      if [ "$SUBNET_ROUTE_ISSUES" -eq 1 ] && [ -n "$MISSING_SUBNET_ROUTES" ]; then
        echo "[WARN] Subnet routes not found for: $MISSING_SUBNET_ROUTES (may use default route)"
        warnings=$((warnings+1))
        ROUTE_ISSUES=1
      fi
    fi
  fi
  
  # Check for local interface routes (should have route for node's primary IP subnet)
  # Extract node IP subnet from interface routes
  NODE_SUBNET_ROUTE=$(grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+ dev eth0" "$ROUTES_FILE" 2>/dev/null | grep -v "local\|broadcast" | head -1 || echo "")
  
  if [ -z "$NODE_SUBNET_ROUTE" ]; then
    echo "[WARN] Local subnet route not found for primary interface (eth0)"
    warnings=$((warnings+1))
    ROUTE_ISSUES=1
  else
    echo "[OK] Local subnet route present: $NODE_SUBNET_ROUTE"
  fi
  
  # Check for route to metadata service (169.254.169.254) - important for AWS
  METADATA_ROUTE=$(grep -E "169\.254\.169\.254|169\.254\.0\.0/16" "$ROUTES_FILE" 2>/dev/null | head -1 || echo "")
  if [ -z "$METADATA_ROUTE" ]; then
    # Metadata service route may be implicit via default route, so this is informational
    if [ -n "$DEFAULT_ROUTE" ]; then
      echo "[INFO] Explicit route to metadata service (169.254.169.254) not found (using default route)"
    else
      echo "[WARN] No route to metadata service (169.254.169.254) and no default route"
      warnings=$((warnings+1))
      ROUTE_ISSUES=1
    fi
  else
    echo "[OK] Route to metadata service present: $METADATA_ROUTE"
  fi
  
  # Count total routes (excluding local/broadcast/multicast/loopback)
  TOTAL_ROUTES=$(grep -vE "^local|^broadcast|^multicast|^::|^fe80|^127\.0\.0" "$ROUTES_FILE" 2>/dev/null | grep -E "^[0-9]|^default" | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$TOTAL_ROUTES" -lt 2 ]; then
    echo "[WARN] Very few routes found ($TOTAL_ROUTES) - may indicate routing issues"
    warnings=$((warnings+1))
    ROUTE_ISSUES=1
  else
    echo "[INFO] Found $TOTAL_ROUTES route(s) (excluding local/broadcast/multicast/loopback)"
  fi
  
  if [ "$ROUTE_ISSUES" -eq 0 ]; then
    echo "[OK] No route table issues detected"
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

# Health probe analysis
if [ -n "$POD_DIR" ] && [ -s "$POD_DIR/pod_full.json" ]; then
  echo ""
  echo "=== Health Probe Analysis ==="
  
  PROBE_ISSUES=0
  
  # Extract probe configurations
  POD_FULL_JSON="$POD_DIR/pod_full.json"
  CONTAINERS=$(jq -r '.spec.containers[]?.name // empty' "$POD_FULL_JSON" 2>/dev/null || echo "")
  
  if [ -z "$CONTAINERS" ]; then
    echo "[INFO] No containers found in pod spec"
  else
    HAS_PROBES=0
    while IFS= read -r CONTAINER_NAME; do
      [ -z "$CONTAINER_NAME" ] && continue
      
      # Check for each probe type
      LIVENESS_PROBE=$(jq -r --arg name "$CONTAINER_NAME" '.spec.containers[]? | select(.name == $name) | .livenessProbe // "null"' "$POD_FULL_JSON" 2>/dev/null || echo "null")
      READINESS_PROBE=$(jq -r --arg name "$CONTAINER_NAME" '.spec.containers[]? | select(.name == $name) | .readinessProbe // "null"' "$POD_FULL_JSON" 2>/dev/null || echo "null")
      STARTUP_PROBE=$(jq -r --arg name "$CONTAINER_NAME" '.spec.containers[]? | select(.name == $name) | .startupProbe // "null"' "$POD_FULL_JSON" 2>/dev/null || echo "null")
      
      if [ "$LIVENESS_PROBE" != "null" ] && [ "$LIVENESS_PROBE" != "" ]; then
        HAS_PROBES=1
        # Check if httpGet exists
        if jq -e '.httpGet' <<< "$LIVENESS_PROBE" >/dev/null 2>&1; then
          PROBE_PORT=$(jq -r '.httpGet.port // "unknown"' <<< "$LIVENESS_PROBE" 2>/dev/null || echo "unknown")
          PROBE_PATH=$(jq -r '.httpGet.path // "/"' <<< "$LIVENESS_PROBE" 2>/dev/null || echo "/")
          PROBE_SCHEME=$(jq -r '.httpGet.scheme // "HTTP"' <<< "$LIVENESS_PROBE" 2>/dev/null || echo "HTTP")
          echo "[INFO] Container '$CONTAINER_NAME': Liveness probe - $PROBE_SCHEME on port $PROBE_PORT, path: $PROBE_PATH"
        elif jq -e '.tcpSocket' <<< "$LIVENESS_PROBE" >/dev/null 2>&1; then
          PROBE_PORT=$(jq -r '.tcpSocket.port // "unknown"' <<< "$LIVENESS_PROBE" 2>/dev/null || echo "unknown")
          echo "[INFO] Container '$CONTAINER_NAME': Liveness probe - TCP on port $PROBE_PORT"
        fi
      fi
      
      if [ "$READINESS_PROBE" != "null" ] && [ "$READINESS_PROBE" != "" ]; then
        HAS_PROBES=1
        # Check if httpGet exists
        if jq -e '.httpGet' <<< "$READINESS_PROBE" >/dev/null 2>&1; then
          PROBE_PORT=$(jq -r '.httpGet.port // "unknown"' <<< "$READINESS_PROBE" 2>/dev/null || echo "unknown")
          PROBE_PATH=$(jq -r '.httpGet.path // "/"' <<< "$READINESS_PROBE" 2>/dev/null || echo "/")
          PROBE_SCHEME=$(jq -r '.httpGet.scheme // "HTTP"' <<< "$READINESS_PROBE" 2>/dev/null || echo "HTTP")
          echo "[INFO] Container '$CONTAINER_NAME': Readiness probe - $PROBE_SCHEME on port $PROBE_PORT, path: $PROBE_PATH"
          
          # Check if probe port is listening (from pod connections)
          if [ -s "$POD_DIR/pod_connections.txt" ]; then
            # Check if port is listening (from ss/netstat output)
            if grep -qE ":$PROBE_PORT[[:space:]]|LISTEN.*:$PROBE_PORT" "$POD_DIR/pod_connections.txt" 2>/dev/null; then
              echo "[OK] Readiness probe port $PROBE_PORT is listening"
            else
              echo "[WARN] Readiness probe port $PROBE_PORT not found in listening ports (may be blocked or not listening)"
              warnings=$((warnings+1))
              PROBE_ISSUES=1
            fi
          fi
        elif jq -e '.tcpSocket' <<< "$READINESS_PROBE" >/dev/null 2>&1; then
          PROBE_PORT=$(jq -r '.tcpSocket.port // "unknown"' <<< "$READINESS_PROBE" 2>/dev/null || echo "unknown")
          echo "[INFO] Container '$CONTAINER_NAME': Readiness probe - TCP on port $PROBE_PORT"
          
          # Check if probe port is listening
          if [ -s "$POD_DIR/pod_connections.txt" ]; then
            if grep -qE ":$PROBE_PORT[[:space:]]|LISTEN.*:$PROBE_PORT" "$POD_DIR/pod_connections.txt" 2>/dev/null; then
              echo "[OK] Readiness probe port $PROBE_PORT is listening"
            else
              echo "[WARN] Readiness probe port $PROBE_PORT not found in listening ports (may be blocked or not listening)"
              warnings=$((warnings+1))
              PROBE_ISSUES=1
            fi
          fi
        fi
      fi
      
      if [ "$STARTUP_PROBE" != "null" ] && [ "$STARTUP_PROBE" != "" ]; then
        HAS_PROBES=1
        # Check if httpGet exists
        if jq -e '.httpGet' <<< "$STARTUP_PROBE" >/dev/null 2>&1; then
          PROBE_PORT=$(jq -r '.httpGet.port // "unknown"' <<< "$STARTUP_PROBE" 2>/dev/null || echo "unknown")
          PROBE_PATH=$(jq -r '.httpGet.path // "/"' <<< "$STARTUP_PROBE" 2>/dev/null || echo "/")
          PROBE_SCHEME=$(jq -r '.httpGet.scheme // "HTTP"' <<< "$STARTUP_PROBE" 2>/dev/null || echo "HTTP")
          echo "[INFO] Container '$CONTAINER_NAME': Startup probe - $PROBE_SCHEME on port $PROBE_PORT, path: $PROBE_PATH"
        elif jq -e '.tcpSocket' <<< "$STARTUP_PROBE" >/dev/null 2>&1; then
          PROBE_PORT=$(jq -r '.tcpSocket.port // "unknown"' <<< "$STARTUP_PROBE" 2>/dev/null || echo "unknown")
          echo "[INFO] Container '$CONTAINER_NAME': Startup probe - TCP on port $PROBE_PORT"
        fi
      fi
    done <<< "$CONTAINERS"
    
    if [ "$HAS_PROBES" -eq 0 ]; then
      echo "[WARN] No health probes configured for any container (liveness, readiness, or startup)"
      warnings=$((warnings+1))
      PROBE_ISSUES=1
    fi
  fi
  
  # Check pod conditions for probe failures
  if [ -s "$POD_DIR/pod_conditions.json" ]; then
    READY_STATUS=$(jq -r '.[]? | select(.type == "Ready") | .status // "Unknown"' "$POD_DIR/pod_conditions.json" 2>/dev/null || echo "Unknown")
    CONTAINERS_READY_STATUS=$(jq -r '.[]? | select(.type == "ContainersReady") | .status // "Unknown"' "$POD_DIR/pod_conditions.json" 2>/dev/null || echo "Unknown")
    
    if [ "$READY_STATUS" = "False" ]; then
      READY_REASON=$(jq -r '.[]? | select(.type == "Ready") | .reason // "Unknown"' "$POD_DIR/pod_conditions.json" 2>/dev/null || echo "Unknown")
      echo "[ISSUE] Pod Ready condition is False (reason: $READY_REASON) - may indicate probe failures"
      issues=$((issues+1))
      PROBE_ISSUES=1
    elif [ "$READY_STATUS" = "True" ]; then
      echo "[OK] Pod Ready condition is True"
    fi
    
    if [ "$CONTAINERS_READY_STATUS" = "False" ]; then
      CONTAINERS_READY_REASON=$(jq -r '.[]? | select(.type == "ContainersReady") | .reason // "Unknown"' "$POD_DIR/pod_conditions.json" 2>/dev/null || echo "Unknown")
      echo "[ISSUE] ContainersReady condition is False (reason: $CONTAINERS_READY_REASON) - may indicate probe failures"
      issues=$((issues+1))
      PROBE_ISSUES=1
    elif [ "$CONTAINERS_READY_STATUS" = "True" ]; then
      echo "[OK] ContainersReady condition is True"
    fi
  fi
  
  # Check pod events for probe failures
  if [ -s "$POD_DIR/pod_events.txt" ]; then
    PROBE_FAILURES=$(grep -iE "probe.*fail|unhealthy|readiness.*fail|liveness.*fail" "$POD_DIR/pod_events.txt" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    if [ "$PROBE_FAILURES" != "0" ] && [ "$PROBE_FAILURES" -gt 0 ]; then
      echo "[ISSUE] Found $PROBE_FAILURES probe failure event(s) in pod events"
      grep -iE "probe.*fail|unhealthy|readiness.*fail|liveness.*fail" "$POD_DIR/pod_events.txt" 2>/dev/null | head -3 | sed 's/^/  - /'
      issues=$((issues+1))
      PROBE_ISSUES=1
    else
      echo "[OK] No probe failure events found"
    fi
  fi
  
  # NetworkPolicy analysis will be done in a separate section
  
  # Check if node SG allows probe traffic (if we have node SG info)
  if [ -n "$AWS_DIR" ] && [ -s "$AWS_DIR/all_instance_enis.json" ]; then
    # Get node primary ENI SGs
    NODE_SGS=$(jq -r '.[0]?.Groups[]?.GroupId // empty' "$AWS_DIR/all_instance_enis.json" 2>/dev/null | grep -v "^$" | head -5 || echo "")
    if [ -n "$NODE_SGS" ]; then
      echo "[INFO] Node Security Groups: $(echo "$NODE_SGS" | tr '\n' ',' | sed 's/,$//')"
      echo "[INFO] Verify node SG allows ingress to pod on probe ports (kubelet needs to reach pod for health checks)"
    fi
  fi
  
  if [ "$PROBE_ISSUES" -eq 0 ]; then
    echo "[OK] No health probe issues detected"
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

# Reverse path filtering (rp_filter) analysis
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_rp_filter.txt" ]; then
  echo ""
  echo "=== Reverse Path Filtering (rp_filter) ==="
  
  RP_FILTER_ISSUES=0
  RP_FILTER_FILE="$NODE_DIR/node_rp_filter.txt"
  
  # rp_filter values:
  # 0 = No source validation (disabled)
  # 1 = Strict mode (RFC 3704) - recommended for most cases, but can break pod ENI
  # 2 = Loose mode - recommended for pod ENI/custom networking to allow asymmetric routing
  
  # Check for interfaces with rp_filter=1 (strict mode) which can cause issues with pod ENIs
  STRICT_MODE_COUNT=0
  LOOSE_MODE_COUNT=0
  DISABLED_COUNT=0
  STRICT_IFACES=""
  
  while IFS='=' read -r iface rp_value; do
    # Skip empty lines and comments
    [ -z "$iface" ] && continue
    [ "$iface" = "#" ] && continue
    
    rp_value=$(echo "$rp_value" | tr -d '[:space:]')
    case "$rp_value" in
      "1")
        STRICT_MODE_COUNT=$((STRICT_MODE_COUNT + 1))
        if [ -z "$STRICT_IFACES" ]; then
          STRICT_IFACES="$iface"
        else
          STRICT_IFACES="$STRICT_IFACES, $iface"
        fi
        ;;
      "2")
        LOOSE_MODE_COUNT=$((LOOSE_MODE_COUNT + 1))
        ;;
      "0")
        DISABLED_COUNT=$((DISABLED_COUNT + 1))
        ;;
    esac
  done < "$RP_FILTER_FILE"
  
  # Check if pod uses pod ENI (branch ENI)
  POD_USES_POD_ENI=0
  if [ -s "$POD_DIR/pod_branch_eni_id.txt" ]; then
    POD_ENI_ID=$(cat "$POD_DIR/pod_branch_eni_id.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$POD_ENI_ID" ] && [ "$POD_ENI_ID" != "unknown" ] && [ "$POD_ENI_ID" != "null" ]; then
      POD_USES_POD_ENI=1
    fi
  fi
  
  if [ "$POD_USES_POD_ENI" -eq 1 ]; then
    # For pod ENI scenarios, rp_filter=2 (loose mode) is recommended
    if [ "$STRICT_MODE_COUNT" -gt 0 ]; then
      echo "[ISSUE] Found $STRICT_MODE_COUNT interface(s) with rp_filter=1 (strict mode) - may cause asymmetric routing issues with pod ENI"
      echo "[INFO] Interfaces with strict mode: $STRICT_IFACES"
      echo "[INFO] Recommendation: Set rp_filter=2 (loose mode) for pod ENI scenarios to allow asymmetric routing"
      issues=$((issues+1))
      RP_FILTER_ISSUES=1
    elif [ "$LOOSE_MODE_COUNT" -gt 0 ]; then
      echo "[OK] Found $LOOSE_MODE_COUNT interface(s) with rp_filter=2 (loose mode) - appropriate for pod ENI"
    else
      # No loose mode found - check if disabled (0) or just not set
      if [ "$DISABLED_COUNT" -gt 0 ]; then
        echo "[ISSUE] Found $DISABLED_COUNT interface(s) with rp_filter=0 (disabled) - security risk AND may cause asymmetric routing issues with pod ENI"
        echo "[INFO] Recommendation: Set rp_filter=2 (loose mode) for pod ENI scenarios to allow asymmetric routing and improve security"
        issues=$((issues+1))
        RP_FILTER_ISSUES=1
      else
        echo "[WARN] No interfaces found with rp_filter=2 (loose mode) - pod ENI may experience asymmetric routing issues"
        warnings=$((warnings+1))
        RP_FILTER_ISSUES=1
      fi
    fi
  else
    # For non-pod ENI scenarios, rp_filter=1 (strict mode) is typically fine
    if [ "$STRICT_MODE_COUNT" -gt 0 ]; then
      echo "[OK] Found $STRICT_MODE_COUNT interface(s) with rp_filter=1 (strict mode) - appropriate for standard networking"
    elif [ "$LOOSE_MODE_COUNT" -gt 0 ]; then
      echo "[INFO] Found $LOOSE_MODE_COUNT interface(s) with rp_filter=2 (loose mode) - allows asymmetric routing"
    fi
    
    # Warn about disabled rp_filter (0) as it's a security risk (even for non-pod ENI)
    if [ "$DISABLED_COUNT" -gt 0 ]; then
      echo "[WARN] Found $DISABLED_COUNT interface(s) with rp_filter=0 (disabled) - security risk (allows source address spoofing)"
      warnings=$((warnings+1))
      RP_FILTER_ISSUES=1
    fi
  fi
  
  if [ "$RP_FILTER_ISSUES" -eq 0 ]; then
    echo "[OK] No reverse path filtering issues detected"
  fi
fi

echo ""
# NetworkPolicy analysis
if [ -n "$POD_DIR" ] && [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_k8s_networkpolicies.json" ]; then
  echo ""
  echo "=== NetworkPolicy Analysis ==="
  
  NP_ISSUES=0
  NP_FILE="$NODE_DIR/node_k8s_networkpolicies.json"
  
  # Get pod namespace and labels
  POD_NAMESPACE=$(jq -r '.metadata.namespace // "default"' "$POD_DIR/pod_full.json" 2>/dev/null || echo "default")
  POD_LABELS=$(jq -r '.metadata.labels // {}' "$POD_DIR/pod_full.json" 2>/dev/null || echo "{}")
  
  # Get node IP for health probe checks
  NODE_IP=$(grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$NODE_DIR/node_all_ips.txt" 2>/dev/null | grep -v "127.0.0.1" | head -1 || echo "")
  
  # Count NetworkPolicies
  NP_COUNT=$(jq -r '.items | length' "$NP_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
  
  if [ "$NP_COUNT" = "0" ] || [ -z "$NP_COUNT" ]; then
    echo "[OK] No NetworkPolicies found in cluster"
  else
    echo "[INFO] Found $NP_COUNT NetworkPolicy(ies) in cluster"
    
    # Find NetworkPolicies that apply to this pod (same namespace and matching podSelector)
    APPLICABLE_NPS=0
    MISSING_DNS_EGRESS=0
    MISSING_METRICS_EGRESS=0
    RESTRICTIVE_INGRESS=0
    
    # Function to check if podSelector matches pod labels
    check_pod_selector() {
      local selector="$1"
      local pod_labels="$2"
      
      # Empty selector matches all pods
      if [ -z "$selector" ] || [ "$selector" = "{}" ] || [ "$selector" = "null" ]; then
        return 0
      fi
      
      # Check matchLabels
      if echo "$selector" | jq -e '.matchLabels' >/dev/null 2>&1; then
        local match_labels=$(echo "$selector" | jq -r '.matchLabels // {}')
        while IFS='=' read -r key value; do
          [ -z "$key" ] && continue
          local pod_value=$(echo "$pod_labels" | jq -r --arg k "$key" '.[$k] // ""')
          if [ "$pod_value" != "$value" ]; then
            return 1  # Label doesn't match
          fi
        done <<< "$(echo "$match_labels" | jq -r 'to_entries[] | "\(.key)=\(.value)"')"
      fi
      
      # Check matchExpressions (simplified - would need full evaluation)
      if echo "$selector" | jq -e '.matchExpressions' >/dev/null 2>&1; then
        # For now, we'll note that matchExpressions exist but not fully evaluate them
        # This is a limitation - full evaluation would require more complex logic
        echo "[INFO] NetworkPolicy uses matchExpressions (not fully evaluated)"
      fi
      
      return 0  # Matches
    }
    
    # Analyze each NetworkPolicy
    NP_INDEX=0
    while [ "$NP_INDEX" -lt "$NP_COUNT" ]; do
      np_json=$(jq -r --argjson idx "$NP_INDEX" '.items[$idx]' "$NP_FILE" 2>/dev/null || echo "")
      [ -z "$np_json" ] || [ "$np_json" = "null" ] && { NP_INDEX=$((NP_INDEX + 1)); continue; }
      
      NP_NAME=$(echo "$np_json" | jq -r '.metadata.name // "unknown"' 2>/dev/null || echo "unknown")
      NP_NAMESPACE=$(echo "$np_json" | jq -r '.metadata.namespace // "default"' 2>/dev/null || echo "default")
      POD_SELECTOR=$(echo "$np_json" | jq -r '.spec.podSelector // {}' 2>/dev/null || echo "{}")
      POLICY_TYPES=$(echo "$np_json" | jq -r '.spec.policyTypes // ["Ingress", "Egress"]' 2>/dev/null || echo '["Ingress", "Egress"]')
      INGRESS_RULES=$(echo "$np_json" | jq -r '.spec.ingress // []' 2>/dev/null || echo "[]")
      EGRESS_RULES=$(echo "$np_json" | jq -r '.spec.egress // []' 2>/dev/null || echo "[]")
      
      # Only check policies in the same namespace
      if [ "$NP_NAMESPACE" != "$POD_NAMESPACE" ]; then
        continue
      fi
      
      # Check if podSelector matches this pod
      if check_pod_selector "$POD_SELECTOR" "$POD_LABELS" 2>/dev/null; then
        APPLICABLE_NPS=$((APPLICABLE_NPS + 1))
        echo "[INFO] NetworkPolicy '$NP_NAME' in namespace '$NP_NAMESPACE' applies to this pod"
        
        # Check policy types
        HAS_INGRESS=$(echo "$POLICY_TYPES" | jq -r '.[]? | select(. == "Ingress")' 2>/dev/null || echo "")
        HAS_EGRESS=$(echo "$POLICY_TYPES" | jq -r '.[]? | select(. == "Egress")' 2>/dev/null || echo "")
        
        # Check ingress rules
        if [ -n "$HAS_INGRESS" ]; then
          INGRESS_COUNT=$(echo "$INGRESS_RULES" | jq -r 'length' 2>/dev/null || echo "0")
          if [ "$INGRESS_COUNT" = "0" ]; then
            echo "[WARN] NetworkPolicy '$NP_NAME' has Ingress policy type but no ingress rules - all ingress blocked"
            warnings=$((warnings+1))
            RESTRICTIVE_INGRESS=1
            NP_ISSUES=1
          else
            # Check if ingress allows from node (for health probes)
            ALLOWS_NODE=0
            if [ -n "$NODE_IP" ]; then
              # Check if any ingress rule allows from all sources (empty from array or null)
              ALLOWS_ALL=$(echo "$INGRESS_RULES" | jq -r '[.[] | select(.from == null or (.from | length == 0))] | length' 2>/dev/null || echo "0")
              if [ "$ALLOWS_ALL" != "0" ] && [ "$ALLOWS_ALL" -gt 0 ]; then
                ALLOWS_NODE=1
              else
                # Check if any ingress rule has ipBlock that might include node IP
                # This is simplified - full CIDR matching would require more complex logic
                HAS_IPBLOCK=$(echo "$INGRESS_RULES" | jq -r '[.[] | select(.from[]?.ipBlock != null)] | length' 2>/dev/null || echo "0")
                if [ "$HAS_IPBLOCK" != "0" ] && [ "$HAS_IPBLOCK" -gt 0 ]; then
                  # Note that we can't fully validate CIDR matching without more complex logic
                  echo "[INFO] NetworkPolicy '$NP_NAME' has ipBlock rules - verify they allow node IP ($NODE_IP) for health probes"
                else
                  # Check for namespaceSelector or podSelector that might allow from nodes
                  HAS_SELECTOR=$(echo "$INGRESS_RULES" | jq -r '[.[] | select(.from[]?.namespaceSelector != null or .from[]?.podSelector != null)] | length' 2>/dev/null || echo "0")
                  if [ "$HAS_SELECTOR" = "0" ]; then
                    echo "[WARN] NetworkPolicy '$NP_NAME' may block health probes from node ($NODE_IP) - no catch-all or node-specific ingress rules"
                    warnings=$((warnings+1))
                    RESTRICTIVE_INGRESS=1
                    NP_ISSUES=1
                  fi
                fi
              fi
            fi
          fi
        fi
        
        # Check egress rules
        if [ -n "$HAS_EGRESS" ]; then
          EGRESS_COUNT=$(echo "$EGRESS_RULES" | jq -r 'length' 2>/dev/null || echo "0")
          if [ "$EGRESS_COUNT" = "0" ]; then
            echo "[WARN] NetworkPolicy '$NP_NAME' has Egress policy type but no egress rules - all egress blocked (DNS/metrics will fail)"
            issues=$((issues+1))
            MISSING_DNS_EGRESS=1
            NP_ISSUES=1
          else
            # Check for DNS egress (port 53 UDP/TCP)
            HAS_DNS_EGRESS=$(echo "$EGRESS_RULES" | jq -r '[.[] | select(.ports[]?.port // .ports[]?.protocol // "" | tostring | test("53|DNS|dns"))] | length' 2>/dev/null || echo "0")
            if [ "$HAS_DNS_EGRESS" = "0" ]; then
              # Check if there's a catch-all egress rule
              HAS_CATCHALL=$(echo "$EGRESS_RULES" | jq -r '[.[] | select(.to == null or (.to | length == 0))] | length' 2>/dev/null || echo "0")
              if [ "$HAS_CATCHALL" = "0" ]; then
                echo "[WARN] NetworkPolicy '$NP_NAME' may block DNS egress (port 53) - DNS resolution may fail"
                warnings=$((warnings+1))
                MISSING_DNS_EGRESS=1
                NP_ISSUES=1
              fi
            fi
            
            # Check for metrics egress (common ports: 8080, 9090, 10250, etc.)
            HAS_METRICS_EGRESS=$(echo "$EGRESS_RULES" | jq -r '[.[] | select(.ports[]?.port // "" | tostring | test("8080|9090|10250|9100"))] | length' 2>/dev/null || echo "0")
            if [ "$HAS_METRICS_EGRESS" = "0" ]; then
              HAS_CATCHALL=$(echo "$EGRESS_RULES" | jq -r '[.[] | select(.to == null or (.to | length == 0))] | length' 2>/dev/null || echo "0")
              if [ "$HAS_CATCHALL" = "0" ]; then
                echo "[INFO] NetworkPolicy '$NP_NAME' may restrict metrics egress - verify metrics endpoints are allowed"
              fi
            fi
          fi
        fi
      fi
      NP_INDEX=$((NP_INDEX + 1))
    done
    
    if [ "$APPLICABLE_NPS" -eq 0 ]; then
      echo "[OK] No NetworkPolicies apply to this pod (no matching podSelector in namespace '$POD_NAMESPACE')"
    else
      echo "[INFO] Found $APPLICABLE_NPS NetworkPolicy(ies) that apply to this pod"
      
      if [ "$MISSING_DNS_EGRESS" -eq 1 ]; then
        echo "[ISSUE] Some NetworkPolicies may block DNS egress - DNS resolution may fail"
        issues=$((issues+1))
        NP_ISSUES=1
      fi
      
      if [ "$RESTRICTIVE_INGRESS" -eq 1 ]; then
        echo "[WARN] Some NetworkPolicies may block health probes or service traffic"
        warnings=$((warnings+1))
        NP_ISSUES=1
      fi
    fi
    
    if [ "$NP_ISSUES" -eq 0 ]; then
      echo "[OK] No NetworkPolicy issues detected"
    fi
  fi
fi

echo ""
echo "=== Custom Networking / ENIConfig Analysis ==="

# Check for ENIConfig resources
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_eniconfigs.json" ]; then
  ENICONFIG_FILE="$NODE_DIR/node_eniconfigs.json"
  ENICONFIG_COUNT=$(jq -r '.items | length' "$ENICONFIG_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
  
  if [ "$ENICONFIG_COUNT" = "0" ] || [ -z "$ENICONFIG_COUNT" ]; then
    echo "[OK] No ENIConfig resources found (custom networking not enabled - using default VPC CNI)"
  else
    echo "[INFO] Found $ENICONFIG_COUNT ENIConfig resource(s) (custom networking enabled)"
    
    ENICONFIG_ISSUES=0
    
    # Get subnet information from AWS data for validation
    if [ -n "$AWS_DIR" ] && [ -s "$AWS_DIR/subnets.json" ]; then
      # Build subnet lookup: subnet-id -> [cidr, az]
      # subnets.json format: [subnet-id, available-ips, cidr, az]
      
      # Validate each ENIConfig
      ENICONFIG_INDEX=0
      while [ "$ENICONFIG_INDEX" -lt "$ENICONFIG_COUNT" ]; do
        ENICONFIG_NAME=$(jq -r ".items[$ENICONFIG_INDEX].metadata.name // \"\"" "$ENICONFIG_FILE" 2>/dev/null || echo "")
        ENICONFIG_SUBNET=$(jq -r ".items[$ENICONFIG_INDEX].spec.subnet // \"\"" "$ENICONFIG_FILE" 2>/dev/null || echo "")
        ENICONFIG_SGS=$(jq -r ".items[$ENICONFIG_INDEX].spec.securityGroups // []" "$ENICONFIG_FILE" 2>/dev/null || echo "[]")
        ENICONFIG_TAGS=$(jq -r ".items[$ENICONFIG_INDEX].spec.tags // {}" "$ENICONFIG_FILE" 2>/dev/null || echo "{}")
        
        if [ -n "$ENICONFIG_NAME" ] && [ "$ENICONFIG_NAME" != "null" ]; then
          echo "[INFO] ENIConfig '$ENICONFIG_NAME':"
          
          # Validate subnet exists and get its AZ
          if [ -n "$ENICONFIG_SUBNET" ] && [ "$ENICONFIG_SUBNET" != "null" ] && [ "$ENICONFIG_SUBNET" != "" ]; then
            # Find subnet in AWS data
            SUBNET_INFO=$(jq -r ".[] | select(.[0] == \"$ENICONFIG_SUBNET\") | [.[2], .[3]] | @tsv" "$AWS_DIR/subnets.json" 2>/dev/null || echo "")
            
            if [ -n "$SUBNET_INFO" ]; then
              SUBNET_CIDR=$(echo "$SUBNET_INFO" | cut -f1)
              SUBNET_AZ=$(echo "$SUBNET_INFO" | cut -f2)
              echo "  - Subnet: $ENICONFIG_SUBNET (CIDR: $SUBNET_CIDR, AZ: $SUBNET_AZ)"
              
              # Check if ENIConfig name matches AZ (common pattern: ENIConfig name = AZ)
              if [ "$ENICONFIG_NAME" != "$SUBNET_AZ" ] && [ "$ENICONFIG_NAME" != "default" ]; then
                echo "  - [WARN] ENIConfig name '$ENICONFIG_NAME' does not match subnet AZ '$SUBNET_AZ' (may cause confusion)"
                warnings=$((warnings+1))
                ENICONFIG_ISSUES=1
              fi
            else
              echo "  - [ISSUE] Subnet '$ENICONFIG_SUBNET' not found in VPC (may be in different VPC or deleted)"
              issues=$((issues+1))
              ENICONFIG_ISSUES=1
            fi
          else
            echo "  - [ISSUE] ENIConfig missing subnet specification"
            issues=$((issues+1))
            ENICONFIG_ISSUES=1
          fi
          
          # Show security groups if specified
          SG_COUNT=$(echo "$ENICONFIG_SGS" | jq -r 'length' 2>/dev/null || echo "0")
          if [ "$SG_COUNT" -gt 0 ]; then
            echo "  - Security Groups: $SG_COUNT SG(s) specified"
          fi
          
          # Show tags if specified
          TAG_COUNT=$(echo "$ENICONFIG_TAGS" | jq -r 'length' 2>/dev/null || echo "0")
          if [ "$TAG_COUNT" -gt 0 ]; then
            echo "  - Tags: $TAG_COUNT tag(s) specified"
          fi
        fi
        
        ENICONFIG_INDEX=$((ENICONFIG_INDEX + 1))
      done
      
      # Check node ENIConfig assignment
      if [ -s "$NODE_DIR/node_annotations.json" ]; then
        NODE_ENICONFIG=$(jq -r '.["k8s.amazonaws.com/eniConfig"] // .["vpc.amazonaws.com/eniConfig"] // ""' "$NODE_DIR/node_annotations.json" 2>/dev/null || echo "")
        if [ -n "$NODE_ENICONFIG" ] && [ "$NODE_ENICONFIG" != "null" ] && [ "$NODE_ENICONFIG" != "" ]; then
          echo "[INFO] Node ENIConfig assignment: $NODE_ENICONFIG"
          
          # Verify assigned ENIConfig exists
          ENICONFIG_EXISTS=$(jq -r ".items[] | select(.metadata.name == \"$NODE_ENICONFIG\") | .metadata.name" "$ENICONFIG_FILE" 2>/dev/null || echo "")
          if [ -z "$ENICONFIG_EXISTS" ] || [ "$ENICONFIG_EXISTS" = "" ]; then
            echo "[ISSUE] Node assigned to ENIConfig '$NODE_ENICONFIG' but this ENIConfig does not exist"
            issues=$((issues+1))
            ENICONFIG_ISSUES=1
          else
            echo "[OK] Node ENIConfig assignment valid"
          fi
        else
          # Check node labels as fallback
          if [ -s "$NODE_DIR/node_labels.json" ]; then
            NODE_ENICONFIG_LABEL=$(jq -r '.["k8s.amazonaws.com/eniConfig"] // .["vpc.amazonaws.com/eniConfig"] // ""' "$NODE_DIR/node_labels.json" 2>/dev/null || echo "")
            if [ -n "$NODE_ENICONFIG_LABEL" ] && [ "$NODE_ENICONFIG_LABEL" != "null" ] && [ "$NODE_ENICONFIG_LABEL" != "" ]; then
              echo "[INFO] Node ENIConfig assignment (from label): $NODE_ENICONFIG_LABEL"
              
              # Verify assigned ENIConfig exists
              ENICONFIG_EXISTS=$(jq -r ".items[] | select(.metadata.name == \"$NODE_ENICONFIG_LABEL\") | .metadata.name" "$ENICONFIG_FILE" 2>/dev/null || echo "")
              if [ -z "$ENICONFIG_EXISTS" ] || [ "$ENICONFIG_EXISTS" = "" ]; then
                echo "[ISSUE] Node assigned to ENIConfig '$NODE_ENICONFIG_LABEL' but this ENIConfig does not exist"
                issues=$((issues+1))
                ENICONFIG_ISSUES=1
              else
                echo "[OK] Node ENIConfig assignment valid"
              fi
            else
              echo "[INFO] Node not explicitly assigned to an ENIConfig (may use default or node group settings)"
            fi
          fi
        fi
      fi
      
      if [ "$ENICONFIG_ISSUES" -eq 0 ]; then
        echo "[OK] No ENIConfig validation issues detected"
      else
        echo "[INFO] Recommendation: Verify ENIConfig subnet → AZ mapping matches actual subnets, ensure node assignments are correct"
      fi
    else
      echo "[WARN] Subnet information not available - cannot validate ENIConfig subnet → AZ mapping"
      warnings=$((warnings+1))
    fi
  fi
else
  echo "[INFO] ENIConfig data not available (custom networking may not be enabled)"
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

