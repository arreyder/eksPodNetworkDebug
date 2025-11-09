#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-}"
if [ -z "$BUNDLE" ]; then echo "Usage: $0 <sgfp_bundle_dir>"; exit 1; fi
if [ ! -d "$BUNDLE" ]; then
  echo "ERROR: Bundle directory does not exist: $BUNDLE" >&2
  exit 1
fi
REPORT="$BUNDLE/report.md"

POD_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'pod_*' | head -n1 || true)
NODE_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'node_*' | head -n1 || true)
AWS_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'aws_*' | head -n1 || true)

if [ -z "$POD_DIR" ] || [ ! -d "$POD_DIR" ]; then
  echo "ERROR: Pod directory not found in bundle: $BUNDLE" >&2
  exit 1
fi

# Extract pod name: bundle format is sgfp_bundle_<pod-name>_YYYYMMDD_HHMMSS
# Match timestamp pattern (8 digits, underscore, 6 digits) at the end
POD=$(basename "$BUNDLE" | sed 's/^sgfp_bundle_\(.*\)_[0-9]\{8\}_[0-9]\{6\}$/\1/')
NODE="$(basename "${NODE_DIR:-}" | sed 's/^node_//')"

POD_ANNO="$POD_DIR/pod_annotations.json"
POD_COND="$POD_DIR/pod_conditions.json"
POD_NET="$POD_DIR/pod_netns_routes_rules.txt"
POD_SGS="$POD_DIR/pod_branch_eni_sgs.txt"
POD_SGS_DETAILS="$POD_DIR/pod_branch_eni_sgs_details.json"
POD_EXPECTED_SGS="$POD_DIR/pod_expected_sgs.txt"
NAMESPACE_EXPECTED_SGS="$POD_DIR/namespace_expected_sgs.txt"
DEPLOYMENT_EXPECTED_SGS="$POD_DIR/deployment_expected_sgs.txt"
REPLICASET_EXPECTED_SGS="$POD_DIR/replicaset_expected_sgs.txt"
REACH="$POD_DIR/pod_reachability.txt"
AWS_NODE_LOG_POD="$POD_DIR/aws_node_full.log"
POD_ENI_ID="$POD_DIR/pod_branch_eni_id.txt"
POD_VETH="$POD_DIR/pod_veth_interface.txt"
POD_IF_STATS="$POD_DIR/pod_interface_stats.txt"
POD_SNMP="$POD_DIR/pod_snmp.txt"
CONN="${NODE_DIR:+$NODE_DIR/node_conntrack_mtu.txt}"
NODE_IF_DEV="${NODE_DIR:+$NODE_DIR/node_interface_dev_stats.txt}"
NODE_IF_IP="${NODE_DIR:+$NODE_DIR/node_interface_ip_stats.txt}"
NODE_SNMP="${NODE_DIR:+$NODE_DIR/node_snmp.txt}"
TRUNK_JSON="${AWS_DIR:+$AWS_DIR/trunk_eni.json}"
BR_JSON="${AWS_DIR:+$AWS_DIR/_all_branch_enis_in_vpc.json}"

say(){ echo "- $1" >> "$REPORT"; }

echo "# SGFP Network Diagnostics Report" > "$REPORT"
echo "Pod: \`$POD\`" >> "$REPORT"
[ -n "$NODE" ] && echo "Node: \`$NODE\`" >> "$REPORT"
echo "Generated: \`$(date)\`" >> "$REPORT"
echo >> "$REPORT"

echo "## Pod Networking" >> "$REPORT"

if [ -s "$POD_ANNO" ] && jq -er '."vpc.amazonaws.com/pod-eni"' "$POD_ANNO" >/dev/null 2>&1; then
  say "[OK] Pod ENI assigned (SG-for-Pods)"
  # Show ENI ID
  if [ -s "$POD_ENI_ID" ]; then
    ENI_ID=$(cat "$POD_ENI_ID" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$ENI_ID" ] && [ "$ENI_ID" != "unknown" ]; then
      say "[INFO] Pod ENI ID: \`$ENI_ID\`"
    fi
  fi
  # Show veth interface
  if [ -s "$POD_VETH" ]; then
    VETH_NAME=$(cat "$POD_VETH" 2>/dev/null | tr -d '[:space:]' || echo "")
    if [ -n "$VETH_NAME" ] && [ "$VETH_NAME" != "unknown" ]; then
      say "[INFO] Pod veth interface: \`$VETH_NAME\`"
    fi
  fi
else
  say "[ISSUE] No Pod ENI annotation (mutation may have failed)"
fi

if [ -s "$POD_NET" ]; then
  if grep -qi "not available" "$POD_NET"; then
    say "[INFO] Per-pod routing table check skipped (network tools not available in pod)"
  elif grep -Eq 'table (100|101)' "$POD_NET"; then
    say "[OK] Per-pod routing table exists"
  else
    say "[ISSUE] Missing per-pod routing table (or routing data unavailable)"
  fi
else
  say "[INFO] Per-pod routing table data not collected"
fi

if [ -s "$POD_SGS" ]; then
  echo >> "$REPORT"
  echo "### Pod ENI Security Groups" >> "$REPORT"
  SG_COUNT=$(wc -l < "$POD_SGS" 2>/dev/null | tr -d '[:space:]' || echo "0")
  say "[INFO] Actual SGs on Pod ENI: $SG_COUNT SG(s)"
  
  # Show SGs with names and descriptions if available
  if [ -s "$POD_SGS_DETAILS" ] && jq -e 'length > 0' "$POD_SGS_DETAILS" >/dev/null 2>&1; then
    jq -r '.[] | "  - `\(.[0])`\(if .[1] and .[1] != "" then " - \(.[1])" else "" end)\(if .[2] and .[2] != "" then " - \(.[2])" else "" end)"' "$POD_SGS_DETAILS" >> "$REPORT" 2>/dev/null || sed 's/^/  - `&`/' "$POD_SGS" >> "$REPORT"
  else
    # Fallback to just IDs if details not available
    sed 's/^/  - `&`/' "$POD_SGS" >> "$REPORT"
  fi
  
  # Check for expected SGs (priority: pod > deployment > replicaset > namespace)
  # Check if file exists and has non-empty content (after trimming whitespace)
  EXPECTED_SGS=""
  SG_SOURCE=""
  check_sg_file() {
    local file="$1"
    if [ -f "$file" ] && [ -s "$file" ]; then
      # Check if file has non-whitespace content
      if grep -q '[^[:space:]]' "$file" 2>/dev/null; then
        return 0
      fi
    fi
    return 1
  }
  
  if check_sg_file "$POD_EXPECTED_SGS"; then
    EXPECTED_SGS="$POD_EXPECTED_SGS"
    SG_SOURCE="pod annotation"
    say "[INFO] Expected SGs (from pod annotation):"
    sed 's/^/  - `&`/' "$POD_EXPECTED_SGS" >> "$REPORT"
  elif check_sg_file "$DEPLOYMENT_EXPECTED_SGS"; then
    EXPECTED_SGS="$DEPLOYMENT_EXPECTED_SGS"
    SG_SOURCE="deployment annotation"
    say "[INFO] Expected SGs (from deployment annotation):"
    sed 's/^/  - `&`/' "$DEPLOYMENT_EXPECTED_SGS" >> "$REPORT"
  elif check_sg_file "$REPLICASET_EXPECTED_SGS"; then
    EXPECTED_SGS="$REPLICASET_EXPECTED_SGS"
    SG_SOURCE="replicaset annotation"
    say "[INFO] Expected SGs (from replicaset annotation):"
    sed 's/^/  - `&`/' "$REPLICASET_EXPECTED_SGS" >> "$REPORT"
  elif check_sg_file "$NAMESPACE_EXPECTED_SGS"; then
    EXPECTED_SGS="$NAMESPACE_EXPECTED_SGS"
    SG_SOURCE="namespace annotation"
    say "[INFO] Expected SGs (from namespace annotation):"
    sed 's/^/  - `&`/' "$NAMESPACE_EXPECTED_SGS" >> "$REPORT"
  fi
  
  # Compare expected vs actual
  if [ -n "$EXPECTED_SGS" ] && check_sg_file "$EXPECTED_SGS"; then
    echo >> "$REPORT"
    # Use temporary files for comparison (more portable than process substitution)
    TMP_ACTUAL=$(mktemp) && sort "$POD_SGS" > "$TMP_ACTUAL" 2>/dev/null || true
    TMP_EXPECTED=$(mktemp) && sort "$EXPECTED_SGS" > "$TMP_EXPECTED" 2>/dev/null || true
    
    if cmp -s "$TMP_ACTUAL" "$TMP_EXPECTED" 2>/dev/null; then
      say "[OK] SG Validation: Match (Actual SGs match expected)"
    else
      say "[ISSUE] SG Validation: Mismatch (Actual SGs differ from expected)"
      echo >> "$REPORT"
      MISSING=$(comm -23 "$TMP_EXPECTED" "$TMP_ACTUAL" 2>/dev/null || true)
      if [ -n "$MISSING" ]; then
        say "[ISSUE] Missing SGs:"
        echo "$MISSING" | sed 's/^/  - `&`/' >> "$REPORT"
      fi
      UNEXPECTED=$(comm -13 "$TMP_EXPECTED" "$TMP_ACTUAL" 2>/dev/null || true)
      if [ -n "$UNEXPECTED" ]; then
        say "[ISSUE] Unexpected SGs:"
        echo "$UNEXPECTED" | sed 's/^/  - `&`/' >> "$REPORT"
      fi
    fi
    rm -f "$TMP_ACTUAL" "$TMP_EXPECTED" 2>/dev/null || true
  else
    say "[INFO] SG Validation: No expected SGs specified (checking actual SGs only)"
  fi
fi

if [ -s "$REACH" ]; then
  if grep -qi "100% packet loss" "$REACH"; then
    say "[INFO] ICMP reachability failed (often blocked)"
  else
    say "[OK] ICMP reachability OK"
  fi
fi

if [ -s "$AWS_NODE_LOG_POD" ]; then
  if grep -Eiq 'rate.?exceeded|throttl|attach|branch|trunk|fail|error' "$AWS_NODE_LOG_POD"; then
    say "[ISSUE] Interesting CNI events in pod aws-node logs (see \`pod_*/aws_node_full.log\`)"
  else
    say "[OK] aws-node logs (pod scope) look clean"
  fi
fi

echo >> "$REPORT"
echo "## Node State" >> "$REPORT"

if [ -n "$CONN" ] && [ -s "$CONN" ]; then
  pair="$(grep -Eo '[0-9]+\s*/\s*[0-9]+' "$CONN" | head -n1 || true)"
  if [ -n "$pair" ]; then
    CT="$(printf '%s' "$pair" | awk -F'/' '{gsub(/ /,"",$1); print $1}')"
    MX="$(printf '%s' "$pair" | awk -F'/' '{gsub(/ /,"",$2); print $2}')"
    if printf '%s' "$CT" | grep -Eq '^[0-9]+$' && printf '%s' "$MX" | grep -Eq '^[0-9]+$' && [ "$MX" -gt 0 ]; then
      PCT="$(awk -v c="$CT" -v m="$MX" 'BEGIN{printf "%d%%", (100*c)/m}')"
      say "Conntrack usage: **$CT / $MX (~$PCT)**"
    fi
  fi
  if grep -Eiq 'nf_conntrack|fragmentation needed|blackhole' "$CONN"; then
    say "[ISSUE] Kernel shows conntrack/fragmentation/blackhole hints"
  fi
else
  say "[INFO] Conntrack/MTU capture missing"
fi

# Interface error statistics
if [ -n "$NODE_IF_DEV" ] && [ -s "$NODE_IF_DEV" ]; then
  echo >> "$REPORT"
  say "[INFO] Node interface error statistics (from /proc/net/dev):"
  # Extract interfaces with errors (rx_errors, tx_errors, rx_drop, tx_drop)
  grep -v "^Inter-\|^ face" "$NODE_IF_DEV" 2>/dev/null | awk '{
    if ($4+0 > 0 || $5+0 > 0 || $12+0 > 0 || $13+0 > 0) {
      printf "  - %s: rx_err=%s tx_err=%s rx_drop=%s tx_drop=%s\n", $1, $4, $5, $12, $13
    }
  }' >> "$REPORT" 2>/dev/null || true
  # If no errors found, note that
  if ! grep -q "rx_err\|tx_err\|rx_drop\|tx_drop" "$REPORT" 2>/dev/null; then
    say "[OK] No interface errors detected on node"
  fi
fi

# Socket overruns
# /proc/net/snmp has two lines per protocol: header and values. We need the second line (values).
if [ -n "$NODE_SNMP" ] && [ -s "$NODE_SNMP" ]; then
  echo >> "$REPORT"
  # Get the second line (values) for each protocol
  UDP_LINE=$(grep "^Udp:" "$NODE_SNMP" 2>/dev/null | tail -1 || echo "")
  TCP_LINE=$(grep "^Tcp:" "$NODE_SNMP" 2>/dev/null | tail -1 || echo "")
  
  # UDP format: "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors ..."
  # So: $1="Udp:", $2=InDatagrams, $3=NoPorts, $4=InErrors, $5=OutDatagrams, $6=RcvbufErrors
  UDP_ERRORS=$(echo "$UDP_LINE" | awk '{print $4}' 2>/dev/null || echo "0")
  UDP_RCVBUF_ERR=$(echo "$UDP_LINE" | awk '{print $6}' 2>/dev/null || echo "0")
  
  # TCP format: "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails ..."
  # So: $1="Tcp:", $2=RtoAlgorithm, ..., $8=AttemptFails
  TCP_ATTEMPT_FAIL=$(echo "$TCP_LINE" | awk '{print $8}' 2>/dev/null || echo "0")
  
  if [ "$UDP_ERRORS" != "0" ] || [ "$UDP_RCVBUF_ERR" != "0" ] || [ "$TCP_ATTEMPT_FAIL" != "0" ]; then
    say "[ISSUE] Socket overruns detected on node:"
    [ "$UDP_ERRORS" != "0" ] && say "  - UDP InErrors: $UDP_ERRORS" || true
    [ "$UDP_RCVBUF_ERR" != "0" ] && say "  - UDP RcvbufErrors: $UDP_RCVBUF_ERR" || true
    [ "$TCP_ATTEMPT_FAIL" != "0" ] && say "  - TCP AttemptFail: $TCP_ATTEMPT_FAIL" || true
  else
    say "[OK] No socket overruns detected on node"
  fi
fi

# Pod socket overruns
if [ -s "$POD_SNMP" ]; then
  POD_UDP_LINE=$(grep "^Udp:" "$POD_SNMP" 2>/dev/null | tail -1 || echo "")
  POD_TCP_LINE=$(grep "^Tcp:" "$POD_SNMP" 2>/dev/null | tail -1 || echo "")
  
  POD_UDP_ERRORS=$(echo "$POD_UDP_LINE" | awk '{print $4}' 2>/dev/null || echo "0")
  POD_UDP_RCVBUF_ERR=$(echo "$POD_UDP_LINE" | awk '{print $6}' 2>/dev/null || echo "0")
  POD_TCP_ATTEMPT_FAIL=$(echo "$POD_TCP_LINE" | awk '{print $8}' 2>/dev/null || echo "0")
  
  if [ "$POD_UDP_ERRORS" != "0" ] || [ "$POD_UDP_RCVBUF_ERR" != "0" ] || [ "$POD_TCP_ATTEMPT_FAIL" != "0" ]; then
    echo >> "$REPORT"
    say "[ISSUE] Socket overruns detected in pod:"
    [ "$POD_UDP_ERRORS" != "0" ] && say "  - UDP InErrors: $POD_UDP_ERRORS" || true
    [ "$POD_UDP_RCVBUF_ERR" != "0" ] && say "  - UDP RcvbufErrors: $POD_UDP_RCVBUF_ERR" || true
    [ "$POD_TCP_ATTEMPT_FAIL" != "0" ] && say "  - TCP AttemptFail: $POD_TCP_ATTEMPT_FAIL" || true
  fi
fi

# Node CNI logs (from /var/log/aws-routed-eni/)
NODE_CNI_LOGS_DIR=""
if [ -n "$NODE_DIR" ] && [ -d "$NODE_DIR/cni_logs" ]; then
  NODE_CNI_LOGS_DIR="$NODE_DIR/cni_logs"
fi

if [ -n "$NODE_CNI_LOGS_DIR" ] && [ -d "$NODE_CNI_LOGS_DIR" ]; then
  echo >> "$REPORT"
  say "[INFO] Node CNI logs (from /var/log/aws-routed-eni/):"
  CNI_ERRORS_FOUND=0
  
  for ERROR_FILE in "$NODE_CNI_LOGS_DIR"/*.errors; do
    if [ -f "$ERROR_FILE" ] && [ -s "$ERROR_FILE" ]; then
      LOG_NAME=$(basename "$ERROR_FILE" .errors)
      ERROR_COUNT=$(wc -l < "$ERROR_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
      if [ "$ERROR_COUNT" -gt 0 ]; then
        say "[ISSUE] $LOG_NAME: $ERROR_COUNT error/warning line(s)"
        CNI_ERRORS_FOUND=$((CNI_ERRORS_FOUND + 1))
        # Show recent errors
        tail -3 "$ERROR_FILE" | sed 's/^/    /' >> "$REPORT" 2>/dev/null || true
      fi
    fi
  done
  
  if [ "$CNI_ERRORS_FOUND" -eq 0 ]; then
    say "[OK] No errors found in node CNI logs"
  fi
  
  # List available log files
  LOG_FILES=$(ls -1 "$NODE_CNI_LOGS_DIR"/*.log 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$LOG_FILES" -gt 0 ]; then
    say "[INFO] Collected $LOG_FILES CNI log file(s) (see node diagnostics for full logs)"
  fi
fi

# Network namespace analysis
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_netns_details.json" ]; then
  if jq -e 'length > 0' "$NODE_DIR/node_netns_details.json" >/dev/null 2>&1; then
    echo >> "$REPORT"
    NETNS_COUNT=$(jq -r 'length' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "0")
    EMPTY_NS=$(jq -r '[.[] | select(.interface_count == 0)] | length' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "0")
    say "[INFO] Network namespaces: $NETNS_COUNT total"
    if [ "$EMPTY_NS" != "0" ]; then
      say "[ISSUE] Found $EMPTY_NS network namespace(s) with no interfaces (potential leaks)"
    fi
  fi
fi

# IP address conflicts
if [ -n "$NODE_DIR" ] && [ -f "$NODE_DIR/node_duplicate_ips.txt" ]; then
  if [ -s "$NODE_DIR/node_duplicate_ips.txt" ] && grep -q '[^[:space:]]' "$NODE_DIR/node_duplicate_ips.txt" 2>/dev/null; then
    echo >> "$REPORT"
    say "[ISSUE] IP address conflicts detected:"
    grep '[^[:space:]]' "$NODE_DIR/node_duplicate_ips.txt" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
  fi
fi

# DNS resolution
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_dns_tests.txt" ]; then
  echo >> "$REPORT"
  K8S_DNS_FAILED=$(grep -A 5 "kubernetes.default.svc.cluster.local" "$NODE_DIR/node_dns_tests.txt" 2>/dev/null | grep -qi "FAILED" && echo "1" || echo "0")
  if [ "$K8S_DNS_FAILED" = "1" ]; then
    say "[ISSUE] Kubernetes DNS resolution failed"
  else
    say "[OK] DNS resolution tests passed"
  fi
fi

# Resource exhaustion
if [ -n "$NODE_DIR" ]; then
  echo >> "$REPORT"
  say "[INFO] Resource usage:"
  
  # File descriptors
  if [ -s "$NODE_DIR/node_file_descriptors.txt" ]; then
    ALLOCATED=$(awk '{print $1}' "$NODE_DIR/node_file_descriptors.txt" 2>/dev/null || echo "0")
    MAX=$(awk '{print $3}' "$NODE_DIR/node_file_descriptors.txt" 2>/dev/null || echo "0")
    if [ "$MAX" != "0" ] && [ "$ALLOCATED" != "0" ]; then
      USAGE_PCT=$((ALLOCATED * 100 / MAX))
      if [ "$USAGE_PCT" -gt 80 ]; then
        say "[ISSUE] File descriptors: $ALLOCATED / $MAX (~$USAGE_PCT%)"
      else
        say "[OK] File descriptors: $ALLOCATED / $MAX (~$USAGE_PCT%)"
      fi
    fi
  fi
  
  # Memory
  if [ -s "$NODE_DIR/node_memory_info.txt" ]; then
    MEM_AVAILABLE=$(grep "^MemAvailable:" "$NODE_DIR/node_memory_info.txt" 2>/dev/null | awk '{print $2}' || echo "0")
    MEM_TOTAL=$(grep "^MemTotal:" "$NODE_DIR/node_memory_info.txt" 2>/dev/null | awk '{print $2}' || echo "0")
    if [ "$MEM_TOTAL" != "0" ] && [ "$MEM_AVAILABLE" != "0" ]; then
      MEM_USAGE_PCT=$(((MEM_TOTAL - MEM_AVAILABLE) * 100 / MEM_TOTAL))
      if [ "$MEM_USAGE_PCT" -gt 90 ]; then
        say "[ISSUE] Memory: ~$MEM_USAGE_PCT%"
      else
        say "[OK] Memory: ~$MEM_USAGE_PCT%"
      fi
    fi
  fi
fi

# Network interface state
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_interfaces_state.txt" ]; then
  echo >> "$REPORT"
  DOWN_COUNT=$(grep -E "state DOWN" "$NODE_DIR/node_interfaces_state.txt" 2>/dev/null | grep -v " lo:" | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$DOWN_COUNT" -gt 0 ]; then
    say "[ISSUE] Found $DOWN_COUNT interface(s) in DOWN state (excluding lo)"
  else
    say "[OK] No interfaces in unexpected DOWN state"
  fi
fi

# CloudTrail API Diagnostics (if available)
API_DIAG_DIR=""
# Try to find the most recent API diag directory (same parent as bundle)
if [ -d "$(dirname "$BUNDLE")" ]; then
  API_DIAG_DIR=$(ls -dt "$(dirname "$BUNDLE")"/sgfp_api_diag_* 2>/dev/null | head -1 || echo "")
fi

if [ -n "$API_DIAG_DIR" ] && [ -d "$API_DIAG_DIR" ]; then
  echo >> "$REPORT"
  echo "## CloudTrail API Diagnostics" >> "$REPORT"
  
  # Check for real errors/throttles
  if [ -s "$API_DIAG_DIR/eni_errors.tsv" ]; then
    ERROR_COUNT=$(wc -l < "$API_DIAG_DIR/eni_errors.tsv" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$ERROR_COUNT" -gt 0 ]; then
      say "[ISSUE] Found $ERROR_COUNT real error/throttle event(s) in CloudTrail"
      # Show recent errors
      head -5 "$API_DIAG_DIR/eni_errors.tsv" | awk -F'\t' '{printf "  - %s: %s (%s)\n", $2, $5, $6}' >> "$REPORT" 2>/dev/null || true
    else
      say "[OK] No real errors/throttles found in CloudTrail"
    fi
  fi
  
  # Show throttle summary by action
  if [ -s "$API_DIAG_DIR/throttle_by_action.txt" ]; then
    THROTTLE_COUNT=$(wc -l < "$API_DIAG_DIR/throttle_by_action.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$THROTTLE_COUNT" -gt 0 ]; then
      say "[INFO] Throttles by action:"
      head -5 "$API_DIAG_DIR/throttle_by_action.txt" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
    fi
  fi
  
  # Show summary stats
  if [ -s "$API_DIAG_DIR/flat_events.json" ]; then
    TOTAL_EVENTS=$(jq -r 'length' "$API_DIAG_DIR/flat_events.json" 2>/dev/null || echo "0")
    DRYRUN_COUNT=$(wc -l < "$API_DIAG_DIR/eni_dryruns.tsv" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$TOTAL_EVENTS" != "0" ]; then
      say "[INFO] Total ENI API events: $TOTAL_EVENTS (dry-runs: $DRYRUN_COUNT)"
    fi
  fi
else
  echo >> "$REPORT"
  say "[INFO] CloudTrail API diagnostics not available (run with --skip-api to skip, or provide --api-dir)"
fi

echo >> "$REPORT"
echo "## AWS ENI State" >> "$REPORT"

if [ -n "$TRUNK_JSON" ] && [ -s "$TRUNK_JSON" ] && jq -e '.NetworkInterfaces or .[0]?' "$TRUNK_JSON" >/dev/null 2>&1; then
  say "[OK] Trunk ENI present"
else
  say "[ISSUE] Trunk ENI not found"
fi

if [ -n "$BR_JSON" ] && [ -s "$BR_JSON" ] && jq -e 'length>0' "$BR_JSON" >/dev/null 2>&1; then
  say "[OK] Branch ENIs present (in VPC scan)"
else
  say "[INFO] No branch ENIs found in VPC scan (or insufficient perms)"
fi

echo >> "$REPORT"
echo "---" >> "$REPORT"
echo "_Report generated by sgfp_report.sh_" >> "$REPORT"

echo "[REPORT] Report written to: $REPORT"
