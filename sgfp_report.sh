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
AWS_NODE_ERRORS="$POD_DIR/aws_node_errors.log"
POD_ENI_ID="$POD_DIR/pod_branch_eni_id.txt"
POD_VETH="$POD_DIR/pod_veth_interface.txt"
POD_IF_STATS="$POD_DIR/pod_interface_stats.txt"
POD_SNMP="$POD_DIR/pod_snmp.txt"
POD_CONNECTIONS="$POD_DIR/pod_connections.txt"
POD_CONNTRACK="$POD_DIR/pod_conntrack_connections.txt"
POD_TIMING="$POD_DIR/pod_timing.txt"
POD_FULL="$POD_DIR/pod_full.json"
POD_IP_FILE="$POD_DIR/pod_ip.txt"
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

# Network connections
# Note: /proc/net/tcp and ss/netstat show connections from the pod's perspective:
# - LISTEN: ports the pod is listening on (waiting for inbound connections)
# - ESTABLISHED: active connections (both inbound TO pod and outbound FROM pod)
#   We can't definitively determine direction from /proc/net/tcp alone, but we can identify VPC/internal IPs
if [ -s "$POD_CONNECTIONS" ]; then
  if grep -qi "not available\|command failed\|Failed to" "$POD_CONNECTIONS"; then
    say "[INFO] Network connection tools not available in pod"
  else
    echo >> "$REPORT"
    say "[INFO] Pod network connections (from pod's perspective - includes both inbound and outbound):"
    
    # Check if this is /proc/net/tcp format (hex addresses) or ss/netstat format
    if grep -qE "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$POD_CONNECTIONS" 2>/dev/null; then
      # /proc/net/tcp format - parse hex addresses
      # State 0A = LISTEN (10), 01 = ESTABLISHED (1), 02 = SYN_SENT (2)
      # Skip header lines (sl, local_address, etc.) and section headers (--- TCP connections ---)
      LISTEN_COUNT=$(grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | awk '{print $4}' | grep -cE "^0A$|^0a$" | tr -d '[:space:]' || echo "0")
      ESTAB_COUNT=$(grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | awk '{print $4}' | grep -cE "^01$" | tr -d '[:space:]' || echo "0")
      SYN_SENT_COUNT=$(grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | awk '{print $4}' | grep -cE "^02$" | tr -d '[:space:]' || echo "0")
      
      if [ "$LISTEN_COUNT" != "0" ] || [ "$ESTAB_COUNT" != "0" ]; then
        say "[INFO] Listening ports: $LISTEN_COUNT | Established connections: $ESTAB_COUNT"
        # Convert and show first few connections in readable format
        CONN_TMP=$(mktemp)
        grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | head -10 | while read line; do
          # Extract local and remote addresses (hex IP:port) and state
          LOCAL_HEX=$(echo "$line" | awk '{print $2}' | cut -d: -f1)
          LOCAL_PORT_HEX=$(echo "$line" | awk '{print $2}' | cut -d: -f2)
          REMOTE_HEX=$(echo "$line" | awk '{print $3}' | cut -d: -f1)
          REMOTE_PORT_HEX=$(echo "$line" | awk '{print $3}' | cut -d: -f2)
          STATE=$(echo "$line" | awk '{print $4}')
          
          # Convert hex IP to decimal (little-endian format in /proc/net/tcp)
          # Format: 0100007F means 127.0.0.1 (bytes reversed: 7F 00 00 01)
          if [ ${#LOCAL_HEX} -eq 8 ]; then
            LOCAL_IP=$(printf "%d.%d.%d.%d" 0x${LOCAL_HEX:6:2} 0x${LOCAL_HEX:4:2} 0x${LOCAL_HEX:2:2} 0x${LOCAL_HEX:0:2} 2>/dev/null || echo "unknown")
          else
            LOCAL_IP="unknown"
          fi
          LOCAL_PORT=$(printf "%d" 0x$LOCAL_PORT_HEX 2>/dev/null || echo "unknown")
          if [ ${#REMOTE_HEX} -eq 8 ]; then
            REMOTE_IP=$(printf "%d.%d.%d.%d" 0x${REMOTE_HEX:6:2} 0x${REMOTE_HEX:4:2} 0x${REMOTE_HEX:2:2} 0x${REMOTE_HEX:0:2} 2>/dev/null || echo "unknown")
          else
            REMOTE_IP="unknown"
          fi
          REMOTE_PORT=$(printf "%d" 0x$REMOTE_PORT_HEX 2>/dev/null || echo "unknown")
          
          # Map state codes
          case "$STATE" in
            01) STATE_NAME="ESTABLISHED" ;;
            0A) STATE_NAME="LISTEN" ;;
            02) STATE_NAME="SYN_SENT" ;;
            03) STATE_NAME="SYN_RECV" ;;
            04) STATE_NAME="FIN_WAIT1" ;;
            05) STATE_NAME="FIN_WAIT2" ;;
            06) STATE_NAME="TIME_WAIT" ;;
            07) STATE_NAME="CLOSE" ;;
            08) STATE_NAME="CLOSE_WAIT" ;;
            09) STATE_NAME="LAST_ACK" ;;
            *) STATE_NAME="STATE_$STATE" ;;
          esac
          
          # Only output if we successfully parsed the IP
          if [ "$LOCAL_IP" != "unknown" ] && [ "$LOCAL_PORT" != "unknown" ]; then
            if [ "$STATE" = "0A" ] || [ "$STATE" = "0a" ]; then
              echo "  - LISTEN: $LOCAL_IP:$LOCAL_PORT" >> "$CONN_TMP"
            elif [ "$REMOTE_IP" != "unknown" ] && [ "$REMOTE_PORT" != "unknown" ]; then
              # Try to determine if this is likely an inbound or outbound connection
              # Inbound: remote IP connects TO pod's local port
              # Outbound: pod connects FROM local port TO remote IP
              # We can't definitively tell from /proc/net/tcp, but we can note VPC IPs
              if echo "$REMOTE_IP" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
                # Remote is in private IP range (likely VPC/internal)
                echo "  - $STATE_NAME: $LOCAL_IP:$LOCAL_PORT <-> $REMOTE_IP:$REMOTE_PORT (VPC/internal)" >> "$CONN_TMP"
              else
                # Remote is public IP (likely outbound)
                echo "  - $STATE_NAME: $LOCAL_IP:$LOCAL_PORT -> $REMOTE_IP:$REMOTE_PORT (external)" >> "$CONN_TMP"
              fi
            else
              echo "  - $STATE_NAME: $LOCAL_IP:$LOCAL_PORT -> (connecting...)" >> "$CONN_TMP"
            fi
          fi
        done
        [ -s "$CONN_TMP" ] && cat "$CONN_TMP" >> "$REPORT" 2>/dev/null || true
        rm -f "$CONN_TMP" 2>/dev/null || true
        
        TOTAL_CONN=$(grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
        if [ "$TOTAL_CONN" -gt 10 ]; then
          say "[INFO] ... (see pod_connections.txt for full connection list)"
        fi
      else
        say "[INFO] No active connections detected"
      fi
      
      # Check for SYN_SENT connections (pod trying to connect but waiting for ACK)
      # Only show if count is greater than 0 (handle numeric comparison)
      if [ -n "$SYN_SENT_COUNT" ] && [ "$SYN_SENT_COUNT" != "0" ] && [ "$SYN_SENT_COUNT" -gt 0 ] 2>/dev/null; then
        echo >> "$REPORT"
        say "[ISSUE] Found $SYN_SENT_COUNT connection(s) in SYN_SENT state (pod sending SYN but waiting for ACK - potential connectivity issue)"
        SYN_SENT_TMP=$(mktemp)
        # Filter for lines with state 02 (SYN_SENT)
        grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | awk '$4 == "02" || $4 == "2"' | while read line; do
          LOCAL_HEX=$(echo "$line" | awk '{print $2}' | cut -d: -f1)
          LOCAL_PORT_HEX=$(echo "$line" | awk '{print $2}' | cut -d: -f2)
          REMOTE_HEX=$(echo "$line" | awk '{print $3}' | cut -d: -f1)
          REMOTE_PORT_HEX=$(echo "$line" | awk '{print $3}' | cut -d: -f2)
          
          if [ ${#LOCAL_HEX} -eq 8 ]; then
            LOCAL_IP=$(printf "%d.%d.%d.%d" 0x${LOCAL_HEX:6:2} 0x${LOCAL_HEX:4:2} 0x${LOCAL_HEX:2:2} 0x${LOCAL_HEX:0:2} 2>/dev/null || echo "unknown")
          else
            LOCAL_IP="unknown"
          fi
          LOCAL_PORT=$(printf "%d" 0x$LOCAL_PORT_HEX 2>/dev/null || echo "unknown")
          if [ ${#REMOTE_HEX} -eq 8 ]; then
            REMOTE_IP=$(printf "%d.%d.%d.%d" 0x${REMOTE_HEX:6:2} 0x${REMOTE_HEX:4:2} 0x${REMOTE_HEX:2:2} 0x${REMOTE_HEX:0:2} 2>/dev/null || echo "unknown")
          else
            REMOTE_IP="unknown"
          fi
          REMOTE_PORT=$(printf "%d" 0x$REMOTE_PORT_HEX 2>/dev/null || echo "unknown")
          
          if [ "$REMOTE_IP" != "unknown" ] && [ "$REMOTE_PORT" != "unknown" ]; then
            # Determine connection type
            if echo "$REMOTE_IP" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
              echo "  - $LOCAL_IP:$LOCAL_PORT -> $REMOTE_IP:$REMOTE_PORT (VPC/internal - cannot connect)" >> "$SYN_SENT_TMP"
            else
              echo "  - $LOCAL_IP:$LOCAL_PORT -> $REMOTE_IP:$REMOTE_PORT (external - cannot connect)" >> "$SYN_SENT_TMP"
            fi
          fi
        done
        [ -s "$SYN_SENT_TMP" ] && cat "$SYN_SENT_TMP" >> "$REPORT" 2>/dev/null || true
        rm -f "$SYN_SENT_TMP" 2>/dev/null || true
      fi
    else
      # ss or netstat format
      LISTEN_COUNT=$(grep -iE "listen|0\.0\.0\.0|:::" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
      ESTAB_COUNT=$(grep -iE "established|estab" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
      SYN_SENT_COUNT=$(grep -iE "syn-sent|syn_sent" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
      
      if [ "$LISTEN_COUNT" != "0" ] || [ "$ESTAB_COUNT" != "0" ]; then
        say "[INFO] Listening ports: $LISTEN_COUNT | Established connections: $ESTAB_COUNT"
        # Show first 10 non-header lines
        grep -v "^---" "$POD_CONNECTIONS" 2>/dev/null | head -10 | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
        TOTAL_LINES=$(grep -v "^---" "$POD_CONNECTIONS" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
        if [ "$TOTAL_LINES" -gt 10 ]; then
          say "[INFO] ... (see pod_connections.txt for full connection list)"
        fi
      else
        say "[INFO] No active connections detected"
      fi
      
      # Check for SYN_SENT connections (ss/netstat format)
      # Only show if count is greater than 0 (handle numeric comparison)
      if [ -n "$SYN_SENT_COUNT" ] && [ "$SYN_SENT_COUNT" != "0" ] && [ "$SYN_SENT_COUNT" -gt 0 ] 2>/dev/null; then
        echo >> "$REPORT"
        say "[ISSUE] Found $SYN_SENT_COUNT connection(s) in SYN_SENT state (pod sending SYN but waiting for ACK - potential connectivity issue)"
        grep -iE "syn-sent|syn_sent" "$POD_CONNECTIONS" 2>/dev/null | grep -v "^---" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
      fi
    fi
  fi
fi

# Conntrack connections (from node, filtered by pod IP)
# Conntrack shows both directions: connections TO the pod (inbound) and FROM the pod (outbound)
# This is the best way to see all connections involving the pod, including inbound connections
if [ -s "$POD_CONNTRACK" ]; then
  # Get pod IP for direction detection (set it here if not already set)
  if [ -z "${POD_IP:-}" ]; then
    POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
  fi
  
  # Get node pod IPs for same-node vs cross-node analysis
  NODE_POD_IPS=""
  if [ -n "$NODE_DIR" ] && [ -f "$NODE_DIR/node_pod_ips.txt" ]; then
    NODE_POD_IPS="$NODE_DIR/node_pod_ips.txt"
  fi
  
  # Count non-empty, non-whitespace lines
  CONNTRACK_COUNT=$(grep -v '^[[:space:]]*$' "$POD_CONNTRACK" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$CONNTRACK_COUNT" -gt 0 ]; then
    echo >> "$REPORT"
    say "[INFO] Connections tracked by conntrack (node-level, filtered by pod IP - shows both inbound TO pod and outbound FROM pod): $CONNTRACK_COUNT connection(s)"
    
    # Count inbound vs outbound if we have pod IP
    # Note: We count based on the FIRST src/dst pair (original direction) to avoid double-counting
    # Each conntrack entry has both original and reply directions, so we only look at the first match
    INBOUND_COUNT=0
    OUTBOUND_COUNT=0
    if [ -n "$POD_IP" ]; then
      # Count connections where pod IP is the destination in the first src/dst pair (inbound)
      INBOUND_COUNT=$(grep -v '^[[:space:]]*$' "$POD_CONNTRACK" 2>/dev/null | grep -oE "src=[0-9.]+[[:space:]]+dst=${POD_IP}[[:space:]]" | wc -l | tr -d '[:space:]' || echo "0")
      # Count connections where pod IP is the source in the first src/dst pair (outbound)
      OUTBOUND_COUNT=$(grep -v '^[[:space:]]*$' "$POD_CONNTRACK" 2>/dev/null | grep -oE "src=${POD_IP}[[:space:]]+dst=[0-9.]+[[:space:]]" | wc -l | tr -d '[:space:]' || echo "0")
    fi
    
    if [ "$INBOUND_COUNT" -gt 0 ] || [ "$OUTBOUND_COUNT" -gt 0 ]; then
      say "[INFO]   Inbound (TO pod): $INBOUND_COUNT | Outbound (FROM pod): $OUTBOUND_COUNT"
    fi
    
    # Show non-empty lines only, format for readability
    CONN_TMP=$(mktemp)
    # Use process substitution to avoid subshell issues with while read
    while IFS= read -r line || [ -n "$line" ]; do
      [ -z "$line" ] && continue
      # Try to extract and format conntrack entry for better readability
      # Conntrack format: ipv4 2 tcp 6 <timeout> <STATE> src=... dst=... sport=... dport=... src=... dst=... sport=... dport=...
      # The first src/dst pair is the original direction, second is the reply
      if echo "$line" | grep -qE "src=|dst="; then
        # Extract first src/dst pair (original direction) - use head -1 to get only the first match
        SRC=$(echo "$line" | grep -oE "src=[0-9.]+" | head -1 | cut -d= -f2 || echo "")
        DST=$(echo "$line" | grep -oE "dst=[0-9.]+" | head -1 | cut -d= -f2 || echo "")
        SPORT=$(echo "$line" | grep -oE "sport=[0-9]+" | head -1 | cut -d= -f2 || echo "")
        DPORT=$(echo "$line" | grep -oE "dport=[0-9]+" | head -1 | cut -d= -f2 || echo "")
        # State is usually a field before the src=, extract it
        STATE=$(echo "$line" | grep -oE "[[:space:]](ESTABLISHED|CLOSE|TIME_WAIT|SYN_SENT|SYN_RECV|FIN_WAIT1|FIN_WAIT2|CLOSE_WAIT|LAST_ACK|LISTEN)[[:space:]]" | tr -d '[:space:]' || echo "")
        if [ -z "$STATE" ]; then
          # Try alternative format where state might be after protocol
          STATE=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(ESTABLISHED|CLOSE|TIME_WAIT|SYN_SENT|SYN_RECV|FIN_WAIT1|FIN_WAIT2|CLOSE_WAIT|LAST_ACK|LISTEN)$/) {print $i; exit}}' || echo "")
        fi
        if [ -n "$SRC" ] && [ -n "$DST" ] && [ -n "$SPORT" ] && [ -n "$DPORT" ]; then
          # Determine if connection is same-node or cross-node
          REMOTE_IP=""
          NODE_TYPE=""
          if [ -n "$POD_IP" ] && echo "$DST" | grep -q "^${POD_IP}$"; then
            # Connection TO pod (inbound) - remote is SRC
            REMOTE_IP="$SRC"
            DIRECTION="INBOUND"
          elif [ -n "$POD_IP" ] && echo "$SRC" | grep -q "^${POD_IP}$"; then
            # Connection FROM pod (outbound) - remote is DST
            REMOTE_IP="$DST"
            DIRECTION="OUTBOUND"
          else
            # Can't determine direction
            REMOTE_IP=""
            DIRECTION=""
          fi
          
          # Check if remote IP is on same node
          if [ -n "$REMOTE_IP" ] && [ -n "$NODE_POD_IPS" ] && [ -s "$NODE_POD_IPS" ]; then
            if grep -q "^${REMOTE_IP}$" "$NODE_POD_IPS" 2>/dev/null; then
              NODE_TYPE=" (same-node)"
            elif echo "$REMOTE_IP" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
              # VPC IP but not on this node = cross-node
              NODE_TYPE=" (cross-node)"
            else
              # External IP
              NODE_TYPE=" (external)"
            fi
          elif [ -n "$REMOTE_IP" ]; then
            # Can't determine node location
            if echo "$REMOTE_IP" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
              NODE_TYPE=" (VPC/internal)"
            else
              NODE_TYPE=" (external)"
            fi
          fi
          
          # Format output
          if [ -n "$DIRECTION" ]; then
            echo "  - ${DIRECTION}: $SRC:$SPORT -> $DST:$DPORT${NODE_TYPE}${STATE:+ ($STATE)}" >> "$CONN_TMP" 2>/dev/null || true
          else
            echo "  - $SRC:$SPORT <-> $DST:$DPORT${NODE_TYPE}${STATE:+ ($STATE)}" >> "$CONN_TMP" 2>/dev/null || true
          fi
        else
          # Fallback: show raw line
          echo "  - $line" >> "$CONN_TMP" 2>/dev/null || true
        fi
      else
        # Not standard conntrack format, show as-is
        echo "  - $line" >> "$CONN_TMP" 2>/dev/null || true
      fi
    done < <(grep -v '^[[:space:]]*$' "$POD_CONNTRACK" 2>/dev/null | head -10)
    [ -s "$CONN_TMP" ] && cat "$CONN_TMP" >> "$REPORT" 2>/dev/null || true
    rm -f "$CONN_TMP" 2>/dev/null || true
    
    if [ "$CONNTRACK_COUNT" -gt 10 ]; then
      say "[INFO] ... and $((CONNTRACK_COUNT - 10)) more connection(s) (see pod_conntrack_connections.txt)"
    fi
  fi
fi

# Log Files Summary (with error counts and file locations)
# Show summary of log files with errors, making it easy to find and review them
echo >> "$REPORT"
echo "## Log Files Summary" >> "$REPORT"

LOG_FILES_WITH_ERRORS=0

# Check aws-node errors log from pod diagnostics
if [ -s "$AWS_NODE_ERRORS" ]; then
  ERROR_COUNT=$(grep -v '^[[:space:]]*$' "$AWS_NODE_ERRORS" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$ERROR_COUNT" -gt 0 ]; then
    LOG_FILES_WITH_ERRORS=$((LOG_FILES_WITH_ERRORS + 1))
    REL_PATH=$(echo "$AWS_NODE_ERRORS" | sed "s|^$BUNDLE/||" || echo "$AWS_NODE_ERRORS")
    say "[ISSUE] aws_node_errors.log: $ERROR_COUNT error/warning line(s) - \`$REL_PATH\`"
  fi
fi

# Check aws-node full log from pod diagnostics
if [ -s "$AWS_NODE_LOG_POD" ]; then
  TOTAL_LINES=$(wc -l < "$AWS_NODE_LOG_POD" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$TOTAL_LINES" -gt 0 ]; then
    REL_PATH=$(echo "$AWS_NODE_LOG_POD" | sed "s|^$BUNDLE/||" || echo "$AWS_NODE_LOG_POD")
    say "[INFO] aws_node_full.log: $TOTAL_LINES line(s) - \`$REL_PATH\`"
  fi
fi

# Check CNI logs from node diagnostics
NODE_CNI_LOGS_DIR=""
if [ -n "$NODE_DIR" ]; then
  NODE_CNI_LOGS_DIR="$NODE_DIR/cni_logs"
fi

if [ -n "$NODE_CNI_LOGS_DIR" ] && [ -d "$NODE_CNI_LOGS_DIR" ]; then
  # Check each log file and its error summary
  for LOG_FILE in "$NODE_CNI_LOGS_DIR"/*.log; do
    [ ! -f "$LOG_FILE" ] && continue
    LOG_NAME=$(basename "$LOG_FILE")
    ERROR_FILE="${LOG_FILE}.errors"
    
    # Count total lines in log file
    TOTAL_LINES=$(wc -l < "$LOG_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
    
    # Count errors if error file exists
    ERROR_COUNT=0
    if [ -f "$ERROR_FILE" ] && [ -s "$ERROR_FILE" ]; then
      ERROR_COUNT=$(grep -v '^[[:space:]]*$' "$ERROR_FILE" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    fi
    
    if [ "$TOTAL_LINES" -gt 0 ] || [ "$ERROR_COUNT" -gt 0 ]; then
      REL_PATH=$(echo "$LOG_FILE" | sed "s|^$BUNDLE/||" || echo "$LOG_FILE")
      if [ "$ERROR_COUNT" -gt 0 ]; then
        LOG_FILES_WITH_ERRORS=$((LOG_FILES_WITH_ERRORS + 1))
        say "[ISSUE] $LOG_NAME: $ERROR_COUNT error/warning line(s) (of $TOTAL_LINES total) - \`$REL_PATH\`"
      else
        say "[INFO] $LOG_NAME: $TOTAL_LINES line(s) (no errors) - \`$REL_PATH\`"
      fi
    fi
  done
fi

# Check node-level aws-node logs
NODE_AWS_LOG="${NODE_DIR:+$NODE_DIR/aws_node_full.log}"
if [ -n "$NODE_AWS_LOG" ] && [ -s "$NODE_AWS_LOG" ]; then
  TOTAL_LINES=$(wc -l < "$NODE_AWS_LOG" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$TOTAL_LINES" -gt 0 ]; then
    REL_PATH=$(echo "$NODE_AWS_LOG" | sed "s|^$BUNDLE/||" || echo "$NODE_AWS_LOG")
    say "[INFO] aws_node_full.log (node): $TOTAL_LINES line(s) - \`$REL_PATH\`"
  fi
fi

if [ "$LOG_FILES_WITH_ERRORS" -eq 0 ]; then
  say "[OK] No log files with errors found"
fi

# Optional: Show related log lines if SHOW_RELATED_LOGS environment variable is set
if [ "${SHOW_RELATED_LOGS:-}" = "1" ] || [ "${SHOW_RELATED_LOGS:-}" = "true" ]; then
  echo >> "$REPORT"
  echo "### Related Log Lines (pod-specific)" >> "$REPORT"
  say "[INFO] Showing related log lines (set SHOW_RELATED_LOGS=1 to enable)"
  
  # Collect pod identifiers for matching
  POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
  POD_UID=$(grep "^UID=" "$POD_TIMING" 2>/dev/null | cut -d= -f2- || echo "")
  ENI_ID=$(cat "$POD_ENI_ID" 2>/dev/null | tr -d '[:space:]' || echo "")
  
  # Extract container ID from pod status (infra/pause container)
  CONTAINER_ID=""
  if [ -s "$POD_FULL" ]; then
    CONTAINER_ID=$(jq -r '.status.containerStatuses[]? | select(.name | test("POD|infra|pause")) | .containerID // empty' "$POD_FULL" 2>/dev/null | head -1 || echo "")
    if [ -z "$CONTAINER_ID" ] || [ "$CONTAINER_ID" = "null" ] || [ "$CONTAINER_ID" = "" ]; then
      CONTAINER_ID=$(jq -r '.status.containerStatuses[0]? | .containerID // empty' "$POD_FULL" 2>/dev/null | head -1 || echo "")
    fi
    # Remove container runtime prefix
    if [ -n "$CONTAINER_ID" ] && [ "$CONTAINER_ID" != "null" ] && [ "$CONTAINER_ID" != "" ]; then
      CONTAINER_ID=$(echo "$CONTAINER_ID" | sed 's|^[^:]*://||' || echo "$CONTAINER_ID")
    fi
  fi
  
  # Short container ID (first 12 chars, commonly used in logs)
  CONTAINER_ID_SHORT=""
  if [ -n "$CONTAINER_ID" ] && [ "$CONTAINER_ID" != "null" ] && [ "$CONTAINER_ID" != "" ]; then
    CONTAINER_ID_SHORT=$(echo "$CONTAINER_ID" | head -c 12 || echo "")
  fi
  
  RELATED_LOGS_FOUND=0
  RELATED_LOGS_TMP=$(mktemp)
  
  # Search aws-node logs from pod diagnostics
  if [ -s "$AWS_NODE_LOG_POD" ]; then
    {
      [ -n "$POD" ] && grep -i "$POD" "$AWS_NODE_LOG_POD" 2>/dev/null || true
      [ -n "$CONTAINER_ID" ] && grep -i "$CONTAINER_ID" "$AWS_NODE_LOG_POD" 2>/dev/null || true
      [ -n "$CONTAINER_ID_SHORT" ] && grep -i "$CONTAINER_ID_SHORT" "$AWS_NODE_LOG_POD" 2>/dev/null || true
      [ -n "$ENI_ID" ] && grep -i "$ENI_ID" "$AWS_NODE_LOG_POD" 2>/dev/null || true
      [ -n "$POD_IP" ] && grep -i "$POD_IP" "$AWS_NODE_LOG_POD" 2>/dev/null || true
      [ -n "$POD_UID" ] && grep -i "$POD_UID" "$AWS_NODE_LOG_POD" 2>/dev/null || true
    } | sort -u > "$RELATED_LOGS_TMP" 2>/dev/null || true
    
    if [ -s "$RELATED_LOGS_TMP" ]; then
      RELATED_LOGS_FOUND=1
      say "[INFO] Related lines from aws-node logs:"
      head -20 "$RELATED_LOGS_TMP" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
      TOTAL_LINES=$(wc -l < "$RELATED_LOGS_TMP" 2>/dev/null | tr -d '[:space:]' || echo "0")
      if [ "$TOTAL_LINES" -gt 20 ]; then
        say "[INFO] ... and $((TOTAL_LINES - 20)) more line(s)"
      fi
    fi
  fi
  
  # Search CNI logs from node diagnostics
  if [ -n "$NODE_CNI_LOGS_DIR" ] && [ -d "$NODE_CNI_LOGS_DIR" ]; then
    for CNI_LOG in "$NODE_CNI_LOGS_DIR"/*.log; do
      [ ! -f "$CNI_LOG" ] && continue
      LOG_NAME=$(basename "$CNI_LOG")
      
      {
        [ -n "$POD" ] && grep -i "$POD" "$CNI_LOG" 2>/dev/null || true
        [ -n "$CONTAINER_ID" ] && grep -i "$CONTAINER_ID" "$CNI_LOG" 2>/dev/null || true
        [ -n "$CONTAINER_ID_SHORT" ] && grep -i "$CONTAINER_ID_SHORT" "$CNI_LOG" 2>/dev/null || true
        [ -n "$ENI_ID" ] && grep -i "$ENI_ID" "$CNI_LOG" 2>/dev/null || true
        [ -n "$POD_IP" ] && grep -i "$POD_IP" "$CNI_LOG" 2>/dev/null || true
        [ -n "$POD_UID" ] && grep -i "$POD_UID" "$CNI_LOG" 2>/dev/null || true
      } | sort -u > "$RELATED_LOGS_TMP" 2>/dev/null || true
      
      if [ -s "$RELATED_LOGS_TMP" ]; then
        if [ "$RELATED_LOGS_FOUND" -eq 0 ]; then
          RELATED_LOGS_FOUND=1
        fi
        say "[INFO] Related lines from $LOG_NAME:"
        head -15 "$RELATED_LOGS_TMP" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
        TOTAL_LINES=$(wc -l < "$RELATED_LOGS_TMP" 2>/dev/null | tr -d '[:space:]' || echo "0")
        if [ "$TOTAL_LINES" -gt 15 ]; then
          say "[INFO] ... and $((TOTAL_LINES - 15)) more line(s) from $LOG_NAME"
        fi
      fi
    done
  fi
  
  # Search node-level aws-node logs
  if [ -n "$NODE_AWS_LOG" ] && [ -s "$NODE_AWS_LOG" ]; then
    {
      [ -n "$POD" ] && grep -i "$POD" "$NODE_AWS_LOG" 2>/dev/null || true
      [ -n "$CONTAINER_ID" ] && grep -i "$CONTAINER_ID" "$NODE_AWS_LOG" 2>/dev/null || true
      [ -n "$CONTAINER_ID_SHORT" ] && grep -i "$CONTAINER_ID_SHORT" "$NODE_AWS_LOG" 2>/dev/null || true
      [ -n "$ENI_ID" ] && grep -i "$ENI_ID" "$NODE_AWS_LOG" 2>/dev/null || true
      [ -n "$POD_IP" ] && grep -i "$POD_IP" "$NODE_AWS_LOG" 2>/dev/null || true
      [ -n "$POD_UID" ] && grep -i "$POD_UID" "$NODE_AWS_LOG" 2>/dev/null || true
    } | sort -u > "$RELATED_LOGS_TMP" 2>/dev/null || true
    
    if [ -s "$RELATED_LOGS_TMP" ]; then
      if [ "$RELATED_LOGS_FOUND" -eq 0 ]; then
        RELATED_LOGS_FOUND=1
      fi
      say "[INFO] Related lines from aws-node logs (node):"
      head -20 "$RELATED_LOGS_TMP" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
      TOTAL_LINES=$(wc -l < "$RELATED_LOGS_TMP" 2>/dev/null | tr -d '[:space:]' || echo "0")
      if [ "$TOTAL_LINES" -gt 20 ]; then
        say "[INFO] ... and $((TOTAL_LINES - 20)) more line(s)"
      fi
    fi
  fi
  
  if [ "$RELATED_LOGS_FOUND" -eq 0 ]; then
    say "[INFO] No related log lines found"
  fi
  
  rm -f "$RELATED_LOGS_TMP" 2>/dev/null || true
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
      ERROR_COUNT=$(grep -v '^[[:space:]]*$' "$ERROR_FILE" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
      if [ "$ERROR_COUNT" -gt 0 ]; then
        say "[ISSUE] $LOG_NAME: $ERROR_COUNT error/warning line(s)"
        CNI_ERRORS_FOUND=$((CNI_ERRORS_FOUND + 1))
        # Show recent errors (limit to 2 to keep it concise)
        tail -2 "$ERROR_FILE" | sed 's/^/    /' >> "$REPORT" 2>/dev/null || true
      fi
    fi
  done
  
  if [ "$CNI_ERRORS_FOUND" -eq 0 ]; then
    say "[OK] No errors found in node CNI logs"
  fi
  
  # List available log files count
  LOG_FILES=$(ls -1 "$NODE_CNI_LOGS_DIR"/*.log 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$LOG_FILES" -gt 0 ]; then
    say "[INFO] Collected $LOG_FILES CNI log file(s) (see Log Files Summary for details)"
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

# MTU configuration
if [ -n "$NODE_DIR" ] && [ -s "$NODE_DIR/node_interface_ip_stats.txt" ]; then
  echo >> "$REPORT"
  MTU_TMP=$(mktemp)
  # Extract MTU from non-loopback interfaces
  grep -E "^[0-9]+:" "$NODE_DIR/node_interface_ip_stats.txt" 2>/dev/null | grep -v " lo:" | grep -oE "mtu [0-9]+" | sed 's/mtu //' | sort -u > "$MTU_TMP" || true
  
  if [ -s "$MTU_TMP" ]; then
    MTU_COUNT=$(wc -l < "$MTU_TMP" | tr -d '[:space:]' || echo "0")
    MTU_VALUES=$(cat "$MTU_TMP" | tr '\n' ',' | sed 's/,$//')
    
    if [ "$MTU_COUNT" -gt 1 ]; then
      say "[WARN] Multiple MTU values found on node interfaces: $MTU_VALUES"
      # Show interface breakdown
      grep -E "^[0-9]+:" "$NODE_DIR/node_interface_ip_stats.txt" 2>/dev/null | grep -v " lo:" | grep -oE "^[0-9]+:[^:]+:.*mtu [0-9]+" | head -5 | sed 's/^/    /' >> "$REPORT" 2>/dev/null || true
    else
      MTU_VALUE=$(cat "$MTU_TMP" | head -1 | tr -d '[:space:]' || echo "")
      if [ -n "$MTU_VALUE" ]; then
        if [ "$MTU_VALUE" = "1500" ]; then
          say "[OK] Standard MTU (1500) on all interfaces"
        elif [ "$MTU_VALUE" = "9001" ]; then
          say "[OK] Jumbo frames enabled (MTU 9001)"
        else
          say "[INFO] MTU: $MTU_VALUE on all interfaces"
        fi
      fi
    fi
    
    # Check pod MTU if available
    if [ -s "$POD_DIR/pod_interface_stats.txt" ] && ! grep -qi "not available\|command failed" "$POD_DIR/pod_interface_stats.txt" 2>/dev/null; then
      POD_MTU_TMP=$(mktemp)
      grep -oE "mtu [0-9]+" "$POD_DIR/pod_interface_stats.txt" 2>/dev/null | sed 's/mtu //' | sort -u > "$POD_MTU_TMP" || true
      if [ -s "$POD_MTU_TMP" ]; then
        POD_MTU=$(cat "$POD_MTU_TMP" | head -1 | tr -d '[:space:]' || echo "")
        if [ -n "$POD_MTU" ] && [ -s "$MTU_TMP" ]; then
          NODE_MTU=$(cat "$MTU_TMP" | head -1 | tr -d '[:space:]' || echo "")
          if [ -n "$NODE_MTU" ] && [ "$POD_MTU" != "$NODE_MTU" ]; then
            say "[ISSUE] MTU mismatch: pod ($POD_MTU) != node ($NODE_MTU) - may cause fragmentation"
          fi
        fi
      fi
      rm -f "$POD_MTU_TMP" 2>/dev/null || true
    fi
    
    # Check for fragmentation hints in kernel logs
    if [ -s "$NODE_DIR/node_dmesg_network.txt" ]; then
      FRAG_HINTS=$(grep -iE "fragmentation needed|frag.*drop|mtu.*exceed" "$NODE_DIR/node_dmesg_network.txt" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
      if [ "$FRAG_HINTS" != "0" ] && [ "$FRAG_HINTS" -gt 0 ]; then
        say "[ISSUE] Found $FRAG_HINTS fragmentation-related message(s) in kernel logs"
      fi
    fi
  fi
  rm -f "$MTU_TMP" 2>/dev/null || true
fi

# iptables rules summary
if [ -n "$NODE_DIR" ]; then
  NODE_IPTABLES_FILTER="${NODE_DIR}/node_iptables_filter.txt"
  NODE_IPTABLES_NAT="${NODE_DIR}/node_iptables_nat.txt"
  
  if [ -s "$NODE_IPTABLES_FILTER" ] || [ -s "$NODE_IPTABLES_NAT" ]; then
    echo >> "$REPORT"
    say "[INFO] iptables rules collected:"
    
    if [ -s "$NODE_IPTABLES_FILTER" ]; then
      # Count chains and rules (lines starting with Chain or rule lines with packet counts)
      # iptables -L -n -v format: "Chain CHAIN_NAME (policy ...)" or "    pkts bytes target     prot opt in     out     source               destination"
      FILTER_CHAINS=$(grep -c "^Chain" "$NODE_IPTABLES_FILTER" 2>/dev/null | tr -d '[:space:]' || echo "0")
      # Count rule lines (lines that start with spaces and have numbers in first column, but not empty lines or headers)
      FILTER_RULES=$(grep -E "^[[:space:]]+[0-9]+" "$NODE_IPTABLES_FILTER" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
      if [ -n "$FILTER_CHAINS" ] && [ -n "$FILTER_RULES" ] && ([ "$FILTER_CHAINS" != "0" ] || [ "$FILTER_RULES" != "0" ]); then
        say "  - Filter table: $FILTER_CHAINS chain(s), $FILTER_RULES rule(s) - \`node_*/node_iptables_filter.txt\`"
      else
        say "  - Filter table: collected (see \`node_*/node_iptables_filter.txt\`)"
      fi
    else
      say "  - Filter table: not available"
    fi
    
    if [ -s "$NODE_IPTABLES_NAT" ]; then
      NAT_CHAINS=$(grep -c "^Chain" "$NODE_IPTABLES_NAT" 2>/dev/null | tr -d '[:space:]' || echo "0")
      NAT_RULES=$(grep -E "^[[:space:]]+[0-9]+" "$NODE_IPTABLES_NAT" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
      if [ -n "$NAT_CHAINS" ] && [ -n "$NAT_RULES" ] && ([ "$NAT_CHAINS" != "0" ] || [ "$NAT_RULES" != "0" ]); then
        say "  - NAT table: $NAT_CHAINS chain(s), $NAT_RULES rule(s) - \`node_*/node_iptables_nat.txt\`"
      else
        say "  - NAT table: collected (see \`node_*/node_iptables_nat.txt\`)"
      fi
    else
      say "  - NAT table: not available"
    fi
    
    # Check for pod-specific iptables rules
    POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
    VETH_NAME=$(cat "$POD_VETH" 2>/dev/null | tr -d '[:space:]' || echo "")
    
    if [ -n "$POD_IP" ] && [ "$POD_IP" != "unknown" ]; then
      POD_IPTABLES_FOUND=0
      POD_IPTABLES_TMP=$(mktemp)
      
      # Search for pod IP in iptables rules
      if [ -s "$NODE_IPTABLES_FILTER" ]; then
        grep -i "$POD_IP" "$NODE_IPTABLES_FILTER" 2>/dev/null | head -5 > "$POD_IPTABLES_TMP" || true
        if [ -s "$POD_IPTABLES_TMP" ]; then
          POD_IPTABLES_FOUND=1
        fi
      fi
      if [ -s "$NODE_IPTABLES_NAT" ]; then
        grep -i "$POD_IP" "$NODE_IPTABLES_NAT" 2>/dev/null | head -5 >> "$POD_IPTABLES_TMP" || true
        if [ -s "$POD_IPTABLES_TMP" ]; then
          POD_IPTABLES_FOUND=1
        fi
      fi
      
      # Also check for veth interface name if available
      if [ -n "$VETH_NAME" ] && [ "$VETH_NAME" != "unknown" ]; then
        if [ -s "$NODE_IPTABLES_FILTER" ]; then
          grep -i "$VETH_NAME" "$NODE_IPTABLES_FILTER" 2>/dev/null | head -3 >> "$POD_IPTABLES_TMP" || true
        fi
        if [ -s "$NODE_IPTABLES_NAT" ]; then
          grep -i "$VETH_NAME" "$NODE_IPTABLES_NAT" 2>/dev/null | head -3 >> "$POD_IPTABLES_TMP" || true
        fi
      fi
      
      # Count total matches
      POD_RULE_COUNT=$(grep -v '^[[:space:]]*$' "$POD_IPTABLES_TMP" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
      
      if [ "$POD_RULE_COUNT" -gt 0 ]; then
        say "[OK] Found $POD_RULE_COUNT iptables rule(s) matching pod IP $POD_IP"
        # Show a few example rules
        if [ "$POD_RULE_COUNT" -le 5 ]; then
          grep -v '^[[:space:]]*$' "$POD_IPTABLES_TMP" 2>/dev/null | head -3 | sed 's/^/    /' >> "$REPORT" 2>/dev/null || true
        else
          grep -v '^[[:space:]]*$' "$POD_IPTABLES_TMP" 2>/dev/null | head -2 | sed 's/^/    /' >> "$REPORT" 2>/dev/null || true
          say "    ... and $((POD_RULE_COUNT - 2)) more rule(s) (see iptables files for full details)"
        fi
      else
        say "[INFO] No iptables rules found matching pod IP $POD_IP (may be normal if no network policies apply)"
      fi
      
      rm -f "$POD_IPTABLES_TMP" 2>/dev/null || true
    fi
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
  ERROR_COUNT=0
  if [ -f "$API_DIAG_DIR/eni_errors.tsv" ]; then
    ERROR_COUNT=$(wc -l < "$API_DIAG_DIR/eni_errors.tsv" 2>/dev/null | tr -d '[:space:]' || echo "0")
  fi
  
  if [ "$ERROR_COUNT" -gt 0 ]; then
    say "[ISSUE] Found $ERROR_COUNT real error/throttle event(s) in CloudTrail"
    # Show recent errors
    head -5 "$API_DIAG_DIR/eni_errors.tsv" | awk -F'\t' '{printf "  - %s: %s (%s)\n", $2, $5, $6}' >> "$REPORT" 2>/dev/null || true
  else
    say "[OK] No real errors/throttles found in CloudTrail"
  fi
  
  # Show throttle summary by action
  if [ -s "$API_DIAG_DIR/throttle_by_action.txt" ]; then
    THROTTLE_COUNT=$(wc -l < "$API_DIAG_DIR/throttle_by_action.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$THROTTLE_COUNT" -gt 0 ]; then
      say "[INFO] Throttles by action:"
      head -5 "$API_DIAG_DIR/throttle_by_action.txt" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
    fi
  fi
  
  # Show API calls by user/caller
  if [ -s "$API_DIAG_DIR/calls_by_user.txt" ]; then
    USER_COUNT=$(wc -l < "$API_DIAG_DIR/calls_by_user.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [ "$USER_COUNT" -gt 0 ]; then
      say "[INFO] API calls by user/caller:"
      head -10 "$API_DIAG_DIR/calls_by_user.txt" | sed 's/^/  - /' >> "$REPORT" 2>/dev/null || true
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

# Commands to view related logs
echo >> "$REPORT"
echo "## View Related Logs" >> "$REPORT"
say "[INFO] Use the helper script to view pod-specific log lines from the collected bundle:"
echo "" >> "$REPORT"
echo "\`\`\`bash" >> "$REPORT"
echo "# View all pod-related log lines" >> "$REPORT"
echo "./sgfp_view_logs.sh \"$BUNDLE\"" >> "$REPORT"
echo "" >> "$REPORT"
echo "# View only errors/warnings" >> "$REPORT"
echo "./sgfp_view_logs.sh \"$BUNDLE\" --errors-only" >> "$REPORT"
echo "" >> "$REPORT"
echo "# View all log lines (not filtered)" >> "$REPORT"
echo "./sgfp_view_logs.sh \"$BUNDLE\" --all-logs" >> "$REPORT"
echo "\`\`\`" >> "$REPORT"

echo >> "$REPORT"
echo "---" >> "$REPORT"
echo "_Report generated by sgfp_report.sh_" >> "$REPORT"

echo "[REPORT] Report written to: $REPORT"
