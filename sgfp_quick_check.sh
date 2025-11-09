#!/usr/bin/env bash
set -euo pipefail

# Quick check script for pod ENI status
# Provides a basic summary without full diagnostic collection

SHOW_CONNECTIONS=0
NS="default"

log()  { printf "[QUICK] %s\n" "$*"; }
warn() { printf "[QUICK] WARN: %s\n" "$*" >&2; }
err()  { printf "[QUICK] ERROR: %s\n" "$*" >&2; }

# Parse arguments (similar to sgfp_collect.sh and sgfp_doctor.sh)
while [ $# -gt 0 ]; do
  case "$1" in
    --connections|-c)
      SHOW_CONNECTIONS=1
      shift
      ;;
    -n|--namespace)
      NS="${2:?}"
      shift 2
      ;;
    --help|-h)
      echo "Usage: $0 [options] <pod-name>" >&2
      echo "" >&2
      echo "Options:" >&2
      echo "  -n, --namespace <ns>  Namespace (default: default)" >&2
      echo "  --connections, -c     Show current network connections" >&2
      echo "  --help, -h            Show this help message" >&2
      exit 0
      ;;
    *)
      # First positional argument is pod name
      if [ -z "${POD:-}" ]; then
        POD="$1"
        shift
      else
        err "Too many arguments"
        exit 1
      fi
      ;;
  esac
done

if [ -z "${POD:-}" ]; then
  echo "Usage: $0 [options] <pod-name>" >&2
  echo "" >&2
  echo "Options:" >&2
  echo "  -n, --namespace <ns>  Namespace (default: default)" >&2
  echo "  --connections, -c     Show current network connections" >&2
  echo "  --help, -h            Show this help message" >&2
  exit 1
fi

# Detect shell in pod (similar to sgfp_pod_diag.sh)
detect_shell() {
  local pod="$1"
  local ns="$2"
  for shell in sh /bin/sh /bin/bash bash; do
    if kubectl -n "$ns" exec "$pod" -- "$shell" -c 'true' >/dev/null 2>&1; then
      echo "$shell"
      return 0
    fi
  done
  echo ""
}

for cmd in kubectl jq aws; do 
  command -v "$cmd" >/dev/null || { err "Missing dependency: $cmd"; exit 1; }
done

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [ -z "$REGION" ]; then 
  REGION="$(aws configure get region 2>/dev/null || true)"
fi
if [ -z "$REGION" ]; then 
  err "No AWS region. Set AWS_REGION (e.g., us-west-2)."
  exit 1
fi

log "Checking pod $NS/$POD"

# Get pod ENI annotation
ANN_JSON=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/pod-eni}' 2>/dev/null || echo "")
POD_IP=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")
SG_REQ=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/security-groups}' 2>/dev/null || echo "")

if [ -z "$ANN_JSON" ] || [ "$ANN_JSON" = "true" ]; then
  err "Pod ENI status annotation missing or only shows request=true"
  err "=> SGP not confirmed by status; check aws-node logs"
  exit 1
fi

# Normalize to JSON array (some CNI versions emit a single object)
if [ "${ANN_JSON:0:1}" != "[" ]; then 
  ANN_JSON="[$ANN_JSON]"
fi

ENI_ID=$(echo "$ANN_JSON" | jq -r '.[0].eniId // empty')
ASSOC_ID=$(echo "$ANN_JSON" | jq -r '.[0].associationID // empty')
IP_IN_ANN=$(echo "$ANN_JSON" | jq -r '.[0].privateIp // empty')

echo ""
echo "=== Pod ENI Status ==="
echo "Pod IP:            $POD_IP"
echo "CNI status IP:     $IP_IN_ANN"
echo "Branch ENI ID:     $ENI_ID"
[ -n "$ASSOC_ID" ] && echo "Trunk Assoc ID:    $ASSOC_ID"
if [ -n "$SG_REQ" ]; then
  echo "Requested SGs:"
  # Display one SG per line
  echo "$SG_REQ" | tr ',' '\n' | tr -d '[:space:]' | grep -v '^$' | while read -r SG_ID; do
    echo "  - $SG_ID"
  done
else
  echo "Requested SGs:     (none on pod)"
fi

# Query the branch ENI directly for SGs
if [ -n "$ENI_ID" ] && [ "$ENI_ID" != "null" ] && [ "$ENI_ID" != "" ]; then
  echo ""
  echo "=== Branch ENI Details ==="
  ENI_DESC=$(aws ec2 describe-network-interfaces --region "$REGION" --network-interface-ids "$ENI_ID" --output json 2>/dev/null || echo "{}")
  
  if [ "$ENI_DESC" != "{}" ] && echo "$ENI_DESC" | jq -e '.NetworkInterfaces[0]' >/dev/null 2>&1; then
    IFT=$(echo "$ENI_DESC" | jq -r '.NetworkInterfaces[0].InterfaceType // "unknown"')
    STATUS=$(echo "$ENI_DESC" | jq -r '.NetworkInterfaces[0].Status // "unknown"')
    ATTACH_STATUS=$(echo "$ENI_DESC" | jq -r '.Attachment.Status // "unknown"')
    
    echo "Branch ENI type:   $IFT"
    echo "Branch ENI status: $STATUS"
    [ "$ATTACH_STATUS" != "unknown" ] && echo "Attachment status: $ATTACH_STATUS"
    
    # Extract SGs directly from jq output (one per line) and process each
    SGS_COUNT=$(echo "$ENI_DESC" | jq -r '.NetworkInterfaces[0].Groups | length' 2>/dev/null || echo "0")
    if [ "$SGS_COUNT" -gt 0 ] 2>/dev/null; then
      echo "Branch ENI SGs:"
      # Process each SG ID from jq output (one per line)
      echo "$ENI_DESC" | jq -r '.NetworkInterfaces[0].Groups[]?.GroupId // empty' 2>/dev/null | while IFS= read -r SG_ID; do
        [ -z "$SG_ID" ] && continue
        SG_ID=$(echo "$SG_ID" | tr -d '[:space:]')
        [ -z "$SG_ID" ] && continue
        
        SG_NAME=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$SG_ID" --query 'SecurityGroups[0].GroupName' --output text 2>/dev/null || echo "")
        SG_DESC=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$SG_ID" --query 'SecurityGroups[0].Description' --output text 2>/dev/null || echo "")
        if [ -n "$SG_NAME" ] && [ "$SG_NAME" != "None" ] && [ "$SG_NAME" != "null" ]; then
          if [ -n "$SG_DESC" ] && [ "$SG_DESC" != "None" ] && [ "$SG_DESC" != "null" ]; then
            echo "  - $SG_ID ($SG_NAME) - $SG_DESC"
          else
            echo "  - $SG_ID ($SG_NAME)"
          fi
        else
          echo "  - $SG_ID"
        fi
      done
    else
      warn "Could not read SGs from branch ENI"
      if [ -n "$ASSOC_ID" ] && [ "$ASSOC_ID" != "null" ] && [ "$ASSOC_ID" != "" ]; then
        echo "Checking trunk association..."
        aws ec2 describe-trunk-interface-associations --region "$REGION" --association-ids "$ASSOC_ID" --output table 2>/dev/null || true
      fi
    fi
  else
    warn "Failed to describe branch ENI: $ENI_ID"
  fi
fi

echo ""
echo "=== Result ==="
if [ "$IP_IN_ANN" = "$POD_IP" ] && [ -n "$ENI_ID" ] && [ "$ENI_ID" != "null" ] && [ "$ENI_ID" != "" ]; then
  echo "[OK] Pod is using a Pod ENI (SGP active)"
  
  # Check SG match if requested SGs are specified
  if [ -n "$SG_REQ" ] && [ -n "$SGS" ]; then
    # Compare requested vs actual
    REQ_SGS_SORTED=$(echo "$SG_REQ" | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//')
    ACT_SGS_SORTED=$(echo "$SGS" | tr ',' '\n' | sort | tr '\n' ',' | sed 's/,$//')
    
    if [ "$REQ_SGS_SORTED" = "$ACT_SGS_SORTED" ]; then
      echo "[OK] Security Groups match requested"
    else
      echo "[ISSUE] Security Groups mismatch:"
      echo "  Requested: $SG_REQ"
      echo "  Actual:    $SGS"
    fi
  fi
else
  warn "Annotation present but IP/ENI mismatch — inspect aws-node logs"
  [ "$IP_IN_ANN" != "$POD_IP" ] && warn "  IP mismatch: annotation=$IP_IN_ANN, pod=$POD_IP"
  [ -z "$ENI_ID" ] && warn "  ENI ID missing from annotation"
  exit 1
fi

# Show connections if requested
if [ "$SHOW_CONNECTIONS" -eq 1 ]; then
  echo ""
  echo "=== Network Connections ==="
  
  POD_SHELL=$(detect_shell "$POD" "$NS")
  if [ -z "$POD_SHELL" ]; then
    warn "Could not detect shell in pod, trying default 'sh'"
    POD_SHELL="sh"
  fi
  
  # Collect connections to a temp file for parsing
  CONN_TMP=$(mktemp)
  
  # Try ss first (more modern), then netstat, then /proc/net/tcp
  if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ss >/dev/null 2>&1' >/dev/null 2>&1; then
    {
      echo "--- Listening ports (ss -tuln) ---"
      kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ss -tuln 2>/dev/null || echo "ss command failed"' 2>/dev/null || echo "Failed to execute ss"
      echo ""
      echo "--- Established connections (ss -tun) ---"
      kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ss -tun 2>/dev/null || echo "ss command failed"' 2>/dev/null || echo "Failed to execute ss"
    } > "$CONN_TMP"
    
    # Parse ss output
    LISTEN_COUNT=$(grep -iE "listen|0\.0\.0\.0|:::" "$CONN_TMP" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
    ESTAB_COUNT=$(grep -iE "established|estab" "$CONN_TMP" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
    
    if [ "$LISTEN_COUNT" != "0" ] || [ "$ESTAB_COUNT" != "0" ]; then
      log "Listening ports: $LISTEN_COUNT | Established connections: $ESTAB_COUNT"
      grep -v "^---" "$CONN_TMP" 2>/dev/null | head -20 | sed 's/^/  /'
      TOTAL=$(grep -v "^---" "$CONN_TMP" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
      [ "$TOTAL" -gt 20 ] && log "... ($((TOTAL - 20)) more connection(s))"
    else
      log "No active connections detected"
    fi
    
  elif kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v netstat >/dev/null 2>&1' >/dev/null 2>&1; then
    {
      echo "--- Listening ports (netstat -tuln) ---"
      kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'netstat -tuln 2>/dev/null || echo "netstat command failed"' 2>/dev/null || echo "Failed to execute netstat"
      echo ""
      echo "--- Established connections (netstat -tun) ---"
      kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'netstat -tun 2>/dev/null || echo "netstat command failed"' 2>/dev/null || echo "Failed to execute netstat"
    } > "$CONN_TMP"
    
    # Parse netstat output
    LISTEN_COUNT=$(grep -iE "listen|0\.0\.0\.0|:::" "$CONN_TMP" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
    ESTAB_COUNT=$(grep -iE "established|estab" "$CONN_TMP" 2>/dev/null | grep -v "^---" | wc -l | tr -d '[:space:]' || echo "0")
    
    if [ "$LISTEN_COUNT" != "0" ] || [ "$ESTAB_COUNT" != "0" ]; then
      log "Listening ports: $LISTEN_COUNT | Established connections: $ESTAB_COUNT"
      grep -v "^---" "$CONN_TMP" 2>/dev/null | head -20 | sed 's/^/  /'
      TOTAL=$(grep -v "^---" "$CONN_TMP" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
      [ "$TOTAL" -gt 20 ] && log "... ($((TOTAL - 20)) more connection(s))"
    else
      log "No active connections detected"
    fi
    
  elif kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'test -r /proc/net/tcp 2>/dev/null' >/dev/null 2>&1; then
    {
      kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/tcp 2>/dev/null || echo "Failed to read /proc/net/tcp"' 2>/dev/null || echo "Failed to read /proc/net/tcp"
    } > "$CONN_TMP"
    
    # Parse /proc/net/tcp format (hex addresses)
    if grep -qE "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$CONN_TMP" 2>/dev/null; then
      LISTEN_COUNT=$(grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$CONN_TMP" 2>/dev/null | awk '{print $4}' | grep -cE "^0A$|^0a$" || echo "0")
      ESTAB_COUNT=$(grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$CONN_TMP" 2>/dev/null | awk '{print $4}' | grep -cE "^01$" || echo "0")
      
      if [ "$LISTEN_COUNT" != "0" ] || [ "$ESTAB_COUNT" != "0" ]; then
        log "Listening ports: $LISTEN_COUNT | Established connections: $ESTAB_COUNT"
        
        # Convert hex addresses to readable format
        grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$CONN_TMP" 2>/dev/null | head -20 | while read line; do
          LOCAL_HEX=$(echo "$line" | awk '{print $2}' | cut -d: -f1)
          LOCAL_PORT_HEX=$(echo "$line" | awk '{print $2}' | cut -d: -f2)
          REMOTE_HEX=$(echo "$line" | awk '{print $3}' | cut -d: -f1)
          REMOTE_PORT_HEX=$(echo "$line" | awk '{print $3}' | cut -d: -f2)
          STATE=$(echo "$line" | awk '{print $4}')
          
          # Convert hex IP to decimal (little-endian format)
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
            0A|0a) STATE_NAME="LISTEN" ;;
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
          
          # Format output
          if [ "$LOCAL_IP" != "unknown" ] && [ "$LOCAL_PORT" != "unknown" ]; then
            if [ "$STATE" = "0A" ] || [ "$STATE" = "0a" ]; then
              echo "  - LISTEN: $LOCAL_IP:$LOCAL_PORT"
            elif [ "$REMOTE_IP" != "unknown" ] && [ "$REMOTE_PORT" != "unknown" ]; then
              if echo "$REMOTE_IP" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
                echo "  - $STATE_NAME: $LOCAL_IP:$LOCAL_PORT <-> $REMOTE_IP:$REMOTE_PORT (VPC/internal)"
              else
                echo "  - $STATE_NAME: $LOCAL_IP:$LOCAL_PORT -> $REMOTE_IP:$REMOTE_PORT (external)"
              fi
            else
              echo "  - $STATE_NAME: $LOCAL_IP:$LOCAL_PORT -> (connecting...)"
            fi
          fi
        done
        
        TOTAL_CONN=$(grep -E "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-F]{8}:" "$CONN_TMP" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
        [ "$TOTAL_CONN" -gt 20 ] && log "... ($((TOTAL_CONN - 20)) more connection(s))"
      else
        log "No active connections detected"
      fi
    else
      warn "Failed to parse /proc/net/tcp output"
      cat "$CONN_TMP"
    fi
  else
    warn "Network connection tools (ss/netstat) not available and /proc/net/tcp not accessible"
  fi
  
  rm -f "$CONN_TMP" 2>/dev/null || true
  
  # Try to get conntrack connections (node-level, filtered by pod IP)
  echo ""
  log "Collecting conntrack connections (node-level)..."
  
  # Get node name
  NODE=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "")
  if [ -z "$NODE" ]; then
    warn "Could not determine node name for pod"
  elif [ -z "$POD_IP" ]; then
    warn "Could not determine pod IP for conntrack filtering"
  else
      CONNTRACK_TMP=$(mktemp)
    CONNTRACK_FILTERED=$(mktemp)
    CONNTRACK_COLLECTED=0
    TEMP_POD_NAME=""
    TEMP_POD_CREATED=0
    
    # Try direct access first (if running on node)
    if command -v conntrack >/dev/null 2>&1; then
      if conntrack -L -n 2>/dev/null | grep -i "$POD_IP" > "$CONNTRACK_FILTERED" 2>/dev/null; then
        CONNTRACK_COLLECTED=1
      fi
    elif [ -r /proc/net/nf_conntrack ]; then
      if grep -i "$POD_IP" /proc/net/nf_conntrack > "$CONNTRACK_FILTERED" 2>/dev/null; then
        CONNTRACK_COLLECTED=1
      fi
    fi
    
    # If direct access didn't work, create a temporary privileged pod to access conntrack
    if [ "$CONNTRACK_COLLECTED" -eq 0 ]; then
      log "Creating temporary privileged pod on node $NODE for conntrack access..."
      TEMP_POD_NAME="quick-check-conntrack-$(date +%s)"
      
      # Create a temporary privileged pod with host access (similar to sgfp_node_diag.sh)
      if kubectl run "$TEMP_POD_NAME" \
        --image=busybox:latest \
        --restart=Never \
        --overrides="{\"spec\":{\"nodeName\":\"$NODE\",\"hostNetwork\":true,\"hostPID\":true,\"hostIPC\":true,\"containers\":[{\"name\":\"collector\",\"image\":\"busybox:latest\",\"command\":[\"sleep\",\"300\"],\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"name\":\"host-root\",\"mountPath\":\"/host\"}]}],\"volumes\":[{\"name\":\"host-root\",\"hostPath\":{\"path\":\"/\"}}]}}" \
        --namespace=kube-system \
        >/dev/null 2>&1; then
        
        TEMP_POD_CREATED=1
        # Wait for pod to be ready
        sleep 2
        
        # Try to get conntrack data via temporary pod (use container name 'collector')
        if kubectl -n kube-system exec "$TEMP_POD_NAME" -c collector -- sh -c 'command -v conntrack >/dev/null 2>&1 && conntrack -L -n 2>/dev/null || cat /host/proc/net/nf_conntrack 2>/dev/null || true' > "$CONNTRACK_TMP" 2>/dev/null; then
          if [ -s "$CONNTRACK_TMP" ]; then
            grep -i "$POD_IP" "$CONNTRACK_TMP" > "$CONNTRACK_FILTERED" 2>/dev/null || true
            [ -s "$CONNTRACK_FILTERED" ] && CONNTRACK_COLLECTED=1
          fi
        fi
      else
        warn "Failed to create temporary pod for conntrack access"
      fi
    fi
    
    # Get node pod IPs for same-node vs cross-node detection
    # Try to get pod IPs from kubectl (if we have access)
    NODE_POD_IPS=""
    NODE_POD_IPS_TMP=$(mktemp)
    if kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName="$NODE" 2>/dev/null | awk '{print $7}' | grep -E "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\." | sort -u > "$NODE_POD_IPS_TMP" 2>/dev/null; then
      if [ -s "$NODE_POD_IPS_TMP" ]; then
        NODE_POD_IPS="$NODE_POD_IPS_TMP"
      fi
    fi
    
    # Parse and display conntrack connections
    CONNTRACK_COUNT=$(grep -v '^[[:space:]]*$' "$CONNTRACK_FILTERED" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    if [ "$CONNTRACK_COUNT" -gt 0 ]; then
      log "Connections tracked by conntrack (node-level, filtered by pod IP - shows both inbound TO pod and outbound FROM pod): $CONNTRACK_COUNT connection(s)"
      
      # Count inbound vs outbound
      INBOUND_COUNT=$(grep -v '^[[:space:]]*$' "$CONNTRACK_FILTERED" 2>/dev/null | grep -oE "src=[0-9.]+[[:space:]]+dst=${POD_IP}[[:space:]]" | wc -l | tr -d '[:space:]' || echo "0")
      OUTBOUND_COUNT=$(grep -v '^[[:space:]]*$' "$CONNTRACK_FILTERED" 2>/dev/null | grep -oE "src=${POD_IP}[[:space:]]+dst=[0-9.]+[[:space:]]" | wc -l | tr -d '[:space:]' || echo "0")
      
      if [ "$INBOUND_COUNT" -gt 0 ] || [ "$OUTBOUND_COUNT" -gt 0 ]; then
        log "  Inbound (TO pod): $INBOUND_COUNT | Outbound (FROM pod): $OUTBOUND_COUNT"
      fi
      
      # Format and display connections
      grep -v '^[[:space:]]*$' "$CONNTRACK_FILTERED" 2>/dev/null | head -10 | while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        
        # Extract conntrack fields
        if echo "$line" | grep -qE "src=|dst="; then
          SRC=$(echo "$line" | grep -oE "src=[0-9.]+" | head -1 | cut -d= -f2 || echo "")
          DST=$(echo "$line" | grep -oE "dst=[0-9.]+" | head -1 | cut -d= -f2 || echo "")
          SPORT=$(echo "$line" | grep -oE "sport=[0-9]+" | head -1 | cut -d= -f2 || echo "")
          DPORT=$(echo "$line" | grep -oE "dport=[0-9]+" | head -1 | cut -d= -f2 || echo "")
          STATE=$(echo "$line" | grep -oE "[[:space:]](ESTABLISHED|CLOSE|TIME_WAIT|SYN_SENT|SYN_RECV|FIN_WAIT1|FIN_WAIT2|CLOSE_WAIT|LAST_ACK|LISTEN)[[:space:]]" | tr -d '[:space:]' || echo "")
          if [ -z "$STATE" ]; then
            STATE=$(echo "$line" | awk '{for(i=1;i<=NF;i++) if($i ~ /^(ESTABLISHED|CLOSE|TIME_WAIT|SYN_SENT|SYN_RECV|FIN_WAIT1|FIN_WAIT2|CLOSE_WAIT|LAST_ACK|LISTEN)$/) {print $i; exit}}' || echo "")
          fi
          
          if [ -n "$SRC" ] && [ -n "$DST" ] && [ -n "$SPORT" ] && [ -n "$DPORT" ]; then
            # Determine direction and node type
            REMOTE_IP=""
            DIRECTION=""
            NODE_TYPE=""
            
            if echo "$DST" | grep -q "^${POD_IP}$"; then
              REMOTE_IP="$SRC"
              DIRECTION="INBOUND"
            elif echo "$SRC" | grep -q "^${POD_IP}$"; then
              REMOTE_IP="$DST"
              DIRECTION="OUTBOUND"
            fi
            
            # Check if remote IP is on same node
            if [ -n "$REMOTE_IP" ] && [ -n "$NODE_POD_IPS" ] && [ -s "$NODE_POD_IPS" ]; then
              if grep -q "^${REMOTE_IP}$" "$NODE_POD_IPS" 2>/dev/null; then
                NODE_TYPE=" (same-node)"
              elif echo "$REMOTE_IP" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
                NODE_TYPE=" (cross-node)"
              else
                NODE_TYPE=" (external)"
              fi
            elif [ -n "$REMOTE_IP" ]; then
              if echo "$REMOTE_IP" | grep -qE "^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."; then
                NODE_TYPE=" (VPC/internal)"
              else
                NODE_TYPE=" (external)"
              fi
            fi
            
            # Format output
            if [ -n "$DIRECTION" ]; then
              echo "  - ${DIRECTION}: $SRC:$SPORT -> $DST:$DPORT${NODE_TYPE}${STATE:+ ($STATE)}"
            else
              echo "  - $SRC:$SPORT <-> $DST:$DPORT${NODE_TYPE}${STATE:+ ($STATE)}"
            fi
          else
            echo "  - $line"
          fi
        else
          echo "  - $line"
        fi
      done
      
      if [ "$CONNTRACK_COUNT" -gt 10 ]; then
        log "... and $((CONNTRACK_COUNT - 10)) more connection(s)"
      fi
    else
      if [ "$CONNTRACK_COLLECTED" -eq 0 ]; then
        warn "Conntrack data not accessible (requires node-level access or privileged pod with host filesystem mount)"
        warn "  Note: Use 'make collect' or 'make doctor' for full diagnostics that include conntrack data"
      else
        log "No conntrack entries found for pod IP $POD_IP"
      fi
    fi
    
    # Clean up temporary pod if we created one
    if [ "$TEMP_POD_CREATED" -eq 1 ] && [ -n "$TEMP_POD_NAME" ]; then
      kubectl -n kube-system delete pod "$TEMP_POD_NAME" --ignore-not-found=true >/dev/null 2>&1 || true
    fi
    
    rm -f "$CONNTRACK_TMP" "$CONNTRACK_FILTERED" "$NODE_POD_IPS_TMP" 2>/dev/null || true
  fi
fi

