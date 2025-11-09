#!/usr/bin/env bash
set -euo pipefail

NODE="${1:?usage: sgfp_node_diag.sh <node-name>}"
OUT="sgfp_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

log()  { printf "[NODE] %s\n" "$*"; }
warn() { printf "[NODE] WARN: %s\n" "$*" >&2; }

log "Collecting node diagnostics for: $NODE"
log "Output: $OUT"

# Collect all pod IPs on this node (for connection analysis)
log "Collecting pod IPs on node..."
if command -v kubectl >/dev/null 2>&1; then
  # Get all pods on this node with their IPs
  kubectl get pods --all-namespaces -o wide --field-selector spec.nodeName="$NODE" 2>/dev/null | \
    awk 'NR>1 {print $6}' | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | sort -u > "$OUT/node_pod_ips.txt" 2>/dev/null || echo "" > "$OUT/node_pod_ips.txt"
  POD_IP_COUNT=$(wc -l < "$OUT/node_pod_ips.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$POD_IP_COUNT" -gt 0 ]; then
    log "Found $POD_IP_COUNT pod IP(s) on node"
  else
    log "No pod IPs collected (may need kubectl access)"
  fi
else
  echo "" > "$OUT/node_pod_ips.txt"
  warn "kubectl not available, cannot collect pod IPs on node"
fi

# Conntrack usage + hints
log "Checking conntrack usage..."
CONNTRACK_COLLECTED=0
CONNTRACK_DATA=""
if [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
  COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
  MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max   2>/dev/null || echo 0)
  if [ "$COUNT" != "0" ] || [ "$MAX" != "0" ]; then
    CONNTRACK_DATA="$COUNT / $MAX"
    log "Conntrack: $CONNTRACK_DATA"
    echo "$CONNTRACK_DATA" > "$OUT/node_conntrack_mtu.txt"
    
    # Try to collect conntrack table (if conntrack tool is available)
    if command -v conntrack >/dev/null 2>&1; then
      log "Collecting conntrack table..."
      if conntrack -L -n 2>/dev/null | head -1000 > "$OUT/node_conntrack_table.txt" 2>/dev/null; then
        CONNTRACK_COLLECTED=1
      else
        echo "" > "$OUT/node_conntrack_table.txt"
      fi
    elif [ -r /proc/net/nf_conntrack ]; then
      log "Collecting conntrack table from /proc/net/nf_conntrack..."
      if head -1000 /proc/net/nf_conntrack > "$OUT/node_conntrack_table.txt" 2>/dev/null; then
        CONNTRACK_COLLECTED=1
      else
        echo "" > "$OUT/node_conntrack_table.txt"
      fi
    else
      echo "" > "$OUT/node_conntrack_table.txt"
    fi
  else
    warn "Conntrack data not available (not running on node or procfs not accessible)"
    echo "" > "$OUT/node_conntrack_mtu.txt"
    echo "" > "$OUT/node_conntrack_table.txt"
  fi
else
  warn "Conntrack procfs not accessible directly, will try via temporary pod if available"
  echo "" > "$OUT/node_conntrack_mtu.txt"
  echo "" > "$OUT/node_conntrack_table.txt"
fi

# Also capture aws-node logs (cluster scope best-effort)
log "Collecting aws-node logs..."
if kubectl -n kube-system logs -l k8s-app=aws-node --tail=200 --since=30m > "$OUT/aws_node_full.log" 2>/dev/null; then
  LOG_LINES=$(wc -l < "$OUT/aws_node_full.log" 2>/dev/null | tr -d '[:space:]' || echo 0)
  log "Collected $LOG_LINES lines of aws-node logs"
else
  warn "Failed to collect aws-node logs"
  echo "" > "$OUT/aws_node_full.log"
fi

# Interface error statistics (from /proc/net/dev and ip -s link)
log "Collecting interface error statistics..."
if [ -r /proc/net/dev ]; then
  cat /proc/net/dev > "$OUT/node_interface_dev_stats.txt" 2>/dev/null || echo "" > "$OUT/node_interface_dev_stats.txt"
  log "Collected /proc/net/dev"
else
  warn "/proc/net/dev not accessible (this script should run on the node)"
  echo "" > "$OUT/node_interface_dev_stats.txt"
fi

if command -v ip >/dev/null 2>&1; then
  ip -s link > "$OUT/node_interface_ip_stats.txt" 2>/dev/null || echo "" > "$OUT/node_interface_ip_stats.txt"
  log "Collected ip -s link statistics"
else
  warn "ip command not available"
  echo "" > "$OUT/node_interface_ip_stats.txt"
fi

# Socket statistics (including overruns)
log "Collecting socket statistics..."
if [ -r /proc/net/sockstat ]; then
  cat /proc/net/sockstat > "$OUT/node_sockstat.txt" 2>/dev/null || echo "" > "$OUT/node_sockstat.txt"
  log "Collected /proc/net/sockstat"
else
  echo "" > "$OUT/node_sockstat.txt"
fi

if [ -r /proc/net/sockstat6 ]; then
  cat /proc/net/sockstat6 > "$OUT/node_sockstat6.txt" 2>/dev/null || echo "" > "$OUT/node_sockstat6.txt"
fi

# Socket overruns from /proc/net/snmp
if [ -r /proc/net/snmp ]; then
  grep -E "^(Udp|Tcp|Ip):" /proc/net/snmp > "$OUT/node_snmp.txt" 2>/dev/null || echo "" > "$OUT/node_snmp.txt"
  log "Collected /proc/net/snmp (socket overruns)"
else
  echo "" > "$OUT/node_snmp.txt"
fi

# AWS VPC CNI logs from /var/log/aws-routed-eni/ (if accessible)
log "Collecting AWS VPC CNI logs..."
CNI_LOG_DIR="/var/log/aws-routed-eni"
CNI_LOG_DIR_HOST="/host/var/log/aws-routed-eni"
CNI_LOGS_FOUND=0

# Try both paths (direct and /host mount)
for LOG_DIR in "$CNI_LOG_DIR" "$CNI_LOG_DIR_HOST"; do
  if [ -d "$LOG_DIR" ] && [ -r "$LOG_DIR" ]; then
    log "Found CNI logs directory: $LOG_DIR"
    CNI_LOGS_FOUND=1
    
    # Create logs subdirectory
    mkdir -p "$OUT/cni_logs"
    
    # Collect each log file if it exists and is readable
    for LOG_FILE in ipamd.log plugin.log network-policy-agent.log ebpf-sdk.log egress-v6-plugin.log; do
      if [ -r "$LOG_DIR/$LOG_FILE" ]; then
        # Copy last 1000 lines to avoid huge files
        tail -1000 "$LOG_DIR/$LOG_FILE" > "$OUT/cni_logs/$LOG_FILE" 2>/dev/null || true
        log "Collected $LOG_FILE"
      fi
    done
    
    # Also collect rotated logs (ipamd-*.log.gz) - get the most recent one
    if [ -d "$LOG_DIR" ]; then
      LATEST_ROTATED=$(ls -t "$LOG_DIR"/ipamd-*.log.gz 2>/dev/null | head -1 || echo "")
      if [ -n "$LATEST_ROTATED" ] && [ -r "$LATEST_ROTATED" ]; then
        # Decompress and get last 1000 lines
        zcat "$LATEST_ROTATED" 2>/dev/null | tail -1000 > "$OUT/cni_logs/ipamd-latest-rotated.log" 2>/dev/null || true
        log "Collected latest rotated ipamd log"
      fi
    fi
    
    # Create error summaries for each log
    for LOG_FILE in "$OUT/cni_logs"/*.log; do
      if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
        LOG_BASENAME=$(basename "$LOG_FILE")
        # Extract errors and warnings
        grep -iE "(error|warn|fail|fatal|panic|timeout|throttle)" "$LOG_FILE" > "$OUT/cni_logs/${LOG_BASENAME}.errors" 2>/dev/null || true
        if [ -s "$OUT/cni_logs/${LOG_BASENAME}.errors" ]; then
          ERROR_COUNT=$(wc -l < "$OUT/cni_logs/${LOG_BASENAME}.errors" 2>/dev/null | tr -d '[:space:]' || echo "0")
          log "Found $ERROR_COUNT error/warning lines in $LOG_BASENAME"
        fi
      fi
    done
    
    break
  fi
done

if [ "$CNI_LOGS_FOUND" -eq 0 ]; then
  warn "CNI logs directory not accessible directly, trying via temporary debug pod..."
  mkdir -p "$OUT/cni_logs"
  
  # Try to collect via temporary pod on the node
  TEMP_POD_NAME="cni-logs-collector-$(date +%s)"
  CNI_LOG_DIR="/host/var/log/aws-routed-eni"
  
  log "Creating temporary pod on node to collect CNI logs..."
  
  # Create a temporary pod on the node with host access
  if kubectl run "$TEMP_POD_NAME" \
    --image=busybox:latest \
    --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$NODE\",\"hostNetwork\":true,\"hostPID\":true,\"hostIPC\":true,\"containers\":[{\"name\":\"collector\",\"image\":\"busybox:latest\",\"command\":[\"sleep\",\"300\"],\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"name\":\"host-root\",\"mountPath\":\"/host\"}]}],\"volumes\":[{\"name\":\"host-root\",\"hostPath\":{\"path\":\"/\"}}]}}" \
    >/dev/null 2>&1; then
    
    # Wait for pod to be ready
    sleep 2
    
    # Collect each log file
    for LOG_FILE in ipamd.log plugin.log network-policy-agent.log ebpf-sdk.log egress-v6-plugin.log; do
      if kubectl exec "$TEMP_POD_NAME" -- sh -c "tail -1000 $CNI_LOG_DIR/$LOG_FILE 2>/dev/null || true" > "$OUT/cni_logs/$LOG_FILE" 2>/dev/null; then
        if [ -s "$OUT/cni_logs/$LOG_FILE" ]; then
          log "Collected $LOG_FILE"
          CNI_LOGS_FOUND=1
        else
          rm -f "$OUT/cni_logs/$LOG_FILE" 2>/dev/null || true
        fi
      fi
    done
    
    # Collect latest rotated log
    if kubectl exec "$TEMP_POD_NAME" -- sh -c "LATEST=\$(ls -t $CNI_LOG_DIR/ipamd-*.log.gz 2>/dev/null | head -1); [ -n \"\$LATEST\" ] && zcat \"\$LATEST\" 2>/dev/null | tail -1000 || true" > "$OUT/cni_logs/ipamd-latest-rotated.log" 2>/dev/null; then
      if [ -s "$OUT/cni_logs/ipamd-latest-rotated.log" ]; then
        log "Collected latest rotated ipamd log"
        CNI_LOGS_FOUND=1
      else
        rm -f "$OUT/cni_logs/ipamd-latest-rotated.log" 2>/dev/null || true
      fi
    fi
    
    # Create error summaries for collected logs
    if [ "$CNI_LOGS_FOUND" -eq 1 ]; then
      for LOG_FILE in "$OUT/cni_logs"/*.log; do
        if [ -f "$LOG_FILE" ] && [ -s "$LOG_FILE" ]; then
          LOG_BASENAME=$(basename "$LOG_FILE")
          grep -iE "(error|warn|fail|fatal|panic|timeout|throttle)" "$LOG_FILE" > "$OUT/cni_logs/${LOG_BASENAME}.errors" 2>/dev/null || true
          if [ -s "$OUT/cni_logs/${LOG_BASENAME}.errors" ]; then
            ERROR_COUNT=$(wc -l < "$OUT/cni_logs/${LOG_BASENAME}.errors" 2>/dev/null | tr -d '[:space:]' || echo "0")
            log "Found $ERROR_COUNT error/warning lines in $LOG_BASENAME"
          fi
        fi
      done
      log "Successfully collected CNI logs via temporary debug pod"
    fi
    
    # Use the same temporary pod for network namespace and conntrack collection (before deleting it)
    TEMP_POD_AVAILABLE=1
    
    # Collect conntrack data via temporary pod if not already collected
    if [ "$CONNTRACK_COLLECTED" -eq 0 ]; then
      log "Collecting conntrack table via temporary pod..."
      # Try conntrack command first
      if kubectl exec "$TEMP_POD_NAME" -- sh -c "command -v conntrack >/dev/null 2>&1 && conntrack -L -n 2>/dev/null | head -1000 || cat /host/proc/net/nf_conntrack 2>/dev/null | head -1000 || true" > "$OUT/node_conntrack_table.txt" 2>/dev/null; then
        if [ -s "$OUT/node_conntrack_table.txt" ]; then
          CONNTRACK_COLLECTED=1
          log "Collected conntrack table via temporary pod"
          # Also get conntrack count/max if available
          if kubectl exec "$TEMP_POD_NAME" -- sh -c "cat /host/proc/sys/net/netfilter/nf_conntrack_count /host/proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null | tr '\n' ' '" > "$OUT/node_conntrack_mtu.txt" 2>/dev/null; then
            COUNT_MAX=$(cat "$OUT/node_conntrack_mtu.txt" 2>/dev/null | awk '{print $1" / "$2}' || echo "")
            if [ -n "$COUNT_MAX" ] && [ "$COUNT_MAX" != " / " ]; then
              echo "$COUNT_MAX" > "$OUT/node_conntrack_mtu.txt"
              log "Conntrack: $COUNT_MAX"
            fi
          fi
        else
          echo "" > "$OUT/node_conntrack_table.txt"
        fi
      fi
    fi
  else
    warn "Failed to create temporary pod for CNI log collection"
    TEMP_POD_AVAILABLE=0
  fi
  
  if [ "$CNI_LOGS_FOUND" -eq 0 ]; then
    warn "CNI logs not accessible (requires running on node or debug pod with /host mount)"
    echo "" > "$OUT/cni_logs/.not_accessible"
  fi
fi

# Track if we need to clean up the temporary pod
CLEANUP_TEMP_POD=0
if [ "${TEMP_POD_AVAILABLE:-0}" = "1" ] && [ -n "${TEMP_POD_NAME:-}" ]; then
  CLEANUP_TEMP_POD=1
fi

# Additional network diagnostics (when running on node or via debug pod)
log "Collecting additional network diagnostics..."

# Network namespace count (check for leaks)
if [ -d /var/run/netns ] || [ -d /host/var/run/netns ]; then
  NETNS_DIR="/var/run/netns"
  [ ! -d "$NETNS_DIR" ] && NETNS_DIR="/host/var/run/netns"
  if [ -d "$NETNS_DIR" ]; then
    NETNS_COUNT=$(ls -1 "$NETNS_DIR" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
    echo "$NETNS_COUNT" > "$OUT/node_netns_count.txt" 2>/dev/null || echo "0" > "$OUT/node_netns_count.txt"
    log "Found $NETNS_COUNT network namespace(s)"
  fi
fi

# Kernel logs (dmesg) - network-related errors
if command -v dmesg >/dev/null 2>&1; then
  dmesg | grep -iE "(network|net|eni|veth|route|arp|conntrack|nf_conntrack)" | tail -200 > "$OUT/node_dmesg_network.txt" 2>/dev/null || echo "" > "$OUT/node_dmesg_network.txt"
  log "Collected network-related kernel messages"
elif [ -r /host/var/log/dmesg ] || [ -r /var/log/dmesg ]; then
  DMESG_FILE="/var/log/dmesg"
  [ ! -r "$DMESG_FILE" ] && DMESG_FILE="/host/var/log/dmesg"
  if [ -r "$DMESG_FILE" ]; then
    grep -iE "(network|net|eni|veth|route|arp|conntrack|nf_conntrack)" "$DMESG_FILE" | tail -200 > "$OUT/node_dmesg_network.txt" 2>/dev/null || echo "" > "$OUT/node_dmesg_network.txt"
    log "Collected network-related kernel messages from dmesg log"
  fi
fi

# ARP table (check for stale entries or issues)
if [ -r /proc/net/arp ] || [ -r /host/proc/net/arp ]; then
  ARP_FILE="/proc/net/arp"
  [ ! -r "$ARP_FILE" ] && ARP_FILE="/host/proc/net/arp"
  if [ -r "$ARP_FILE" ]; then
    cat "$ARP_FILE" > "$OUT/node_arp_table.txt" 2>/dev/null || echo "" > "$OUT/node_arp_table.txt"
    log "Collected ARP table"
  fi
fi

# iptables rules (check for network policy or routing issues)
if command -v iptables >/dev/null 2>&1; then
  iptables -L -n -v > "$OUT/node_iptables_filter.txt" 2>/dev/null || echo "" > "$OUT/node_iptables_filter.txt"
  iptables -t nat -L -n -v > "$OUT/node_iptables_nat.txt" 2>/dev/null || echo "" > "$OUT/node_iptables_nat.txt"
  log "Collected iptables rules"
fi

# Route table (more detailed)
if command -v ip >/dev/null 2>&1; then
  ip route show table all > "$OUT/node_routes_all.txt" 2>/dev/null || echo "" > "$OUT/node_routes_all.txt"
  log "Collected route table (all tables)"
fi

# Check for veth interfaces (count and state)
if command -v ip >/dev/null 2>&1; then
  ip link show type veth > "$OUT/node_veth_interfaces.txt" 2>/dev/null || echo "" > "$OUT/node_veth_interfaces.txt"
  VETH_COUNT=$(grep -c "^[0-9]" "$OUT/node_veth_interfaces.txt" 2>/dev/null || echo "0")
  log "Found $VETH_COUNT veth interface(s)"
fi

# Check for network interface errors in syslog (if accessible)
if [ -r /var/log/syslog ] || [ -r /host/var/log/syslog ]; then
  SYSLOG_FILE="/var/log/syslog"
  [ ! -r "$SYSLOG_FILE" ] && SYSLOG_FILE="/host/var/log/syslog"
  if [ -r "$SYSLOG_FILE" ]; then
    grep -iE "(network|net|eni|veth|route|arp|conntrack|error|fail)" "$SYSLOG_FILE" | tail -100 > "$OUT/node_syslog_network.txt" 2>/dev/null || echo "" > "$OUT/node_syslog_network.txt"
    log "Collected network-related syslog entries"
  fi
fi

# Network namespace analysis (stuck/orphaned namespaces)
log "Analyzing network namespaces for leaks..."
# Try both direct access and via /host mount (for temporary debug pods)
NETNS_DIRS="/var/run/netns /host/var/run/netns"
NETNS_DIR=""
for dir in $NETNS_DIRS; do
  if [ -d "$dir" ]; then
    NETNS_DIR="$dir"
    break
  fi
done

# If we have a temporary pod available, use it for network namespace and conntrack collection
if [ "${TEMP_POD_AVAILABLE:-0}" = "1" ] && [ -n "${TEMP_POD_NAME:-}" ] && command -v kubectl >/dev/null 2>&1; then
  # Collect conntrack if not already collected
  if [ "$CONNTRACK_COLLECTED" -eq 0 ]; then
    log "Collecting conntrack table via temporary pod..."
    if kubectl exec "$TEMP_POD_NAME" -- sh -c "command -v conntrack >/dev/null 2>&1 && conntrack -L -n 2>/dev/null | head -1000 || cat /host/proc/net/nf_conntrack 2>/dev/null | head -1000 || true" > "$OUT/node_conntrack_table.txt" 2>/dev/null; then
      if [ -s "$OUT/node_conntrack_table.txt" ]; then
        CONNTRACK_COLLECTED=1
        log "Collected conntrack table via temporary pod"
        # Also get conntrack count/max if available
        if kubectl exec "$TEMP_POD_NAME" -- sh -c "cat /host/proc/sys/net/netfilter/nf_conntrack_count /host/proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null | tr '\n' ' '" > "$OUT/node_conntrack_mtu.txt" 2>/dev/null; then
          COUNT_MAX=$(cat "$OUT/node_conntrack_mtu.txt" 2>/dev/null | awk '{print $1" / "$2}' || echo "")
          if [ -n "$COUNT_MAX" ] && [ "$COUNT_MAX" != " / " ]; then
            echo "$COUNT_MAX" > "$OUT/node_conntrack_mtu.txt"
            log "Conntrack: $COUNT_MAX"
          fi
        fi
      else
        echo "" > "$OUT/node_conntrack_table.txt"
      fi
    fi
  fi
  
  log "Collecting network namespace details via temporary pod..."
  NETNS_JSON_TMP=$(mktemp)
  echo "[]" > "$NETNS_JSON_TMP"
  
  # List network namespaces via the temporary pod
  kubectl exec "$TEMP_POD_NAME" -- sh -c "ls -1 /host/var/run/netns 2>/dev/null || ls -1 /var/run/netns 2>/dev/null || echo ''" 2>/dev/null > "$OUT/node_netns_list.txt" || echo "" > "$OUT/node_netns_list.txt"
  
  # Get details for each namespace
  while IFS= read -r NS_NAME; do
    [ -z "$NS_NAME" ] && continue
    # Try multiple methods to get interface count (some namespaces may not be accessible via ip netns exec)
    # Method 1: Try ip netns exec (works for active namespaces)
    NS_INTERFACES=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "ip netns exec \"$NS_NAME\" ip link show 2>/dev/null | grep -E '^[0-9]+:' | wc -l || echo 0" 2>/dev/null | tr -d '[:space:]' || echo "0")
    NS_IPS=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "ip netns exec \"$NS_NAME\" ip addr show 2>/dev/null | grep -E 'inet ' | wc -l || echo 0" 2>/dev/null | tr -d '[:space:]' || echo "0")
    
    # If we got 0 interfaces, try checking if namespace file is stale (might be a leak indicator)
    # Check namespace file age
    NS_MTIME=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "stat -c %Y \"/host/var/run/netns/$NS_NAME\" 2>/dev/null || stat -c %Y \"/var/run/netns/$NS_NAME\" 2>/dev/null || echo 0" 2>/dev/null | tr -d '[:space:]' || echo "0")
    
    # Also try to see if we can list interfaces via nsenter (alternative method)
    if [ "$NS_INTERFACES" = "0" ]; then
      # Try using nsenter with the namespace file directly
      NS_INTERFACES=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "nsenter --net=/host/var/run/netns/$NS_NAME ip link show 2>/dev/null | grep -E '^[0-9]+:' | wc -l || nsenter --net=/var/run/netns/$NS_NAME ip link show 2>/dev/null | grep -E '^[0-9]+:' | wc -l || echo 0" 2>/dev/null | tr -d '[:space:]' || echo "0")
    fi
    
    # Add to JSON
    jq --arg name "$NS_NAME" --arg interfaces "$NS_INTERFACES" --arg ips "$NS_IPS" --arg mtime "$NS_MTIME" \
      '. += [{"name": $name, "interface_count": ($interfaces | tonumber), "ip_count": ($ips | tonumber), "mtime": ($mtime | tonumber)}]' \
      "$NETNS_JSON_TMP" > "${NETNS_JSON_TMP}.new" && mv "${NETNS_JSON_TMP}.new" "$NETNS_JSON_TMP"
  done < "$OUT/node_netns_list.txt"
  
  jq . "$NETNS_JSON_TMP" > "$OUT/node_netns_details.json" 2>/dev/null || echo "[]" > "$OUT/node_netns_details.json"
  rm -f "$NETNS_JSON_TMP" 2>/dev/null || true
  log "Collected network namespace details via temporary pod"
elif [ -n "$NETNS_DIR" ] && command -v ip >/dev/null 2>&1; then
  # Direct access (running on node)
  ls -1 "$NETNS_DIR" 2>/dev/null > "$OUT/node_netns_list.txt" || echo "" > "$OUT/node_netns_list.txt"
  
  # Get network namespace details (creation time, interfaces, etc.)
  NETNS_JSON_TMP=$(mktemp)
  echo "[]" > "$NETNS_JSON_TMP"
  
  for ns in "$NETNS_DIR"/*; do
    [ ! -e "$ns" ] && continue
    NS_NAME=$(basename "$ns")
    # Get interfaces in this namespace
    NS_INTERFACES=$(ip netns exec "$NS_NAME" ip link show 2>/dev/null | grep -E "^[0-9]+:" | wc -l | tr -d '[:space:]' || echo "0")
    # Get IPs in this namespace
    NS_IPS=$(ip netns exec "$NS_NAME" ip addr show 2>/dev/null | grep -E "inet " | wc -l | tr -d '[:space:]' || echo "0")
    # Get namespace file modification time (approximate creation time)
    NS_MTIME=$(stat -c %Y "$ns" 2>/dev/null || echo "0")
    
    # Add to JSON
    jq --arg name "$NS_NAME" --arg interfaces "$NS_INTERFACES" --arg ips "$NS_IPS" --arg mtime "$NS_MTIME" \
      '. += [{"name": $name, "interface_count": ($interfaces | tonumber), "ip_count": ($ips | tonumber), "mtime": ($mtime | tonumber)}]' \
      "$NETNS_JSON_TMP" > "${NETNS_JSON_TMP}.new" && mv "${NETNS_JSON_TMP}.new" "$NETNS_JSON_TMP"
  done
  
  jq . "$NETNS_JSON_TMP" > "$OUT/node_netns_details.json" 2>/dev/null || echo "[]" > "$OUT/node_netns_details.json"
  rm -f "$NETNS_JSON_TMP" 2>/dev/null || true
  log "Collected network namespace details"
fi

# Network interface state check (interfaces in wrong states)
log "Checking network interface states..."
if command -v ip >/dev/null 2>&1; then
  # Get all interfaces and their states
  ip link show > "$OUT/node_interfaces_state.txt" 2>/dev/null || echo "" > "$OUT/node_interfaces_state.txt"
  # Check for interfaces in DOWN state (excluding expected ones like lo)
  DOWN_INTERFACES=$(grep -E "^[0-9]+:.*state DOWN" "$OUT/node_interfaces_state.txt" 2>/dev/null | grep -v " lo:" | wc -l | tr -d '[:space:]' || echo "0")
  if [ "$DOWN_INTERFACES" -gt 0 ]; then
    log "Found $DOWN_INTERFACES interface(s) in DOWN state"
  fi
fi

# IP address conflict detection
log "Checking for IP address conflicts..."
if command -v ip >/dev/null 2>&1; then
  # Get all IP addresses on the node
  ip addr show | grep -E "inet " | awk '{print $2}' | cut -d/ -f1 | sort > "$OUT/node_all_ips.txt" 2>/dev/null || echo "" > "$OUT/node_all_ips.txt"
  # Check for duplicates (only if file has content)
  if [ -s "$OUT/node_all_ips.txt" ]; then
    DUPLICATE_IPS=$(sort "$OUT/node_all_ips.txt" | uniq -d 2>/dev/null | grep -v '^[[:space:]]*$' || true)
    if [ -n "$DUPLICATE_IPS" ]; then
      echo "$DUPLICATE_IPS" > "$OUT/node_duplicate_ips.txt"
      log "WARN: Found duplicate IP addresses"
    else
      echo "" > "$OUT/node_duplicate_ips.txt"
    fi
  else
    echo "" > "$OUT/node_duplicate_ips.txt"
  fi
fi

# DNS resolution test
log "Testing DNS resolution..."
if command -v nslookup >/dev/null 2>&1 || command -v host >/dev/null 2>&1; then
  {
    echo "## DNS Resolution Tests"
    # Test Kubernetes DNS
    if command -v nslookup >/dev/null 2>&1; then
      echo "### kubernetes.default.svc.cluster.local"
      if nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
        echo "SUCCESS"
        nslookup kubernetes.default.svc.cluster.local 2>&1
      else
        echo "FAILED"
        nslookup kubernetes.default.svc.cluster.local 2>&1
      fi
      echo ""
      echo "### AWS metadata service (reverse lookup)"
      if nslookup 169.254.169.254 >/dev/null 2>&1; then
        echo "SUCCESS"
        nslookup 169.254.169.254 2>&1
      else
        echo "FAILED (expected - metadata service may not resolve via DNS)"
        nslookup 169.254.169.254 2>&1
      fi
    elif command -v host >/dev/null 2>&1; then
      echo "### kubernetes.default.svc.cluster.local"
      if host kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
        echo "SUCCESS"
        host kubernetes.default.svc.cluster.local 2>&1
      else
        echo "FAILED"
        host kubernetes.default.svc.cluster.local 2>&1
      fi
      echo ""
      echo "### AWS metadata service (reverse lookup)"
      if host 169.254.169.254 >/dev/null 2>&1; then
        echo "SUCCESS"
        host 169.254.169.254 2>&1
      else
        echo "FAILED (expected - metadata service may not resolve via DNS)"
        host 169.254.169.254 2>&1
      fi
    fi
  } > "$OUT/node_dns_tests.txt" 2>/dev/null || echo "" > "$OUT/node_dns_tests.txt"
  log "Collected DNS resolution tests"
fi

# Resource exhaustion checks
log "Checking for resource exhaustion..."
# File descriptors
if [ -r /proc/sys/fs/file-nr ] || [ -r /host/proc/sys/fs/file-nr ]; then
  FILE_NR="/proc/sys/fs/file-nr"
  [ ! -r "$FILE_NR" ] && FILE_NR="/host/proc/sys/fs/file-nr"
  if [ -r "$FILE_NR" ]; then
    cat "$FILE_NR" > "$OUT/node_file_descriptors.txt" 2>/dev/null || echo "" > "$OUT/node_file_descriptors.txt"
    # Parse: allocated, unused, max
    ALLOCATED=$(awk '{print $1}' "$OUT/node_file_descriptors.txt" 2>/dev/null || echo "0")
    MAX=$(awk '{print $3}' "$OUT/node_file_descriptors.txt" 2>/dev/null || echo "0")
    if [ "$MAX" != "0" ] && [ "$ALLOCATED" != "0" ]; then
      USAGE_PCT=$((ALLOCATED * 100 / MAX))
      log "File descriptors: $ALLOCATED / $MAX (~$USAGE_PCT%)"
      if [ "$USAGE_PCT" -gt 80 ]; then
        warn "File descriptor usage high: $USAGE_PCT%"
      fi
    fi
  fi
fi

# Memory pressure
if [ -r /proc/meminfo ] || [ -r /host/proc/meminfo ]; then
  MEMINFO="/proc/meminfo"
  [ ! -r "$MEMINFO" ] && MEMINFO="/host/proc/meminfo"
  if [ -r "$MEMINFO" ]; then
    grep -E "^(MemTotal|MemAvailable|MemFree|Buffers|Cached|SwapTotal|SwapFree):" "$MEMINFO" > "$OUT/node_memory_info.txt" 2>/dev/null || echo "" > "$OUT/node_memory_info.txt"
    log "Collected memory information"
  fi
fi

# Network policy rules (Kubernetes and CNI-specific)
log "Checking network policy enforcement..."

# Kubernetes NetworkPolicies (cluster-wide)
if command -v kubectl >/dev/null 2>&1; then
  kubectl get networkpolicies --all-namespaces -o json > "$OUT/node_k8s_networkpolicies.json" 2>/dev/null || echo "[]" > "$OUT/node_k8s_networkpolicies.json"
  NP_COUNT=$(jq -r 'length' "$OUT/node_k8s_networkpolicies.json" 2>/dev/null || echo "0")
  log "Collected $NP_COUNT Kubernetes NetworkPolicy(ies)"
fi

# Calico-specific (if available)
if command -v calicoctl >/dev/null 2>&1; then
  calicoctl get networkpolicies --all-namespaces -o yaml > "$OUT/node_calico_networkpolicies.yaml" 2>/dev/null || echo "" > "$OUT/node_calico_networkpolicies.yaml"
  log "Collected Calico network policies"
fi

# Check for Cilium (eBPF programs)
if [ -d /sys/fs/bpf/tc/globals ] || [ -d /host/sys/fs/bpf/tc/globals ]; then
  BPF_DIR="/sys/fs/bpf"
  [ ! -d "$BPF_DIR" ] && BPF_DIR="/host/sys/fs/bpf"
  if [ -d "$BPF_DIR" ]; then
    find "$BPF_DIR" -type f 2>/dev/null | head -50 > "$OUT/node_bpf_programs.txt" 2>/dev/null || echo "" > "$OUT/node_bpf_programs.txt"
    log "Found BPF programs (Cilium/other eBPF CNI)"
  fi
fi

# Clean up temporary pod if we created one
if [ "${CLEANUP_TEMP_POD:-0}" = "1" ] && [ -n "${TEMP_POD_NAME:-}" ]; then
  log "Cleaning up temporary pod..."
  kubectl delete pod "$TEMP_POD_NAME" >/dev/null 2>&1 || true
fi

log "Done. Output directory: $OUT"
