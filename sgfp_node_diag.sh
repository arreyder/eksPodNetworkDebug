#!/usr/bin/env bash
set -euo pipefail

NODE="${1:?usage: sgfp_node_diag.sh <node-name> [data-dir]}"
DATA_DIR="${2:-data/unknown}"
mkdir -p "$DATA_DIR"
OUT="$DATA_DIR/sgfp_diag_$(date +%Y%m%d_%H%M%S)"
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
  # Use ubuntu image instead of busybox for better tool availability (iptables, etc.)
  if kubectl run "$TEMP_POD_NAME" \
    --image=ubuntu:latest \
    --restart=Never \
    --overrides="{\"spec\":{\"nodeName\":\"$NODE\",\"hostNetwork\":true,\"hostPID\":true,\"hostIPC\":true,\"containers\":[{\"name\":\"collector\",\"image\":\"ubuntu:latest\",\"command\":[\"sleep\",\"300\"],\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"name\":\"host-root\",\"mountPath\":\"/host\"}]}],\"volumes\":[{\"name\":\"host-root\",\"hostPath\":{\"path\":\"/\"}}]}}" \
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
IPTABLES_COLLECTED=0
if command -v iptables >/dev/null 2>&1; then
  if iptables -L -n -v > "$OUT/node_iptables_filter.txt" 2>/dev/null && iptables -t nat -L -n -v > "$OUT/node_iptables_nat.txt" 2>/dev/null; then
    log "Collected iptables rules"
    IPTABLES_COLLECTED=1
  else
    echo "" > "$OUT/node_iptables_filter.txt"
    echo "" > "$OUT/node_iptables_nat.txt"
  fi
fi

# Try to collect iptables via temporary pod if direct access didn't work
if [ "$IPTABLES_COLLECTED" -eq 0 ] && [ "${TEMP_POD_AVAILABLE:-0}" = "1" ] && [ -n "${TEMP_POD_NAME:-}" ]; then
  log "Collecting iptables rules via temporary pod..."
  # Try iptables command first, then fall back to reading from /host/proc if available
  # busybox may not have iptables, but we can try to read from /host/sys or use nsenter
  if kubectl exec "$TEMP_POD_NAME" -- sh -c "command -v iptables >/dev/null 2>&1 && iptables -L -n -v 2>/dev/null || true" > "$OUT/node_iptables_filter.txt" 2>/dev/null; then
    if kubectl exec "$TEMP_POD_NAME" -- sh -c "command -v iptables >/dev/null 2>&1 && iptables -t nat -L -n -v 2>/dev/null || true" > "$OUT/node_iptables_nat.txt" 2>/dev/null; then
      if [ -s "$OUT/node_iptables_filter.txt" ] || [ -s "$OUT/node_iptables_nat.txt" ]; then
        log "Collected iptables rules via temporary pod"
        IPTABLES_COLLECTED=1
      fi
    fi
  fi
  # If busybox doesn't have iptables, try using nsenter to run iptables from host namespace
  if [ "$IPTABLES_COLLECTED" -eq 0 ]; then
    if kubectl exec "$TEMP_POD_NAME" -- sh -c "nsenter --target 1 --mount --uts --ipc --net --pid iptables -L -n -v 2>/dev/null || true" > "$OUT/node_iptables_filter.txt" 2>/dev/null; then
      if kubectl exec "$TEMP_POD_NAME" -- sh -c "nsenter --target 1 --mount --uts --ipc --net --pid iptables -t nat -L -n -v 2>/dev/null || true" > "$OUT/node_iptables_nat.txt" 2>/dev/null; then
        if [ -s "$OUT/node_iptables_filter.txt" ] || [ -s "$OUT/node_iptables_nat.txt" ]; then
          log "Collected iptables rules via temporary pod (using nsenter)"
          IPTABLES_COLLECTED=1
        fi
      fi
    fi
  fi
fi

if [ "$IPTABLES_COLLECTED" -eq 0 ]; then
  echo "" > "$OUT/node_iptables_filter.txt"
  echo "" > "$OUT/node_iptables_nat.txt"
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

# Reverse path filtering (rp_filter) - important for pod ENI and asymmetric routing
log "Collecting reverse path filtering (rp_filter) settings..."
RP_FILTER_COLLECTED=0
if [ -d /proc/sys/net/ipv4/conf ]; then
  # Collect rp_filter for all interfaces
  for iface_dir in /proc/sys/net/ipv4/conf/*; do
    if [ -d "$iface_dir" ] && [ -r "$iface_dir/rp_filter" ]; then
      iface_name=$(basename "$iface_dir")
      rp_value=$(cat "$iface_dir/rp_filter" 2>/dev/null | tr -d '[:space:]' || echo "")
      if [ -n "$rp_value" ]; then
        echo "$iface_name=$rp_value" >> "$OUT/node_rp_filter.txt" 2>/dev/null || true
        RP_FILTER_COLLECTED=1
      fi
    fi
  done
  if [ "$RP_FILTER_COLLECTED" -eq 1 ]; then
    log "Collected rp_filter settings"
  else
    echo "" > "$OUT/node_rp_filter.txt"
  fi
elif [ -d /host/proc/sys/net/ipv4/conf ]; then
  # Try via /host mount (for temporary debug pods)
  for iface_dir in /host/proc/sys/net/ipv4/conf/*; do
    if [ -d "$iface_dir" ] && [ -r "$iface_dir/rp_filter" ]; then
      iface_name=$(basename "$iface_dir")
      rp_value=$(cat "$iface_dir/rp_filter" 2>/dev/null | tr -d '[:space:]' || echo "")
      if [ -n "$rp_value" ]; then
        echo "$iface_name=$rp_value" >> "$OUT/node_rp_filter.txt" 2>/dev/null || true
        RP_FILTER_COLLECTED=1
      fi
    fi
  done
  if [ "$RP_FILTER_COLLECTED" -eq 1 ]; then
    log "Collected rp_filter settings (via /host mount)"
  else
    echo "" > "$OUT/node_rp_filter.txt"
  fi
else
  echo "" > "$OUT/node_rp_filter.txt"
fi

# Try to collect rp_filter via temporary pod if direct access didn't work
if [ "$RP_FILTER_COLLECTED" -eq 0 ] && [ "${TEMP_POD_AVAILABLE:-0}" = "1" ] && [ -n "${TEMP_POD_NAME:-}" ] && command -v kubectl >/dev/null 2>&1; then
  log "Collecting rp_filter settings via temporary pod..."
  if kubectl exec "$TEMP_POD_NAME" -- sh -c "for iface_dir in /host/proc/sys/net/ipv4/conf/*; do if [ -d \"\$iface_dir\" ] && [ -r \"\$iface_dir/rp_filter\" ]; then iface_name=\$(basename \"\$iface_dir\"); rp_value=\$(cat \"\$iface_dir/rp_filter\" 2>/dev/null | tr -d '[:space:]' || echo ''); if [ -n \"\$rp_value\" ]; then echo \"\$iface_name=\$rp_value\"; fi; fi; done" > "$OUT/node_rp_filter.txt" 2>/dev/null; then
    if [ -s "$OUT/node_rp_filter.txt" ]; then
      RP_FILTER_COLLECTED=1
      log "Collected rp_filter settings via temporary pod"
    else
      echo "" > "$OUT/node_rp_filter.txt"
    fi
  else
    echo "" > "$OUT/node_rp_filter.txt"
  fi
fi

# Collect pod IP map for orphaned namespace detection (before namespace collection)
log "Collecting pod IP map for namespace matching..."
if command -v kubectl >/dev/null 2>&1; then
  # Build map of podIP -> namespace/name (only active, non-terminating pods)
  # Format: IP namespace/name phase
  kubectl get pods -A -o json 2>/dev/null | jq -r '.items[] | 
    select(.status.podIP != null and .status.podIP != "") | 
    select(.status.phase != "Failed") | 
    select(.metadata.deletionTimestamp == null) | 
    "\(.status.podIP) \(.metadata.namespace)/\(.metadata.name) \(.status.phase)"' \
    | sort > "$OUT/node_pod_ip_map.txt" 2>/dev/null || echo "" > "$OUT/node_pod_ip_map.txt"
  
  # Also collect IPv6 IPs if present
  kubectl get pods -A -o json 2>/dev/null | jq -r '.items[] | 
    select(.status.podIPs != null) | 
    .status.podIPs[]? | 
    select(.ip != null and .ip != "") | 
    select(.ip | test(":")) |  # IPv6 addresses contain ":"
    "\(.ip) \(.metadata.namespace)/\(.metadata.name)"' \
    | sort > "$OUT/node_pod_ipv6_map.txt" 2>/dev/null || touch "$OUT/node_pod_ipv6_map.txt"
  
  POD_IP_MAP_COUNT=$(wc -l < "$OUT/node_pod_ip_map.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  POD_IPV6_MAP_COUNT=$(wc -l < "$OUT/node_pod_ipv6_map.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  log "Collected $POD_IP_MAP_COUNT IPv4 pod IP(s) and $POD_IPV6_MAP_COUNT IPv6 pod IP(s) for namespace matching"
else
  echo "" > "$OUT/node_pod_ip_map.txt"
  touch "$OUT/node_pod_ipv6_map.txt"
  warn "kubectl not available, cannot collect pod IP map"
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

# Helper function to get all IPs from a namespace (IPv4 and IPv6)
get_namespace_ips() {
  local ns_name="$1"
  local via_pod="${2:-}"
  local ns_file_path="${3:-}"
  local ipv4_ips=""
  local ipv6_ips=""
  
  if [ -n "$via_pod" ]; then
    # Via temporary pod - use exact same commands as user's manual check
    # Enter host namespace with nsenter --target 1, then use ip -n to access network namespace
    # Tools are already in the pod and in PATH, no need to find them
    
    # Method 1: Enter host namespace, then use ip -n (exact match to user's manual check)
    ipv4_ips=$(kubectl exec "$via_pod" -- sh -c "nsenter --target 1 --mount --uts --ipc --net --pid ip -n \"$ns_name\" -o -4 addr show dev eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
    ipv6_ips=$(kubectl exec "$via_pod" -- sh -c "nsenter --target 1 --mount --uts --ipc --net --pid ip -n \"$ns_name\" -o -6 addr show dev eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
    
    # Method 2: If no IPs found with eth0, try all interfaces
    if [ -z "$ipv4_ips" ] && [ -z "$ipv6_ips" ]; then
      ipv4_ips=$(kubectl exec "$via_pod" -- sh -c "nsenter --target 1 --mount --uts --ipc --net --pid ip -n \"$ns_name\" -o -4 addr show 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
      ipv6_ips=$(kubectl exec "$via_pod" -- sh -c "nsenter --target 1 --mount --uts --ipc --net --pid ip -n \"$ns_name\" -o -6 addr show 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
    fi
  else
    # Direct access - use ip netns exec (more reliable)
    ipv4_ips=$(ip netns exec "$ns_name" ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ' || echo "")
    ipv6_ips=$(ip netns exec "$ns_name" ip -o -6 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ' || echo "")
  fi
  
  # Return as JSON array
  local ipv4_json="[]"
  local ipv6_json="[]"
  if [ -n "$ipv4_ips" ]; then
    ipv4_json=$(echo "$ipv4_ips" | tr ' ' '\n' | grep -v '^$' | jq -R . | jq -s . 2>/dev/null || echo "[]")
  fi
  if [ -n "$ipv6_ips" ]; then
    ipv6_json=$(echo "$ipv6_ips" | tr ' ' '\n' | grep -v '^$' | jq -R . | jq -s . 2>/dev/null || echo "[]")
  fi
  
  echo "{\"ipv4\": $ipv4_json, \"ipv6\": $ipv6_json}"
}

# Helper function to get process count in namespace
get_namespace_process_count() {
  local ns_name="$1"
  local via_pod="${2:-}"
  local proc_count="0"
  
  if [ -n "$via_pod" ]; then
    # Via temporary pod - use ip netns pids (most reliable method)
    # This lists PIDs that are actually in the network namespace
    proc_count=$(kubectl exec "$via_pod" -- sh -c "ip netns pids \"$ns_name\" 2>/dev/null | wc -l || echo 0" 2>/dev/null | tr -d '[:space:]' || echo "0")
    
    # If ip netns pids doesn't work, try alternative: check if namespace is accessible
    # If namespace has no interfaces and ip netns pids fails, it's likely truly empty
    if [ "$proc_count" = "0" ] || [ -z "$proc_count" ]; then
      # Try to verify namespace is accessible - if not, process count is 0
      if ! kubectl exec "$via_pod" -- sh -c "ip netns exec \"$ns_name\" true 2>/dev/null" >/dev/null 2>&1; then
        proc_count="0"
      fi
    fi
  else
    # Direct access - use ip netns pids (lists PIDs in the network namespace)
    proc_count=$(ip netns pids "$ns_name" 2>/dev/null | wc -l | tr -d '[:space:]' || echo "0")
  fi
  
  echo "$proc_count"
}

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
    
    # Check if namespace is actually active (not just a stale file)
    NS_ACTIVE=0
    if kubectl exec "$TEMP_POD_NAME" -- sh -c "ip netns exec \"$NS_NAME\" true 2>/dev/null" >/dev/null 2>&1; then
      NS_ACTIVE=1
    fi
    
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
    
    # Get actual IP addresses (IPv4 and IPv6)
    # Try with full namespace file path first (more reliable from temporary pod)
    # Check which path exists
    NS_FILE_PATH=""
    if kubectl exec "$TEMP_POD_NAME" -- sh -c "test -e /host/var/run/netns/$NS_NAME" >/dev/null 2>&1; then
      NS_FILE_PATH="/host/var/run/netns/$NS_NAME"
    elif kubectl exec "$TEMP_POD_NAME" -- sh -c "test -e /var/run/netns/$NS_NAME" >/dev/null 2>&1; then
      NS_FILE_PATH="/var/run/netns/$NS_NAME"
    fi
    
    # Also try using ip -n directly (like user's manual check) - this might work better
    # The user's manual check used: ip -n "$ns" -o -4 addr show dev eth0
    # Try this method first since it worked for the user
    NS_IPS_JSON_TMP=$(mktemp)
    if [ -n "$NS_FILE_PATH" ]; then
      # Try ip -n with nsenter to the namespace (simulating what user did)
      # First try all interfaces
      NS_IPV4_TMP=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "nsenter --net=$NS_FILE_PATH ip -o -4 addr show 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
      NS_IPV6_TMP=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "nsenter --net=$NS_FILE_PATH ip -o -6 addr show 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
      
      # If no IPs, try eth0 specifically (matches user's manual check exactly)
      if [ -z "$NS_IPV4_TMP" ] && [ -z "$NS_IPV6_TMP" ]; then
        NS_IPV4_TMP=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "nsenter --net=$NS_FILE_PATH ip -o -4 addr show dev eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
        NS_IPV6_TMP=$(kubectl exec "$TEMP_POD_NAME" -- sh -c "nsenter --net=$NS_FILE_PATH ip -o -6 addr show dev eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | tr '\n' ' ' || echo ''" 2>/dev/null | tr -d '[:space:]' || echo "")
      fi
      
      # Convert to JSON
      if [ -n "$NS_IPV4_TMP" ] || [ -n "$NS_IPV6_TMP" ]; then
        NS_IPV4_JSON="[]"
        NS_IPV6_JSON="[]"
        if [ -n "$NS_IPV4_TMP" ]; then
          NS_IPV4_JSON=$(echo "$NS_IPV4_TMP" | tr ' ' '\n' | grep -v '^$' | jq -R . | jq -s . 2>/dev/null || echo "[]")
        fi
        if [ -n "$NS_IPV6_TMP" ]; then
          NS_IPV6_JSON=$(echo "$NS_IPV6_TMP" | tr ' ' '\n' | grep -v '^$' | jq -R . | jq -s . 2>/dev/null || echo "[]")
        fi
        echo "{\"ipv4\": $NS_IPV4_JSON, \"ipv6\": $NS_IPV6_JSON}" > "$NS_IPS_JSON_TMP"
      else
        # Fall back to the helper function
        get_namespace_ips "$NS_NAME" "$TEMP_POD_NAME" "$NS_FILE_PATH" > "$NS_IPS_JSON_TMP"
      fi
    else
      # No namespace file path found, use helper function
      get_namespace_ips "$NS_NAME" "$TEMP_POD_NAME" "" > "$NS_IPS_JSON_TMP"
    fi
    NS_IPS_JSON=$(cat "$NS_IPS_JSON_TMP" 2>/dev/null || echo "{\"ipv4\": [], \"ipv6\": []}")
    rm -f "$NS_IPS_JSON_TMP" 2>/dev/null || true
    
    # Get process count in namespace
    NS_PROC_COUNT=$(get_namespace_process_count "$NS_NAME" "$TEMP_POD_NAME")
    
    # Add to JSON
    jq --arg name "$NS_NAME" \
       --arg interfaces "$NS_INTERFACES" \
       --arg ips "$NS_IPS" \
       --arg mtime "$NS_MTIME" \
       --arg active "$NS_ACTIVE" \
       --arg proc_count "$NS_PROC_COUNT" \
       --argjson ips_json "$NS_IPS_JSON" \
      '. += [{"name": $name, "interface_count": ($interfaces | tonumber), "ip_count": ($ips | tonumber), "mtime": ($mtime | tonumber), "active": ($active | tonumber), "process_count": ($proc_count | tonumber), "ips": $ips_json}]' \
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
    
    # Check if namespace is actually active
    NS_ACTIVE=0
    if ip netns exec "$NS_NAME" true 2>/dev/null; then
      NS_ACTIVE=1
    fi
    
    # Get interfaces in this namespace
    NS_INTERFACES=$(ip netns exec "$NS_NAME" ip link show 2>/dev/null | grep -E "^[0-9]+:" | wc -l | tr -d '[:space:]' || echo "0")
    # Get IPs in this namespace
    NS_IPS=$(ip netns exec "$NS_NAME" ip addr show 2>/dev/null | grep -E "inet " | wc -l | tr -d '[:space:]' || echo "0")
    # Get namespace file modification time (approximate creation time)
    NS_MTIME=$(stat -c %Y "$ns" 2>/dev/null || echo "0")
    
    # Get actual IP addresses (IPv4 and IPv6)
    # For direct access, namespace file path is not needed
    NS_IPS_JSON=$(get_namespace_ips "$NS_NAME" "" "")
    
    # Get process count in namespace
    NS_PROC_COUNT=$(get_namespace_process_count "$NS_NAME" "")
    
    # Add to JSON
    jq --arg name "$NS_NAME" \
       --arg interfaces "$NS_INTERFACES" \
       --arg ips "$NS_IPS" \
       --arg mtime "$NS_MTIME" \
       --arg active "$NS_ACTIVE" \
       --arg proc_count "$NS_PROC_COUNT" \
       --argjson ips_json "$NS_IPS_JSON" \
      '. += [{"name": $name, "interface_count": ($interfaces | tonumber), "ip_count": ($ips | tonumber), "mtime": ($mtime | tonumber), "active": ($active | tonumber), "process_count": ($proc_count | tonumber), "ips": $ips_json}]' \
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

# DNS service and CoreDNS/NodeLocal DNSCache status
log "Collecting DNS service and CoreDNS/NodeLocal DNSCache information..."
if command -v kubectl >/dev/null 2>&1; then
  # CoreDNS pods
  kubectl get pods -n kube-system -l k8s-app=kube-dns -o json > "$OUT/node_coredns_pods.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/node_coredns_pods.json"
  COREDNS_COUNT=$(jq -r '.items | length' "$OUT/node_coredns_pods.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
  log "Found $COREDNS_COUNT CoreDNS pod(s)"
  
  # NodeLocal DNSCache pods
  kubectl get pods -n kube-system -l k8s-app=node-local-dns -o json > "$OUT/node_nodelocal_dns_pods.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/node_nodelocal_dns_pods.json"
  NODELOCAL_COUNT=$(jq -r '.items | length' "$OUT/node_nodelocal_dns_pods.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
  log "Found $NODELOCAL_COUNT NodeLocal DNSCache pod(s)"
  
  # DNS service (kube-dns)
  kubectl get svc -n kube-system kube-dns -o json > "$OUT/node_dns_service.json" 2>/dev/null || echo '{}' > "$OUT/node_dns_service.json"
  
  # DNS service endpoints
  kubectl get endpoints -n kube-system kube-dns -o json > "$OUT/node_dns_endpoints.json" 2>/dev/null || echo '{}' > "$OUT/node_dns_endpoints.json"
  
  # NodeLocal DNSCache service (if exists)
  kubectl get svc -n kube-system node-local-dns -o json > "$OUT/node_nodelocal_dns_service.json" 2>/dev/null || echo '{}' > "$OUT/node_nodelocal_dns_service.json"
  
  # DNS ConfigMap (CoreDNS config)
  kubectl get configmap -n kube-system coredns -o json > "$OUT/node_coredns_config.json" 2>/dev/null || echo '{}' > "$OUT/node_coredns_config.json"
  
  # AWS VPC CNI ConfigMap (contains CNI configuration settings like branch-eni-cooldown)
  # Note: ConfigMap name is 'amazon-vpc-cni' (not 'aws-vpc-cni')
  kubectl get configmap -n kube-system amazon-vpc-cni -o json > "$OUT/node_aws_vpc_cni_config.json" 2>/dev/null || echo '{}' > "$OUT/node_aws_vpc_cni_config.json"
  
  log "Collected DNS service and CoreDNS/NodeLocal DNSCache information"
fi

# Collect pods in Pending state (for IP exhaustion analysis)
log "Collecting pods in Pending state..."
if command -v kubectl >/dev/null 2>&1; then
  # Get all pods in Pending state (all namespaces, on this node)
  # Use the NODE variable passed to the script
  if [ -n "$NODE" ]; then
    # Get pending pods on this node
    kubectl get pods --all-namespaces --field-selector spec.nodeName="$NODE",status.phase=Pending -o json > "$OUT/node_pending_pods.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/node_pending_pods.json"
    PENDING_COUNT=$(jq -r '.items | length' "$OUT/node_pending_pods.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
    log "Found $PENDING_COUNT pending pod(s) on this node"
  else
    # Fallback: get all pending pods (not node-specific)
    kubectl get pods --all-namespaces --field-selector status.phase=Pending -o json > "$OUT/node_pending_pods.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/node_pending_pods.json"
    PENDING_COUNT=$(jq -r '.items | length' "$OUT/node_pending_pods.json" 2>/dev/null | tr -d '[:space:]' || echo "0")
    log "Found $PENDING_COUNT pending pod(s) (all nodes)"
  fi
fi

# Collect version information (AMI / CNI / kernel drift detection)
log "Collecting version information..."
if command -v kubectl >/dev/null 2>&1; then
  # Node information (Kubernetes version, OS image, kernel)
  kubectl get node "$NODE" -o json > "$OUT/node_info.json" 2>/dev/null || echo '{}' > "$OUT/node_info.json"
  
  # Extract Kubernetes version
  K8S_VERSION=$(jq -r '.status.nodeInfo.kubeletVersion // .status.nodeInfo.kubeProxyVersion // ""' "$OUT/node_info.json" 2>/dev/null || echo "")
  if [ -n "$K8S_VERSION" ] && [ "$K8S_VERSION" != "null" ] && [ "$K8S_VERSION" != "" ]; then
    echo "$K8S_VERSION" > "$OUT/node_k8s_version.txt"
    log "Kubernetes version: $K8S_VERSION"
  else
    echo "" > "$OUT/node_k8s_version.txt"
  fi
  
  # Extract OS image (AMI)
  OS_IMAGE=$(jq -r '.status.nodeInfo.osImage // ""' "$OUT/node_info.json" 2>/dev/null || echo "")
  if [ -n "$OS_IMAGE" ] && [ "$OS_IMAGE" != "null" ] && [ "$OS_IMAGE" != "" ]; then
    echo "$OS_IMAGE" > "$OUT/node_os_image.txt"
    log "OS image: $OS_IMAGE"
  else
    echo "" > "$OUT/node_os_image.txt"
  fi
  
  # Extract kernel version
  KERNEL_VERSION=$(jq -r '.status.nodeInfo.kernelVersion // ""' "$OUT/node_info.json" 2>/dev/null || echo "")
  if [ -n "$KERNEL_VERSION" ] && [ "$KERNEL_VERSION" != "null" ] && [ "$KERNEL_VERSION" != "" ]; then
    echo "$KERNEL_VERSION" > "$OUT/node_kernel_version.txt"
    log "Kernel version: $KERNEL_VERSION"
  else
    echo "" > "$OUT/node_kernel_version.txt"
  fi
  
  # Extract container runtime version
  CONTAINERD_VERSION=$(jq -r '.status.nodeInfo.containerRuntimeVersion // ""' "$OUT/node_info.json" 2>/dev/null || echo "")
  if [ -n "$CONTAINERD_VERSION" ] && [ "$CONTAINERD_VERSION" != "null" ] && [ "$CONTAINERD_VERSION" != "" ]; then
    echo "$CONTAINERD_VERSION" > "$OUT/node_container_runtime_version.txt"
    log "Container runtime: $CONTAINERD_VERSION"
  else
    echo "" > "$OUT/node_container_runtime_version.txt"
  fi
  
  # aws-node DaemonSet version (from image tag) and environment variables
  kubectl get daemonset -n kube-system aws-node -o json > "$OUT/node_aws_node_daemonset.json" 2>/dev/null || echo '{}' > "$OUT/node_aws_node_daemonset.json"
  # Extract environment variables from aws-node daemonset (for settings like branch-eni-cooldown)
  if [ -s "$OUT/node_aws_node_daemonset.json" ]; then
    jq -r '.spec.template.spec.containers[0].env // []' "$OUT/node_aws_node_daemonset.json" > "$OUT/node_aws_node_env.json" 2>/dev/null || echo '[]' > "$OUT/node_aws_node_env.json"
  else
    echo '[]' > "$OUT/node_aws_node_env.json"
  fi
  AWS_NODE_IMAGE=$(jq -r '.spec.template.spec.containers[0].image // ""' "$OUT/node_aws_node_daemonset.json" 2>/dev/null || echo "")
  if [ -n "$AWS_NODE_IMAGE" ] && [ "$AWS_NODE_IMAGE" != "null" ] && [ "$AWS_NODE_IMAGE" != "" ]; then
    echo "$AWS_NODE_IMAGE" > "$OUT/node_aws_node_image.txt"
    # Extract version/tag from image
    AWS_NODE_VERSION=$(echo "$AWS_NODE_IMAGE" | sed -E 's/.*:([^@]+).*/\1/' | sed 's/@.*//' || echo "")
    if [ -n "$AWS_NODE_VERSION" ] && [ "$AWS_NODE_VERSION" != "latest" ]; then
      echo "$AWS_NODE_VERSION" > "$OUT/node_aws_node_version.txt"
      log "aws-node version: $AWS_NODE_VERSION"
    else
      echo "" > "$OUT/node_aws_node_version.txt"
    fi
  else
    echo "" > "$OUT/node_aws_node_image.txt"
    echo "" > "$OUT/node_aws_node_version.txt"
  fi
  
  # kube-proxy DaemonSet version (from image tag)
  kubectl get daemonset -n kube-system kube-proxy -o json > "$OUT/node_kube_proxy_daemonset.json" 2>/dev/null || echo '{}' > "$OUT/node_kube_proxy_daemonset.json"
  KUBE_PROXY_IMAGE=$(jq -r '.spec.template.spec.containers[0].image // ""' "$OUT/node_kube_proxy_daemonset.json" 2>/dev/null || echo "")
  if [ -n "$KUBE_PROXY_IMAGE" ] && [ "$KUBE_PROXY_IMAGE" != "null" ] && [ "$KUBE_PROXY_IMAGE" != "" ]; then
    echo "$KUBE_PROXY_IMAGE" > "$OUT/node_kube_proxy_image.txt"
    # Extract version/tag from image
    KUBE_PROXY_VERSION=$(echo "$KUBE_PROXY_IMAGE" | sed -E 's/.*:([^@]+).*/\1/' | sed 's/@.*//' || echo "")
    if [ -n "$KUBE_PROXY_VERSION" ] && [ "$KUBE_PROXY_VERSION" != "latest" ]; then
      echo "$KUBE_PROXY_VERSION" > "$OUT/node_kube_proxy_version.txt"
      log "kube-proxy version: $KUBE_PROXY_VERSION"
    else
      echo "" > "$OUT/node_kube_proxy_version.txt"
    fi
  else
    echo "" > "$OUT/node_kube_proxy_image.txt"
    echo "" > "$OUT/node_kube_proxy_version.txt"
  fi
  
  # Node labels (may contain AMI/version info)
  kubectl get node "$NODE" -o jsonpath='{.metadata.labels}' > "$OUT/node_labels.json" 2>/dev/null || echo '{}' > "$OUT/node_labels.json"
  
  log "Collected version information"
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
  kubectl get networkpolicies --all-namespaces -o json > "$OUT/node_k8s_networkpolicies.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/node_k8s_networkpolicies.json"
  NP_COUNT=$(jq -r '.items | length' "$OUT/node_k8s_networkpolicies.json" 2>/dev/null || echo "0")
  log "Collected $NP_COUNT Kubernetes NetworkPolicy(ies)"
fi

# ENIConfig (Custom Networking) - AWS VPC CNI CRD
log "Collecting ENIConfig resources (custom networking)..."
if command -v kubectl >/dev/null 2>&1; then
  # Try cluster-scoped first, then kube-system namespace
  kubectl get eniconfig -o json > "$OUT/node_eniconfigs.json" 2>/dev/null || \
    kubectl get eniconfig -n kube-system -o json > "$OUT/node_eniconfigs.json" 2>/dev/null || \
    echo '{"items":[]}' > "$OUT/node_eniconfigs.json"
  ENICONFIG_COUNT=$(jq -r '.items | length' "$OUT/node_eniconfigs.json" 2>/dev/null || echo "0")
  if [ "$ENICONFIG_COUNT" = "0" ]; then
    # Try alternative CRD name (some clusters use different naming)
    kubectl get eniconfigs -o json > "$OUT/node_eniconfigs.json" 2>/dev/null || \
      kubectl get eniconfigs -n kube-system -o json > "$OUT/node_eniconfigs.json" 2>/dev/null || \
      echo '{"items":[]}' > "$OUT/node_eniconfigs.json"
    ENICONFIG_COUNT=$(jq -r '.items | length' "$OUT/node_eniconfigs.json" 2>/dev/null || echo "0")
  fi
  if [ "$ENICONFIG_COUNT" -gt 0 ]; then
    log "Collected $ENICONFIG_COUNT ENIConfig resource(s)"
  else
    log "No ENIConfig resources found (custom networking may not be enabled)"
  fi
  
  # Collect node annotations (may contain ENIConfig references)
  kubectl get node "$NODE" -o jsonpath='{.metadata.annotations}' > "$OUT/node_annotations.json" 2>/dev/null || echo '{}' > "$OUT/node_annotations.json"
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
