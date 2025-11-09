#!/usr/bin/env bash
set -euo pipefail

NODE="${1:?usage: sgfp_node_diag.sh <node-name>}"
OUT="sgfp_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

log()  { printf "[NODE] %s\n" "$*"; }
warn() { printf "[NODE] WARN: %s\n" "$*" >&2; }

log "Collecting node diagnostics for: $NODE"
log "Output: $OUT"

# Conntrack usage + hints
log "Checking conntrack usage..."
CONNTRACK_DATA=""
if [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
  COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
  MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max   2>/dev/null || echo 0)
  if [ "$COUNT" != "0" ] || [ "$MAX" != "0" ]; then
    CONNTRACK_DATA="$COUNT / $MAX"
    log "Conntrack: $CONNTRACK_DATA"
    echo "$CONNTRACK_DATA" > "$OUT/node_conntrack_mtu.txt"
  else
    warn "Conntrack data not available (not running on node or procfs not accessible)"
    echo "" > "$OUT/node_conntrack_mtu.txt"
  fi
else
  warn "Conntrack procfs not accessible (this script should run on the node for conntrack data)"
  echo "" > "$OUT/node_conntrack_mtu.txt"
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
    
    # Clean up temporary pod
    kubectl delete pod "$TEMP_POD_NAME" >/dev/null 2>&1 || true
    
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
  else
    warn "Failed to create temporary pod for CNI log collection"
  fi
  
  if [ "$CNI_LOGS_FOUND" -eq 0 ]; then
    warn "CNI logs not accessible (requires running on node or debug pod with /host mount)"
    echo "" > "$OUT/cni_logs/.not_accessible"
  fi
fi

log "Done. Output directory: $OUT"
