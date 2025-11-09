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

log "Done. Output directory: $OUT"
