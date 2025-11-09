#!/usr/bin/env bash
set -euo pipefail

NODE="${1:?usage: sgfp_node_diag.sh <node-name>}"
OUT="sgfp_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

# Conntrack usage + hints
{
  # try procfs first
  if [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && [ -r /proc/sys/net/netfilter/nf_conntrack_max ]; then
    COUNT=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo 0)
    MAX=$(cat /proc/sys/net/netfilter/nf_conntrack_max   2>/dev/null || echo 0)
    echo "$COUNT / $MAX"
  fi
  # node kernel messages (needs node access; we use aws-node logs as a proxy)
  kubectl -n kube-system logs -l k8s-app=aws-node --tail=200 --since=30m > /dev/null 2>&1 || true
} | tee "$OUT/node_conntrack_mtu.txt" >/dev/null

# Also capture aws-node logs (cluster scope best-effort)
kubectl -n kube-system logs -l k8s-app=aws-node --tail=200 --since=30m > "$OUT/aws_node_full.log" 2>/dev/null || true
