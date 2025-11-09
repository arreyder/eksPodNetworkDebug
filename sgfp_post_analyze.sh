#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:?Usage: sgfp_post_analyze.sh <sgfp_bundle_dir>}"

echo "Analyzing bundle: $BUNDLE"
POD_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'pod_*' | head -n1 || true)
NODE_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'node_*' | head -n1 || true)
AWS_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'aws_*' | head -n1 || true)

issues=0

# Pod status
if grep -q "Running" "$POD_DIR/pod_wide.txt" 2>/dev/null; then
  echo "b Pod is Running (per $POD_DIR/pod_wide.txt)"
else
  echo "! Pod is not Running (see $POD_DIR/pod_wide.txt)"; issues=$((issues+1))
fi

# SGFP readiness
if [ -s "$POD_DIR/pod_conditions.json" ] && jq -e '.[]? | select(.type=="PodReadyToStartContainers") | .status=="True"' "$POD_DIR/pod_conditions.json" >/dev/null 2>&1; then
  echo "b SG-for-Pods readiness gate True"
else
  echo "! SG-for-Pods readiness gate not True (see $POD_DIR/pod_conditions.json)"; issues=$((issues+1))
fi

# Pod-ENI annotation
if [ -s "$POD_DIR/pod_annotations.json" ] && jq -er '."vpc.amazonaws.com/pod-eni"' "$POD_DIR/pod_annotations.json" >/dev/null 2>&1; then
  echo "b Pod ENI annotation present"
else
  echo "! Missing pod-eni annotation (see $POD_DIR/pod_annotations.json)"; issues=$((issues+1))
fi

# Routing tables
if grep -Eq 'table (100|101)' "$POD_DIR/pod_netns_routes_rules.txt" 2>/dev/null; then
  echo "b Per-pod routing table present"
else
  echo "! No non-main policy tables found in pod netns (see $POD_DIR/pod_netns_routes_rules.txt)"; issues=$((issues+1))
fi

# aws-node log quick scan
if [ -s "$POD_DIR/aws_node_full.log" ]; then
  if grep -Eiq 'rate.?exceeded|throttl|attach|branch|trunk|fail|error' "$POD_DIR/aws_node_full.log"; then
    echo "! CNI events in aws-node logs (see $POD_DIR/aws_node_full.log)"; issues=$((issues+1))
  else
    echo "b aws-node logs look clean ($POD_DIR/aws_node_full.log)"
  fi
fi

# Conntrack
if [ -s "$NODE_DIR/node_conntrack_mtu.txt" ]; then
  PAIR=$(grep -Eo '[0-9]+\s*/\s*[0-9]+' "$NODE_DIR/node_conntrack_mtu.txt" | head -1 || true)
  if [ -n "$PAIR" ]; then
    echo "b Conntrack snapshot: $PAIR ($NODE_DIR/node_conntrack_mtu.txt)"
  fi
  if grep -Eiq 'nf_conntrack|fragmentation needed|blackhole' "$NODE_DIR/node_conntrack_mtu.txt"; then
    echo "! Kernel logs show conntrack/fragmentation/blackhole hints. See $NODE_DIR/node_conntrack_mtu.txt"; issues=$((issues+1))
  fi
fi

# AWS ENI
if [ -s "$AWS_DIR/trunk_eni.json" ] && jq -e '.NetworkInterfaces or .[0]?' "$AWS_DIR/trunk_eni.json" >/dev/null 2>&1; then
  echo "b Trunk ENI present ($AWS_DIR/trunk_eni.json)"
else
  echo "! Trunk ENI not present or not described ($AWS_DIR/trunk_eni.json)"; issues=$((issues+1))
fi

echo
echo "[!] Potential issues found: $issues"
