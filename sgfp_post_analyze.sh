#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:?Usage: sgfp_post_analyze.sh <sgfp_bundle_dir>}"

if [ ! -d "$BUNDLE" ]; then
  echo "ERROR: Bundle directory does not exist: $BUNDLE" >&2
  exit 1
fi

echo "[ANALYZE] Analyzing bundle: $BUNDLE"
POD_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'pod_*' | head -n1 || true)
NODE_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'node_*' | head -n1 || true)
AWS_DIR=$(find "$BUNDLE" -maxdepth 1 -type d -name 'aws_*' | head -n1 || true)

if [ -z "$POD_DIR" ] || [ ! -d "$POD_DIR" ]; then
  echo "[ANALYZE] ERROR: Pod directory not found in bundle: $BUNDLE" >&2
  exit 1
fi

issues=0

# Pod status
if [ -f "$POD_DIR/pod_wide.txt" ] && grep -q "Running" "$POD_DIR/pod_wide.txt" 2>/dev/null; then
  echo "[ANALYZE] OK: Pod is Running"
else
  echo "[ANALYZE] ISSUE: Pod is not Running (see $POD_DIR/pod_wide.txt)"; issues=$((issues+1))
fi

# SGFP readiness
if [ -s "$POD_DIR/pod_conditions.json" ] && jq -e '.[]? | select(.type=="PodReadyToStartContainers") | .status=="True"' "$POD_DIR/pod_conditions.json" >/dev/null 2>&1; then
  echo "[ANALYZE] OK: SG-for-Pods readiness gate True"
else
  echo "[ANALYZE] ISSUE: SG-for-Pods readiness gate not True (see $POD_DIR/pod_conditions.json)"; issues=$((issues+1))
fi

# Pod-ENI annotation
if [ -s "$POD_DIR/pod_annotations.json" ] && jq -er '."vpc.amazonaws.com/pod-eni"' "$POD_DIR/pod_annotations.json" >/dev/null 2>&1; then
  echo "[ANALYZE] OK: Pod ENI annotation present"
  
  # Check Security Group validation
  if [ -s "$POD_DIR/pod_branch_eni_sgs.txt" ]; then
    ACTUAL_SGS="$POD_DIR/pod_branch_eni_sgs.txt"
    EXPECTED_SGS=""
    # Check for expected SGs, but only if file has non-whitespace content
    if [ -f "$POD_DIR/pod_expected_sgs.txt" ] && [ -s "$POD_DIR/pod_expected_sgs.txt" ] && [ -n "$(grep -v '^[[:space:]]*$' "$POD_DIR/pod_expected_sgs.txt" 2>/dev/null || true)" ]; then
      EXPECTED_SGS="$POD_DIR/pod_expected_sgs.txt"
    elif [ -f "$POD_DIR/deployment_expected_sgs.txt" ] && [ -s "$POD_DIR/deployment_expected_sgs.txt" ] && [ -n "$(grep -v '^[[:space:]]*$' "$POD_DIR/deployment_expected_sgs.txt" 2>/dev/null || true)" ]; then
      EXPECTED_SGS="$POD_DIR/deployment_expected_sgs.txt"
    elif [ -f "$POD_DIR/replicaset_expected_sgs.txt" ] && [ -s "$POD_DIR/replicaset_expected_sgs.txt" ] && [ -n "$(grep -v '^[[:space:]]*$' "$POD_DIR/replicaset_expected_sgs.txt" 2>/dev/null || true)" ]; then
      EXPECTED_SGS="$POD_DIR/replicaset_expected_sgs.txt"
    elif [ -f "$POD_DIR/namespace_expected_sgs.txt" ] && [ -s "$POD_DIR/namespace_expected_sgs.txt" ] && [ -n "$(grep -v '^[[:space:]]*$' "$POD_DIR/namespace_expected_sgs.txt" 2>/dev/null || true)" ]; then
      EXPECTED_SGS="$POD_DIR/namespace_expected_sgs.txt"
    fi
    
    if [ -n "$EXPECTED_SGS" ] && [ -s "$EXPECTED_SGS" ]; then
      TMP_ACTUAL=$(mktemp) && sort "$ACTUAL_SGS" > "$TMP_ACTUAL" 2>/dev/null || true
      TMP_EXPECTED=$(mktemp) && grep -v '^[[:space:]]*$' "$EXPECTED_SGS" 2>/dev/null | sort > "$TMP_EXPECTED" 2>/dev/null || true
      if [ -s "$TMP_EXPECTED" ] && cmp -s "$TMP_ACTUAL" "$TMP_EXPECTED" 2>/dev/null; then
        echo "[ANALYZE] OK: Pod Security Groups match expected"
      else
        echo "[ANALYZE] ISSUE: Pod Security Groups mismatch (see $POD_DIR/pod_branch_eni_sgs.txt vs expected)"; issues=$((issues+1))
      fi
      rm -f "$TMP_ACTUAL" "$TMP_EXPECTED" 2>/dev/null || true
    else
      echo "[ANALYZE] INFO: Pod Security Groups: $(wc -l < "$ACTUAL_SGS" | tr -d '[:space:]') SG(s) attached (no expected SGs specified)"
    fi
  fi
else
  echo "[ANALYZE] ISSUE: Missing pod-eni annotation (see $POD_DIR/pod_annotations.json)"; issues=$((issues+1))
fi

# Routing tables
if [ -s "$POD_DIR/pod_netns_routes_rules.txt" ]; then
  if grep -qi "not available" "$POD_DIR/pod_netns_routes_rules.txt" 2>/dev/null; then
    echo "[ANALYZE] INFO: Per-pod routing table check skipped (network tools not available in pod)"
  elif grep -Eq 'table (100|101)' "$POD_DIR/pod_netns_routes_rules.txt" 2>/dev/null; then
    echo "[ANALYZE] OK: Per-pod routing table present"
  else
    echo "[ANALYZE] ISSUE: No non-main policy tables found in pod netns (see $POD_DIR/pod_netns_routes_rules.txt)"; issues=$((issues+1))
  fi
else
  echo "[ANALYZE] INFO: Per-pod routing table data not collected"
fi

# aws-node log quick scan
if [ -s "$POD_DIR/aws_node_full.log" ]; then
  if grep -Eiq 'rate.?exceeded|throttl|attach|branch|trunk|fail|error' "$POD_DIR/aws_node_full.log"; then
    echo "[ANALYZE] ISSUE: CNI events in aws-node logs (see $POD_DIR/aws_node_full.log)"; issues=$((issues+1))
  else
    echo "[ANALYZE] OK: aws-node logs look clean"
  fi
fi

# Conntrack
if [ -n "$NODE_DIR" ] && [ -d "$NODE_DIR" ] && [ -s "$NODE_DIR/node_conntrack_mtu.txt" ]; then
  PAIR=$(grep -Eo '[0-9]+\s*/\s*[0-9]+' "$NODE_DIR/node_conntrack_mtu.txt" | head -1 || true)
  if [ -n "$PAIR" ]; then
    echo "[ANALYZE] OK: Conntrack snapshot: $PAIR"
  fi
  if grep -Eiq 'nf_conntrack|fragmentation needed|blackhole' "$NODE_DIR/node_conntrack_mtu.txt"; then
    echo "[ANALYZE] ISSUE: Kernel logs show conntrack/fragmentation/blackhole hints. See $NODE_DIR/node_conntrack_mtu.txt"; issues=$((issues+1))
  fi
else
  echo "[ANALYZE] INFO: Conntrack data not available (node diagnostics may be missing)"
fi

# AWS ENI
if [ -n "$AWS_DIR" ] && [ -d "$AWS_DIR" ] && [ -s "$AWS_DIR/trunk_eni.json" ] && jq -e '.NetworkInterfaces or .[0]?' "$AWS_DIR/trunk_eni.json" >/dev/null 2>&1; then
  echo "[ANALYZE] OK: Trunk ENI present"
else
  echo "[ANALYZE] ISSUE: Trunk ENI not present or not described ($AWS_DIR/trunk_eni.json)"; issues=$((issues+1))
fi

echo "[ANALYZE] Potential issues found: $issues"
