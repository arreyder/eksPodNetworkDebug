#!/usr/bin/env bash
set -euo pipefail

# Compare baseline metrics with incident/diagnostic bundle
# Usage: ./sgfp_compare_baseline.sh [<baseline-dir>] <incident-bundle-dir>
#   - If <baseline-dir> is not provided, uses SGFP_BASELINE_DIR env var or .sgfp_baseline_latest file

# Determine baseline directory (priority: 2 args > env var > saved file > error)
# If 2 arguments provided, use them directly
if [ -n "${2:-}" ]; then
  BASELINE_DIR="$1"
  INCIDENT_DIR="$2"
# If 1 argument provided, try to find baseline from env var or saved file
elif [ -n "${SGFP_BASELINE_DIR:-}" ] && [ -d "$SGFP_BASELINE_DIR" ]; then
  BASELINE_DIR="$SGFP_BASELINE_DIR"
  INCIDENT_DIR="${1:?usage: sgfp_compare_baseline.sh [<baseline-dir>] <incident-bundle-dir> (or set SGFP_BASELINE_DIR)}"
elif [ -f .sgfp_baseline_latest ]; then
  BASELINE_DIR=$(cat .sgfp_baseline_latest 2>/dev/null | tr -d '[:space:]' || echo "")
  if [ -z "$BASELINE_DIR" ] || [ ! -d "$BASELINE_DIR" ]; then
    # Try to find in data directory if incident dir is provided
    if [ -n "${1:-}" ] && echo "$1" | grep -q "^data/"; then
      DATA_DIR=$(dirname "$(dirname "$1")")
      if [ -f "$DATA_DIR/.sgfp_baseline_latest" ]; then
        BASELINE_DIR=$(cat "$DATA_DIR/.sgfp_baseline_latest" 2>/dev/null | tr -d '[:space:]' || echo "")
      fi
    fi
    if [ -z "$BASELINE_DIR" ] || [ ! -d "$BASELINE_DIR" ]; then
      echo "Error: Saved baseline directory not found or invalid: $BASELINE_DIR" >&2
      echo "Usage: ./sgfp_compare_baseline.sh [<baseline-dir>] <incident-bundle-dir>" >&2
      echo "   Or: export SGFP_BASELINE_DIR=<baseline-dir>" >&2
      exit 1
    fi
  fi
  INCIDENT_DIR="${1:?usage: sgfp_compare_baseline.sh [<baseline-dir>] <incident-bundle-dir>}"
else
  # Try to find .sgfp_baseline_latest in data directory if incident dir is provided
  if [ -n "${1:-}" ] && echo "$1" | grep -q "^data/"; then
    DATA_DIR=$(dirname "$(dirname "$1")")
    if [ -f "$DATA_DIR/.sgfp_baseline_latest" ]; then
      BASELINE_DIR=$(cat "$DATA_DIR/.sgfp_baseline_latest" 2>/dev/null | tr -d '[:space:]' || echo "")
      if [ -n "$BASELINE_DIR" ] && [ -d "$BASELINE_DIR" ]; then
        INCIDENT_DIR="${1:?usage: sgfp_compare_baseline.sh [<baseline-dir>] <incident-bundle-dir>}"
      fi
    fi
  fi
  if [ -z "${BASELINE_DIR:-}" ] || [ ! -d "${BASELINE_DIR:-}" ]; then
    echo "Error: Baseline directory not specified and not found in:" >&2
    echo "  - Command argument (provide 2 arguments: <baseline-dir> <incident-dir>)" >&2
    echo "  - SGFP_BASELINE_DIR environment variable" >&2
    echo "  - .sgfp_baseline_latest file (root or in data/<context>/)" >&2
  echo "" >&2
  echo "Usage: ./sgfp_compare_baseline.sh [<baseline-dir>] <incident-bundle-dir>" >&2
  echo "   Or: export SGFP_BASELINE_DIR=<baseline-dir>" >&2
  exit 1
fi

if [ ! -d "$BASELINE_DIR" ]; then
  echo "Error: Baseline directory not found: $BASELINE_DIR" >&2
  exit 1
fi

if [ ! -d "$INCIDENT_DIR" ]; then
  echo "Error: Incident directory not found: $INCIDENT_DIR" >&2
  exit 1
fi

log()  { printf "[COMPARE] %s\n" "$*"; }
warn() { printf "[COMPARE] WARN: %s\n" "$*" >&2; }

log "Comparing baseline vs incident state"
log "Baseline: $BASELINE_DIR"
log "Incident: $INCIDENT_DIR"
[ -n "${SGFP_BASELINE_DIR:-}" ] && log "Using SGFP_BASELINE_DIR environment variable"

echo ""
echo "=== Resource Usage Comparison ==="

# Compare kubectl top pods
if [ -s "$BASELINE_DIR/kubectl_top_pods.txt" ] && [ -s "$INCIDENT_DIR/kubectl_top_pods.txt" ]; then
  BASELINE_PODS=$(wc -l < "$BASELINE_DIR/kubectl_top_pods.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  INCIDENT_PODS=$(wc -l < "$INCIDENT_DIR/kubectl_top_pods.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  echo "[INFO] Pod metrics: Baseline=$BASELINE_PODS, Incident=$INCIDENT_PODS"
  
  # Compare specific pod CPU/memory if available
  # This is a simplified comparison - could be enhanced
else
  echo "[INFO] Pod metrics not available for comparison"
fi

# Compare kubectl top nodes
if [ -s "$BASELINE_DIR/kubectl_top_nodes.txt" ] && [ -s "$INCIDENT_DIR/kubectl_top_nodes.txt" ]; then
  BASELINE_NODES=$(wc -l < "$BASELINE_DIR/kubectl_top_nodes.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  INCIDENT_NODES=$(wc -l < "$INCIDENT_DIR/kubectl_top_nodes.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  echo "[INFO] Node metrics: Baseline=$BASELINE_NODES, Incident=$INCIDENT_NODES"
else
  echo "[INFO] Node metrics not available for comparison"
fi

# Compare pod counts
if [ -s "$BASELINE_DIR/cluster_pods.json" ] && [ -s "$INCIDENT_DIR/cluster_pods.json" ]; then
  BASELINE_POD_COUNT=$(jq -r '.items | length' "$BASELINE_DIR/cluster_pods.json" 2>/dev/null || echo "0")
  INCIDENT_POD_COUNT=$(jq -r '.items | length' "$INCIDENT_DIR/cluster_pods.json" 2>/dev/null || echo "0")
  echo "[INFO] Total pods: Baseline=$BASELINE_POD_COUNT, Incident=$INCIDENT_POD_COUNT"
  
  if [ "$BASELINE_POD_COUNT" != "$INCIDENT_POD_COUNT" ]; then
    DIFF=$((INCIDENT_POD_COUNT - BASELINE_POD_COUNT))
    if [ "$DIFF" -gt 0 ]; then
      echo "[INFO] Pod count increased by $DIFF"
    else
      echo "[WARN] Pod count decreased by $((DIFF * -1))"
    fi
  fi
fi

# Compare pending pods
if [ -s "$BASELINE_DIR/pending_pods_count.txt" ] && [ -s "$INCIDENT_DIR/pending_pods_count.txt" ]; then
  BASELINE_PENDING=$(cat "$BASELINE_DIR/pending_pods_count.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  INCIDENT_PENDING=$(cat "$INCIDENT_DIR/pending_pods_count.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  echo "[INFO] Pending pods: Baseline=$BASELINE_PENDING, Incident=$INCIDENT_PENDING"
  
  if [ "$INCIDENT_PENDING" -gt "$BASELINE_PENDING" ]; then
    DIFF=$((INCIDENT_PENDING - BASELINE_PENDING))
    echo "[WARN] Pending pods increased by $DIFF (may indicate IP exhaustion or scheduling issues)"
  fi
fi

# Compare pods with pod ENI
if [ -s "$BASELINE_DIR/pods_with_pod_eni.txt" ] && [ -s "$INCIDENT_DIR/pods_with_pod_eni.txt" ]; then
  BASELINE_ENI=$(cat "$BASELINE_DIR/pods_with_pod_eni.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  INCIDENT_ENI=$(cat "$INCIDENT_DIR/pods_with_pod_eni.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  echo "[INFO] Pods with pod ENI: Baseline=$BASELINE_ENI, Incident=$INCIDENT_ENI"
fi

echo ""
echo "=== Metrics Comparison ==="
echo "[INFO] Detailed metrics comparison:"
echo "  - Baseline metrics: $BASELINE_DIR/"
echo "  - Incident metrics: $INCIDENT_DIR/"
echo ""
echo "[INFO] Key metrics to compare manually:"
echo "  - CoreDNS metrics: coredns_*_metrics.txt"
echo "  - aws-node metrics: aws_node_*_metrics.txt"
echo "  - kube-proxy metrics: kube_proxy_*_metrics.txt"
echo "  - kubelet metrics: kubelet_*_metrics.txt"

log "Comparison complete"

