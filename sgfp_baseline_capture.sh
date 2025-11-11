#!/usr/bin/env bash
set -euo pipefail

# Baseline metrics capture script
# Captures current state of cluster metrics for comparison during incidents
# Usage: ./sgfp_baseline_capture.sh [--label <label>]

# Helper function to get kubectl context and sanitize for directory names
get_kubectl_context() {
  local context
  if command -v kubectl >/dev/null 2>&1; then
    context=$(kubectl config current-context 2>/dev/null || echo "unknown")
  else
    context="unknown"
  fi
  # Sanitize: replace special chars with dashes, remove leading/trailing dashes
  echo "$context" | sed 's/[^a-zA-Z0-9._-]/-/g' | sed 's/^-\+//;s/-\+$//' | sed 's/-\+/-/g'
}

LABEL="${1:-}"
if [ -n "$LABEL" ] && [ "$LABEL" != "--label" ]; then
  LABEL="$1"
elif [ "$1" = "--label" ] && [ -n "${2:-}" ]; then
  LABEL="$2"
fi

KUBECTL_CONTEXT=$(get_kubectl_context)
DATA_DIR="data/${KUBECTL_CONTEXT}"
mkdir -p "$DATA_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT="$DATA_DIR/sgfp_baseline_${LABEL:+${LABEL}_}${TIMESTAMP}"
mkdir -p "$OUT"

log()  { printf "[BASELINE] %s\n" "$*"; }
warn() { printf "[BASELINE] WARN: %s\n" "$*" >&2; }

log "Capturing baseline metrics snapshot"
log "Cluster: ${KUBECTL_CONTEXT}"
log "Output: $OUT"
[ -n "$LABEL" ] && log "Label: $LABEL"

# Check dependencies
for cmd in kubectl jq curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    warn "Missing dependency: $cmd (some metrics may not be collected)"
  fi
done

# Capture timestamp
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$OUT/timestamp.txt" 2>/dev/null || date -u +"%Y-%m-%d %H:%M:%S" > "$OUT/timestamp.txt"
log "Timestamp: $(cat "$OUT/timestamp.txt")"

# 1. kubectl top pods (all namespaces)
log "Collecting kubectl top pods..."
if command -v kubectl >/dev/null 2>&1; then
  # Get top pods with CPU and memory
  kubectl top pods --all-namespaces --no-headers > "$OUT/kubectl_top_pods.txt" 2>/dev/null || echo "" > "$OUT/kubectl_top_pods.txt"
  POD_COUNT=$(wc -l < "$OUT/kubectl_top_pods.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$POD_COUNT" -gt 0 ]; then
    log "Collected metrics for $POD_COUNT pod(s)"
  else
    warn "No pod metrics collected (may need metrics-server or heapster)"
  fi
  
  # Get top nodes
  log "Collecting kubectl top nodes..."
  kubectl top nodes --no-headers > "$OUT/kubectl_top_nodes.txt" 2>/dev/null || echo "" > "$OUT/kubectl_top_nodes.txt"
  NODE_COUNT=$(wc -l < "$OUT/kubectl_top_nodes.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  if [ "$NODE_COUNT" -gt 0 ]; then
    log "Collected metrics for $NODE_COUNT node(s)"
  else
    warn "No node metrics collected (may need metrics-server or heapster)"
  fi
else
  echo "" > "$OUT/kubectl_top_pods.txt"
  echo "" > "$OUT/kubectl_top_nodes.txt"
  warn "kubectl not available"
fi

# 2. Prometheus metrics from kubelet (node metrics)
log "Collecting kubelet metrics..."
if command -v kubectl >/dev/null 2>&1; then
  # Get all nodes
  NODES=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
  if [ -n "$NODES" ]; then
    NODE_COUNT=0
    for NODE in $NODES; do
      NODE_COUNT=$((NODE_COUNT + 1))
      # Try to get kubelet metrics via port-forward or direct access
      # kubelet metrics are typically on port 10250 (read-only) or 10255 (deprecated)
      # We'll try to get them via kubectl proxy or port-forward
      NODE_METRICS_FILE="$OUT/kubelet_${NODE}_metrics.txt"
      
      # Try kubectl proxy method (if proxy is running)
      if curl -s -m 5 "http://127.0.0.1:8001/api/v1/nodes/${NODE}/proxy/metrics" > "$NODE_METRICS_FILE" 2>/dev/null; then
        METRIC_LINES=$(wc -l < "$NODE_METRICS_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
        if [ "$METRIC_LINES" -gt 10 ]; then
          log "Collected kubelet metrics for $NODE ($METRIC_LINES lines)"
        fi
      else
        # Try direct node IP (if accessible)
        NODE_IP=$(kubectl get node "$NODE" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || echo "")
        if [ -n "$NODE_IP" ] && [ "$NODE_IP" != "null" ]; then
          # Try port 10255 (deprecated but sometimes still available)
          if curl -s -m 5 -k "http://${NODE_IP}:10255/metrics" > "$NODE_METRICS_FILE" 2>/dev/null; then
            METRIC_LINES=$(wc -l < "$NODE_METRICS_FILE" 2>/dev/null | tr -d '[:space:]' || echo "0")
            if [ "$METRIC_LINES" -gt 10 ]; then
              log "Collected kubelet metrics for $NODE via direct access ($METRIC_LINES lines)"
            fi
          else
            echo "# kubelet metrics not accessible (may require kubectl proxy or node access)" > "$NODE_METRICS_FILE"
          fi
        else
          echo "# Node IP not available" > "$NODE_METRICS_FILE"
        fi
      fi
      
      # Limit to first 5 nodes to avoid too many files
      [ "$NODE_COUNT" -ge 5 ] && break
    done
  fi
fi

# 3. CoreDNS metrics
log "Collecting CoreDNS metrics..."
if command -v kubectl >/dev/null 2>&1; then
  COREDNS_PODS=$(kubectl get pods -n kube-system -l k8s-app=kube-dns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")
  if [ -n "$COREDNS_PODS" ]; then
    POD_COUNT=0
    for POD in $COREDNS_PODS; do
      POD_COUNT=$((POD_COUNT + 1))
      # CoreDNS metrics are typically on port 9153
      # Try exec first (if wget/curl available in pod)
      if kubectl -n kube-system exec "$POD" -- sh -c 'wget -qO- http://localhost:9153/metrics 2>/dev/null || curl -s http://localhost:9153/metrics 2>/dev/null' > "$OUT/coredns_${POD}_metrics.txt" 2>/dev/null; then
        METRIC_LINES=$(wc -l < "$OUT/coredns_${POD}_metrics.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
        if [ "$METRIC_LINES" -gt 10 ]; then
          log "Collected CoreDNS metrics for $POD ($METRIC_LINES lines)"
        else
          rm -f "$OUT/coredns_${POD}_metrics.txt"
        fi
      else
        # Fallback: try port-forward (background process)
        PF_PID=""
        if kubectl -n kube-system port-forward "$POD" 9153:9153 >/dev/null 2>&1 & then
          PF_PID=$!
          sleep 3
          if curl -s -m 5 http://localhost:9153/metrics > "$OUT/coredns_${POD}_metrics.txt" 2>/dev/null; then
            METRIC_LINES=$(wc -l < "$OUT/coredns_${POD}_metrics.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
            if [ "$METRIC_LINES" -gt 10 ]; then
              log "Collected CoreDNS metrics for $POD via port-forward ($METRIC_LINES lines)"
            else
              rm -f "$OUT/coredns_${POD}_metrics.txt"
            fi
          fi
          [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || pkill -f "port-forward.*$POD" 2>/dev/null || true
        fi
      fi
      
      # Limit to first 3 CoreDNS pods
      [ "$POD_COUNT" -ge 3 ] && break
    done
  else
    log "No CoreDNS pods found"
  fi
fi

# 4. aws-node (VPC CNI) metrics
log "Collecting aws-node metrics..."
if command -v kubectl >/dev/null 2>&1; then
  AWS_NODE_PODS=$(kubectl get pods -n kube-system -l k8s-app=aws-node -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | awk '{print $1}' || echo "")
  if [ -n "$AWS_NODE_PODS" ]; then
    for POD in $AWS_NODE_PODS; do
      # aws-node metrics are typically on port 61678
      if kubectl -n kube-system exec "$POD" -- sh -c 'wget -qO- http://localhost:61678/metrics 2>/dev/null || curl -s http://localhost:61678/metrics 2>/dev/null' > "$OUT/aws_node_${POD}_metrics.txt" 2>/dev/null; then
        METRIC_LINES=$(wc -l < "$OUT/aws_node_${POD}_metrics.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
        if [ "$METRIC_LINES" -gt 10 ]; then
          log "Collected aws-node metrics for $POD ($METRIC_LINES lines)"
        else
          rm -f "$OUT/aws_node_${POD}_metrics.txt"
        fi
      else
        # Fallback: try port-forward
        PF_PID=""
        if kubectl -n kube-system port-forward "$POD" 61678:61678 >/dev/null 2>&1 & then
          PF_PID=$!
          sleep 3
          if curl -s -m 5 http://localhost:61678/metrics > "$OUT/aws_node_${POD}_metrics.txt" 2>/dev/null; then
            METRIC_LINES=$(wc -l < "$OUT/aws_node_${POD}_metrics.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
            if [ "$METRIC_LINES" -gt 10 ]; then
              log "Collected aws-node metrics for $POD via port-forward ($METRIC_LINES lines)"
            else
              rm -f "$OUT/aws_node_${POD}_metrics.txt"
            fi
          fi
          [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || pkill -f "port-forward.*$POD" 2>/dev/null || true
        fi
      fi
      
      # Limit to first pod
      break
    done
  else
    log "No aws-node pods found"
  fi
fi

# 5. kube-proxy metrics
log "Collecting kube-proxy metrics..."
if command -v kubectl >/dev/null 2>&1; then
  KUBE_PROXY_PODS=$(kubectl get pods -n kube-system -l k8s-app=kube-proxy -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | awk '{print $1}' || echo "")
  if [ -n "$KUBE_PROXY_PODS" ]; then
    for POD in $KUBE_PROXY_PODS; do
      # kube-proxy metrics are typically on port 10249
      if kubectl -n kube-system exec "$POD" -- sh -c 'wget -qO- http://localhost:10249/metrics 2>/dev/null || curl -s http://localhost:10249/metrics 2>/dev/null' > "$OUT/kube_proxy_${POD}_metrics.txt" 2>/dev/null; then
        METRIC_LINES=$(wc -l < "$OUT/kube_proxy_${POD}_metrics.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
        if [ "$METRIC_LINES" -gt 10 ]; then
          log "Collected kube-proxy metrics for $POD ($METRIC_LINES lines)"
        else
          rm -f "$OUT/kube_proxy_${POD}_metrics.txt"
        fi
      else
        # Fallback: try port-forward
        PF_PID=""
        if kubectl -n kube-system port-forward "$POD" 10249:10249 >/dev/null 2>&1 & then
          PF_PID=$!
          sleep 3
          if curl -s -m 5 http://localhost:10249/metrics > "$OUT/kube_proxy_${POD}_metrics.txt" 2>/dev/null; then
            METRIC_LINES=$(wc -l < "$OUT/kube_proxy_${POD}_metrics.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
            if [ "$METRIC_LINES" -gt 10 ]; then
              log "Collected kube-proxy metrics for $POD via port-forward ($METRIC_LINES lines)"
            else
              rm -f "$OUT/kube_proxy_${POD}_metrics.txt"
            fi
          fi
          [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || pkill -f "port-forward.*$POD" 2>/dev/null || true
        fi
      fi
      
      # Limit to first pod
      break
    done
  else
    log "No kube-proxy pods found"
  fi
fi

# 6. Cluster state summary
log "Collecting cluster state summary..."
if command -v kubectl >/dev/null 2>&1; then
  # Pod counts by namespace
  kubectl get pods --all-namespaces -o json > "$OUT/cluster_pods.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/cluster_pods.json"
  POD_TOTAL=$(jq -r '.items | length' "$OUT/cluster_pods.json" 2>/dev/null || echo "0")
  log "Total pods in cluster: $POD_TOTAL"
  
  # Node counts
  kubectl get nodes -o json > "$OUT/cluster_nodes.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/cluster_nodes.json"
  NODE_TOTAL=$(jq -r '.items | length' "$OUT/cluster_nodes.json" 2>/dev/null || echo "0")
  log "Total nodes in cluster: $NODE_TOTAL"
  
  # Service counts
  kubectl get services --all-namespaces -o json > "$OUT/cluster_services.json" 2>/dev/null || echo '{"items":[]}' > "$OUT/cluster_services.json"
  SERVICE_TOTAL=$(jq -r '.items | length' "$OUT/cluster_services.json" 2>/dev/null || echo "0")
  log "Total services in cluster: $SERVICE_TOTAL"
  
  # Pod status summary
  kubectl get pods --all-namespaces -o json | jq -r '[.items[] | .status.phase] | group_by(.) | map({phase: .[0], count: length})' > "$OUT/pod_status_summary.json" 2>/dev/null || echo '[]' > "$OUT/pod_status_summary.json"
fi

# 7. Network-related metrics summary
log "Collecting network metrics summary..."
if command -v kubectl >/dev/null 2>&1; then
  # ENI annotations count (pods using pod ENI)
  ENI_PODS=$(kubectl get pods --all-namespaces -o json | jq -r '[.items[] | select(.metadata.annotations."vpc.amazonaws.com/pod-eni" != null)] | length' 2>/dev/null || echo "0")
  echo "$ENI_PODS" > "$OUT/pods_with_pod_eni.txt"
  log "Pods using pod ENI: $ENI_PODS"
  
  # Pending pods count
  PENDING_PODS=$(kubectl get pods --all-namespaces --field-selector status.phase=Pending -o json | jq -r '.items | length' 2>/dev/null || echo "0")
  echo "$PENDING_PODS" > "$OUT/pending_pods_count.txt"
  log "Pods in Pending state: $PENDING_PODS"
fi

log "Done. Baseline snapshot: $OUT"
log "Use this baseline for comparison during incidents"

# Export baseline directory for use by compare script
export SGFP_BASELINE_DIR="$OUT"
echo "$OUT" > "$DATA_DIR/.sgfp_baseline_latest" 2>/dev/null || true
log "Baseline directory exported: SGFP_BASELINE_DIR=$OUT"
log "To use this baseline: export SGFP_BASELINE_DIR=\"$OUT\""

