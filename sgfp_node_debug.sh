#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?usage: sgfp_node_debug.sh <pod-name|node-name> [namespace] [image]}"
NS="${2:-default}"
IMAGE="${3:-ubuntu}"

log()  { printf "[NODE_DEBUG] %s\n" "$*"; }
warn() { printf "[NODE_DEBUG] WARN: %s\n" "$*" >&2; }

# Determine if TARGET is a pod name or node name
# Try to get pod first (most common case)
POD_NODE=$(kubectl -n "$NS" get pod "$TARGET" -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "")

if [ -n "$POD_NODE" ]; then
  # TARGET is a pod name
  NODE="$POD_NODE"
  log "Pod '$TARGET' is running on node: $NODE"
else
  # TARGET might be a node name, or pod doesn't exist
  # Check if it's a valid node
  if kubectl get node "$TARGET" >/dev/null 2>&1; then
    NODE="$TARGET"
    log "Using node: $NODE"
  else
    warn "Could not find pod '$TARGET' in namespace '$NS' or node '$TARGET'"
    warn "Usage: sgfp_node_debug.sh <pod-name|node-name> [namespace] [image]"
    exit 1
  fi
fi

log "Creating debug pod on node: $NODE"
log "Image: $IMAGE"

# Check if kubectl debug is available (Kubernetes 1.23+)
if ! kubectl debug --help >/dev/null 2>&1; then
  warn "kubectl debug command not available (requires Kubernetes 1.23+)"
  warn "Falling back to manual pod creation..."
  
  # Create a debug pod manually
  POD_NAME="node-debugger-$(date +%s)"
  log "Creating pod: $POD_NAME in namespace: $NS"
  
  kubectl run "$POD_NAME" \
    --namespace="$NS" \
    --image="$IMAGE" \
    --overrides="{\"spec\":{\"nodeName\":\"$NODE\",\"hostNetwork\":true,\"hostPID\":true,\"hostIPC\":true,\"containers\":[{\"name\":\"debugger\",\"image\":\"$IMAGE\",\"stdin\":true,\"tty\":true,\"securityContext\":{\"privileged\":true},\"volumeMounts\":[{\"name\":\"host-root\",\"mountPath\":\"/host\"}]}],\"volumes\":[{\"name\":\"host-root\",\"hostPath\":{\"path\":\"/\"}}]}}" \
    --rm -it --restart=Never -- /bin/sh || {
    warn "Failed to create debug pod"
    exit 1
  }
else
  # Use kubectl debug node/<node-name> (preferred method for node debugging)
  log "Using kubectl debug node/$NODE"
  kubectl debug "node/$NODE" -it --image="$IMAGE" || {
    warn "Failed to create debug pod on node"
    exit 1
  }
fi

log "Debug session ended"

