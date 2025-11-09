#!/usr/bin/env bash
set -euo pipefail

POD="${1:?usage: sgfp_pod_diag.sh <pod-name> [namespace]}"
NS="${2:-default}"
OUT="sgfp_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

# 1) Basic pod state
kubectl -n "$NS" get pod "$POD" -o wide             | tee "$OUT/pod_wide.txt" >/dev/null
kubectl -n "$NS" get pod "$POD" -o json | jq '.metadata.annotations' > "$OUT/pod_annotations.json"
kubectl -n "$NS" get pod "$POD" -o json | jq '.status.conditions'    > "$OUT/pod_conditions.json"

POD_IP=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.podIP}')
NODE=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')
echo "POD_IP=$POD_IP" | tee "$OUT/pod_ip.txt" >/dev/null
echo "NODE=$NODE"     | tee "$OUT/node_name.txt" >/dev/null

# 2) Pod netns routes/rules (best-effort: needs a shell + ip tool in pod)
{
  echo "--- ip addr ---"
  kubectl -n "$NS" exec "$POD" -- sh -c 'ip addr 2>/dev/null || true' || true
  echo "--- ip rule ---"
  kubectl -n "$NS" exec "$POD" -- sh -c 'ip rule 2>/dev/null || true' || true
  echo "--- main table ---"
  kubectl -n "$NS" exec "$POD" -- sh -c 'ip route show table main 2>/dev/null || true' || true
} | tee "$OUT/pod_netns_routes_rules.txt" >/dev/null || true

# 3) Reachability probes (informational, often blocked)
{
  echo "## ping $POD_IP"
  kubectl -n "$NS" exec "$POD" -- sh -c "ping -c1 -W1 $POD_IP 2>/dev/null || true" || true
  echo "## ping 169.254.169.254"
  kubectl -n "$NS" exec "$POD" -- sh -c "ping -c1 -W1 169.254.169.254 2>/dev/null || true" || true
} | tee "$OUT/pod_reachability.txt" >/dev/null || true

# 4) SG-for-Pods detection helper
if jq -er '."vpc.amazonaws.com/pod-eni"' "$OUT/pod_annotations.json" >/dev/null 2>&1; then
  echo 1 > "$OUT/.is_sgfp"
else
  echo 0 > "$OUT/.is_sgfp"
fi

# 5) Try to capture ipamd introspection via aws-node on this node
AWS_NODE_POD=$(kubectl -n kube-system get pod -o wide \
  --field-selector spec.nodeName="$NODE" \
  -l k8s-app=aws-node -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [ -n "${AWS_NODE_POD:-}" ]; then
  kubectl -n kube-system exec "$AWS_NODE_POD" -c aws-node -- \
    sh -c 'curl -s 127.0.0.1:61678/v1/enis 2>/dev/null || true' \
    > "$OUT/ipamd_introspection.json" || echo '{}' > "$OUT/ipamd_introspection.json"
  kubectl -n kube-system logs "$AWS_NODE_POD" -c aws-node --since=30m > "$OUT/aws_node_full.log" 2>/dev/null || true
else
  echo '{}' > "$OUT/ipamd_introspection.json"
  echo ""   > "$OUT/aws_node_full.log"
fi

# 6) Save which aws-node pod we hit
echo "${AWS_NODE_POD:-}" > "$OUT/aws_node_pod.txt"
