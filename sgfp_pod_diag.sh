#!/usr/bin/env bash
set -euo pipefail

POD="${1:?usage: sgfp_pod_diag.sh <pod-name> [namespace]}"
NS="${2:-default}"
OUT="sgfp_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

# 1) Basic pod state
kubectl -n "$NS" get pod "$POD" -o wide > "$OUT/pod_wide.txt" 2>/dev/null || true
kubectl -n "$NS" get pod "$POD" -o json > "$OUT/pod_full.json" 2>/dev/null || echo '{}' > "$OUT/pod_full.json"
kubectl -n "$NS" get pod "$POD" -o json | jq '.metadata.annotations' > "$OUT/pod_annotations.json" 2>/dev/null || echo '{}' > "$OUT/pod_annotations.json"
kubectl -n "$NS" get pod "$POD" -o json | jq '.status.conditions'    > "$OUT/pod_conditions.json" 2>/dev/null || echo '[]' > "$OUT/pod_conditions.json"
kubectl -n "$NS" get pod "$POD" -o json | jq '.status.containerStatuses' > "$OUT/pod_container_statuses.json" 2>/dev/null || echo '[]' > "$OUT/pod_container_statuses.json"

# Pod events (for network-related issues)
kubectl -n "$NS" get events --field-selector involvedObject.name="$POD" --sort-by='.lastTimestamp' > "$OUT/pod_events.txt" 2>/dev/null || echo "" > "$OUT/pod_events.txt"

# Pod timing information
POD_CREATED=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.creationTimestamp}' 2>/dev/null || echo "")
POD_STARTED=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.startTime}' 2>/dev/null || echo "")
POD_UID=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "")
echo "CREATED=$POD_CREATED" > "$OUT/pod_timing.txt"
echo "STARTED=$POD_STARTED" >> "$OUT/pod_timing.txt"
echo "UID=$POD_UID" >> "$OUT/pod_timing.txt"

POD_IP=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")
NODE=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "")
echo "POD_IP=$POD_IP" > "$OUT/pod_ip.txt"
echo "NODE=$NODE"     > "$OUT/node_name.txt"

# Detect available shell in pod (try common shells)
detect_shell() {
  local pod="$1"
  local ns="$2"
  for shell in sh /bin/sh /bin/bash bash; do
    if kubectl -n "$ns" exec "$pod" -- "$shell" -c 'true' >/dev/null 2>&1; then
      echo "$shell"
      return 0
    fi
  done
  echo ""
}

POD_SHELL=$(detect_shell "$POD" "$NS")
if [ -z "$POD_SHELL" ]; then
  echo "WARN: No shell found in pod, skipping exec-based diagnostics" >&2
  POD_SHELL="sh"  # fallback, will fail gracefully
fi

# 2) Pod netns routes/rules (best-effort: needs a shell + ip tool in pod)
{
  echo "--- ip addr ---"
  if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ip >/dev/null 2>&1' >/dev/null 2>&1; then
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip addr 2>/dev/null || echo "ip addr command failed"' 2>/dev/null || echo "Failed to execute ip addr command"
  else
    echo "Note: 'ip' command not available in pod container"
  fi
  echo "--- ip rule ---"
  if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ip >/dev/null 2>&1' >/dev/null 2>&1; then
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip rule 2>/dev/null || echo "ip rule command failed"' 2>/dev/null || echo "Failed to execute ip rule command"
  else
    echo "Note: 'ip' command not available in pod container"
  fi
  echo "--- main table ---"
  if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ip >/dev/null 2>&1' >/dev/null 2>&1; then
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip route show table main 2>/dev/null || echo "ip route command failed"' 2>/dev/null || echo "Failed to execute ip route command"
  else
    echo "Note: 'ip' command not available in pod container"
  fi
} > "$OUT/pod_netns_routes_rules.txt" 2>/dev/null || true

# 2.1) Extract veth interface name from ip addr output
if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ip >/dev/null 2>&1' >/dev/null 2>&1; then
  # Get interface name (typically eth0, but could be veth*)
  # Use ip -o link show and extract first non-lo interface
  VETH_TMP=$(mktemp)
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip -o link show 2>/dev/null' 2>/dev/null > "$VETH_TMP" || true
  if [ -s "$VETH_TMP" ]; then
    VETH=$(grep -v " lo " "$VETH_TMP" 2>/dev/null | head -1 | sed 's/^[0-9]*: *\([^:]*\):.*/\1/' | awk '{print $1}' || echo "")
  fi
  rm -f "$VETH_TMP" 2>/dev/null || true
  if [ -z "$VETH" ]; then
    # Fallback: try to extract from ip addr output we already collected
    VETH=$(grep -E "^[0-9]+:" "$OUT/pod_netns_routes_rules.txt" 2>/dev/null | grep -v "lo:" | head -1 | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || echo "")
  fi
  echo "${VETH:-unknown}" > "$OUT/pod_veth_interface.txt" 2>/dev/null || echo "unknown" > "$OUT/pod_veth_interface.txt"
else
  echo "unknown" > "$OUT/pod_veth_interface.txt"
fi

# 2.2) Collect interface statistics with errors (ip -s link)
if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ip >/dev/null 2>&1' >/dev/null 2>&1; then
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip -s link 2>/dev/null || echo "ip -s link command failed"' 2>/dev/null > "$OUT/pod_interface_stats.txt" || echo "" > "$OUT/pod_interface_stats.txt"
else
  echo "Note: 'ip' command not available in pod container" > "$OUT/pod_interface_stats.txt"
fi

# 2.3) Collect socket statistics (including overruns)
if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'test -r /proc/net/sockstat 2>/dev/null' >/dev/null 2>&1; then
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/sockstat 2>/dev/null || echo ""' 2>/dev/null > "$OUT/pod_sockstat.txt" || echo "" > "$OUT/pod_sockstat.txt"
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/sockstat6 2>/dev/null || echo ""' 2>/dev/null > "$OUT/pod_sockstat6.txt" || echo "" > "$OUT/pod_sockstat6.txt"
else
  echo "" > "$OUT/pod_sockstat.txt"
  echo "" > "$OUT/pod_sockstat6.txt"
fi
# Collect /proc/net/snmp for socket overruns (UdpInErrors, UdpRcvbufErrors, etc.)
if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'test -r /proc/net/snmp 2>/dev/null' >/dev/null 2>&1; then
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'grep -E "^(Udp|Tcp|Ip):" /proc/net/snmp 2>/dev/null || echo ""' 2>/dev/null > "$OUT/pod_snmp.txt" || echo "" > "$OUT/pod_snmp.txt"
else
  echo "" > "$OUT/pod_snmp.txt"
fi

# 2.4) Collect network connections (listening ports and established connections)
# Try ss first (more modern), then netstat, then /proc/net/tcp
if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ss >/dev/null 2>&1' >/dev/null 2>&1; then
  {
    echo "--- Listening ports (ss -tuln) ---"
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ss -tuln 2>/dev/null || echo "ss command failed"' 2>/dev/null || echo "Failed to execute ss"
    echo ""
    echo "--- Established connections (ss -tun) ---"
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ss -tun 2>/dev/null || echo "ss command failed"' 2>/dev/null || echo "Failed to execute ss"
  } > "$OUT/pod_connections.txt" 2>/dev/null || echo "" > "$OUT/pod_connections.txt"
elif kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v netstat >/dev/null 2>&1' >/dev/null 2>&1; then
  {
    echo "--- Listening ports (netstat -tuln) ---"
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'netstat -tuln 2>/dev/null || echo "netstat command failed"' 2>/dev/null || echo "Failed to execute netstat"
    echo ""
    echo "--- Established connections (netstat -tun) ---"
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'netstat -tun 2>/dev/null || echo "netstat command failed"' 2>/dev/null || echo "Failed to execute netstat"
  } > "$OUT/pod_connections.txt" 2>/dev/null || echo "" > "$OUT/pod_connections.txt"
elif kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'test -r /proc/net/tcp 2>/dev/null' >/dev/null 2>&1; then
  {
    echo "--- TCP connections (from /proc/net/tcp) ---"
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/tcp 2>/dev/null | head -50 || echo "Failed to read /proc/net/tcp"' 2>/dev/null || echo "Failed to read /proc/net/tcp"
    echo ""
    echo "--- UDP connections (from /proc/net/udp) ---"
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/udp 2>/dev/null | head -50 || echo "Failed to read /proc/net/udp"' 2>/dev/null || echo "Failed to read /proc/net/udp"
  } > "$OUT/pod_connections.txt" 2>/dev/null || echo "" > "$OUT/pod_connections.txt"
else
  echo "Note: Network connection tools (ss/netstat) not available and /proc/net/tcp not accessible" > "$OUT/pod_connections.txt"
fi

# 3) Reachability probes (informational, often blocked)
{
  echo "## ping $POD_IP"
  if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ping >/dev/null 2>&1' >/dev/null 2>&1; then
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c "ping -c1 -W1 $POD_IP 2>/dev/null || echo 'ping failed or timed out'" 2>/dev/null || echo "Failed to execute ping command"
  else
    echo "Note: 'ping' command not available in pod container"
  fi
  echo "## ping 169.254.169.254"
  if kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'command -v ping >/dev/null 2>&1' >/dev/null 2>&1; then
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c "ping -c1 -W1 169.254.169.254 2>/dev/null || echo 'ping failed or timed out'" 2>/dev/null || echo "Failed to execute ping command"
  else
    echo "Note: 'ping' command not available in pod container"
  fi
} > "$OUT/pod_reachability.txt" 2>/dev/null || true

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
  # Detect shell for aws-node container (usually has sh)
  AWS_NODE_SHELL=$(detect_shell "$AWS_NODE_POD" "kube-system")
  if [ -z "$AWS_NODE_SHELL" ]; then
    AWS_NODE_SHELL="sh"  # fallback
  fi
  # IPAMD introspection endpoints
  kubectl -n kube-system exec "$AWS_NODE_POD" -c aws-node -- \
    "$AWS_NODE_SHELL" -c 'curl -s 127.0.0.1:61678/v1/enis 2>/dev/null || true' \
    > "$OUT/ipamd_introspection.json" 2>/dev/null || echo '{}' > "$OUT/ipamd_introspection.json"
  kubectl -n kube-system exec "$AWS_NODE_POD" -c aws-node -- \
    "$AWS_NODE_SHELL" -c 'curl -s 127.0.0.1:61678/v1/ipam-pool 2>/dev/null || true' \
    > "$OUT/ipamd_pool.json" 2>/dev/null || echo '{}' > "$OUT/ipamd_pool.json"
  kubectl -n kube-system exec "$AWS_NODE_POD" -c aws-node -- \
    "$AWS_NODE_SHELL" -c 'curl -s 127.0.0.1:61678/v1/networkutils-env 2>/dev/null || true' \
    > "$OUT/ipamd_networkutils.json" 2>/dev/null || echo '{}' > "$OUT/ipamd_networkutils.json"
  # Extended logs (1 hour to catch issues during large churns)
  kubectl -n kube-system logs "$AWS_NODE_POD" -c aws-node --since=1h > "$OUT/aws_node_full.log" 2>/dev/null || true
  # Filter for errors/warnings around this pod (exclude empty lines)
  kubectl -n kube-system logs "$AWS_NODE_POD" -c aws-node --since=1h 2>/dev/null | \
    grep -iE "(error|warn|fail|$POD|$POD_IP|eni-)" | grep -v '^[[:space:]]*$' > "$OUT/aws_node_errors.log" 2>/dev/null || echo "" > "$OUT/aws_node_errors.log"
else
  echo '{}' > "$OUT/ipamd_introspection.json"
  echo '{}' > "$OUT/ipamd_pool.json"
  echo '{}' > "$OUT/ipamd_networkutils.json"
  echo ""   > "$OUT/aws_node_full.log"
  echo ""   > "$OUT/aws_node_errors.log"
fi

# 6) Save which aws-node pod we hit
echo "${AWS_NODE_POD:-}" > "$OUT/aws_node_pod.txt"
