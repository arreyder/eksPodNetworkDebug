#!/usr/bin/env bash
# Deep diagnostics for a pod with connectivity issues
# Usage: ./sgfp_pod_deep_diag.sh <pod-name> [namespace]

set -euo pipefail

POD="${1:?usage: sgfp_pod_deep_diag.sh <pod-name> [namespace]}"
NS="${2:-default}"
OUTPUT_DIR="pod_deep_diag_${POD}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[DEEP-DIAG] Collecting deep diagnostics for pod: $POD (namespace: $NS)"
echo "[DEEP-DIAG] Output directory: $OUTPUT_DIR"

# Detect shell
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
  echo "[ERROR] Cannot exec into pod - no shell available"
  exit 1
fi

echo "[DEEP-DIAG] Using shell: $POD_SHELL"

# 1. Application logs (current and previous if restarted)
echo "[DEEP-DIAG] [1/12] Collecting application logs..."
kubectl -n "$NS" logs "$POD" --tail=1000 > "$OUTPUT_DIR/app_logs_current.txt" 2>&1 || echo "Failed to get current logs" > "$OUTPUT_DIR/app_logs_current.txt"
kubectl -n "$NS" logs "$POD" --previous --tail=1000 > "$OUTPUT_DIR/app_logs_previous.txt" 2>&1 || echo "No previous logs" > "$OUTPUT_DIR/app_logs_previous.txt"

# 2. Process list inside pod
echo "[DEEP-DIAG] [2/12] Collecting process list..."
kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ps aux' > "$OUTPUT_DIR/processes.txt" 2>&1 || echo "Failed to get processes" > "$OUTPUT_DIR/processes.txt"
kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ps -ef' > "$OUTPUT_DIR/processes_ps_ef.txt" 2>&1 || echo "Failed" > "$OUTPUT_DIR/processes_ps_ef.txt"

# 3. Network interfaces (detailed)
echo "[DEEP-DIAG] [3/12] Collecting network interface details..."
kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip -d addr show' > "$OUTPUT_DIR/ip_addr_detailed.txt" 2>&1 || echo "Failed" > "$OUTPUT_DIR/ip_addr_detailed.txt"
kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip link show' > "$OUTPUT_DIR/ip_link.txt" 2>&1 || echo "Failed" > "$OUTPUT_DIR/ip_link.txt"
kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/dev' > "$OUTPUT_DIR/proc_net_dev.txt" 2>&1 || echo "Failed" > "$OUTPUT_DIR/proc_net_dev.txt"

# 4. Listening ports (multiple methods)
echo "[DEEP-DIAG] [4/12] Collecting listening ports..."
{
  echo "=== ss -tulnp ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ss -tulnp 2>&1' 2>&1 || echo "ss failed"
  echo ""
  echo "=== netstat -tulnp ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'netstat -tulnp 2>&1' 2>&1 || echo "netstat failed"
  echo ""
  echo "=== lsof -i ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'lsof -i 2>&1' 2>&1 || echo "lsof not available"
  echo ""
  echo "=== /proc/net/tcp (raw) ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/tcp 2>&1' 2>&1 || echo "Failed"
} > "$OUTPUT_DIR/listening_ports_detailed.txt"

# 5. DNS resolution tests
echo "[DEEP-DIAG] [5/12] Testing DNS resolution..."
{
  echo "=== /etc/resolv.conf ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /etc/resolv.conf 2>&1' 2>&1 || echo "Failed"
  echo ""
  echo "=== nslookup kubernetes.default ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'nslookup kubernetes.default 2>&1' 2>&1 || echo "nslookup failed"
  echo ""
  echo "=== getent hosts kubernetes.default ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'getent hosts kubernetes.default 2>&1' 2>&1 || echo "getent failed"
  echo ""
  echo "=== ping -c 1 kubernetes.default (DNS test) ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ping -c 1 kubernetes.default 2>&1' 2>&1 || echo "ping failed"
} > "$OUTPUT_DIR/dns_tests.txt"

# 6. Connectivity tests
echo "[DEEP-DIAG] [6/12] Testing connectivity..."
POD_IP=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")
{
  echo "=== Ping self (pod IP) ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c "ping -c 2 $POD_IP 2>&1" 2>&1 || echo "ping self failed"
  echo ""
  echo "=== Ping gateway ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip route | grep default | awk "{print \$3}" | head -1 | xargs -I {} ping -c 2 {} 2>&1' 2>&1 || echo "ping gateway failed"
  echo ""
  echo "=== Ping metadata service ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ping -c 2 169.254.169.254 2>&1' 2>&1 || echo "ping metadata failed"
  echo ""
  echo "=== Test Kubernetes API connectivity ==="
  KUBE_API=$(kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'getent hosts kubernetes.default | awk "{print \$1}"' 2>&1 | head -1 || echo "")
  if [ -n "$KUBE_API" ]; then
    kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c "curl -k -m 2 https://$KUBE_API:443 2>&1 | head -5" 2>&1 || echo "curl API failed"
  fi
} > "$OUTPUT_DIR/connectivity_tests.txt"

# 7. Environment variables (to check configuration)
echo "[DEEP-DIAG] [7/12] Collecting environment variables..."
kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'env | sort' > "$OUTPUT_DIR/environment.txt" 2>&1 || echo "Failed" > "$OUTPUT_DIR/environment.txt"

# 8. Application-specific checks
echo "[DEEP-DIAG] [8/12] Application-specific checks..."
{
  echo "=== Check if application is listening on expected port (6000) ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ss -tuln | grep :6000 || netstat -tuln | grep :6000 || echo "Port 6000 not found in listening ports"' 2>&1
  echo ""
  echo "=== Check for application process ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ps aux | grep -v grep | grep -E "(python|streaming|umap|app)" || echo "No application process found"' 2>&1
  echo ""
  echo "=== Check application working directory ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'pwd 2>&1' 2>&1
  echo ""
  echo "=== Check if application files exist ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ls -la /app 2>&1 | head -20' 2>&1 || echo "No /app directory"
} > "$OUTPUT_DIR/app_specific_checks.txt"

# 9. Network routes and rules (detailed)
echo "[DEEP-DIAG] [9/12] Collecting routing information..."
{
  echo "=== ip route show ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip route show 2>&1' 2>&1 || echo "Failed"
  echo ""
  echo "=== ip rule show ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip rule show 2>&1' 2>&1 || echo "Failed"
  echo ""
  echo "=== ip route show table all ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ip route show table all 2>&1' 2>&1 || echo "Failed"
} > "$OUTPUT_DIR/routing_detailed.txt"

# 10. Socket statistics (detailed)
echo "[DEEP-DIAG] [10/12] Collecting socket statistics..."
{
  echo "=== /proc/net/sockstat ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'cat /proc/net/sockstat 2>&1' 2>&1 || echo "Failed"
  echo ""
  echo "=== /proc/net/snmp (TCP/UDP stats) ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'grep -E "^(Tcp|Udp|Ip):" /proc/net/snmp 2>&1' 2>&1 || echo "Failed"
  echo ""
  echo "=== ss -s (socket summary) ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'ss -s 2>&1' 2>&1 || echo "ss -s failed"
} > "$OUTPUT_DIR/socket_stats_detailed.txt"

# 11. Pod events (detailed)
echo "[DEEP-DIAG] [11/12] Collecting pod events..."
kubectl -n "$NS" get events --field-selector involvedObject.name="$POD" --sort-by='.lastTimestamp' > "$OUTPUT_DIR/pod_events_detailed.txt" 2>&1 || echo "Failed" > "$OUTPUT_DIR/pod_events_detailed.txt"
kubectl -n "$NS" describe pod "$POD" > "$OUTPUT_DIR/pod_describe.txt" 2>&1 || echo "Failed" > "$OUTPUT_DIR/pod_describe.txt"

# 12. Container runtime info (if accessible)
echo "[DEEP-DIAG] [12/12] Collecting container runtime information..."
{
  echo "=== Container ID ==="
  kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].containerID}' 2>&1 || echo "Failed"
  echo ""
  echo "=== Container state ==="
  kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].state}' 2>&1 || echo "Failed"
  echo ""
  echo "=== Check /proc/self/ns/net (network namespace) ==="
  kubectl -n "$NS" exec "$POD" -- "$POD_SHELL" -c 'readlink /proc/self/ns/net 2>&1' 2>&1 || echo "Failed"
} > "$OUTPUT_DIR/container_runtime_info.txt"

echo ""
echo "[DEEP-DIAG] Done! All diagnostics saved to: $OUTPUT_DIR"
echo "[DEEP-DIAG] Key files to check:"
echo "  - app_logs_current.txt (application logs)"
echo "  - processes.txt (is the app actually running?)"
echo "  - listening_ports_detailed.txt (is port 6000 listening?)"
echo "  - connectivity_tests.txt (can the pod reach other services?)"
echo "  - pod_events_detailed.txt (any startup errors?)"
echo "  - pod_describe.txt (full pod description)"

