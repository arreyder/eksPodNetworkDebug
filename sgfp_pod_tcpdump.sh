#!/usr/bin/env bash
# Enter a pod's network namespace and run tcpdump
# Usage: ./sgfp_pod_tcpdump.sh <pod-name> [namespace] [tcpdump-args]

set -euo pipefail

POD="${1:?usage: sgfp_pod_tcpdump.sh <pod-name> [namespace] [tcpdump-args]}"
NS="${2:-default}"
TCPDUMP_ARGS="${3:--i any -n port 6000}"

echo "[TCPDUMP] Finding pod network namespace for: $POD (namespace: $NS)"

# Get the node where the pod is running
NODE=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "")
if [ -z "$NODE" ]; then
  echo "[ERROR] Pod '$POD' not found in namespace '$NS'"
  exit 1
fi

echo "[TCPDUMP] Pod is on node: $NODE"

# Try to find information from diagnostic reports first
# Look for the latest bundle directory for this pod
BUNDLE_DIR=""
if [ -d "data" ]; then
  # Find the most recent bundle for this pod
  BUNDLE_DIR=$(find data -type d -name "*bundle*${POD}*" -o -name "*bundle*${NS}*${POD}*" 2>/dev/null | sort -r | head -1 || echo "")
fi

# Extract pod IP from reports or kubectl
POD_IP=""
VETH_INTERFACE=""
NETNS_NAME=""

if [ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ]; then
  # Try to get pod IP from reports
  POD_IP_FILE=$(find "$BUNDLE_DIR" -name "pod_ip.txt" -type f 2>/dev/null | head -1 || echo "")
  if [ -n "$POD_IP_FILE" ] && [ -f "$POD_IP_FILE" ]; then
    POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
    if [ -n "$POD_IP" ]; then
      echo "[TCPDUMP] Found pod IP from diagnostics: $POD_IP"
    fi
  fi
  
  # Try to get veth interface from reports
  VETH_FILE=$(find "$BUNDLE_DIR" -name "pod_veth_interface.txt" -type f 2>/dev/null | head -1 || echo "")
  if [ -n "$VETH_FILE" ] && [ -f "$VETH_FILE" ]; then
    VETH_INTERFACE=$(cat "$VETH_FILE" 2>/dev/null | grep -v "unknown" | head -1 || echo "")
    if [ -n "$VETH_INTERFACE" ] && [ "$VETH_INTERFACE" != "unknown" ]; then
      echo "[TCPDUMP] Found veth interface from diagnostics: $VETH_INTERFACE"
    fi
  fi
  
  # Look for network namespace name
  NETNS_JSON=$(find "$BUNDLE_DIR" -name "node_netns_details.json" -type f 2>/dev/null | head -1 || echo "")
  
  if [ -n "$NETNS_JSON" ] && [ -f "$NETNS_JSON" ]; then
    if command -v jq >/dev/null 2>&1; then
      # If we have pod IP, use it to find namespace
      if [ -n "$POD_IP" ]; then
        NETNS_NAME=$(jq -r --arg ip "$POD_IP" '.[] | select(.ips.ipv4[]? == $ip) | .name' "$NETNS_JSON" 2>/dev/null | head -1 || echo "")
      fi
      
      if [ -n "$NETNS_NAME" ] && [ "$NETNS_NAME" != "null" ]; then
        echo "[TCPDUMP] Found network namespace from diagnostics: $NETNS_NAME"
      fi
    else
      echo "[WARN] jq not available, cannot parse diagnostic JSON"
    fi
  fi
fi

# Fallback to kubectl if not found in reports
if [ -z "$POD_IP" ]; then
  POD_IP=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.podIP}' 2>/dev/null || echo "")
  if [ -z "$POD_IP" ]; then
    echo "[ERROR] Could not get pod IP"
    exit 1
  fi
  echo "[TCPDUMP] Pod IP (from kubectl): $POD_IP"
fi

if [ -z "$NETNS_NAME" ]; then
  echo "[WARN] Could not find namespace name from diagnostic reports"
  echo "[TCPDUMP] Will need to find it manually in the debug pod"
fi

echo "[TCPDUMP] Creating debug pod on node to access network namespaces..."

# Create a debug pod on the same node
DEBUG_POD="tcpdump-debug-$(date +%s)"

# Use kubectl debug if available, otherwise create manually
if kubectl debug --help >/dev/null 2>&1; then
  echo "[TCPDUMP] Using kubectl debug node/$NODE"
  
  if [ -n "$NETNS_NAME" ]; then
    echo "[TCPDUMP] Network namespace: $NETNS_NAME"
    echo "[TCPDUMP] Pod IP: $POD_IP"
    if [ -n "$VETH_INTERFACE" ]; then
      echo "[TCPDUMP] Veth interface: $VETH_INTERFACE"
    fi
    echo "[TCPDUMP] Once inside, run:"
    echo ""
    echo "  # Enter host namespace and install tcpdump if needed:"
    echo "  nsenter --target 1 --mount --uts --ipc --net --pid sh"
    echo "  yum install -y tcpdump || apt-get update && apt-get install -y tcpdump || apk add tcpdump"
    echo ""
    echo "  # Option 1: Capture from pod's network namespace (recommended - sees traffic as pod sees it):"
    echo "  ip netns exec $NETNS_NAME tcpdump $TCPDUMP_ARGS"
    echo ""
    if [ -n "$VETH_INTERFACE" ] && [ "$VETH_INTERFACE" != "unknown" ]; then
      echo "  # Option 2: Capture on veth interface from host namespace:"
      echo "  tcpdump -i $VETH_INTERFACE $TCPDUMP_ARGS"
      echo ""
    fi
    echo "Or install and run in one command (Option 1):"
    echo "  nsenter --target 1 --mount --uts --ipc --net --pid sh -c \"(yum install -y tcpdump || apt-get update && apt-get install -y tcpdump || apk add tcpdump) && ip netns exec $NETNS_NAME tcpdump $TCPDUMP_ARGS\""
    echo ""
    echo "[TCPDUMP] Starting debug session..."
    kubectl debug "node/$NODE" -it --image=nicolaka/netshoot --profile sysadmin -- sh
  else
    echo "[TCPDUMP] Once inside, run these commands:"
    echo ""
    echo "  # Enter host namespace and install tcpdump:"
    echo "  nsenter --target 1 --mount --uts --ipc --net --pid sh"
    echo "  yum install -y tcpdump || apt-get update && apt-get install -y tcpdump || apk add tcpdump"
    echo ""
    echo "  # Find the pod's network namespace by IP ($POD_IP):"
    echo "  for ns in /var/run/netns/*; do"
    echo "    ns_name=\$(basename \"\$ns\")"
    echo "    ip=\$(ip netns exec \"\$ns_name\" ip -o -4 addr show dev eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 || echo '')"
    echo "    if [ \"\$ip\" = \"$POD_IP\" ]; then"
    echo "      echo \"Found: \$ns_name\""
    echo "      ip netns exec \"\$ns_name\" tcpdump $TCPDUMP_ARGS"
    echo "    fi"
    echo "  done"
    echo ""
    echo "[TCPDUMP] Starting debug session..."
    kubectl debug "node/$NODE" -it --image=nicolaka/netshoot --profile sysadmin -- sh
  fi
else
  # Manual pod creation
  echo "[TCPDUMP] Creating debug pod: $DEBUG_POD"
  
  kubectl run "$DEBUG_POD" \
    --namespace="$NS" \
    --image=nicolaka/netshoot \
    --overrides="{
      \"spec\": {
        \"nodeName\": \"$NODE\",
        \"hostNetwork\": true,
        \"hostPID\": true,
        \"hostIPC\": true,
        \"containers\": [{
          \"name\": \"debugger\",
          \"image\": \"nicolaka/netshoot\",
          \"stdin\": true,
          \"tty\": true,
          \"securityContext\": {
            \"privileged\": true
          },
          \"volumeMounts\": [{
            \"name\": \"host-root\",
            \"mountPath\": \"/host\"
          }]
        }],
        \"volumes\": [{
          \"name\": \"host-root\",
          \"hostPath\": {
            \"path\": \"/\"
          }
        }]
      }
    }" \
    --rm -it --restart=Never -- sh -c "
      echo '[TCPDUMP] Debug pod ready.'
      echo ''
      if [ -n '$NETNS_NAME' ]; then
        echo 'Using namespace from diagnostic reports: $NETNS_NAME'
        echo 'Pod IP: $POD_IP'
        if [ -n '$VETH_INTERFACE' ] && [ '$VETH_INTERFACE' != 'unknown' ]; then
          echo 'Veth interface: $VETH_INTERFACE'
        fi
        echo 'Installing tcpdump and starting capture in pod network namespace...'
        echo 'Press Ctrl+C to stop'
        echo ''
        nsenter --target 1 --mount --uts --ipc --net --pid sh -c \"(yum install -y tcpdump 2>/dev/null || apt-get update -qq && apt-get install -y -qq tcpdump 2>/dev/null || apk add -q tcpdump 2>/dev/null || echo 'tcpdump install failed, trying to use existing...') && ip netns exec $NETNS_NAME tcpdump $TCPDUMP_ARGS\"
      else
        echo 'Installing tcpdump and finding namespace for pod IP $POD_IP...'
        nsenter --target 1 --mount --uts --ipc --net --pid sh -c '
          # Install tcpdump
          yum install -y tcpdump 2>/dev/null || apt-get update -qq && apt-get install -y -qq tcpdump 2>/dev/null || apk add -q tcpdump 2>/dev/null || echo \"Warning: tcpdump install may have failed\"
          
          # Find namespace
          for ns in /var/run/netns/*; do
            ns_name=\$(basename \"\$ns\")
            ip=\$(ip netns exec \"\$ns_name\" ip -o -4 addr show dev eth0 2>/dev/null | awk \"{print \\\$4}\" | cut -d/ -f1 || echo \"\")
            if [ \"\$ip\" = \"$POD_IP\" ]; then
              echo \"Found namespace: \$ns_name (IP: \$ip)\"
              echo \"Starting tcpdump...\"
              echo \"Press Ctrl+C to stop\"
              echo \"\"
              ip netns exec \"\$ns_name\" tcpdump $TCPDUMP_ARGS
              exit 0
            fi
          done
          echo \"Could not find namespace. Listing all namespaces:\"
          for ns in /var/run/netns/*; do
            ns_name=\$(basename \"\$ns\")
            echo \"  \$ns_name\"
          done
          echo \"\"
          echo \"You can manually enter a namespace with:\"
          echo \"  nsenter --target 1 --mount --uts --ipc --net --pid sh\"
          echo \"  ip netns exec <namespace-name> tcpdump $TCPDUMP_ARGS\"
        '
        exec sh
      fi
    "
fi

