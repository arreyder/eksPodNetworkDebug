#!/usr/bin/env bash
# Analyze packet capture with pod IP mapping from diagnostic bundle
# Usage: ./sgfp_analyze_pcap_with_pod_mapping.sh <capture-file> <bundle-dir>

set -euo pipefail

CAPTURE_FILE="${1:?usage: sgfp_analyze_pcap_with_pod_mapping.sh <capture-file> <bundle-dir>}"
BUNDLE_DIR="${2:?usage: sgfp_analyze_pcap_with_pod_mapping.sh <capture-file> <bundle-dir>}"

if [ ! -f "$CAPTURE_FILE" ]; then
  echo "[ERROR] Capture file not found: $CAPTURE_FILE"
  exit 1
fi

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "[ERROR] Bundle directory not found: $BUNDLE_DIR"
  exit 1
fi

# Find pod IP map and node info
POD_IP_MAP=$(find "$BUNDLE_DIR" -name "node_pod_ip_map.txt" -type f 2>/dev/null | head -1)
NODE_DIR=$(find "$BUNDLE_DIR" -type d -name "node_*" 2>/dev/null | head -1)
POD_IP_FILE=$(find "$BUNDLE_DIR" -name "pod_ip.txt" -type f 2>/dev/null | head -1)

if [ -z "$POD_IP_MAP" ] || [ ! -f "$POD_IP_MAP" ]; then
  echo "[ERROR] Could not find node_pod_ip_map.txt in bundle"
  exit 1
fi

# Get target pod IP
TARGET_POD_IP=""
if [ -n "$POD_IP_FILE" ] && [ -f "$POD_IP_FILE" ]; then
  TARGET_POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
fi

# Get node IP (from node directory name or pod IP map)
NODE_IP=""
if [ -n "$NODE_DIR" ]; then
  NODE_IP=$(basename "$NODE_DIR" | grep -oE "10\.[0-9]+\.[0-9]+\.[0-9]+" | head -1 || echo "")
fi

# If node IP not found, try to get from pod IP map (first IP on node)
if [ -z "$NODE_IP" ] && [ -f "$POD_IP_MAP" ]; then
  NODE_IP=$(head -1 "$POD_IP_MAP" 2>/dev/null | awk '{print $1}' || echo "")
fi

OUTPUT_DIR="pcap_pod_mapping_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[PCAP-MAP] Analyzing packet capture with pod mapping"
echo "[PCAP-MAP] Capture file: $CAPTURE_FILE"
echo "[PCAP-MAP] Bundle directory: $BUNDLE_DIR"
echo "[PCAP-MAP] Target pod IP: ${TARGET_POD_IP:-unknown}"
echo "[PCAP-MAP] Node IP: ${NODE_IP:-unknown}"
echo "[PCAP-MAP] Output directory: $OUTPUT_DIR"
echo ""

# Extract all unique IPs from capture
echo "[PCAP-MAP] [1/5] Extracting IP addresses from capture..."
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" "$CAPTURE_FILE" 2>/dev/null | \
  sort | uniq -c | sort -rn > "$OUTPUT_DIR/capture_ips.txt" || echo "" > "$OUTPUT_DIR/capture_ips.txt"

# Create IP to pod mapping
echo "[PCAP-MAP] [2/5] Creating IP to pod mapping..."
{
  echo "# IP Address | Pod (namespace/name) | Phase | Local/Remote"
  echo "# Local = pod is on the same node as target pod"
  echo ""
  
  while read -r count ip; do
    [ -z "$ip" ] && continue
    [ "$ip" = "0.0.0.0" ] && continue
    
    # Look up pod in map
    pod_info=$(grep -m1 "^$ip " "$POD_IP_MAP" 2>/dev/null | awk '{print $2, $3}' || echo "")
    
    if [ -n "$pod_info" ]; then
      pod_name=$(echo "$pod_info" | awk '{print $1}')
      phase=$(echo "$pod_info" | awk '{print $2}')
      
      # Determine if local (on same node) or remote
      # Check if this IP appears in the node's pod list
      is_local="Remote"
      if [ -n "$NODE_IP" ] && [ -f "$POD_IP_MAP" ]; then
        # Check if this pod is on the same node by checking if IP is in node's pod list
        # We can infer local if the IP is in the first part of the map (node's pods)
        # Or we can check if there's a pattern - for now, we'll mark as local if it's in the map
        # and the node IP matches the subnet pattern
        if grep -q "^$ip " "$POD_IP_MAP" 2>/dev/null; then
          # Check if it's likely on the same node (same subnet or in node directory)
          if [ -n "$NODE_DIR" ]; then
            # If we can find this IP in node-specific files, it's local
            if find "$NODE_DIR" -type f -exec grep -l "$ip" {} \; 2>/dev/null | grep -q .; then
              is_local="Local"
            fi
          fi
        fi
      fi
      
      echo "$ip | $pod_name | $phase | $is_local"
    else
      # Not a pod IP - could be service IP, external IP, etc.
      ip_type="External/Service"
      if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || [[ "$ip" =~ ^192\.168\. ]]; then
        if [ "$ip" = "169.254.169.254" ]; then
          ip_type="Metadata Service"
        elif [ "$ip" = "$NODE_IP" ]; then
          ip_type="Node IP"
        else
          ip_type="VPC Internal"
        fi
      fi
      echo "$ip | $ip_type | - | -"
    fi
  done < "$OUTPUT_DIR/capture_ips.txt"
} > "$OUTPUT_DIR/ip_to_pod_mapping.txt"

# Analyze traffic to/from target pod
if [ -n "$TARGET_POD_IP" ]; then
  echo "[PCAP-MAP] [3/5] Analyzing traffic to/from target pod ($TARGET_POD_IP)..."
  
  # Traffic TO pod (inbound)
  {
    echo "=== Traffic TO pod $TARGET_POD_IP (Inbound) ==="
    echo ""
    grep "$TARGET_POD_IP" "$CAPTURE_FILE" 2>/dev/null | \
      grep -oE "Src: ([0-9]{1,3}\.){3}[0-9]{1,3}" | \
      sed 's/Src: //' | sort | uniq -c | sort -rn | head -20 | \
      while read -r count src_ip; do
        pod_info=$(grep -m1 "^$src_ip " "$POD_IP_MAP" 2>/dev/null | awk '{print $2, $3}' || echo "")
        if [ -n "$pod_info" ]; then
          echo "  $count packets from $src_ip -> $pod_info"
        else
          echo "  $count packets from $src_ip -> (not a pod)"
        fi
      done
  } > "$OUTPUT_DIR/traffic_to_pod.txt"
  
  # Traffic FROM pod (outbound)
  {
    echo "=== Traffic FROM pod $TARGET_POD_IP (Outbound) ==="
    echo ""
    grep "$TARGET_POD_IP" "$CAPTURE_FILE" 2>/dev/null | \
      grep -oE "Dst: ([0-9]{1,3}\.){3}[0-9]{1,3}" | \
      sed 's/Dst: //' | sort | uniq -c | sort -rn | head -20 | \
      while read -r count dst_ip; do
        pod_info=$(grep -m1 "^$dst_ip " "$POD_IP_MAP" 2>/dev/null | awk '{print $2, $3}' || echo "")
        if [ -n "$pod_info" ]; then
          echo "  $count packets to $dst_ip -> $pod_info"
        else
          echo "  $count packets to $dst_ip -> (not a pod)"
        fi
      done
  } > "$OUTPUT_DIR/traffic_from_pod.txt"
else
  echo "[PCAP-MAP] [3/5] Skipping pod-specific analysis (pod IP not found)"
  touch "$OUTPUT_DIR/traffic_to_pod.txt"
  touch "$OUTPUT_DIR/traffic_from_pod.txt"
fi

# Summary of communicating pods
echo "[PCAP-MAP] [4/5] Creating summary of communicating pods..."
{
  echo "# Pods Communicating in Capture"
  echo "# Based on IP addresses found in capture"
  echo ""
  
  # Get all pod IPs that appear in capture
  while read -r count ip; do
    [ -z "$ip" ] && continue
    pod_info=$(grep -m1 "^$ip " "$POD_IP_MAP" 2>/dev/null || echo "")
    if [ -n "$pod_info" ]; then
      pod_name=$(echo "$pod_info" | awk '{print $2}')
      phase=$(echo "$pod_info" | awk '{print $3}')
      echo "$ip | $pod_name | $phase | $count packets"
    fi
  done < "$OUTPUT_DIR/capture_ips.txt" | sort -t'|' -k4 -rn | head -30
} > "$OUTPUT_DIR/communicating_pods_summary.txt"

# Local vs Remote analysis
echo "[PCAP-MAP] [5/5] Analyzing local vs remote traffic..."
if [ -n "$TARGET_POD_IP" ] && [ -n "$NODE_IP" ]; then
  # Get all pods on the same node
  NODE_POD_IPS=$(grep "^[0-9]" "$POD_IP_MAP" 2>/dev/null | awk '{print $1}' | sort || echo "")
  
  {
    echo "=== Local vs Remote Traffic Analysis ==="
    echo "Target Pod: $TARGET_POD_IP"
    echo "Node IP: $NODE_IP"
    echo ""
    echo "=== Local Pods (on same node) ==="
    
    local_count=0
    remote_count=0
    
    while read -r count ip; do
      [ -z "$ip" ] && continue
      pod_info=$(grep -m1 "^$ip " "$POD_IP_MAP" 2>/dev/null || echo "")
      if [ -n "$pod_info" ]; then
        # Check if this pod is on the same node
        # For now, we'll use a heuristic: if the IP is in the pod map and matches node subnet pattern
        if echo "$NODE_POD_IPS" | grep -q "^$ip$" 2>/dev/null; then
          pod_name=$(echo "$pod_info" | awk '{print $2}')
          echo "  $ip -> $pod_name ($count packets) [LOCAL]"
          local_count=$((local_count + count))
        else
          pod_name=$(echo "$pod_info" | awk '{print $2}')
          echo "  $ip -> $pod_name ($count packets) [REMOTE]"
          remote_count=$((remote_count + count))
        fi
      fi
    done < <(grep "$TARGET_POD_IP" "$CAPTURE_FILE" 2>/dev/null | \
      grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | \
      grep -v "$TARGET_POD_IP" | sort | uniq -c | sort -rn | head -20)
    
    echo ""
    echo "Summary:"
    echo "  Local traffic: $local_count packets"
    echo "  Remote traffic: $remote_count packets"
  } > "$OUTPUT_DIR/local_vs_remote.txt"
else
  echo "[PCAP-MAP] [5/5] Skipping local/remote analysis (missing pod IP or node IP)"
  touch "$OUTPUT_DIR/local_vs_remote.txt"
fi

echo ""
echo "[PCAP-MAP] Analysis complete!"
echo "[PCAP-MAP] Results saved to: $OUTPUT_DIR"
echo "[PCAP-MAP] Key files:"
echo "  - ip_to_pod_mapping.txt (all IPs mapped to pods)"
echo "  - traffic_to_pod.txt (inbound traffic analysis)"
echo "  - traffic_from_pod.txt (outbound traffic analysis)"
echo "  - communicating_pods_summary.txt (summary of all pods in capture)"
echo "  - local_vs_remote.txt (local vs remote traffic breakdown)"

