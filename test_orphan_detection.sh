#!/usr/bin/env bash
# Test script to debug orphaned namespace detection using stored data

set -euo pipefail

BUNDLE_DIR="${1:?Usage: $0 <bundle-dir>}"

NODE_DIR="$BUNDLE_DIR/node_ip-10-4-212-141.us-west-2.compute.internal"
POD_IP_MAP="$NODE_DIR/node_pod_ip_map.txt"
NETNS_DETAILS="$NODE_DIR/node_netns_details.json"

if [ ! -f "$POD_IP_MAP" ] || [ ! -f "$NETNS_DETAILS" ]; then
  echo "Error: Required files not found in bundle"
  exit 1
fi

echo "=== Testing Orphaned Namespace Detection ==="
echo ""
echo "Pod IP Map: $POD_IP_MAP"
echo "Namespace Details: $NETNS_DETAILS"
echo ""

# Show pod IP map
echo "=== Pod IP Map (first 10) ==="
head -10 "$POD_IP_MAP"
echo ""

# Test matching logic
echo "=== Testing IP Matching Logic ==="
echo ""

MATCHED=0
ORPHANED=0

while IFS='|' read -r ns_name ipv4_ips ipv6_ips interface_count proc_count mtime active; do
  [ -z "$ns_name" ] && continue
  
  echo "Testing namespace: $ns_name"
  echo "  - IPv4 IPs: '$ipv4_ips'"
  echo "  - IPv6 IPs: '$ipv6_ips'"
  echo "  - Interfaces: $interface_count"
  echo "  - Processes: $proc_count"
  echo "  - Active: $active"
  
  matched=0
  matched_pod=""
  
  # Check IPv4 IPs against pod map
  if [ -n "$ipv4_ips" ] && [ "$ipv4_ips" != "null" ] && [ "$ipv4_ips" != "" ]; then
    echo "  - Checking IPv4 IPs..."
    for ip in $(echo "$ipv4_ips" | tr ',' ' '); do
      [ -z "$ip" ] && continue
      echo "    - Checking IP: $ip"
      owner=$(grep -m1 "^$ip " "$POD_IP_MAP" 2>/dev/null | awk '{print $2}' || echo "")
      if [ -n "$owner" ]; then
        matched=1
        matched_pod="$owner"
        echo "    - MATCHED: $ip -> $owner"
        break
      else
        echo "    - No match for $ip"
      fi
    done
  else
    echo "  - No IPv4 IPs to check"
  fi
  
  # Check IPv6 IPs if no IPv4 match
  if [ "$matched" -eq 0 ] && [ -n "$ipv6_ips" ] && [ "$ipv6_ips" != "null" ] && [ "$ipv6_ips" != "" ]; then
    echo "  - Checking IPv6 IPs..."
    for ipv6 in $(echo "$ipv6_ips" | tr ',' ' '); do
      [ -z "$ipv6" ] && continue
      ipv6_normalized=$(echo "$ipv6" | tr -d '[]' || echo "$ipv6")
      owner=$(grep -m1 "^$ipv6_normalized " "$NODE_DIR/node_pod_ipv6_map.txt" 2>/dev/null | awk '{print $2}' || echo "")
      if [ -n "$owner" ]; then
        matched=1
        matched_pod="$owner"
        echo "    - MATCHED: $ipv6 -> $owner"
        break
      fi
    done
  fi
  
  if [ "$matched" -eq 1 ]; then
    MATCHED=$((MATCHED + 1))
    echo "  - RESULT: MATCHED -> $matched_pod"
  else
    ORPHANED=$((ORPHANED + 1))
    echo "  - RESULT: ORPHANED (no match)"
  fi
  echo ""
done < <(jq -r '.[] | select(.name | startswith("cni-")) | "\(.name)|\(.ips.ipv4 // [] | join(","))|\(.ips.ipv6 // [] | join(","))|\(.interface_count)|\(.process_count)|\(.mtime)|\(.active)"' "$NETNS_DETAILS" 2>/dev/null)

echo "=== Summary ==="
echo "Matched: $MATCHED"
echo "Orphaned: $ORPHANED"
echo ""

# Also show what IPs we actually collected
echo "=== Collected IPs from Namespaces ==="
jq -r '.[] | select(.name | startswith("cni-")) | "\(.name): ipv4=\(.ips.ipv4 | length) items [\(.ips.ipv4 | join(","))], ipv6=\(.ips.ipv6 | length) items [\(.ips.ipv6 | join(","))]"' "$NETNS_DETAILS" | head -5

