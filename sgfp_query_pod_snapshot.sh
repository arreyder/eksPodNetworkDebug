#!/usr/bin/env bash
# Query pod snapshot from diagnostic bundle
# Usage: ./sgfp_query_pod_snapshot.sh <bundle-dir> [ip|name|eni] [value]

set -euo pipefail

BUNDLE_DIR="${1:?usage: sgfp_query_pod_snapshot.sh <bundle-dir> [ip|name|eni] [value]}"
QUERY_TYPE="${2:-}"
QUERY_VALUE="${3:-}"

SNAPSHOT_FILE="$BUNDLE_DIR/cluster_pod_snapshot.json"

if [ ! -f "$SNAPSHOT_FILE" ]; then
  echo "[ERROR] Pod snapshot not found: $SNAPSHOT_FILE" >&2
  echo "[INFO] This bundle may be from an older version. Looking for node_pod_ip_map.txt..." >&2
  POD_IP_MAP=$(find "$BUNDLE_DIR" -name "node_pod_ip_map.txt" -type f 2>/dev/null | head -1)
  if [ -n "$POD_IP_MAP" ] && [ -f "$POD_IP_MAP" ]; then
    echo "[INFO] Found legacy pod IP map: $POD_IP_MAP" >&2
    if [ "$QUERY_TYPE" = "ip" ] && [ -n "$QUERY_VALUE" ]; then
      grep -m1 "^$QUERY_VALUE " "$POD_IP_MAP" 2>/dev/null | awk '{print "IP: " $1 "\nPod: " $2 "\nPhase: " $3}' || echo "Not found"
    else
      echo "[INFO] Legacy format only supports IP lookups. Use: $0 <bundle-dir> ip <ip-address>" >&2
    fi
  else
    echo "[ERROR] No pod mapping data found in bundle" >&2
  fi
  exit 1
fi

if [ ! -f "$SNAPSHOT_FILE" ] || ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] jq not available or snapshot file not found" >&2
  exit 1
fi

# Show metadata
if [ -z "$QUERY_TYPE" ]; then
  echo "=== Pod Snapshot Metadata ==="
  jq -r '.metadata | "Cluster: \(.cluster)\nTimestamp: \(.timestamp)\nTotal Pods: \(.total_pods)"' "$SNAPSHOT_FILE"
  echo ""
  echo "Usage examples:"
  echo "  $0 $BUNDLE_DIR ip 10.4.243.90          # Find pod by IP"
  echo "  $0 $BUNDLE_DIR name be-innkeeper        # Find pods by name pattern"
  echo "  $0 $BUNDLE_DIR eni eni-081829d313cc36576  # Find pod by ENI ID"
  echo "  $0 $BUNDLE_DIR all                      # List all pods"
  exit 0
fi

case "$QUERY_TYPE" in
  ip)
    if [ -z "$QUERY_VALUE" ]; then
      echo "[ERROR] IP address required" >&2
      exit 1
    fi
    jq -r --arg ip "$QUERY_VALUE" '.pods[] | select(.ipv4 == $ip or .ipv6 == $ip or (.all_ips | index($ip) != null)) | {
      namespace: .namespace,
      name: .name,
      ipv4: .ipv4,
      ipv6: .ipv6,
      node: .node,
      phase: .phase,
      pod_eni_id: .pod_eni_id,
      pod_eni_private_ip: .pod_eni_private_ip,
      security_groups: .security_groups,
      ready: .ready
    }' "$SNAPSHOT_FILE" | jq -s '.' || echo "[]"
    ;;
  name)
    if [ -z "$QUERY_VALUE" ]; then
      echo "[ERROR] Pod name pattern required" >&2
      exit 1
    fi
    jq -r --arg pattern "$QUERY_VALUE" '.pods[] | select(.name | contains($pattern)) | {
      namespace: .namespace,
      name: .name,
      ipv4: .ipv4,
      ipv6: .ipv6,
      node: .node,
      phase: .phase,
      pod_eni_id: .pod_eni_id
    }' "$SNAPSHOT_FILE" | jq -s '.' || echo "[]"
    ;;
  eni)
    if [ -z "$QUERY_VALUE" ]; then
      echo "[ERROR] ENI ID required" >&2
      exit 1
    fi
    jq -r --arg eni "$QUERY_VALUE" '.pods[] | select(.pod_eni_id == $eni) | {
      namespace: .namespace,
      name: .name,
      ipv4: .ipv4,
      ipv6: .ipv6,
      node: .node,
      phase: .phase,
      pod_eni_id: .pod_eni_id,
      pod_eni_private_ip: .pod_eni_private_ip,
      security_groups: .security_groups
    }' "$SNAPSHOT_FILE" | jq -s '.' || echo "[]"
    ;;
  all)
    jq -r '.pods[] | "\(.namespace)/\(.name) | \(.ipv4) | \(.node) | \(.phase)"' "$SNAPSHOT_FILE" | \
      column -t -s '|' -N "NAMESPACE/NAME,IPv4,NODE,PHASE" || echo ""
    ;;
  *)
    echo "[ERROR] Unknown query type: $QUERY_TYPE" >&2
    echo "Valid types: ip, name, eni, all" >&2
    exit 1
    ;;
esac

