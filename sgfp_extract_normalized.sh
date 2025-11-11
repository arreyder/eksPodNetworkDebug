#!/usr/bin/env bash
# Extract normalized diagnostic data from bundle for comparison
# Outputs JSON format ideal for AI parsing and comparison

set -euo pipefail

BUNDLE_DIR="${1:?usage: sgfp_extract_normalized.sh <bundle-dir>}"

if [ ! -d "$BUNDLE_DIR" ] || ! command -v jq >/dev/null 2>&1; then
  echo '{"error":"Bundle directory not found or jq not available"}' >&2
  exit 1
fi

# Find directories
POD_DIR=$(find "$BUNDLE_DIR" -type d -name "pod_*" | head -1)
NODE_DIR=$(find "$BUNDLE_DIR" -type d -name "node_*" | head -1)

# Extract pod name
POD_NAME="unknown"
if [ -n "$POD_DIR" ]; then
  POD_NAME=$(basename "$POD_DIR" | sed 's/^pod_//')
fi

# Extract pod IP
POD_IP=""
if [ -f "$POD_DIR/pod_ip.txt" ]; then
  POD_IP=$(grep "^POD_IP=" "$POD_DIR/pod_ip.txt" 2>/dev/null | cut -d= -f2- || echo "")
fi

# Load JSON files into variables first (to validate)
POD_DATA='{}'
if [ -f "$POD_DIR/pod_full.json" ]; then
  POD_DATA=$(cat "$POD_DIR/pod_full.json" 2>/dev/null || echo '{}')
fi

POD_CONDITIONS='[]'
if [ -f "$POD_DIR/pod_conditions.json" ]; then
  POD_CONDITIONS=$(cat "$POD_DIR/pod_conditions.json" 2>/dev/null || echo '[]')
fi

POD_ANNOTATIONS='{}'
if [ -f "$POD_DIR/pod_annotations.json" ]; then
  POD_ANNOTATIONS=$(cat "$POD_DIR/pod_annotations.json" 2>/dev/null || echo '{}')
fi

# Extract ENI readiness
ENI_READINESS='{}'
if [ -f "$POD_DIR/pod_eni_readiness.txt" ]; then
  ENI_TYPE=$(grep "^InterfaceType=" "$POD_DIR/pod_eni_readiness.txt" 2>/dev/null | cut -d= -f2- || echo "")
  ENI_STATUS=$(grep "^Status=" "$POD_DIR/pod_eni_readiness.txt" 2>/dev/null | cut -d= -f2- || echo "")
  ENI_SG_COUNT=$(grep "^SecurityGroupsCount=" "$POD_DIR/pod_eni_readiness.txt" 2>/dev/null | cut -d= -f2- || echo "0")
  ENI_PRIVATE_IP=$(grep "^PrivateIpAddress=" "$POD_DIR/pod_eni_readiness.txt" 2>/dev/null | cut -d= -f2- || echo "")
  ENI_READY=$(grep "^ReadyForTraffic=" "$POD_DIR/pod_eni_readiness.txt" 2>/dev/null | cut -d= -f2- || echo "false")
  ENI_READINESS=$(jq -n \
    --arg type "$ENI_TYPE" \
    --arg status "$ENI_STATUS" \
    --arg sg_count "$ENI_SG_COUNT" \
    --arg private_ip "$ENI_PRIVATE_IP" \
    --arg ready "$ENI_READY" \
    '{
      "InterfaceType": $type,
      "Status": $status,
      "SecurityGroupsCount": (try ($sg_count | tonumber) catch 0),
      "PrivateIpAddress": $private_ip,
      "ReadyForTraffic": $ready
    }' 2>/dev/null || echo '{}')
fi

# Extract network namespace completeness
NETNS_COMPLETENESS='{}'
if [ -f "$NODE_DIR/node_netns_details.json" ] && [ -n "$POD_IP" ]; then
  NETNS_COMPLETENESS=$(jq --arg ip "$POD_IP" '[.[] | select(.ips.ipv4[]? == $ip) | .completeness // {}] | first // {}' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo '{}')
fi

# Extract security groups
SECURITY_GROUPS='[]'
if [ -f "$POD_DIR/pod_branch_eni_sgs_rules.json" ]; then
  SECURITY_GROUPS=$(cat "$POD_DIR/pod_branch_eni_sgs_rules.json" 2>/dev/null || echo '[]')
fi

# Extract node info
NODE_INFO='{}'
if [ -f "$NODE_DIR/node_kernel_version.txt" ] && [ -f "$NODE_DIR/node_os_image.txt" ]; then
  NODE_INFO=$(jq -n \
    --arg kernel "$(cat "$NODE_DIR/node_kernel_version.txt" 2>/dev/null || echo "")" \
    --arg os "$(cat "$NODE_DIR/node_os_image.txt" 2>/dev/null || echo "")" \
    --arg k8s_version "$(cat "$NODE_DIR/node_k8s_version.txt" 2>/dev/null || echo "")" \
    --arg aws_node_version "$(cat "$NODE_DIR/node_aws_node_version.txt" 2>/dev/null || echo "")" \
    '{
      "kernel": $kernel,
      "os": $os,
      "kubernetes": $k8s_version,
      "aws_node": $aws_node_version
    }' 2>/dev/null || echo '{}')
fi

# Build final normalized JSON
jq -n \
  --arg pod_name "$POD_NAME" \
  --arg bundle_dir "$BUNDLE_DIR" \
  --arg pod_ip "$POD_IP" \
  --argjson pod_data "$POD_DATA" \
  --argjson pod_conditions "$POD_CONDITIONS" \
  --argjson pod_annotations "$POD_ANNOTATIONS" \
  --argjson eni_readiness "$ENI_READINESS" \
  --argjson netns_completeness "$NETNS_COMPLETENESS" \
  --argjson security_groups "$SECURITY_GROUPS" \
  --argjson node_info "$NODE_INFO" \
  '{
    "metadata": {
      "pod_name": $pod_name,
      "bundle_dir": $bundle_dir,
      "extracted_at": (now | todateiso8601)
    },
    "pod": {
      "name": $pod_name,
      "ip": $pod_ip,
      "phase": ($pod_data.status.phase // ""),
      "ready": (try (($pod_conditions[]? | select(.type == "Ready") | .status == "True") // false) catch false),
      "containers_ready": (try (($pod_conditions[]? | select(.type == "ContainersReady") | .status == "True") // false) catch false),
      "pod_eni_id": (try ($pod_annotations."vpc.amazonaws.com/pod-eni" | fromjson | .[0].eniId // "") catch ""),
      "pod_eni_private_ip": (try ($pod_annotations."vpc.amazonaws.com/pod-eni" | fromjson | .[0].privateIp // "") catch ""),
      "security_groups": (try (($pod_annotations."vpc.amazonaws.com/security-groups" // "") | split(",") | map(select(. != ""))) catch []),
      "termination_grace_period": (try ($pod_data.spec.terminationGracePeriodSeconds // 30) catch 30)
    },
    "eni": {
      "readiness": $eni_readiness,
      "security_group_rules": {
        "ingress_count": (try ([$security_groups[].IpPermissions[]?] | length) catch 0),
        "egress_count": (try ([$security_groups[].IpPermissionsEgress[]?] | length) catch 0),
        "has_rules": (try (([$security_groups[].IpPermissions[]?] | length) > 0 or ([$security_groups[].IpPermissionsEgress[]?] | length) > 0) catch false)
      }
    },
    "network_namespace": {
      "completeness": $netns_completeness
    },
    "node": $node_info,
    "status_summary": {
      "healthy": (
        (($eni_readiness.ReadyForTraffic // "false") == "true") and
        (try (($pod_conditions[]? | select(.type == "Ready") | .status == "True") // false) catch false) and
        (($netns_completeness.eth0_state // "") == "UP" or ($netns_completeness.eth0_state // "") == "NOT_FOUND") and
        (($netns_completeness.route_count // 0) >= 0)
      )
    }
  }'
