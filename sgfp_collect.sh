#!/usr/bin/env bash
set -euo pipefail

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

# Get context and create directory structure
KUBECTL_CONTEXT=$(get_kubectl_context)
DATA_DIR="data/${KUBECTL_CONTEXT}"
REPORTS_DIR="reports/${KUBECTL_CONTEXT}"
mkdir -p "$DATA_DIR" "$REPORTS_DIR"

NS="default"
MARK_HEALTHY=0
MARK_UNHEALTHY=0
while getopts ":n:" opt; do
  case $opt in
    n) NS="$OPTARG" ;;
    *) echo "usage: sgfp_collect.sh [-n namespace] [--mark-healthy] [--mark-unhealthy] <pod-name>"; exit 1 ;;
  esac
done
shift $((OPTIND-1))
# Handle long options (--mark-healthy, --mark-unhealthy)
while [ $# -gt 0 ]; do
  case "$1" in
    --mark-healthy) MARK_HEALTHY=1; shift ;;
    --mark-unhealthy) MARK_UNHEALTHY=1; shift ;;
    -n|--namespace) NS="${2:?}"; shift 2 ;;
    *) break ;;
  esac
done
POD="${1:?usage: sgfp_collect.sh [-n namespace] [--mark-healthy] [--mark-unhealthy] <pod-name>}"

# 1) Pod diag
./sgfp_pod_diag.sh "$POD" "$NS" "$DATA_DIR"
LATEST=$(ls -dt "$DATA_DIR"/sgfp_diag_* 2>/dev/null | head -n1 || true)
if [ -z "$LATEST" ] || [ ! -d "$LATEST" ]; then
  echo "ERROR: Failed to find pod diagnostic output directory" >&2
  exit 1
fi

# Node name
NODE=$(awk -F= '/^NODE=/{print $2}' "$LATEST/node_name.txt" 2>/dev/null || echo "")
if [ -z "$NODE" ]; then
  echo "ERROR: Failed to determine node name for pod $POD" >&2
  exit 1
fi

# 2) SG-for-Pods flag
if jq -er '."vpc.amazonaws.com/pod-eni"' "$LATEST/pod_annotations.json" >/dev/null 2>&1; then
  echo 1 > "$LATEST/.is_sgfp"
else
  echo 0 > "$LATEST/.is_sgfp"
fi

# 2.1) SG-for-Pods ENI + SG capture
if [ -s "$LATEST/pod_annotations.json" ] && jq -e 'has("vpc.amazonaws.com/pod-eni")' "$LATEST/pod_annotations.json" >/dev/null 2>&1; then
  # Extract ENI ID from annotation (annotation is a JSON string that needs parsing)
  # Try direct extraction first (if jq can parse it in one go)
  POD_ENI_ID=$(jq -r '."vpc.amazonaws.com/pod-eni" | fromjson | .[0].eniId // empty' "$LATEST/pod_annotations.json" 2>/dev/null || echo "")
  # Fallback: extract annotation value then parse
  if [ -z "$POD_ENI_ID" ] || [ "$POD_ENI_ID" = "null" ] || [ "$POD_ENI_ID" = "" ]; then
    POD_ENI_ANNO=$(jq -r '."vpc.amazonaws.com/pod-eni" // empty' "$LATEST/pod_annotations.json" 2>/dev/null || echo "")
    if [ -n "$POD_ENI_ANNO" ] && [ "$POD_ENI_ANNO" != "null" ]; then
      POD_ENI_ID=$(echo "$POD_ENI_ANNO" | jq -r 'fromjson | .[0].eniId // empty' 2>/dev/null || echo "")
    fi
  fi
  if [ -n "$POD_ENI_ID" ] && [ "$POD_ENI_ID" != "null" ] && [ "$POD_ENI_ID" != "" ]; then
      echo "$POD_ENI_ID" > "$LATEST/pod_branch_eni_id.txt"
      if command -v aws >/dev/null 2>&1; then
        if [ -n "${AWS_REGION:-}" ]; then
          aws ec2 describe-network-interfaces --region "$AWS_REGION" --network-interface-ids "$POD_ENI_ID" > "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "{}" > "$LATEST/pod_branch_eni_describe.json"
        else
          aws ec2 describe-network-interfaces --network-interface-ids "$POD_ENI_ID" > "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "{}" > "$LATEST/pod_branch_eni_describe.json"
        fi
        # Extract ENI attachment state and timing
        if [ -s "$LATEST/pod_branch_eni_describe.json" ] && jq -e '.NetworkInterfaces[0]' "$LATEST/pod_branch_eni_describe.json" >/dev/null 2>&1; then
          jq -r '.NetworkInterfaces[0].Status // "unknown"' "$LATEST/pod_branch_eni_describe.json" > "$LATEST/pod_eni_status.txt" 2>/dev/null || echo "unknown" > "$LATEST/pod_eni_status.txt"
          jq -r '.NetworkInterfaces[0].Attachment.Status // "unknown"' "$LATEST/pod_branch_eni_describe.json" > "$LATEST/pod_eni_attachment_status.txt" 2>/dev/null || echo "unknown" > "$LATEST/pod_eni_attachment_status.txt"
          jq -r '.NetworkInterfaces[0].Attachment.AttachTime // "unknown"' "$LATEST/pod_branch_eni_describe.json" > "$LATEST/pod_eni_attach_time.txt" 2>/dev/null || echo "unknown" > "$LATEST/pod_eni_attach_time.txt"
          
          # Extract ENI readiness indicators
          # For branch ENIs, check if InterfaceType is "branch" and Status is "in-use"
          ENI_TYPE=$(jq -r '.NetworkInterfaces[0].InterfaceType // "unknown"' "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "unknown")
          ENI_STATUS=$(jq -r '.NetworkInterfaces[0].Status // "unknown"' "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "unknown")
          ENI_GROUPS_COUNT=$(jq -r '.NetworkInterfaces[0].Groups | length' "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "0")
          ENI_PRIVATE_IP=$(jq -r '.NetworkInterfaces[0].PrivateIpAddress // "unknown"' "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "unknown")
          
          # Create ENI readiness summary
          {
            echo "InterfaceType=$ENI_TYPE"
            echo "Status=$ENI_STATUS"
            echo "SecurityGroupsCount=$ENI_GROUPS_COUNT"
            echo "PrivateIpAddress=$ENI_PRIVATE_IP"
            echo "ReadyForTraffic=$([ "$ENI_TYPE" = "branch" ] && [ "$ENI_STATUS" = "in-use" ] && [ "$ENI_GROUPS_COUNT" -gt 0 ] && [ "$ENI_PRIVATE_IP" != "unknown" ] && echo "true" || echo "false")"
          } > "$LATEST/pod_eni_readiness.txt" 2>/dev/null || true
        fi
        
        # Extract security groups from ENI description
        if [ -s "$LATEST/pod_branch_eni_describe.json" ] && jq -e '.NetworkInterfaces[0].Groups' "$LATEST/pod_branch_eni_describe.json" >/dev/null 2>&1; then
          # Extract SG IDs
          jq -r '.NetworkInterfaces[0].Groups[]?.GroupId' "$LATEST/pod_branch_eni_describe.json" > "$LATEST/pod_branch_eni_sgs.txt" 2>/dev/null || true
          # Extract SG IDs with names (if available in ENI describe)
          jq -r '.NetworkInterfaces[0].Groups[]? | "\(.GroupId)\(if .GroupName then " (\(.GroupName))" else "" end)"' "$LATEST/pod_branch_eni_describe.json" > "$LATEST/pod_branch_eni_sgs_with_names.txt" 2>/dev/null || true
          # Get full SG details (IDs, names, descriptions) via describe-security-groups
          # Build a temporary file with SG IDs (one per line) for safe processing
          SG_TMP=$(mktemp)
          jq -r '.NetworkInterfaces[0].Groups[]?.GroupId' "$LATEST/pod_branch_eni_describe.json" 2>/dev/null | grep -v '^null$' | grep -v '^$' > "$SG_TMP" || true
          if [ -s "$SG_TMP" ]; then
            # Build array of SG IDs for AWS CLI (AWS CLI accepts space-separated values for --group-ids)
            SG_ID_LIST=""
            while IFS= read -r sg_id; do
              [ -n "$sg_id" ] && SG_ID_LIST="$SG_ID_LIST $sg_id"
            done < "$SG_TMP"
            SG_ID_LIST=$(echo "$SG_ID_LIST" | sed 's/^ //')  # trim leading space
            if [ -n "$SG_ID_LIST" ]; then
              if [ -n "${AWS_REGION:-}" ]; then
                # Get SG details (IDs, names, descriptions)
                aws ec2 describe-security-groups --region "$AWS_REGION" --group-ids $SG_ID_LIST \
                  --query 'SecurityGroups[].[GroupId,GroupName,Description]' --output json > "$LATEST/pod_branch_eni_sgs_details.json" 2>/dev/null || echo "[]" > "$LATEST/pod_branch_eni_sgs_details.json"
                # Get full SG rules (including IpPermissions for ingress/egress)
                aws ec2 describe-security-groups --region "$AWS_REGION" --group-ids $SG_ID_LIST \
                  --output json > "$LATEST/pod_branch_eni_sgs_rules.json" 2>/dev/null || echo "[]" > "$LATEST/pod_branch_eni_sgs_rules.json"
              else
                # Get SG details (IDs, names, descriptions)
                aws ec2 describe-security-groups --group-ids $SG_ID_LIST \
                  --query 'SecurityGroups[].[GroupId,GroupName,Description]' --output json > "$LATEST/pod_branch_eni_sgs_details.json" 2>/dev/null || echo "[]" > "$LATEST/pod_branch_eni_sgs_details.json"
                # Get full SG rules (including IpPermissions for ingress/egress)
                aws ec2 describe-security-groups --group-ids $SG_ID_LIST \
                  --output json > "$LATEST/pod_branch_eni_sgs_rules.json" 2>/dev/null || echo "[]" > "$LATEST/pod_branch_eni_sgs_rules.json"
              fi
            else
              echo "[]" > "$LATEST/pod_branch_eni_sgs_details.json"
            fi
          else
            echo "[]" > "$LATEST/pod_branch_eni_sgs_details.json"
          fi
          rm -f "$SG_TMP" 2>/dev/null || true
          # Try to get parent trunk ENI from Attachment.ParentNetworkInterfaceId
          PARENT_ENI=$(jq -r '.NetworkInterfaces[0].Attachment.ParentNetworkInterfaceId // empty' "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "")
          # If not found, try to get from pod-eni annotation (associationID contains trunk info)
          if [ -z "$PARENT_ENI" ] || [ "$PARENT_ENI" = "null" ] || [ "$PARENT_ENI" = "" ]; then
            if [ -s "$LATEST/pod_annotations.json" ]; then
              # Extract trunk association from pod-eni annotation
              ASSOC_ID=$(jq -r '."vpc.amazonaws.com/pod-eni" | fromjson | .[0].associationID // empty' "$LATEST/pod_annotations.json" 2>/dev/null || echo "")
              # Association ID format: trunk-assoc-xxxxx indicates trunk attachment
              # We'll get the trunk ENI ID from the node's aws diagnostics (collected separately)
              # The actual trunk ENI ID will be populated when aws_diag runs
              # For now, just confirm we have an association (trunk attachment confirmed)
              if [ -n "$ASSOC_ID" ] && [ "$ASSOC_ID" != "null" ] && [ "$ASSOC_ID" != "" ]; then
                : # Trunk association found, will populate ENI ID later
              fi
            fi
          fi
          echo "$PARENT_ENI" > "$LATEST/pod_parent_trunk_eni.txt" 2>/dev/null || echo "" > "$LATEST/pod_parent_trunk_eni.txt"
        else
          echo "" > "$LATEST/pod_branch_eni_sgs.txt"
          echo "[]" > "$LATEST/pod_branch_eni_sgs_details.json"
        fi
      else
        echo "WARN: aws CLI not available, skipping ENI SG collection" >&2
        echo "" > "$LATEST/pod_branch_eni_sgs.txt"
      fi
  else
    echo "WARN: Failed to extract ENI ID from pod-eni annotation" >&2
    echo "" > "$LATEST/pod_branch_eni_id.txt"
    echo "" > "$LATEST/pod_branch_eni_sgs.txt"
  fi
  
  # Collect expected security groups from pod annotations
  if jq -e 'has("vpc.amazonaws.com/security-groups")' "$LATEST/pod_annotations.json" >/dev/null 2>&1; then
    jq -r '."vpc.amazonaws.com/security-groups" // empty' "$LATEST/pod_annotations.json" | jq -r 'try (split(",") | .[]) catch empty' > "$LATEST/pod_expected_sgs.txt" 2>/dev/null || true
  else
    echo "" > "$LATEST/pod_expected_sgs.txt"
  fi
  
  # Collect SecurityGroupPolicy CRDs that match this pod
  # SecurityGroupPolicy uses podSelector to match pods
  if command -v kubectl >/dev/null 2>&1; then
    # Get all SecurityGroupPolicy resources in the pod's namespace
    kubectl get securitygrouppolicy -n "$NS" -o json > "$LATEST/pod_securitygrouppolicies.json" 2>/dev/null || echo '{"items":[]}' > "$LATEST/pod_securitygrouppolicies.json"
    
    # Also check cluster-scoped SecurityGroupPolicies (if any)
    kubectl get securitygrouppolicy --all-namespaces -o json > "$LATEST/pod_securitygrouppolicies_all.json" 2>/dev/null || echo '{"items":[]}' > "$LATEST/pod_securitygrouppolicies_all.json"
  else
    echo '{"items":[]}' > "$LATEST/pod_securitygrouppolicies.json"
    echo '{"items":[]}' > "$LATEST/pod_securitygrouppolicies_all.json"
  fi
  
  # Collect namespace annotations for security groups (if available)
  if kubectl get namespace "$NS" -o jsonpath='{.metadata.annotations}' > "$LATEST/namespace_annotations.json" 2>/dev/null; then
    if jq -e 'has("vpc.amazonaws.com/security-groups")' "$LATEST/namespace_annotations.json" >/dev/null 2>&1; then
      jq -r '."vpc.amazonaws.com/security-groups" // empty' "$LATEST/namespace_annotations.json" | jq -r 'try (split(",") | .[]) catch empty' > "$LATEST/namespace_expected_sgs.txt" 2>/dev/null || true
    fi
  fi
  
  # Get owner references to find Deployment/ReplicaSet
  OWNER_KIND=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null || echo "")
  OWNER_NAME=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null || echo "")
  
  # Check ReplicaSet annotations
  if [ "$OWNER_KIND" = "ReplicaSet" ] && [ -n "$OWNER_NAME" ]; then
    if kubectl -n "$NS" get replicaset "$OWNER_NAME" -o jsonpath='{.metadata.annotations}' > "$LATEST/replicaset_annotations.json" 2>/dev/null; then
      if jq -e 'has("vpc.amazonaws.com/security-groups")' "$LATEST/replicaset_annotations.json" >/dev/null 2>&1; then
        jq -r '."vpc.amazonaws.com/security-groups" // empty' "$LATEST/replicaset_annotations.json" | jq -r 'try (split(",") | .[]) catch empty' > "$LATEST/replicaset_expected_sgs.txt" 2>/dev/null || true
      fi
      
      # Get Deployment from ReplicaSet
      DEPLOYMENT_NAME=$(kubectl -n "$NS" get replicaset "$OWNER_NAME" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null || echo "")
      if [ -n "$DEPLOYMENT_NAME" ]; then
        if kubectl -n "$NS" get deployment "$DEPLOYMENT_NAME" -o jsonpath='{.metadata.annotations}' > "$LATEST/deployment_annotations.json" 2>/dev/null; then
          if jq -e 'has("vpc.amazonaws.com/security-groups")' "$LATEST/deployment_annotations.json" >/dev/null 2>&1; then
            jq -r '."vpc.amazonaws.com/security-groups" // empty' "$LATEST/deployment_annotations.json" | jq -r 'try (split(",") | .[]) catch empty' > "$LATEST/deployment_expected_sgs.txt" 2>/dev/null || true
          fi
        fi
      fi
    fi
  # Check Deployment directly if pod is owned by Deployment
  elif [ "$OWNER_KIND" = "Deployment" ] && [ -n "$OWNER_NAME" ]; then
    if kubectl -n "$NS" get deployment "$OWNER_NAME" -o jsonpath='{.metadata.annotations}' > "$LATEST/deployment_annotations.json" 2>/dev/null; then
      if jq -e 'has("vpc.amazonaws.com/security-groups")' "$LATEST/deployment_annotations.json" >/dev/null 2>&1; then
        jq -r '."vpc.amazonaws.com/security-groups" // empty' "$LATEST/deployment_annotations.json" | jq -r 'try (split(",") | .[]) catch empty' > "$LATEST/deployment_expected_sgs.txt" 2>/dev/null || true
      fi
    fi
  fi
fi

# 3) Node + AWS diags
# Get list of existing diag dirs before running node diag
EXISTING_DIRS=$(ls -d "$DATA_DIR"/sgfp_diag_* 2>/dev/null || true)
./sgfp_node_diag.sh "$NODE" "$DATA_DIR"
# Find the newest directory that wasn't there before
NODE_OUT=$(ls -dt "$DATA_DIR"/sgfp_diag_* 2>/dev/null | while read dir; do
  if [ -n "$EXISTING_DIRS" ]; then
    echo "$EXISTING_DIRS" | grep -q "^${dir}$" && continue
  fi
  echo "$dir"
  break
done | head -n1 || true)
if [ -z "$NODE_OUT" ] || [ ! -d "$NODE_OUT" ]; then
  echo "WARN: Failed to find node diagnostic output directory" >&2
  NODE_OUT=""
fi

# Get list of existing diag dirs before running AWS diag
EXISTING_DIRS=$(ls -d "$DATA_DIR"/sgfp_diag_* 2>/dev/null || true)
./sgfp_aws_diag.sh "$NODE" "$DATA_DIR"
# Find the newest directory that wasn't there before
AWS_OUT=$(ls -dt "$DATA_DIR"/sgfp_diag_* 2>/dev/null | while read dir; do
  if [ -n "$EXISTING_DIRS" ]; then
    echo "$EXISTING_DIRS" | grep -q "^${dir}$" && continue
  fi
  echo "$dir"
  break
done | head -n1 || true)
if [ -z "$AWS_OUT" ] || [ ! -d "$AWS_OUT" ]; then
  echo "WARN: Failed to find AWS diagnostic output directory" >&2
  AWS_OUT=""
fi

# 4) Consolidate
MASTER="$DATA_DIR/sgfp_bundle_${KUBECTL_CONTEXT}_${POD}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$MASTER"
mv "$LATEST" "$MASTER/pod_${POD}"

if [ -n "$NODE_OUT" ] && [ -d "$NODE_OUT" ]; then
  mv "$NODE_OUT" "$MASTER/node_${NODE}"
  # Collect pod IP for conntrack filtering
  POD_IP=$(grep "^POD_IP=" "$MASTER/pod_${POD}/pod_ip.txt" 2>/dev/null | cut -d= -f2- || echo "")
  # Filter conntrack table by pod IP if available
  if [ -n "$POD_IP" ] && [ -s "$MASTER/node_${NODE}/node_conntrack_table.txt" ]; then
    grep -i "$POD_IP" "$MASTER/node_${NODE}/node_conntrack_table.txt" > "$MASTER/pod_${POD}/pod_conntrack_connections.txt" 2>/dev/null || echo "" > "$MASTER/pod_${POD}/pod_conntrack_connections.txt"
  fi
else
  echo "WARN: Node diagnostics not found, skipping" >&2
fi

if [ -n "$AWS_OUT" ] && [ -d "$AWS_OUT" ]; then
  mv "$AWS_OUT" "$MASTER/aws_${NODE}"
  # Now that we have AWS diag, try to populate parent trunk ENI if we have association ID
  if [ -s "$MASTER/pod_${POD}/pod_annotations.json" ] && [ -f "$MASTER/aws_${NODE}/trunk_eni_id.txt" ]; then
    ASSOC_ID=$(jq -r '."vpc.amazonaws.com/pod-eni" | fromjson | .[0].associationID // empty' "$MASTER/pod_${POD}/pod_annotations.json" 2>/dev/null || echo "")
    if [ -n "$ASSOC_ID" ] && [ "$ASSOC_ID" != "null" ] && [ "$ASSOC_ID" != "" ]; then
      # We have a trunk association, use the trunk ENI ID from aws_diag
      TRUNK_ID=$(cat "$MASTER/aws_${NODE}/trunk_eni_id.txt" 2>/dev/null | tr -d '[:space:]' || echo "")
      if [ -n "$TRUNK_ID" ] && [ "$TRUNK_ID" != "null" ] && [ "$TRUNK_ID" != "" ]; then
        echo "$TRUNK_ID" > "$MASTER/pod_${POD}/pod_parent_trunk_eni.txt" 2>/dev/null || true
      fi
    fi
  fi
else
  echo "WARN: AWS diagnostics not found, skipping" >&2
fi

# 5) Collect comprehensive cluster-wide pod snapshot for later analysis (packet captures, etc.)
echo "[COLLECT] Collecting cluster-wide pod snapshot..."
if command -v kubectl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  SNAPSHOT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  SNAPSHOT_TMP=$(mktemp)
  if kubectl get pods -A -o json 2>/dev/null | jq --arg timestamp "$SNAPSHOT_TIMESTAMP" --arg cluster "$KUBECTL_CONTEXT" '{
    "metadata": {
      "cluster": $cluster,
      "timestamp": $timestamp,
      "total_pods": (.items | length)
    },
    "pods": [
      .items[] | {
        "namespace": (.metadata.namespace // ""),
        "name": (.metadata.name // ""),
        "uid": (.metadata.uid // ""),
        "node": (.spec.nodeName // ""),
        "phase": (.status.phase // ""),
        "ipv4": (.status.podIP // ""),
        "ipv6": (try ([.status.podIPs[]? | select(.ip | test(":")) | .ip] | first) catch ""),
        "all_ips": (try ([.status.podIPs[]?.ip // empty] | map(select(. != null and . != ""))) catch []),
        "pod_eni_id": (try (.metadata.annotations."vpc.amazonaws.com/pod-eni" | fromjson | .[0].eniId // "") catch ""),
        "pod_eni_private_ip": (try (.metadata.annotations."vpc.amazonaws.com/pod-eni" | fromjson | .[0].privateIp // "") catch ""),
        "security_groups": (try ((.metadata.annotations."vpc.amazonaws.com/security-groups" // "") | split(",") | map(select(. != ""))) catch []),
        "labels": (.metadata.labels // {}),
        "creation_timestamp": (.metadata.creationTimestamp // ""),
        "deletion_timestamp": (.metadata.deletionTimestamp // ""),
        "owner_kind": (try (.metadata.ownerReferences[0].kind // "") catch ""),
        "owner_name": (try (.metadata.ownerReferences[0].name // "") catch ""),
        "container_ids": (try ([.status.containerStatuses[]? | .containerID // empty] | map(select(. != null and . != ""))) catch []),
        "ready": (try ((.status.conditions[]? | select(.type == "Ready") | .status == "True") // false) catch false),
        "ready_condition": (try ((.status.conditions[]? | select(.type == "Ready") | {
          "status": .status,
          "reason": (.reason // ""),
          "message": (.message // "")
        }) // null) catch null)
      }
    ]
  }' > "$SNAPSHOT_TMP" 2>/dev/null; then
    mv "$SNAPSHOT_TMP" "$MASTER/cluster_pod_snapshot.json"
    POD_COUNT=$(jq -r '.pods | length' "$MASTER/cluster_pod_snapshot.json" 2>/dev/null || echo "0")
    echo "[COLLECT] Collected snapshot of $POD_COUNT pod(s) at $SNAPSHOT_TIMESTAMP"
  else
    rm -f "$SNAPSHOT_TMP" 2>/dev/null || true
    echo "[COLLECT] WARN: Failed to collect pod snapshot (jq query failed)"
    echo '{"metadata":{"error":"jq query failed","timestamp":"'$SNAPSHOT_TIMESTAMP'","cluster":"'$KUBECTL_CONTEXT'"},"pods":[]}' > "$MASTER/cluster_pod_snapshot.json"
  fi
else
  echo "[COLLECT] WARN: kubectl or jq not available, skipping pod snapshot"
  echo '{"metadata":{"error":"kubectl or jq not available"},"pods":[]}' > "$MASTER/cluster_pod_snapshot.json"
fi

# 6) Mark collection as healthy/unhealthy if requested
if [ "$MARK_HEALTHY" -eq 1 ] || [ "$MARK_UNHEALTHY" -eq 1 ]; then
  HEALTH_STATUS=""
  if [ "$MARK_HEALTHY" -eq 1 ]; then
    HEALTH_STATUS="healthy"
    echo "[COLLECT] Marking collection as HEALTHY and saving as baseline..."
    if ./sgfp_save_healthy_baseline.sh "$MASTER" --label healthy 2>&1; then
      echo "[COLLECT] ✓ Healthy baseline saved"
    else
      echo "[COLLECT] WARN: Failed to save healthy baseline" >&2
    fi
  elif [ "$MARK_UNHEALTHY" -eq 1 ]; then
    HEALTH_STATUS="unhealthy"
    echo "[COLLECT] Marking collection as UNHEALTHY..."
  fi
  
  # Create health status metadata file in bundle
  cat > "$MASTER/health_status.txt" <<EOF
Status: $HEALTH_STATUS
Marked at: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Pod: $POD
Namespace: $NS
EOF
  echo "[COLLECT] Health status saved: $HEALTH_STATUS"
fi

echo
echo "[COLLECT] Cluster: ${KUBECTL_CONTEXT}"
echo "[COLLECT] All diagnostics in: $MASTER"
echo "[COLLECT]   - $MASTER/pod_${POD}"
[ -d "$MASTER/node_${NODE}" ] && echo "[COLLECT]   - $MASTER/node_${NODE}"
[ -d "$MASTER/aws_${NODE}" ] && echo "[COLLECT]   - $MASTER/aws_${NODE}"
[ -f "$MASTER/health_status.txt" ] && echo "[COLLECT]   - Health status: $(grep "^Status:" "$MASTER/health_status.txt" 2>/dev/null | cut -d: -f2- | tr -d ' ' || echo "unknown")"
