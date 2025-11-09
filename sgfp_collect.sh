#!/usr/bin/env bash
set -euo pipefail

NS="default"
while getopts ":n:" opt; do
  case $opt in
    n) NS="$OPTARG" ;;
    *) echo "usage: sgfp_collect.sh [-n namespace] <pod-name>"; exit 1 ;;
  esac
done
shift $((OPTIND-1))
POD="${1:?usage: sgfp_collect.sh [-n namespace] <pod-name>}"

# 1) Pod diag
./sgfp_pod_diag.sh "$POD" "$NS"
LATEST=$(ls -dt sgfp_diag_* 2>/dev/null | head -n1 || true)
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
                aws ec2 describe-security-groups --region "$AWS_REGION" --group-ids $SG_ID_LIST \
                  --query 'SecurityGroups[].[GroupId,GroupName,Description]' --output json > "$LATEST/pod_branch_eni_sgs_details.json" 2>/dev/null || echo "[]" > "$LATEST/pod_branch_eni_sgs_details.json"
              else
                aws ec2 describe-security-groups --group-ids $SG_ID_LIST \
                  --query 'SecurityGroups[].[GroupId,GroupName,Description]' --output json > "$LATEST/pod_branch_eni_sgs_details.json" 2>/dev/null || echo "[]" > "$LATEST/pod_branch_eni_sgs_details.json"
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
EXISTING_DIRS=$(ls -d sgfp_diag_* 2>/dev/null || true)
./sgfp_node_diag.sh "$NODE"
# Find the newest directory that wasn't there before
NODE_OUT=$(ls -dt sgfp_diag_* 2>/dev/null | while read dir; do
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
EXISTING_DIRS=$(ls -d sgfp_diag_* 2>/dev/null || true)
./sgfp_aws_diag.sh "$NODE"
# Find the newest directory that wasn't there before
AWS_OUT=$(ls -dt sgfp_diag_* 2>/dev/null | while read dir; do
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
MASTER="sgfp_bundle_${POD}_$(date +%Y%m%d_%H%M%S)"
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

echo
echo "[COLLECT] All diagnostics in: $MASTER"
echo "[COLLECT]   - $MASTER/pod_${POD}"
[ -d "$MASTER/node_${NODE}" ] && echo "[COLLECT]   - $MASTER/node_${NODE}"
[ -d "$MASTER/aws_${NODE}" ] && echo "[COLLECT]   - $MASTER/aws_${NODE}"
