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
LATEST=$(ls -dt sgfp_diag_* | head -n1)

# Node name
NODE=$(awk -F= '/^NODE=/{print $2}' "$LATEST/node_name.txt")

# 2) SG-for-Pods flag
if jq -er '."vpc.amazonaws.com/pod-eni"' "$LATEST/pod_annotations.json" >/dev/null 2>&1; then
  echo 1 > "$LATEST/.is_sgfp"
else
  echo 0 > "$LATEST/.is_sgfp"
fi

# 2.1) SG-for-Pods ENI + SG capture
if [ -s "$LATEST/pod_annotations.json" ] && jq -e 'has("vpc.amazonaws.com/pod-eni")' "$LATEST/pod_annotations.json" >/dev/null 2>&1; then
  POD_ENI_ID="$( jq -r '."vpc.amazonaws.com/pod-eni" // empty' "$LATEST/pod_annotations.json" | jq -r 'try (fromjson | .[0].eniId) catch empty' )"
  if [ -n "$POD_ENI_ID" ] && [ "$POD_ENI_ID" != "null" ]; then
    echo "$POD_ENI_ID" > "$LATEST/pod_branch_eni_id.txt"
    if command -v aws >/dev/null 2>&1; then
      REG_FLAG=""; [ -n "${AWS_REGION:-}" ] && REG_FLAG="--region $AWS_REGION"
      aws ec2 describe-network-interfaces $REG_FLAG --network-interface-ids "$POD_ENI_ID" > "$LATEST/pod_branch_eni_describe.json" 2>/dev/null || echo "{}" > "$LATEST/pod_branch_eni_describe.json"
      jq -r '.NetworkInterfaces[0].Groups[]?.GroupId' "$LATEST/pod_branch_eni_describe.json" > "$LATEST/pod_branch_eni_sgs.txt" 2>/dev/null || true
      jq -r '.NetworkInterfaces[0].Attachment.ParentNetworkInterfaceId // empty' "$LATEST/pod_branch_eni_describe.json" > "$LATEST/pod_parent_trunk_eni.txt" 2>/dev/null || true
    fi
  fi
fi

# 3) Node + AWS diags
./sgfp_node_diag.sh "$NODE"
NODE_OUT=$(ls -dt sgfp_diag_* | head -n1)
./sgfp_aws_diag.sh "$NODE"
AWS_OUT=$(ls -dt sgfp_diag_* | head -n1)

# 4) Consolidate
MASTER="sgfp_bundle_${POD}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$MASTER"
mv "$LATEST"   "$MASTER/pod_${POD}"
mv "$NODE_OUT" "$MASTER/node_${NODE}"
mv "$AWS_OUT"  "$MASTER/aws_${NODE}"

echo
echo "[b^S] All diagnostics in: $MASTER"
echo "    - $MASTER/pod_${POD}"
echo "    - $MASTER/node_${NODE}"
echo "    - $MASTER/aws_${NODE}"
