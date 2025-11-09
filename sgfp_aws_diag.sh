#!/usr/bin/env bash
set -euo pipefail

NODE_DNS="${1:?usage: sgfp_aws_diag.sh <node-private-dns-or-name>}"
OUT="sgfp_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
REG_ARG=""
if [ -n "${REGION:-}" ]; then REG_ARG="--region $REGION"; fi

# Resolve instance id
IID=$(aws ec2 describe-instances $REG_ARG \
  --filters "Name=private-dns-name,Values=${NODE_DNS}" \
  --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null || echo "unknown")

echo "$IID" > "$OUT/node_instance_id.txt"

# VPC id
VPC=$(aws ec2 describe-instances $REG_ARG --instance-ids "$IID" \
  --query 'Reservations[0].Instances[0].VpcId' --output text 2>/dev/null || echo "")
echo "$VPC" > "$OUT/vpc_id.txt"

# ENIs on instance
aws ec2 describe-network-interfaces $REG_ARG \
  --filters "Name=attachment.instance-id,Values=${IID}" \
  --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,Desc:Description,Status:Status,Subnet:SubnetId,SGs:Groups[].GroupId,PrivIP:PrivateIpAddress,Type:InterfaceType,Dev:Attachment.DeviceIndex}' \
  --output json > "$OUT/all_instance_enis.json" 2>/dev/null || echo "[]" > "$OUT/all_instance_enis.json"

# Find trunk ENI by description or interface type
TRUNK_ID=$(jq -r '.[] | select((.Desc//"")=="aws-k8s-trunk-eni" or (.Type//"")=="trunk") | .Id' "$OUT/all_instance_enis.json" | head -n1)
echo "$TRUNK_ID" > "$OUT/trunk_eni_id.txt"

if [ -n "$TRUNK_ID" ] && [ "$TRUNK_ID" != "null" ]; then
  aws ec2 describe-network-interfaces $REG_ARG --network-interface-ids "$TRUNK_ID" \
    --output json > "$OUT/trunk_eni.json" 2>/dev/null || echo "{}" > "$OUT/trunk_eni.json"
else
  echo "{}" > "$OUT/trunk_eni.json"
fi

# Best-effort scan for branch ENIs in VPC (may require perms; may be large)
if [ -n "$VPC" ]; then
  aws ec2 describe-network-interfaces $REG_ARG \
    --filters "Name=vpc-id,Values=${VPC}" \
    --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,Desc:Description,Status:Status,Subnet:SubnetId,Type:InterfaceType,Attachment:Attachment.ParentNetworkInterfaceId}' \
    --output json > "$OUT/_all_branch_enis_in_vpc.json" 2>/dev/null || echo "[]" > "$OUT/_all_branch_enis_in_vpc.json"
else
  echo "[]" > "$OUT/_all_branch_enis_in_vpc.json"
fi
