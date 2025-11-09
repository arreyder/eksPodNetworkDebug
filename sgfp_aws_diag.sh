#!/usr/bin/env bash
set -euo pipefail

NODE_DNS="${1:?usage: sgfp_aws_diag.sh <node-private-dns-or-name>}"
OUT="sgfp_diag_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT"

log()  { printf "[AWS] %s\n" "$*"; }
warn() { printf "[AWS] WARN: %s\n" "$*" >&2; }

REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [ -z "$REGION" ]; then REGION="$(aws configure get region 2>/dev/null || true)"; fi

log "Collecting AWS ENI diagnostics for node: $NODE_DNS"
[ -n "$REGION" ] && log "Region: $REGION" || log "Region: (using default)"
log "Output: $OUT"

# Resolve instance id and get instance details
if [ -n "${REGION:-}" ]; then
  INSTANCE_DATA=$(aws ec2 describe-instances --region "$REGION" \
    --filters "Name=private-dns-name,Values=${NODE_DNS}" \
    --query 'Reservations[0].Instances[0].{InstanceId:InstanceId,InstanceType:InstanceType}' \
    --output json 2>/dev/null || echo "{}")
else
  INSTANCE_DATA=$(aws ec2 describe-instances \
    --filters "Name=private-dns-name,Values=${NODE_DNS}" \
    --query 'Reservations[0].Instances[0].{InstanceId:InstanceId,InstanceType:InstanceType}' \
    --output json 2>/dev/null || echo "{}")
fi

IID=$(echo "$INSTANCE_DATA" | jq -r '.InstanceId // "unknown"' 2>/dev/null || echo "unknown")
INSTANCE_TYPE=$(echo "$INSTANCE_DATA" | jq -r '.InstanceType // "unknown"' 2>/dev/null || echo "unknown")

echo "$IID" > "$OUT/node_instance_id.txt"
echo "$INSTANCE_TYPE" > "$OUT/node_instance_type.txt"

if [ "$IID" = "unknown" ]; then
  warn "Failed to resolve instance ID for node: $NODE_DNS"
else
  log "Instance ID: $IID"
  [ "$INSTANCE_TYPE" != "unknown" ] && log "Instance Type: $INSTANCE_TYPE"
fi

# VPC id
if [ -n "${REGION:-}" ]; then
  VPC=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].VpcId' --output text 2>/dev/null || echo "")
else
  VPC=$(aws ec2 describe-instances --instance-ids "$IID" \
    --query 'Reservations[0].Instances[0].VpcId' --output text 2>/dev/null || echo "")
fi
echo "$VPC" > "$OUT/vpc_id.txt"
[ -n "$VPC" ] && log "VPC ID: $VPC" || warn "Failed to get VPC ID"

# ENIs on instance
log "Collecting ENIs attached to instance..."
if [ -n "${REGION:-}" ]; then
  aws ec2 describe-network-interfaces --region "$REGION" \
    --filters "Name=attachment.instance-id,Values=${IID}" \
    --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,Desc:Description,Status:Status,Subnet:SubnetId,SGs:Groups[].GroupId,PrivIP:PrivateIpAddress,Type:InterfaceType,Dev:Attachment.DeviceIndex}' \
    --output json > "$OUT/all_instance_enis.json" 2>/dev/null || echo "[]" > "$OUT/all_instance_enis.json"
else
  aws ec2 describe-network-interfaces \
    --filters "Name=attachment.instance-id,Values=${IID}" \
    --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,Desc:Description,Status:Status,Subnet:SubnetId,SGs:Groups[].GroupId,PrivIP:PrivateIpAddress,Type:InterfaceType,Dev:Attachment.DeviceIndex}' \
    --output json > "$OUT/all_instance_enis.json" 2>/dev/null || echo "[]" > "$OUT/all_instance_enis.json"
fi

# Find trunk ENI by description or interface type
ENI_COUNT=$(jq -r 'length' "$OUT/all_instance_enis.json" 2>/dev/null || echo 0)
log "Found $ENI_COUNT ENI(s) attached to instance"

TRUNK_ID=$(jq -r '.[] | select((.Desc//"")=="aws-k8s-trunk-eni" or (.Type//"")=="trunk") | .Id' "$OUT/all_instance_enis.json" | head -n1)
echo "$TRUNK_ID" > "$OUT/trunk_eni_id.txt"

if [ -n "$TRUNK_ID" ] && [ "$TRUNK_ID" != "null" ]; then
  log "Trunk ENI: $TRUNK_ID"
  if [ -n "${REGION:-}" ]; then
    aws ec2 describe-network-interfaces --region "$REGION" --network-interface-ids "$TRUNK_ID" \
      --output json > "$OUT/trunk_eni.json" 2>/dev/null || echo "{}" > "$OUT/trunk_eni.json"
  else
    aws ec2 describe-network-interfaces --network-interface-ids "$TRUNK_ID" \
      --output json > "$OUT/trunk_eni.json" 2>/dev/null || echo "{}" > "$OUT/trunk_eni.json"
  fi
else
  warn "Trunk ENI not found"
  echo "{}" > "$OUT/trunk_eni.json"
fi

# Get subnet information for IP availability analysis
if [ -n "$VPC" ]; then
  log "Collecting subnet information..."
  if [ -n "${REGION:-}" ]; then
    aws ec2 describe-subnets --region "$REGION" \
      --filters "Name=vpc-id,Values=$VPC" \
      --query 'Subnets[].[SubnetId,AvailableIpAddressCount,CidrBlock,AvailabilityZone]' \
      --output json > "$OUT/subnets.json" 2>/dev/null || echo "[]" > "$OUT/subnets.json"
  else
    aws ec2 describe-subnets \
      --filters "Name=vpc-id,Values=$VPC" \
      --query 'Subnets[].[SubnetId,AvailableIpAddressCount,CidrBlock,AvailabilityZone]' \
      --output json > "$OUT/subnets.json" 2>/dev/null || echo "[]" > "$OUT/subnets.json"
  fi
  SUBNET_COUNT=$(jq -r 'length' "$OUT/subnets.json" 2>/dev/null || echo 0)
  log "Found $SUBNET_COUNT subnet(s) in VPC"
fi

# Best-effort scan for branch ENIs in VPC (may require perms; may be large)
if [ -n "$VPC" ]; then
  log "Scanning VPC for branch ENIs (this may take a moment)..."
  if [ -n "${REGION:-}" ]; then
    aws ec2 describe-network-interfaces --region "$REGION" \
      --filters "Name=vpc-id,Values=${VPC}" \
      --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,Desc:Description,Status:Status,Subnet:SubnetId,Type:InterfaceType,Attachment:Attachment.ParentNetworkInterfaceId}' \
      --output json > "$OUT/_all_branch_enis_in_vpc.json" 2>/dev/null || echo "[]" > "$OUT/_all_branch_enis_in_vpc.json"
  else
    aws ec2 describe-network-interfaces \
      --filters "Name=vpc-id,Values=${VPC}" \
      --query 'NetworkInterfaces[].{Id:NetworkInterfaceId,Desc:Description,Status:Status,Subnet:SubnetId,Type:InterfaceType,Attachment:Attachment.ParentNetworkInterfaceId}' \
      --output json > "$OUT/_all_branch_enis_in_vpc.json" 2>/dev/null || echo "[]" > "$OUT/_all_branch_enis_in_vpc.json"
  fi
  BRANCH_COUNT=$(jq -r 'length' "$OUT/_all_branch_enis_in_vpc.json" 2>/dev/null || echo 0)
  log "Found $BRANCH_COUNT branch ENI(s) in VPC"
else
  echo "[]" > "$OUT/_all_branch_enis_in_vpc.json"
  warn "VPC ID not available, skipping branch ENI scan"
fi

log "Done. Output directory: $OUT"
