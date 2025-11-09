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

# Collect NAT gateway information and CloudWatch metrics
if [ -n "$VPC" ] && [ -n "$REGION" ]; then
  log "Collecting NAT gateway information..."
  
  # Get NAT gateways in VPC
  if [ -n "${REGION:-}" ]; then
    aws ec2 describe-nat-gateways --region "$REGION" \
      --filter "Name=vpc-id,Values=$VPC" \
      --filter "Name=state,Values=available" \
      --query 'NatGateways[].[NatGatewayId,SubnetId,State,PublicIp]' \
      --output json > "$OUT/nat_gateways.json" 2>/dev/null || echo "[]" > "$OUT/nat_gateways.json"
  else
    aws ec2 describe-nat-gateways \
      --filter "Name=vpc-id,Values=$VPC" \
      --filter "Name=state,Values=available" \
      --query 'NatGateways[].[NatGatewayId,SubnetId,State,PublicIp]' \
      --output json > "$OUT/nat_gateways.json" 2>/dev/null || echo "[]" > "$OUT/nat_gateways.json"
  fi
  
  NAT_COUNT=$(jq -r 'length' "$OUT/nat_gateways.json" 2>/dev/null || echo 0)
  if [ "$NAT_COUNT" -gt 0 ]; then
    log "Found $NAT_COUNT NAT gateway(s) in VPC"
    
    # Collect CloudWatch metrics for each NAT gateway
    # Metrics: ActiveConnectionCount (indicator of SNAT port usage)
    # Time range: use WINDOW_MINUTES env var (same as CloudTrail), default to 2880 minutes (2 days)
    WINDOW_MINUTES="${WINDOW_MINUTES:-2880}"
    END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "")
    # Try GNU date first, fall back to BSD date
    if date -u -d "${WINDOW_MINUTES} minutes ago" +"%Y-%m-%dT%H:%M:%S" >/dev/null 2>&1; then
      START_TIME=$(date -u -d "${WINDOW_MINUTES} minutes ago" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "")
    elif date -u -v-"${WINDOW_MINUTES}"M +"%Y-%m-%dT%H:%M:%S" >/dev/null 2>&1; then
      START_TIME=$(date -u -v-"${WINDOW_MINUTES}"M +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "")
    else
      # Fallback: calculate seconds and use epoch
      SECONDS_AGO=$((WINDOW_MINUTES * 60))
      START_EPOCH=$(($(date -u +%s) - SECONDS_AGO))
      START_TIME=$(date -u -d "@${START_EPOCH}" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || date -u -r "${START_EPOCH}" +"%Y-%m-%dT%H:%M:%S" 2>/dev/null || echo "")
    fi
    
    if [ -n "$END_TIME" ] && [ -n "$START_TIME" ]; then
      log "Collecting CloudWatch metrics for NAT gateways (last ${WINDOW_MINUTES} minutes)..."
      
      NAT_INDEX=0
      while [ "$NAT_INDEX" -lt "$NAT_COUNT" ]; do
        NAT_ID=$(jq -r ".[$NAT_INDEX][0] // \"\"" "$OUT/nat_gateways.json" 2>/dev/null || echo "")
        if [ -n "$NAT_ID" ] && [ "$NAT_ID" != "null" ] && [ "$NAT_ID" != "" ]; then
          # Get metrics for this NAT gateway
          # ActiveConnectionCount - current active connections (indicator of SNAT port usage)
          # BytesInFromDestination - inbound traffic
          # BytesOutToDestination - outbound traffic
          
          METRICS_FILE="$OUT/nat_${NAT_ID}_metrics.json"
          
          if [ -n "${REGION:-}" ]; then
            aws cloudwatch get-metric-statistics --region "$REGION" \
              --namespace AWS/NATGateway \
              --metric-name ActiveConnectionCount \
              --dimensions Name=NatGatewayId,Value="$NAT_ID" \
              --start-time "$START_TIME" \
              --end-time "$END_TIME" \
              --period 300 \
              --statistics Maximum \
              --statistics Average \
              --output json > "$METRICS_FILE" 2>/dev/null || echo "{}" > "$METRICS_FILE"
          else
            aws cloudwatch get-metric-statistics \
              --namespace AWS/NATGateway \
              --metric-name ActiveConnectionCount \
              --dimensions Name=NatGatewayId,Value="$NAT_ID" \
              --start-time "$START_TIME" \
              --end-time "$END_TIME" \
              --period 300 \
              --statistics Maximum \
              --statistics Average \
              --output json > "$METRICS_FILE" 2>/dev/null || echo "{}" > "$METRICS_FILE"
          fi
          
          # Check if we got valid metrics
          METRIC_COUNT=$(jq -r '.Datapoints | length' "$METRICS_FILE" 2>/dev/null || echo "0")
          if [ "$METRIC_COUNT" != "0" ] && [ "$METRIC_COUNT" != "null" ]; then
            log "Collected metrics for NAT gateway $NAT_ID ($METRIC_COUNT data points)"
          fi
        fi
        NAT_INDEX=$((NAT_INDEX + 1))
      done
    else
      warn "Cannot determine time range for CloudWatch metrics (date command issue)"
    fi
  else
    log "No NAT gateways found in VPC (may use Internet Gateway or no internet access)"
    echo "[]" > "$OUT/nat_gateways.json"
  fi
else
  echo "[]" > "$OUT/nat_gateways.json"
  if [ -z "$VPC" ]; then
    warn "VPC ID not available, skipping NAT gateway collection"
  elif [ -z "$REGION" ]; then
    warn "Region not available, skipping NAT gateway CloudWatch metrics"
  fi
fi

log "Done. Output directory: $OUT"
