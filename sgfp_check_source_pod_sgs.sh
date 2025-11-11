#!/usr/bin/env bash
# Check security groups of source pods trying to connect
# Usage: ./sgfp_check_source_pod_sgs.sh <bundle-dir>

set -euo pipefail

BUNDLE_DIR="${1:?usage: sgfp_check_source_pod_sgs.sh <bundle-dir>}"

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "[ERROR] Bundle directory not found: $BUNDLE_DIR"
  exit 1
fi

# Find files
POD_IP_MAP=$(find "$BUNDLE_DIR" -name "node_pod_ip_map.txt" -type f 2>/dev/null | head -1)
CONNTRACK_FILE=$(find "$BUNDLE_DIR" -name "pod_conntrack_connections.txt" -type f 2>/dev/null | head -1)
POD_IP_FILE=$(find "$BUNDLE_DIR" -name "pod_ip.txt" -type f 2>/dev/null | head -1)
# Try to find security groups rules file in bundle or in recent analysis
SG_RULES_FILE=$(find "$BUNDLE_DIR" -name "pod_branch_eni_sgs_rules.json" -type f 2>/dev/null | head -1)
if [ -z "$SG_RULES_FILE" ]; then
  # Try to find in recent analysis directories
  SG_RULES_FILE=$(find . -name "security_groups_rules.json" -type f -newer "$BUNDLE_DIR" 2>/dev/null | head -1)
fi

if [ -z "$POD_IP_MAP" ] || [ ! -f "$POD_IP_MAP" ]; then
  echo "[ERROR] Could not find node_pod_ip_map.txt"
  exit 1
fi

# Get pod IP
POD_IP=""
if [ -n "$POD_IP_FILE" ] && [ -f "$POD_IP_FILE" ]; then
  POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
fi

# Get allowed security groups for port 6000
ALLOWED_SGS=$(mktemp)
if [ -n "$SG_RULES_FILE" ] && [ -f "$SG_RULES_FILE" ]; then
  jq -r '.SecurityGroups[]? | 
    select(.GroupId == "sg-061dc3b5f5d8419f0") | 
    .IpPermissions[]? | 
    select(.FromPort // 0 <= 6000 and (.ToPort // 65535) >= 6000) |
    select(.IpProtocol == "tcp" or .IpProtocol == "-1") |
    .UserIdGroupPairs[]?.GroupId' "$SG_RULES_FILE" 2>/dev/null | \
    grep -v '^null$' | grep -v '^$' | sort -u > "$ALLOWED_SGS" || echo "" > "$ALLOWED_SGS"
fi

ALLOWED_COUNT=$(wc -l < "$ALLOWED_SGS" 2>/dev/null | tr -d '[:space:]' || echo "0")
echo "[SOURCE-SG] Checking source pod security groups"
echo "[SOURCE-SG] Allowed security groups for port 6000: $ALLOWED_COUNT"
if [ "$ALLOWED_COUNT" -gt 0 ]; then
  echo "[SOURCE-SG] Allowed SGs:"
  cat "$ALLOWED_SGS" | while read -r sg; do
    echo "  - $sg"
  done
fi
echo ""

# Get region - default to us-west-2
AWS_REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
if [ -z "$AWS_REGION" ]; then
  # Try to extract from bundle path
  if echo "$BUNDLE_DIR" | grep -q "uswest2"; then
    AWS_REGION="us-west-2"
  else
    # Default to us-west-2 as specified by user
    AWS_REGION="us-west-2"
  fi
fi

echo "[SOURCE-SG] Using AWS region: $AWS_REGION"

OUTPUT_DIR="source_pod_sgs_check_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

# Extract source IPs from conntrack
echo "[SOURCE-SG] Extracting source IPs from conntrack..."
SOURCE_IPS=$(mktemp)
if [ -n "$CONNTRACK_FILE" ] && [ -f "$CONNTRACK_FILE" ] && [ -n "$POD_IP" ]; then
  grep "dst=$POD_IP.*dport=6000" "$CONNTRACK_FILE" 2>/dev/null | \
    grep -oE "src=([0-9]{1,3}\.){3}[0-9]{1,3}" | \
    sed 's/src=//' | \
    grep -v "^$POD_IP$" | \
    sort -u > "$SOURCE_IPS" || echo "" > "$SOURCE_IPS"
fi

SOURCE_COUNT=$(wc -l < "$SOURCE_IPS" 2>/dev/null | tr -d '[:space:]' || echo "0")
echo "[SOURCE-SG] Found $SOURCE_COUNT unique source IP(s) connecting to port 6000"
echo ""

# For each source IP, find the pod and check its security groups
{
  echo "# Source Pod Security Groups Analysis"
  echo "# Checking if source pods have security groups that match allowed list"
  echo ""
  echo "Allowed Security Groups for Port 6000:"
  cat "$ALLOWED_SGS" | while read -r sg; do
    echo "  - $sg"
  done
  echo ""
  echo "=== Source Pod Security Groups ==="
  echo ""
  
  if [ "$SOURCE_COUNT" -eq 0 ] || [ ! -s "$SOURCE_IPS" ]; then
    echo "No source IPs found"
  else
    cat "$SOURCE_IPS" | while read -r src_ip; do
      [ -z "$src_ip" ] && continue
      
      # Find pod name from IP
      pod_info=$(grep -m1 "^$src_ip " "$POD_IP_MAP" 2>/dev/null | awk '{print $2}' || echo "")
      
      if [ -z "$pod_info" ]; then
        echo "Source IP: $src_ip"
        echo "  Pod: (not found in pod map)"
        echo "  Security Groups: (cannot check - pod not found)"
        echo ""
        continue
      fi
      
      namespace=$(echo "$pod_info" | cut -d/ -f1)
      pod_name=$(echo "$pod_info" | cut -d/ -f2)
      
      echo "Source IP: $src_ip"
      echo "  Pod: $pod_info"
      
      # Get pod ENI ID
      if command -v kubectl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        eni_id=$(kubectl -n "$namespace" get pod "$pod_name" -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/pod-eni}' 2>/dev/null | \
          jq -r '.[0].eniId // empty' 2>/dev/null || echo "")
        
        if [ -n "$eni_id" ] && [ "$eni_id" != "null" ] && [ "$eni_id" != "" ]; then
          # Get security groups from ENI
          if [ -n "${AWS_REGION:-}" ]; then
            pod_sgs=$(aws ec2 describe-network-interfaces --region "$AWS_REGION" \
              --network-interface-ids "$eni_id" \
              --query 'NetworkInterfaces[0].Groups[].GroupId' \
              --output text 2>/dev/null || echo "")
          else
            pod_sgs=$(aws ec2 describe-network-interfaces \
              --network-interface-ids "$eni_id" \
              --query 'NetworkInterfaces[0].Groups[].GroupId' \
              --output text 2>/dev/null || echo "")
          fi
          
          if [ -n "$pod_sgs" ]; then
            echo "  Security Groups (from pod ENI): $pod_sgs"
            
            # Check if any of the pod's SGs are in the allowed list
            matched=0
            for pod_sg in $pod_sgs; do
              if grep -q "^$pod_sg$" "$ALLOWED_SGS" 2>/dev/null; then
                echo "  ✅ MATCH: $pod_sg is in allowed list"
                matched=1
              fi
            done
            
            if [ "$matched" -eq 0 ]; then
              echo "  ❌ NO MATCH: None of the pod's security groups are in the allowed list"
              echo "  ⚠️  This pod's traffic to port 6000 will be BLOCKED by security groups"
            fi
          else
            echo "  Security Groups: (could not retrieve)"
          fi
        else
          # Pod doesn't have pod ENI - it's using node security groups
          echo "  Security Groups: (pod ENI not found - using node security groups)"
          
          # Get node name for this pod
          node_name=$(kubectl -n "$namespace" get pod "$pod_name" -o jsonpath='{.spec.nodeName}' 2>/dev/null || echo "")
          
          # Get node security groups - try bundle first, then AWS API
          node_sgs=""
          if [ -n "$node_name" ]; then
            # Look for this specific node's ENI info in bundle
            NODE_ENI_FILE=$(find "$BUNDLE_DIR" -path "*aws_${node_name}*/all_instance_enis.json" -type f 2>/dev/null | head -1)
            if [ -n "$NODE_ENI_FILE" ] && [ -f "$NODE_ENI_FILE" ]; then
              # Get security groups from primary ENI (device index 0) or first ENI
              node_sgs=$(jq -r '.[] | select(.Dev == 0 or .Dev == null) | .SGs[]?' "$NODE_ENI_FILE" 2>/dev/null | sort -u | tr '\n' ' ' || echo "")
              if [ -z "$node_sgs" ]; then
                # Fallback: get from any ENI (union of all SGs)
                node_sgs=$(jq -r '.[].SGs[]?' "$NODE_ENI_FILE" 2>/dev/null | sort -u | tr '\n' ' ' || echo "")
              fi
            fi
            
            # If not found in bundle, try AWS API
            if [ -z "$node_sgs" ]; then
              # Get node's instance ID and then its security groups
              instance_id=$(aws ec2 describe-instances --region "$AWS_REGION" \
                --filters "Name=private-dns-name,Values=${node_name}" \
                --query 'Reservations[0].Instances[0].InstanceId' \
                --output text 2>/dev/null || echo "")
              
              if [ -n "$instance_id" ] && [ "$instance_id" != "None" ] && [ "$instance_id" != "null" ]; then
                # Get node's security groups
                node_sgs=$(aws ec2 describe-instances --region "$AWS_REGION" \
                  --instance-ids "$instance_id" \
                  --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
                  --output text 2>/dev/null | tr '\t' ' ' || echo "")
              fi
            fi
          else
            # If we don't have node name, try to find instance by private IP
            # Pod IPs are secondary IPs on ENIs, so we need to:
            # 1. Find the ENI that has this IP (try multiple filter approaches)
            # 2. Find the instance that ENI is attached to
            
            # Try filter for any IP on the ENI (primary or secondary)
            eni_data=$(aws ec2 describe-network-interfaces --region "$AWS_REGION" \
              --filters "Name=addresses.private-ip-address,Values=${src_ip}" \
              --query 'NetworkInterfaces[0].{ENI:NetworkInterfaceId,Instance:Attachment.InstanceId,Type:InterfaceType}' \
              --output json 2>/dev/null || echo "{}")
            
            eni_id=$(echo "$eni_data" | jq -r '.ENI // empty' 2>/dev/null || echo "")
            instance_id=$(echo "$eni_data" | jq -r '.Instance // empty' 2>/dev/null || echo "")
            eni_type=$(echo "$eni_data" | jq -r '.Type // empty' 2>/dev/null || echo "")
            
            # If we found a branch ENI (pod ENI), it's attached to a trunk ENI, not directly to instance
            # In that case, we need to get the trunk ENI and then the instance
            if [ -n "$eni_id" ] && [ "$eni_id" != "null" ] && [ "$eni_type" = "branch" ]; then
              # Get trunk ENI ID from the branch ENI
              trunk_eni_id=$(aws ec2 describe-network-interfaces --region "$AWS_REGION" \
                --network-interface-ids "$eni_id" \
                --query 'NetworkInterfaces[0].InterfaceType' \
                --output text 2>/dev/null || echo "")
              # Actually, branch ENIs have a trunk association, let's get the attachment
              trunk_info=$(aws ec2 describe-network-interfaces --region "$AWS_REGION" \
                --network-interface-ids "$eni_id" \
                --query 'NetworkInterfaces[0].Attachment' \
                --output json 2>/dev/null || echo "{}")
              # Branch ENIs are attached to trunk ENIs, not instances
              # We need to find the trunk ENI and then the instance
              # For now, if it's a branch ENI, we can't easily get the instance
              # This pod might actually have a pod ENI, contradicting our earlier check
            fi
            
            # If we have an instance ID, get security groups
            if [ -n "$instance_id" ] && [ "$instance_id" != "None" ] && [ "$instance_id" != "null" ]; then
              # Get node's security groups
              node_sgs=$(aws ec2 describe-instances --region "$AWS_REGION" \
                --instance-ids "$instance_id" \
                --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
                --output text 2>/dev/null | tr '\t' ' ' || echo "")
            fi
          fi
          
          if [ -n "$node_sgs" ]; then
            echo "  Node Security Groups: $node_sgs"
            
            # Check if any of the node's SGs are in the allowed list
            matched=0
            for node_sg in $node_sgs; do
              if grep -q "^$node_sg$" "$ALLOWED_SGS" 2>/dev/null; then
                echo "  ✅ MATCH: $node_sg is in allowed list"
                matched=1
              fi
            done
            
            if [ "$matched" -eq 0 ]; then
              echo "  ❌ NO MATCH: None of the node's security groups are in the allowed list"
              echo "  ⚠️  This pod's traffic to port 6000 will be BLOCKED by security groups"
              echo "  💡 Solution: Add node's security groups to be-conductor-sg-service-b984468 ingress rules"
            fi
          else
            if [ -z "$node_name" ]; then
              echo "  ⚠️  Could not get node name (pod may have been deleted/recreated)"
            fi
            echo "  ⚠️  Could not retrieve node security groups"
            echo "      (Node: ${node_name:-unknown}, Region: $AWS_REGION)"
            echo "  💡 Note: IP ${src_ip} may have been reassigned since diagnostic collection"
            echo "      To verify security groups, run diagnostics while source pods are active"
          fi
        fi
      else
        echo "  Security Groups: (kubectl/jq not available)"
      fi
      echo ""
    done
  fi
  
  echo ""
  echo "=== Summary ==="
  echo ""
  echo "Allowed Security Groups for Port 6000: $(wc -l < "$ALLOWED_SGS" 2>/dev/null | tr -d '[:space:]' || echo "0")"
  echo ""
  echo "Source Pods Analyzed: $SOURCE_COUNT"
  echo ""
  echo "Note: If node security groups could not be retrieved, it may be because:"
  echo "  - Source pods have been deleted/recreated since diagnostic collection"
  echo "  - Pod IPs have been reassigned"
  echo "  - To get accurate results, run this analysis while source pods are still active"
  echo ""
} > "$OUTPUT_DIR/source_pod_sgs_analysis.txt"

rm -f "$SOURCE_IPS" "$ALLOWED_SGS" 2>/dev/null || true

echo ""
echo "[SOURCE-SG] Analysis complete!"
echo "[SOURCE-SG] Results saved to: $OUTPUT_DIR"
echo "[SOURCE-SG] Key file: source_pod_sgs_analysis.txt"
echo ""
echo "[SOURCE-SG] Note: If security groups could not be retrieved for source pods,"
echo "[SOURCE-SG]       they may have been deleted/recreated. Run diagnostics while"
echo "[SOURCE-SG]       source pods are active for accurate results."

