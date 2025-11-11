#!/usr/bin/env bash
# Analyze security group rules to verify if cross-node source IPs are allowed
# Usage: ./sgfp_analyze_sg_rules.sh <bundle-dir>

set -euo pipefail

BUNDLE_DIR="${1:?usage: sgfp_analyze_sg_rules.sh <bundle-dir>}"

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "[ERROR] Bundle directory not found: $BUNDLE_DIR"
  exit 1
fi

# Find security group files
SG_IDS_FILE=$(find "$BUNDLE_DIR" -name "pod_branch_eni_sgs.txt" -type f 2>/dev/null | head -1)
CONNTRACK_FILE=$(find "$BUNDLE_DIR" -name "pod_conntrack_connections.txt" -type f 2>/dev/null | head -1)
POD_IP_FILE=$(find "$BUNDLE_DIR" -name "pod_ip.txt" -type f 2>/dev/null | head -1)

if [ -z "$SG_IDS_FILE" ] || [ ! -f "$SG_IDS_FILE" ]; then
  echo "[ERROR] Could not find pod_branch_eni_sgs.txt"
  exit 1
fi

# Get pod IP
POD_IP=""
if [ -n "$POD_IP_FILE" ] && [ -f "$POD_IP_FILE" ]; then
  POD_IP=$(grep "^POD_IP=" "$POD_IP_FILE" 2>/dev/null | cut -d= -f2- || echo "")
fi

# Get region
AWS_REGION="${AWS_REGION:-}"
if [ -z "$AWS_REGION" ]; then
  # Try to extract from bundle path or node name
  if echo "$BUNDLE_DIR" | grep -q "uswest2"; then
    AWS_REGION="us-west-2"
  elif echo "$BUNDLE_DIR" | grep -q "uswest"; then
    AWS_REGION="us-west-2"
  fi
fi

if [ -z "$AWS_REGION" ]; then
  echo "[ERROR] AWS_REGION not set and could not determine from bundle path"
  exit 1
fi

OUTPUT_DIR="sg_rules_analysis_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[SG-RULES] Analyzing security group rules"
echo "[SG-RULES] Bundle directory: $BUNDLE_DIR"
echo "[SG-RULES] Region: $AWS_REGION"
echo "[SG-RULES] Output directory: $OUTPUT_DIR"
echo ""

# Read security group IDs
SG_IDS=$(cat "$SG_IDS_FILE" 2>/dev/null | grep -v '^$' | tr '\n' ' ' || echo "")
if [ -z "$SG_IDS" ]; then
  echo "[ERROR] No security group IDs found"
  exit 1
fi

echo "[SG-RULES] Security groups: $SG_IDS"
echo ""

# Get full security group details including rules
echo "[SG-RULES] Fetching security group rules from AWS..."
if [ -n "${AWS_REGION:-}" ]; then
  aws ec2 describe-security-groups --region "$AWS_REGION" --group-ids $SG_IDS \
    --output json > "$OUTPUT_DIR/security_groups_full.json" 2>/dev/null || {
    echo "[ERROR] Failed to fetch security group details"
    exit 1
  }
else
  aws ec2 describe-security-groups --group-ids $SG_IDS \
    --output json > "$OUTPUT_DIR/security_groups_full.json" 2>/dev/null || {
    echo "[ERROR] Failed to fetch security group details"
    exit 1
  }
fi

# Extract cross-node source IPs from conntrack
echo "[SG-RULES] Extracting cross-node source IPs from conntrack..."
CROSS_NODE_SOURCES=$(mktemp)
if [ -n "$CONNTRACK_FILE" ] && [ -f "$CONNTRACK_FILE" ] && [ -n "$POD_IP" ]; then
  # Extract source IPs that are cross-node (not from same node)
  grep "dst=$POD_IP" "$CONNTRACK_FILE" 2>/dev/null | \
    grep -oE "src=([0-9]{1,3}\.){3}[0-9]{1,3}" | \
    sed 's/src=//' | \
    grep -v "^$POD_IP$" | \
    sort -u > "$CROSS_NODE_SOURCES" || echo "" > "$CROSS_NODE_SOURCES"
else
  echo "" > "$CROSS_NODE_SOURCES"
fi

CROSS_NODE_COUNT=$(wc -l < "$CROSS_NODE_SOURCES" 2>/dev/null | tr -d '[:space:]' || echo "0")
echo "[SG-RULES] Found $CROSS_NODE_COUNT unique cross-node source IP(s)"
echo ""

# Analyze each security group
echo "[SG-RULES] Analyzing security group rules..."
{
  echo "# Security Group Rules Analysis"
  echo "# Pod IP: ${POD_IP:-unknown}"
  echo "# Cross-node source IPs: $CROSS_NODE_COUNT"
  echo ""
  
  jq -r '.SecurityGroups[] | "=== \(.GroupId) - \(.GroupName) ==="' "$OUTPUT_DIR/security_groups_full.json" 2>/dev/null | while read -r header; do
    echo "$header"
    SG_ID=$(echo "$header" | grep -oE "sg-[a-z0-9]+" | head -1)
    
    if [ -n "$SG_ID" ]; then
      # Get ingress rules for this SG
      echo ""
      echo "Ingress Rules:"
      jq -r --arg sg_id "$SG_ID" '.SecurityGroups[] | select(.GroupId == $sg_id) | .IpPermissions[]? | 
        "  Port: \(.FromPort // "all")-\(.ToPort // "all")/\(.IpProtocol // "all")
        Sources:
        \(.IpRanges[]? | "    - \(.CidrIp // "unknown")\(if .Description then " (\(.Description))" else "" end)")
        \(.UserIdGroupPairs[]? | "    - SG: \(.GroupId // "unknown")\(if .GroupName then " (\(.GroupName))" else "" end)")"' \
        "$OUTPUT_DIR/security_groups_full.json" 2>/dev/null | head -50 || echo "  (no ingress rules or error parsing)"
      
      echo ""
    fi
  done
} > "$OUTPUT_DIR/01_sg_rules_summary.txt"

# Check if cross-node source IPs are allowed
echo "[SG-RULES] Checking if cross-node source IPs are allowed..."
{
  echo "# Cross-Node Source IP Allowance Check"
  echo "# Checking if source IPs from conntrack are allowed by security groups"
  echo ""
  
  if [ "$CROSS_NODE_COUNT" -eq 0 ] || [ ! -s "$CROSS_NODE_SOURCES" ]; then
    echo "No cross-node source IPs found in conntrack data"
  else
    echo "Cross-node source IPs to check:"
    cat "$CROSS_NODE_SOURCES" | while read -r src_ip; do
      [ -z "$src_ip" ] && continue
      echo "  - $src_ip"
    done
    echo ""
    
    # For each source IP, check if it's allowed
    cat "$CROSS_NODE_SOURCES" | while read -r src_ip; do
      [ -z "$src_ip" ] && continue
      
      echo "Checking $src_ip:"
      
      # Check if IP is in any CIDR range in ingress rules
      ALLOWED=0
      jq -r --arg ip "$src_ip" '.SecurityGroups[].IpPermissions[]? | 
        select(.IpRanges[]?.CidrIp != null) | 
        .IpRanges[]?.CidrIp' "$OUTPUT_DIR/security_groups_full.json" 2>/dev/null | \
        while read -r cidr; do
          # Simple CIDR check (basic - for /8, /16, /24, /32)
          if echo "$cidr" | grep -q "/"; then
            cidr_base=$(echo "$cidr" | cut -d/ -f1)
            cidr_mask=$(echo "$cidr" | cut -d/ -f2)
            
            # For common masks, do simple prefix matching
            if [ "$cidr_mask" = "8" ]; then
              ip_prefix=$(echo "$src_ip" | cut -d. -f1)
              cidr_prefix=$(echo "$cidr_base" | cut -d. -f1)
              if [ "$ip_prefix" = "$cidr_prefix" ]; then
                echo "    ✅ ALLOWED by $cidr (matches /8 prefix)"
                ALLOWED=1
              fi
            elif [ "$cidr_mask" = "16" ]; then
              ip_prefix=$(echo "$src_ip" | cut -d. -f1-2)
              cidr_prefix=$(echo "$cidr_base" | cut -d. -f1-2)
              if [ "$ip_prefix" = "$cidr_prefix" ]; then
                echo "    ✅ ALLOWED by $cidr (matches /16 prefix)"
                ALLOWED=1
              fi
            elif [ "$cidr_mask" = "24" ]; then
              ip_prefix=$(echo "$src_ip" | cut -d. -f1-3)
              cidr_prefix=$(echo "$cidr_base" | cut -d. -f1-3)
              if [ "$ip_prefix" = "$cidr_prefix" ]; then
                echo "    ✅ ALLOWED by $cidr (matches /24 prefix)"
                ALLOWED=1
              fi
            elif [ "$cidr_mask" = "32" ] || [ "$cidr_mask" = "" ]; then
              if [ "$src_ip" = "$cidr_base" ]; then
                echo "    ✅ ALLOWED by $cidr (exact match)"
                ALLOWED=1
              fi
            fi
          elif [ "$cidr" = "0.0.0.0/0" ]; then
            echo "    ✅ ALLOWED by $cidr (all traffic)"
            ALLOWED=1
          fi
        done
      
      if [ "$ALLOWED" -eq 0 ]; then
        echo "    ❌ NOT EXPLICITLY ALLOWED (check SG rules manually)"
      fi
      echo ""
    done
  fi
} > "$OUTPUT_DIR/02_cross_node_ip_check.txt"

# Create summary of all ingress rules
{
  echo "# All Ingress Rules Summary"
  echo ""
  jq -r '.SecurityGroups[] | 
    "## \(.GroupId) - \(.GroupName)
\(.Description // "No description")
Ingress Rules:" as $header |
    .IpPermissions[]? | 
    "  Port: \(.FromPort // "all")-\(.ToPort // "all")/\(.IpProtocol // "all")
    \(.IpRanges[]? | "    CIDR: \(.CidrIp // "unknown")\(if .Description then " - \(.Description)" else "" end)")
    \(.UserIdGroupPairs[]? | "    SG: \(.GroupId // "unknown")\(if .GroupName then " (\(.GroupName))" else "" end)")"' \
    "$OUTPUT_DIR/security_groups_full.json" 2>/dev/null | head -200
} > "$OUTPUT_DIR/03_all_ingress_rules.txt"

# Cleanup
rm -f "$CROSS_NODE_SOURCES" 2>/dev/null || true

echo ""
echo "[SG-RULES] Analysis complete!"
echo "[SG-RULES] Results saved to: $OUTPUT_DIR"
echo "[SG-RULES] Key files:"
echo "  - 01_sg_rules_summary.txt (summary of all rules)"
echo "  - 02_cross_node_ip_check.txt (check if source IPs are allowed)"
echo "  - 03_all_ingress_rules.txt (all ingress rules)"
echo "  - security_groups_full.json (full AWS API response)"

