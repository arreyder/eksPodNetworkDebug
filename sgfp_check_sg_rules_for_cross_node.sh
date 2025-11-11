#!/usr/bin/env bash
# Check security group rules to verify if cross-node source IPs are allowed
# Usage: ./sgfp_check_sg_rules_for_cross_node.sh <bundle-dir>

set -euo pipefail

BUNDLE_DIR="${1:?usage: sgfp_check_sg_rules_for_cross_node.sh <bundle-dir>}"

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "[ERROR] Bundle directory not found: $BUNDLE_DIR"
  exit 1
fi

# Find files
SG_IDS_FILE=$(find "$BUNDLE_DIR" -name "pod_branch_eni_sgs.txt" -type f 2>/dev/null | head -1)
SG_RULES_FILE=$(find "$BUNDLE_DIR" -name "pod_branch_eni_sgs_rules.json" -type f 2>/dev/null | head -1)
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
  if echo "$BUNDLE_DIR" | grep -q "uswest2"; then
    AWS_REGION="us-west-2"
  fi
fi

if [ -z "$AWS_REGION" ]; then
  echo "[ERROR] AWS_REGION not set"
  exit 1
fi

OUTPUT_DIR="sg_rules_check_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "[SG-CHECK] Checking security group rules for cross-node traffic"
echo "[SG-CHECK] Bundle directory: $BUNDLE_DIR"
echo "[SG-CHECK] Region: $AWS_REGION"
echo "[SG-CHECK] Pod IP: ${POD_IP:-unknown}"
echo ""

# Get security group rules (from file or fetch)
if [ -n "$SG_RULES_FILE" ] && [ -f "$SG_RULES_FILE" ] && [ -s "$SG_RULES_FILE" ]; then
  echo "[SG-CHECK] Using existing security group rules file"
  cp "$SG_RULES_FILE" "$OUTPUT_DIR/security_groups_rules.json"
else
  echo "[SG-CHECK] Fetching security group rules from AWS..."
  SG_IDS=$(cat "$SG_IDS_FILE" 2>/dev/null | grep -v '^$' | tr '\n' ' ' || echo "")
  if [ -n "$SG_IDS" ]; then
    aws ec2 describe-security-groups --region "$AWS_REGION" --group-ids $SG_IDS \
      --output json > "$OUTPUT_DIR/security_groups_rules.json" 2>/dev/null || {
      echo "[ERROR] Failed to fetch security group rules"
      exit 1
    }
  else
    echo "[ERROR] No security group IDs found"
    exit 1
  fi
fi

# Extract cross-node source IPs
echo "[SG-CHECK] Extracting cross-node source IPs..."
CROSS_NODE_IPS=$(mktemp)
if [ -n "$CONNTRACK_FILE" ] && [ -f "$CONNTRACK_FILE" ] && [ -n "$POD_IP" ]; then
  grep "dst=$POD_IP" "$CONNTRACK_FILE" 2>/dev/null | \
    grep -oE "src=([0-9]{1,3}\.){3}[0-9]{1,3}" | \
    sed 's/src=//' | \
    grep -v "^$POD_IP$" | \
    sort -u > "$CROSS_NODE_IPS" || echo "" > "$CROSS_NODE_IPS"
fi

CROSS_NODE_COUNT=$(wc -l < "$CROSS_NODE_IPS" 2>/dev/null | tr -d '[:space:]' || echo "0")
echo "[SG-CHECK] Found $CROSS_NODE_COUNT cross-node source IP(s)"
echo ""

# Analyze ingress rules for port 6000
echo "[SG-CHECK] Analyzing ingress rules for port 6000..."
{
  echo "# Security Group Ingress Rules Analysis for Port 6000"
  echo "# Pod IP: ${POD_IP:-unknown}"
  echo ""
  
  jq -r '.SecurityGroups[] | 
    "=== \(.GroupId) - \(.GroupName) ===" as $header |
    .IpPermissions[]? | 
    select(.FromPort // 0 <= 6000 and (.ToPort // 65535) >= 6000) |
    select(.IpProtocol == "tcp" or .IpProtocol == "-1") |
    "\($header)
  Port: \(.FromPort // "all")-\(.ToPort // "all")/\(.IpProtocol // "all")
  Allowed Sources:
  \(.IpRanges[]? | "    - CIDR: \(.CidrIp // "unknown")\(if .Description then " (\(.Description))" else "" end)")
  \(.UserIdGroupPairs[]? | "    - SG: \(.GroupId // "unknown")\(if .GroupName then " (\(.GroupName))" else "" end)")"' \
    "$OUTPUT_DIR/security_groups_rules.json" 2>/dev/null | head -100
} > "$OUTPUT_DIR/01_port_6000_ingress_rules.txt"

# Check each cross-node source IP
echo "[SG-CHECK] Checking if cross-node source IPs are allowed..."
{
  echo "# Cross-Node Source IP Allowance Check"
  echo ""
  
  if [ "$CROSS_NODE_COUNT" -eq 0 ] || [ ! -s "$CROSS_NODE_IPS" ]; then
    echo "No cross-node source IPs found in conntrack data"
  else
    echo "Checking if these source IPs are allowed by security group ingress rules:"
    cat "$CROSS_NODE_IPS" | while read -r src_ip; do
      [ -z "$src_ip" ] && continue
      echo ""
      echo "Source IP: $src_ip"
      
      # Check if IP matches any CIDR in ingress rules for port 6000
      ALLOWED=0
      jq -r --arg ip "$src_ip" '.SecurityGroups[].IpPermissions[]? | 
        select(.FromPort // 0 <= 6000 and (.ToPort // 65535) >= 6000) |
        select(.IpProtocol == "tcp" or .IpProtocol == "-1") |
        .IpRanges[]?.CidrIp // empty' "$OUTPUT_DIR/security_groups_rules.json" 2>/dev/null | \
        while read -r cidr; do
          [ -z "$cidr" ] && continue
          
          # Simple CIDR matching (for common cases)
          if [ "$cidr" = "0.0.0.0/0" ]; then
            echo "  ✅ ALLOWED by $cidr (all traffic)"
            ALLOWED=1
          elif echo "$cidr" | grep -q "/"; then
            cidr_base=$(echo "$cidr" | cut -d/ -f1)
            cidr_mask=$(echo "$cidr" | cut -d/ -f2)
            
            # Check if IP is in CIDR (simplified - works for /8, /16, /24, /32)
            if [ "$cidr_mask" = "8" ]; then
              ip_octet1=$(echo "$src_ip" | cut -d. -f1)
              cidr_octet1=$(echo "$cidr_base" | cut -d. -f1)
              if [ "$ip_octet1" = "$cidr_octet1" ]; then
                echo "  ✅ ALLOWED by $cidr (matches /8: $ip_octet1.x.x.x)"
                ALLOWED=1
              fi
            elif [ "$cidr_mask" = "16" ]; then
              ip_prefix=$(echo "$src_ip" | cut -d. -f1-2)
              cidr_prefix=$(echo "$cidr_base" | cut -d. -f1-2)
              if [ "$ip_prefix" = "$cidr_prefix" ]; then
                echo "  ✅ ALLOWED by $cidr (matches /16: $ip_prefix.x.x)"
                ALLOWED=1
              fi
            elif [ "$cidr_mask" = "24" ]; then
              ip_prefix=$(echo "$src_ip" | cut -d. -f1-3)
              cidr_prefix=$(echo "$cidr_base" | cut -d. -f1-3)
              if [ "$ip_prefix" = "$cidr_prefix" ]; then
                echo "  ✅ ALLOWED by $cidr (matches /24: $ip_prefix.x)"
                ALLOWED=1
              fi
            elif [ "$cidr_mask" = "32" ] || [ -z "$cidr_mask" ]; then
              if [ "$src_ip" = "$cidr_base" ]; then
                echo "  ✅ ALLOWED by $cidr (exact match)"
                ALLOWED=1
              fi
            fi
          fi
        done
      
      if [ "$ALLOWED" -eq 0 ]; then
        echo "  ❓ NOT EXPLICITLY ALLOWED by CIDR rules (may be allowed by SG reference - check manually)"
      fi
    done
  fi
} > "$OUTPUT_DIR/02_cross_node_ip_allowance.txt"

# Summary of all ingress rules
{
  echo "# All Ingress Rules Summary"
  echo ""
  jq -r '.SecurityGroups[] | 
    "## \(.GroupId) - \(.GroupName)
\(.Description // "No description")
Ingress Rules:" as $header |
    .IpPermissions[]? | 
    "\($header)
  Port: \(.FromPort // "all")-\(.ToPort // "all")/\(.IpProtocol // "all")
  \(.IpRanges[]? | "    CIDR: \(.CidrIp // "unknown")\(if .Description then " - \(.Description)" else "" end)")
  \(.UserIdGroupPairs[]? | "    SG: \(.GroupId // "unknown")\(if .GroupName then " (\(.GroupName))" else "" end)")"' \
    "$OUTPUT_DIR/security_groups_rules.json" 2>/dev/null | head -200
} > "$OUTPUT_DIR/03_all_ingress_rules.txt"

rm -f "$CROSS_NODE_IPS" 2>/dev/null || true

echo ""
echo "[SG-CHECK] Analysis complete!"
echo "[SG-CHECK] Results saved to: $OUTPUT_DIR"
echo "[SG-CHECK] Key files:"
echo "  - 01_port_6000_ingress_rules.txt (rules allowing port 6000)"
echo "  - 02_cross_node_ip_allowance.txt (check if source IPs are allowed)"
echo "  - 03_all_ingress_rules.txt (all ingress rules)"
echo "  - security_groups_rules.json (full AWS API response)"

