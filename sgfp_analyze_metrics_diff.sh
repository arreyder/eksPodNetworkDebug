#!/usr/bin/env bash
set -euo pipefail

# Analyze metrics differences between baseline and incident
# Usage: ./sgfp_analyze_metrics_diff.sh <baseline-dir> <incident-bundle-dir>

BASELINE_DIR="${1:?usage: sgfp_analyze_metrics_diff.sh <baseline-dir> <incident-bundle-dir>}"
INCIDENT_DIR="${2:?usage: sgfp_analyze_metrics_diff.sh <baseline-dir> <incident-bundle-dir>}"

if [ ! -d "$BASELINE_DIR" ]; then
  echo "Error: Baseline directory not found: $BASELINE_DIR" >&2
  exit 1
fi

if [ ! -d "$INCIDENT_DIR" ]; then
  echo "Error: Incident directory not found: $INCIDENT_DIR" >&2
  exit 1
fi

log()  { printf "[METRICS] %s\n" "$*"; }
warn() { printf "[METRICS] WARN: %s\n" "$*" >&2; }
issue() { printf "[METRICS] [ISSUE] %s\n" "$*" >&2; }

ISSUES=0
WARNINGS=0

# Extract metric value from Prometheus format
# Input: metric line like "coredns_dns_requests_total 12345"
# Output: numeric value
extract_metric() {
  local line="$1"
  echo "$line" | awk '{print $2}' | grep -E '^[0-9]+\.?[0-9]*$' || echo "0"
}

# Compare two metric values and return difference
compare_metric() {
  local baseline_val="${1:-0}"
  local incident_val="${2:-0}"
  local metric_name="$3"
  local threshold_pct="${4:-10}"  # Default 10% change threshold
  
  # Convert to integers for comparison
  baseline_int=$(echo "$baseline_val" | cut -d. -f1 || echo "0")
  incident_int=$(echo "$incident_val" | cut -d. -f1 || echo "0")
  
  if [ "$baseline_int" = "0" ] || [ -z "$baseline_int" ]; then
    baseline_int=1  # Avoid division by zero
  fi
  
  if [ "$incident_int" = "0" ] && [ "$baseline_int" != "0" ]; then
    echo "MISSING"
    return
  fi
  
  # Calculate percentage change
  diff=$((incident_int - baseline_int))
  pct_change=$((diff * 100 / baseline_int))
  
  # Check if change exceeds threshold
  if [ "$pct_change" -gt "$threshold_pct" ] || [ "$pct_change" -lt "-$threshold_pct" ]; then
    echo "$diff|$pct_change"
  else
    echo "OK"
  fi
}

# Extract metric from Prometheus metrics file
extract_prometheus_metric() {
  local file="$1"
  local metric_name="$2"
  
  if [ ! -s "$file" ]; then
    echo "0"
    return
  fi
  
  # Find the metric line (may have labels)
  local line=$(grep "^${metric_name}" "$file" 2>/dev/null | head -1 || echo "")
  if [ -z "$line" ]; then
    echo "0"
    return
  fi
  
  # Extract metric and strip newlines/whitespace
  extract_metric "$line" | tr -d '[:space:]' || echo "0"
}

log "Analyzing metrics differences between baseline and incident"
log "Baseline: $BASELINE_DIR"
log "Incident: $INCIDENT_DIR"

echo ""
echo "=== Cluster State Changes ==="

# 1. Pending pods increase (indicates IP exhaustion or scheduling issues)
if [ -s "$BASELINE_DIR/pending_pods_count.txt" ] && [ -s "$INCIDENT_DIR/pending_pods_count.txt" ]; then
  BASELINE_PENDING=$(cat "$BASELINE_DIR/pending_pods_count.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  INCIDENT_PENDING=$(cat "$INCIDENT_DIR/pending_pods_count.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  
  if [ "$INCIDENT_PENDING" -gt "$BASELINE_PENDING" ]; then
    DIFF=$((INCIDENT_PENDING - BASELINE_PENDING))
    issue "Pending pods increased: $BASELINE_PENDING → $INCIDENT_PENDING (+$DIFF)"
    echo "  - This may indicate IP exhaustion, scheduling issues, or resource constraints"
    ISSUES=$((ISSUES + 1))
  elif [ "$INCIDENT_PENDING" -lt "$BASELINE_PENDING" ]; then
    DIFF=$((BASELINE_PENDING - INCIDENT_PENDING))
    log "Pending pods decreased: $BASELINE_PENDING → $INCIDENT_PENDING (-$DIFF) [OK]"
  else
    log "Pending pods unchanged: $BASELINE_PENDING [OK]"
  fi
fi

# 2. Pods with pod ENI count changes (may indicate ENI attachment issues)
if [ -s "$BASELINE_DIR/pods_with_pod_eni.txt" ] && [ -s "$INCIDENT_DIR/pods_with_pod_eni.txt" ]; then
  BASELINE_ENI=$(cat "$BASELINE_DIR/pods_with_pod_eni.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  INCIDENT_ENI=$(cat "$INCIDENT_DIR/pods_with_pod_eni.txt" 2>/dev/null | tr -d '[:space:]' || echo "0")
  
  if [ "$INCIDENT_ENI" != "$BASELINE_ENI" ]; then
    DIFF=$((INCIDENT_ENI - BASELINE_ENI))
    if [ "$DIFF" -lt 0 ]; then
      warn "Pods with pod ENI decreased: $BASELINE_ENI → $INCIDENT_ENI ($DIFF)"
      echo "  - This may indicate pods lost ENI attachments or were terminated"
      WARNINGS=$((WARNINGS + 1))
    else
      log "Pods with pod ENI increased: $BASELINE_ENI → $INCIDENT_ENI (+$DIFF) [INFO]"
    fi
  fi
fi

echo ""
echo "=== CoreDNS Metrics Analysis ==="

# Find CoreDNS metrics files
COREDNS_BASELINE=$(ls "$BASELINE_DIR"/coredns_*_metrics.txt 2>/dev/null | head -1 || echo "")
COREDNS_INCIDENT=$(ls "$INCIDENT_DIR"/coredns_*_metrics.txt 2>/dev/null | head -1 || echo "")

if [ -n "$COREDNS_BASELINE" ] && [ -n "$COREDNS_INCIDENT" ] && [ -s "$COREDNS_BASELINE" ] && [ -s "$COREDNS_INCIDENT" ]; then
  # DNS request rate
  BASELINE_REQUESTS=$(extract_prometheus_metric "$COREDNS_BASELINE" "coredns_dns_requests_total")
  INCIDENT_REQUESTS=$(extract_prometheus_metric "$COREDNS_INCIDENT" "coredns_dns_requests_total")
  
  if [ "$BASELINE_REQUESTS" != "0" ] || [ "$INCIDENT_REQUESTS" != "0" ]; then
    RESULT=$(compare_metric "$BASELINE_REQUESTS" "$INCIDENT_REQUESTS" "DNS requests" 50)
    if [ "$RESULT" != "OK" ] && [ "$RESULT" != "MISSING" ]; then
      DIFF=$(echo "$RESULT" | cut -d'|' -f1)
      PCT=$(echo "$RESULT" | cut -d'|' -f2)
      if [ "$PCT" -gt 0 ]; then
        warn "DNS request rate increased: $BASELINE_REQUESTS → $INCIDENT_REQUESTS (+$PCT%)"
        echo "  - High DNS request rate may indicate retry storms or DNS resolution issues"
        WARNINGS=$((WARNINGS + 1))
      fi
    fi
  fi
  
  # DNS error rate (SERVFAIL)
  BASELINE_SERVFAIL=$(grep 'coredns_dns_responses_total.*rcode="SERVFAIL"' "$COREDNS_BASELINE" 2>/dev/null | awk '{sum+=$2} END {print sum+0}' || echo "0" | tr -d '[:space:]')
  INCIDENT_SERVFAIL=$(grep 'coredns_dns_responses_total.*rcode="SERVFAIL"' "$COREDNS_INCIDENT" 2>/dev/null | awk '{sum+=$2} END {print sum+0}' || echo "0" | tr -d '[:space:]')
  
  # Ensure values are numeric (strip any non-numeric characters)
  BASELINE_SERVFAIL=$(echo "$BASELINE_SERVFAIL" | grep -oE '^[0-9]+' || echo "0")
  INCIDENT_SERVFAIL=$(echo "$INCIDENT_SERVFAIL" | grep -oE '^[0-9]+' || echo "0")
  
  if [ "$INCIDENT_SERVFAIL" -gt "$BASELINE_SERVFAIL" ] 2>/dev/null; then
    DIFF=$((INCIDENT_SERVFAIL - BASELINE_SERVFAIL))
    issue "DNS SERVFAIL errors increased: $BASELINE_SERVFAIL → $INCIDENT_SERVFAIL (+$DIFF)"
    echo "  - SERVFAIL indicates DNS server errors, upstream failures, or network connectivity issues"
    ISSUES=$((ISSUES + 1))
  fi
  
  # DNS cache hit rate
  BASELINE_CACHE_HITS=$(extract_prometheus_metric "$COREDNS_BASELINE" "coredns_cache_hits_total")
  INCIDENT_CACHE_HITS=$(extract_prometheus_metric "$COREDNS_INCIDENT" "coredns_cache_hits_total")
  BASELINE_CACHE_MISSES=$(extract_prometheus_metric "$COREDNS_BASELINE" "coredns_cache_misses_total")
  INCIDENT_CACHE_MISSES=$(extract_prometheus_metric "$COREDNS_INCIDENT" "coredns_cache_misses_total")
  
  if [ "$BASELINE_CACHE_HITS" != "0" ] && [ "$BASELINE_CACHE_MISSES" != "0" ]; then
    BASELINE_TOTAL=$((BASELINE_CACHE_HITS + BASELINE_CACHE_MISSES))
    BASELINE_HIT_RATE=$((BASELINE_CACHE_HITS * 100 / BASELINE_TOTAL))
  else
    BASELINE_HIT_RATE=0
  fi
  
  if [ "$INCIDENT_CACHE_HITS" != "0" ] && [ "$INCIDENT_CACHE_MISSES" != "0" ]; then
    INCIDENT_TOTAL=$((INCIDENT_CACHE_HITS + INCIDENT_CACHE_MISSES))
    INCIDENT_HIT_RATE=$((INCIDENT_CACHE_HITS * 100 / INCIDENT_TOTAL))
  else
    INCIDENT_HIT_RATE=0
  fi
  
  if [ "$INCIDENT_HIT_RATE" -lt "$BASELINE_HIT_RATE" ] && [ "$BASELINE_HIT_RATE" -gt 0 ]; then
    DIFF=$((BASELINE_HIT_RATE - INCIDENT_HIT_RATE))
    if [ "$DIFF" -gt 10 ]; then
      warn "DNS cache hit rate decreased: $BASELINE_HIT_RATE% → $INCIDENT_HIT_RATE% (-$DIFF%)"
      echo "  - Lower cache hit rate may indicate DNS resolution issues or cache invalidation"
      WARNINGS=$((WARNINGS + 1))
    fi
  fi
else
  log "CoreDNS metrics not available for comparison"
fi

echo ""
echo "=== aws-node (VPC CNI) Metrics Analysis ==="

# Find aws-node metrics files
AWS_NODE_BASELINE=$(ls "$BASELINE_DIR"/aws_node_*_metrics.txt 2>/dev/null | head -1 || echo "")
AWS_NODE_INCIDENT=$(ls "$INCIDENT_DIR"/aws_node_*_metrics.txt 2>/dev/null | head -1 || echo "")

if [ -n "$AWS_NODE_BASELINE" ] && [ -n "$AWS_NODE_INCIDENT" ] && [ -s "$AWS_NODE_BASELINE" ] && [ -s "$AWS_NODE_INCIDENT" ]; then
  # ENI allocation failures
  BASELINE_ENI_FAILED=$(extract_prometheus_metric "$AWS_NODE_BASELINE" "aws_vpc_ipamd_eni_allocated_failed_total")
  INCIDENT_ENI_FAILED=$(extract_prometheus_metric "$AWS_NODE_INCIDENT" "aws_vpc_ipamd_eni_allocated_failed_total")
  
  if [ "$INCIDENT_ENI_FAILED" -gt "$BASELINE_ENI_FAILED" ]; then
    DIFF=$((INCIDENT_ENI_FAILED - BASELINE_ENI_FAILED))
    issue "ENI allocation failures increased: $BASELINE_ENI_FAILED → $INCIDENT_ENI_FAILED (+$DIFF)"
    echo "  - ENI allocation failures indicate IP exhaustion, ENI limits, or AWS API issues"
    ISSUES=$((ISSUES + 1))
  fi
  
  # IP allocation failures
  BASELINE_IP_FAILED=$(extract_prometheus_metric "$AWS_NODE_BASELINE" "aws_vpc_ipamd_ip_allocated_failed_total")
  INCIDENT_IP_FAILED=$(extract_prometheus_metric "$AWS_NODE_INCIDENT" "aws_vpc_ipamd_ip_allocated_failed_total")
  
  if [ "$INCIDENT_IP_FAILED" -gt "$BASELINE_IP_FAILED" ]; then
    DIFF=$((INCIDENT_IP_FAILED - BASELINE_IP_FAILED))
    issue "IP allocation failures increased: $BASELINE_IP_FAILED → $INCIDENT_IP_FAILED (+$DIFF)"
    echo "  - IP allocation failures indicate subnet IP exhaustion or ENI IP limit issues"
    ISSUES=$((ISSUES + 1))
  fi
  
  # Branch ENI allocation failures (for pod ENI)
  BASELINE_BRANCH_FAILED=$(extract_prometheus_metric "$AWS_NODE_BASELINE" "aws_vpc_ipamd_branch_eni_allocated_failed_total")
  INCIDENT_BRANCH_FAILED=$(extract_prometheus_metric "$AWS_NODE_INCIDENT" "aws_vpc_ipamd_branch_eni_allocated_failed_total")
  
  if [ "$INCIDENT_BRANCH_FAILED" -gt "$BASELINE_BRANCH_FAILED" ]; then
    DIFF=$((INCIDENT_BRANCH_FAILED - BASELINE_BRANCH_FAILED))
    issue "Branch ENI allocation failures increased: $BASELINE_BRANCH_FAILED → $INCIDENT_BRANCH_FAILED (+$DIFF)"
    echo "  - Branch ENI failures indicate trunk ENI limits or AWS API throttling"
    ISSUES=$((ISSUES + 1))
  fi
else
  log "aws-node metrics not available for comparison"
fi

echo ""
echo "=== kube-proxy Metrics Analysis ==="

# Find kube-proxy metrics files
KUBE_PROXY_BASELINE=$(ls "$BASELINE_DIR"/kube_proxy_*_metrics.txt 2>/dev/null | head -1 || echo "")
KUBE_PROXY_INCIDENT=$(ls "$INCIDENT_DIR"/kube_proxy_*_metrics.txt 2>/dev/null | head -1 || echo "")

if [ -n "$KUBE_PROXY_BASELINE" ] && [ -n "$KUBE_PROXY_INCIDENT" ] && [ -s "$KUBE_PROXY_BASELINE" ] && [ -s "$KUBE_PROXY_INCIDENT" ]; then
  # iptables rule count
  BASELINE_IPTABLES=$(extract_prometheus_metric "$KUBE_PROXY_BASELINE" "kube_proxy_iptables_total")
  INCIDENT_IPTABLES=$(extract_prometheus_metric "$KUBE_PROXY_INCIDENT" "kube_proxy_iptables_total")
  
  if [ "$BASELINE_IPTABLES" != "0" ] || [ "$INCIDENT_IPTABLES" != "0" ]; then
    if [ "$INCIDENT_IPTABLES" -gt "$BASELINE_IPTABLES" ]; then
      DIFF=$((INCIDENT_IPTABLES - BASELINE_IPTABLES))
      PCT=$((DIFF * 100 / (BASELINE_IPTABLES + 1)))
      if [ "$PCT" -gt 20 ]; then
        warn "iptables rule count increased significantly: $BASELINE_IPTABLES → $INCIDENT_IPTABLES (+$PCT%)"
        echo "  - Large iptables rule increases may indicate service churn or configuration issues"
        WARNINGS=$((WARNINGS + 1))
      fi
    fi
  fi
  
  # Sync duration (proxy rules programming time)
  BASELINE_SYNC=$(grep 'kube_proxy_sync_proxy_rules_duration_seconds' "$KUBE_PROXY_BASELINE" 2>/dev/null | awk '{sum+=$2; count++} END {if(count>0) print sum/count; else print 0}' || echo "0")
  INCIDENT_SYNC=$(grep 'kube_proxy_sync_proxy_rules_duration_seconds' "$KUBE_PROXY_INCIDENT" 2>/dev/null | awk '{sum+=$2; count++} END {if(count>0) print sum/count; else print 0}' || echo "0")
  
  if [ "$INCIDENT_SYNC" != "0" ] && [ "$BASELINE_SYNC" != "0" ]; then
    # Compare as floats (multiply by 1000 for millisecond comparison)
    # Use awk for floating point arithmetic instead of bc
    BASELINE_MS=$(echo "$BASELINE_SYNC" | awk '{printf "%.0f", $1 * 1000}' 2>/dev/null || echo "0")
    INCIDENT_MS=$(echo "$INCIDENT_SYNC" | awk '{printf "%.0f", $1 * 1000}' 2>/dev/null || echo "0")
    
    if [ "$INCIDENT_MS" -gt "$BASELINE_MS" ] && [ "$BASELINE_MS" -gt 0 ]; then
      DIFF=$((INCIDENT_MS - BASELINE_MS))
      PCT=$((DIFF * 100 / BASELINE_MS))
      if [ "$PCT" -gt 50 ]; then
        warn "kube-proxy sync duration increased: ${BASELINE_MS}ms → ${INCIDENT_MS}ms (+$PCT%)"
        echo "  - Increased sync duration may indicate iptables performance issues or rule complexity"
        WARNINGS=$((WARNINGS + 1))
      fi
    fi
  fi
else
  log "kube-proxy metrics not available for comparison"
fi

echo ""
if [ "$ISSUES" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
  log "No significant metrics differences detected [OK]"
else
  log "Summary: $ISSUES issue(s), $WARNINGS warning(s) detected"
fi

