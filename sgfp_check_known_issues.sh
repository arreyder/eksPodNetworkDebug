#!/usr/bin/env bash
# Check diagnostic bundle against known issues from GitHub, changelogs, etc.
# Usage: ./sgfp_check_known_issues.sh <bundle-dir>

set -euo pipefail

BUNDLE_DIR="${1:?usage: sgfp_check_known_issues.sh <bundle-dir>}"

if [ ! -d "$BUNDLE_DIR" ]; then
  echo "[ERROR] Bundle directory not found: $BUNDLE_DIR" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] jq is required" >&2
  exit 1
fi

log() { printf "[KNOWN-ISSUES] %s\n" "$*"; }
warn() { printf "[KNOWN-ISSUES] WARN: %s\n" "$*" >&2; }

# Find directories
NODE_DIR=$(find "$BUNDLE_DIR" -type d -name "node_*" | head -1)
POD_DIR=$(find "$BUNDLE_DIR" -type d -name "pod_*" | head -1)

if [ -z "$NODE_DIR" ]; then
  echo "[ERROR] Could not find node directory in bundle" >&2
  exit 1
fi

log "Checking known issues for bundle: $BUNDLE_DIR"

# Extract versions
K8S_VERSION="unknown"
OS_IMAGE="unknown"
KERNEL_VERSION="unknown"
AWS_NODE_VERSION="unknown"
KUBE_PROXY_VERSION="unknown"
COREDNS_VERSION="unknown"

if [ -f "$NODE_DIR/node_k8s_version.txt" ]; then
  K8S_VERSION=$(cat "$NODE_DIR/node_k8s_version.txt" 2>/dev/null | head -1 || echo "unknown")
fi

if [ -f "$NODE_DIR/node_os_image.txt" ]; then
  OS_IMAGE=$(cat "$NODE_DIR/node_os_image.txt" 2>/dev/null | head -1 || echo "unknown")
fi

if [ -f "$NODE_DIR/node_kernel_version.txt" ]; then
  KERNEL_VERSION=$(cat "$NODE_DIR/node_kernel_version.txt" 2>/dev/null | head -1 || echo "unknown")
fi

if [ -f "$NODE_DIR/node_aws_node_version.txt" ]; then
  AWS_NODE_VERSION=$(cat "$NODE_DIR/node_aws_node_version.txt" 2>/dev/null | head -1 || echo "unknown")
fi

if [ -f "$NODE_DIR/node_kube_proxy_version.txt" ]; then
  KUBE_PROXY_VERSION=$(cat "$NODE_DIR/node_kube_proxy_version.txt" 2>/dev/null | head -1 || echo "unknown")
fi

# Extract CoreDNS version from pods JSON
if [ -f "$NODE_DIR/node_coredns_pods.json" ]; then
  COREDNS_VERSION=$(jq -r '.items[0].spec.containers[0].image // ""' "$NODE_DIR/node_coredns_pods.json" 2>/dev/null | sed -E 's/.*:([^@]+).*/\1/' | sed 's/@.*//' || echo "unknown")
  [ "$COREDNS_VERSION" = "null" ] || [ -z "$COREDNS_VERSION" ] && COREDNS_VERSION="unknown"
fi

log "Detected versions:"
log "  Kubernetes: $K8S_VERSION"
log "  OS Image: $OS_IMAGE"
log "  Kernel: $KERNEL_VERSION"
log "  aws-node: $AWS_NODE_VERSION"
log "  kube-proxy: $KUBE_PROXY_VERSION"
log "  CoreDNS: $COREDNS_VERSION"

# Extract OS version from OS image
AL_VERSION="unknown"
if echo "$OS_IMAGE" | grep -q "Amazon Linux 2023"; then
  AL_VERSION=$(echo "$OS_IMAGE" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
fi

# Known issues database (from GitHub, changelogs, etc.)
echo ""
log "=== Known Issues Check ==="

ISSUES_FOUND=0

# Check for Amazon VPC CNI issues
if [ "$AWS_NODE_VERSION" != "unknown" ]; then
  echo ""
  log "Amazon VPC CNI Plugin (aws-node) Version: $AWS_NODE_VERSION"
  
  # Issue #3109: CNI ipamd reconciliation of in-use addresses
  log "  [INFO] Issue #3109: CNI ipamd reconciliation of in-use addresses"
  log "    - Status: Closed (not planned)"
  log "    - Description: CNI plugin miscounts in-use IP addresses, leading to allocation failures"
  log "    - Impact: May cause IP allocation failures"
  log "    - Reference: https://github.com/aws/amazon-vpc-cni-k8s/issues/3109"
  
  # Issue #3112: Insufficient vpc.amazonaws.com/pod-eni with prefix mode
  log "  [INFO] Issue #3112: Insufficient vpc.amazonaws.com/pod-eni error with prefix mode"
  log "    - Status: Open/Closed (check GitHub)"
  log "    - Description: Error when enabling prefix mode on Nitro-based instances"
  log "    - Impact: Pod ENI allocation failures with prefix mode"
  log "    - Reference: https://github.com/aws/amazon-vpc-cni-k8s/issues/3112"
  
  # Version-specific issues
  if echo "$AWS_NODE_VERSION" | grep -qE "^v1\.20\.[0-3]"; then
    log "  [INFO] Version $AWS_NODE_VERSION is in the v1.20.x series"
    log "    - Latest stable: v1.20.4 (released 2025-10-15)"
    log "    - Check changelog for fixes in v1.20.4"
  fi
fi

# Check for Amazon Linux 2023 issues
if [ "$AL_VERSION" != "unknown" ]; then
  echo ""
  log "Amazon Linux 2023 Version: $AL_VERSION"
  
  # ALAS-2023-132: Multiple vulnerabilities including CVE-2022-27672
  log "  [INFO] ALAS-2023-132: Multiple vulnerabilities (CVE-2022-27672, etc.)"
  log "    - Impact: AMD CPU speculative execution vulnerabilities"
  log "    - Reference: https://alas.aws.amazon.com/AL2023/ALAS-2023-132.html"
  
  # ALAS2023-2025-1054: Traffic Control subsystem DoS
  log "  [INFO] ALAS2023-2025-1054: Linux kernel Traffic Control DoS"
  log "    - Impact: Denial of service conditions"
  log "    - Reference: https://alas.aws.amazon.com/AL2023/ALAS2023-2025-1054.html"
  
  # Version 2023.8.20250804 recall
  if echo "$OS_IMAGE" | grep -q "2023.8.20250804"; then
    warn "  [WARN] OS version 2023.8.20250804 was RECALLED"
    warn "    - Issue: Soft lockups and instance launch failures with auditd"
    warn "    - Action: Update to a newer version"
    warn "    - Reference: https://docs.aws.amazon.com/linux/al2023/release-notes/relnotes-2023.8.20250804.html"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
  fi
fi

# Check kernel version
if [ "$KERNEL_VERSION" != "unknown" ]; then
  echo ""
  log "Kernel Version: $KERNEL_VERSION"
  
  # Check for kernel version 6.12 issues
  if echo "$KERNEL_VERSION" | grep -qE "^6\.12\."; then
    log "  [INFO] Kernel 6.12.x detected"
    log "    - Issue #1023: Kernel backport request for version 6.12"
    log "    - Reference: https://github.com/amazonlinux/amazon-linux-2023/issues/1023"
  fi
fi

# Check for kube-proxy issues
if [ "$KUBE_PROXY_VERSION" != "unknown" ]; then
  echo ""
  log "kube-proxy Version: $KUBE_PROXY_VERSION"
  
  # Extract kube-proxy version number (e.g., v1.33.0-eksbuild.2 -> 1.33.0)
  KUBE_PROXY_MAJOR_MINOR=$(echo "$KUBE_PROXY_VERSION" | grep -oE 'v?[0-9]+\.[0-9]+' | head -1 || echo "")
  
  # Check for kube-proxy compatibility with Kubernetes version
  if [ -n "$KUBE_PROXY_MAJOR_MINOR" ] && [ "$K8S_VERSION" != "unknown" ]; then
    K8S_MAJOR_MINOR=$(echo "$K8S_VERSION" | grep -oE 'v?[0-9]+\.[0-9]+' | head -1 || echo "")
    if [ -n "$K8S_MAJOR_MINOR" ] && [ "$KUBE_PROXY_MAJOR_MINOR" != "$K8S_MAJOR_MINOR" ]; then
      warn "  [WARN] kube-proxy version ($KUBE_PROXY_MAJOR_MINOR) does not match Kubernetes version ($K8S_MAJOR_MINOR)"
      warn "    - This can cause networking issues and service connectivity problems"
      warn "    - Recommendation: Update kube-proxy to match Kubernetes version"
      ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
  fi
  
  # Known kube-proxy issues
  log "  [INFO] kube-proxy manages network rules (iptables/IPVS) for Kubernetes Services"
  log "    - In EKS, kube-proxy updates are user's responsibility"
  log "    - Outdated versions can cause service connectivity issues"
  log "    - Reference: https://github.com/kubernetes/kubernetes/issues (search for kube-proxy)"
  
  # Check for specific version issues
  if echo "$KUBE_PROXY_VERSION" | grep -qE "v1\.33\."; then
    log "  [INFO] kube-proxy v1.33.x series"
    log "    - Check Kubernetes release notes for v1.33.x for kube-proxy fixes"
    log "    - Reference: https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.33.md"
  fi
  
  # IPVS mode issues
  log "  [INFO] Known kube-proxy issues:"
  log "    - IPVS mode: KUBE-MARK-DROP chain issues (fixed in v1.16+)"
  log "    - iptables mode: Performance issues with large numbers of services"
  log "    - Reference: https://github.com/kubernetes/kubernetes/issues"
fi

# Check for CoreDNS issues
if [ "$COREDNS_VERSION" != "unknown" ]; then
  echo ""
  log "CoreDNS Version: $COREDNS_VERSION"
  
  # Extract CoreDNS version number
  COREDNS_MAJOR_MINOR=$(echo "$COREDNS_VERSION" | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "")
  
  # Known CoreDNS issues
  log "  [INFO] CoreDNS handles DNS resolution for Kubernetes services"
  log "    - DNS resolution failures can cause pod connectivity issues"
  log "    - Reference: https://github.com/coredns/coredns/issues"
  
  # Check for specific version issues
  if [ -n "$COREDNS_MAJOR_MINOR" ]; then
    # CoreDNS 1.13.1 security fixes
    if echo "$COREDNS_VERSION" | grep -qE "^1\.(1[0-2]|[0-9])\."; then
      log "  [INFO] CoreDNS version $COREDNS_VERSION may have security vulnerabilities"
      log "    - CoreDNS 1.13.1+ includes security fixes (CVE fixes, Go 1.25.2)"
      log "    - Recommendation: Update to CoreDNS 1.13.1 or later"
      log "    - Reference: https://github.com/coredns/coredns/releases"
    fi
    
    # EKS CoreDNS endpoint issues
    log "  [INFO] Known CoreDNS issues in EKS:"
    log "    - Issue #2298: CoreDNS can't reach Kubernetes endpoint after EKS 1.29 upgrade"
    log "    - Impact: DNS resolution failures, domain name resolution errors"
    log "    - Reference: https://github.com/aws/containers-roadmap/issues/2298"
    
    # CoreDNS 1.12.2 improvements
    if echo "$COREDNS_VERSION" | grep -qE "^1\.(1[0-1]|[0-9])\."; then
      log "  [INFO] CoreDNS version $COREDNS_VERSION is older than 1.12.2"
      log "    - CoreDNS 1.12.2+ includes plugin stability improvements"
      log "    - Recommendation: Consider updating to latest stable version"
    fi
  fi
fi

# Check for specific patterns in diagnostic data that match known issues
echo ""
log "=== Pattern Matching Against Known Issues ==="

# Check for CNI IP allocation failures
if [ -d "$NODE_DIR/cni_logs" ] && [ -f "$NODE_DIR/cni_logs/plugin.log" ]; then
  if grep -q "Failed to assign an IP address to container" "$NODE_DIR/cni_logs/plugin.log" 2>/dev/null; then
    log "  [MATCH] Found 'Failed to assign an IP address to container' in CNI logs"
    log "    - This matches the pattern described in issue #3109"
    log "    - May indicate IP allocation/reconciliation issues"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
  fi
fi

# Check for network namespace completeness issues
if [ -f "$NODE_DIR/node_netns_details.json" ] && [ -n "$POD_DIR" ]; then
  POD_IP=$(grep "^POD_IP=" "$POD_DIR/pod_ip.txt" 2>/dev/null | cut -d= -f2- || echo "")
  if [ -n "$POD_IP" ] && [ "$POD_IP" != "unknown" ]; then
    NETNS_COMPLETE=$(jq -r --arg ip "$POD_IP" '.[] | select(.ips.ipv4[]? == $ip) | .completeness // {}' "$NODE_DIR/node_netns_details.json" 2>/dev/null || echo "{}")
    if [ "$NETNS_COMPLETE" != "{}" ] && [ "$NETNS_COMPLETE" != "null" ]; then
      ETH0_STATE=$(echo "$NETNS_COMPLETE" | jq -r '.eth0_state // "unknown"' 2>/dev/null || echo "unknown")
      ROUTE_COUNT=$(echo "$NETNS_COMPLETE" | jq -r '.route_count // 0' 2>/dev/null || echo "0")
      DEFAULT_ROUTE=$(echo "$NETNS_COMPLETE" | jq -r '.default_route // ""' 2>/dev/null || echo "")
      
      if [ "$ETH0_STATE" != "UP" ] || [ "$ROUTE_COUNT" -eq 0 ] || [ -z "$DEFAULT_ROUTE" ]; then
        warn "  [MATCH] Network namespace completeness issues detected"
        warn "    - eth0 state: $ETH0_STATE (expected: UP)"
        warn "    - Route count: $ROUTE_COUNT (expected: >0)"
        warn "    - Default route: $([ -z "$DEFAULT_ROUTE" ] && echo "missing" || echo "present")"
        warn "    - This matches our theory of incomplete network namespace setup"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
      fi
    fi
  fi
fi

# Summary
echo ""
log "=== Summary ==="
if [ "$ISSUES_FOUND" -eq 0 ]; then
  log "No matching known issues found in diagnostic data"
else
  warn "Found $ISSUES_FOUND potential issue(s) matching known problems"
fi

log ""
log "Component Versions:"
log "  Kubernetes: $K8S_VERSION"
log "  OS: $OS_IMAGE"
log "  Kernel: $KERNEL_VERSION"
log "  aws-node: $AWS_NODE_VERSION"
log "  kube-proxy: $KUBE_PROXY_VERSION"
log "  CoreDNS: $COREDNS_VERSION"

log ""
log "Next Steps:"
log "  1. Review GitHub issues referenced above"
log "  2. Check changelog for aws-node version $AWS_NODE_VERSION"
log "  3. Check Kubernetes release notes for kube-proxy version $KUBE_PROXY_VERSION"
log "  4. Check CoreDNS release notes for version $COREDNS_VERSION"
log "  5. Review Amazon Linux 2023 security advisories"
log "  6. Update investigation document with findings"

