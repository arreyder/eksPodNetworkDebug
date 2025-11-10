# Metrics Comparison (Baseline vs Incident)

## Overview

The metrics comparison feature analyzes differences between a baseline snapshot (healthy state) and an incident snapshot to identify metrics that may indicate network problems. This helps quickly identify what changed when a network issue occurs.

## How It Works

1. **Baseline Capture**: A baseline snapshot is captured when the cluster is healthy (e.g., each morning or before deployment)
2. **Incident Capture**: When investigating an incident, a new snapshot is captured
3. **Comparison**: The toolkit compares key metrics between baseline and incident states
4. **Analysis**: Differences are flagged as issues or warnings based on thresholds

## Metrics Analyzed

### Cluster State Metrics

#### Pending Pods Count
- **What it checks**: Number of pods in Pending state
- **Why it matters**: Increase indicates IP exhaustion, scheduling issues, or resource constraints
- **Threshold**: Any increase is flagged as an issue
- **Recommended actions**:
  - Check CNI logs for IP allocation failures
  - Verify subnet IP availability
  - Check node resource constraints
  - Review pod scheduling events

#### Pods with Pod ENI Count
- **What it checks**: Number of pods using Security Groups for Pods (pod ENI)
- **Why it matters**: Decrease may indicate pods lost ENI attachments
- **Threshold**: Decrease is flagged as warning
- **Recommended actions**:
  - Check ENI attachment status
  - Review CNI logs for ENI allocation failures
  - Verify trunk ENI limits

### CoreDNS Metrics

#### DNS Request Rate
- **What it checks**: `coredns_dns_requests_total` - total DNS queries
- **Why it matters**: Significant increase may indicate retry storms or DNS resolution issues
- **Threshold**: >50% increase triggers warning
- **Recommended actions**:
  - Check DNS resolution tests
  - Review CoreDNS pod status
  - Check for DNS-related errors in application logs
  - Verify NodeLocal DNSCache configuration

#### DNS SERVFAIL Errors
- **What it checks**: `coredns_dns_responses_total{rcode="SERVFAIL"}` - DNS server errors
- **Why it matters**: SERVFAIL indicates DNS server errors, upstream failures, or network connectivity issues
- **Threshold**: Any increase is flagged as an issue
- **Recommended actions**:
  - Check CoreDNS pod health
  - Verify upstream DNS servers are reachable
  - Review CoreDNS configuration
  - Check network connectivity to DNS servers

#### DNS Cache Hit Rate
- **What it checks**: `coredns_cache_hits_total` vs `coredns_cache_misses_total`
- **Why it matters**: Lower cache hit rate may indicate DNS resolution issues or cache invalidation
- **Threshold**: >10% decrease triggers warning
- **Recommended actions**:
  - Review DNS query patterns
  - Check for excessive DNS queries
  - Verify cache configuration
  - Consider enabling NodeLocal DNSCache

### aws-node (VPC CNI) Metrics

#### ENI Allocation Failures
- **What it checks**: `aws_vpc_ipamd_eni_allocated_failed_total` - failed ENI allocations
- **Why it matters**: Indicates IP exhaustion, ENI limits, or AWS API issues
- **Threshold**: Any increase is flagged as an issue
- **Recommended actions**:
  - Check ENI limits for instance type
  - Verify subnet IP availability
  - Review AWS API throttling (CloudTrail)
  - Check IAM permissions for aws-node

#### IP Allocation Failures
- **What it checks**: `aws_vpc_ipamd_ip_allocated_failed_total` - failed IP allocations
- **Why it matters**: Indicates subnet IP exhaustion or ENI IP limit issues
- **Threshold**: Any increase is flagged as an issue
- **Recommended actions**:
  - Check subnet IP availability
  - Verify ENI IP limits
  - Review CNI warm pool configuration
  - Consider using prefix delegation

#### Branch ENI Allocation Failures
- **What it checks**: `aws_vpc_ipamd_branch_eni_allocated_failed_total` - failed branch ENI allocations
- **Why it matters**: Indicates trunk ENI limits or AWS API throttling
- **Threshold**: Any increase is flagged as an issue
- **Recommended actions**:
  - Check trunk ENI branch ENI limits
  - Review AWS API throttling (CloudTrail)
  - Verify trunk ENI configuration
  - Check IAM permissions

### kube-proxy Metrics

#### iptables Rule Count
- **What it checks**: `kube_proxy_iptables_total` - total iptables rules
- **Why it matters**: Large increases may indicate service churn or configuration issues
- **Threshold**: >20% increase triggers warning
- **Recommended actions**:
  - Review service count changes
  - Check for excessive service creation/deletion
  - Verify kube-proxy configuration
  - Consider IPVS mode for large clusters

#### Sync Duration
- **What it checks**: `kube_proxy_sync_proxy_rules_duration_seconds` - time to program proxy rules
- **Why it matters**: Increased sync duration may indicate iptables performance issues
- **Threshold**: >50% increase triggers warning
- **Recommended actions**:
  - Review iptables rule complexity
  - Check for iptables performance issues
  - Consider IPVS mode
  - Verify kube-proxy resource limits

## Usage

### Automatic Comparison (Doctor Script)

When `SGFP_BASELINE_DIR` is set, the doctor script automatically:
1. Captures an incident baseline snapshot
2. Compares it with the baseline
3. Includes results in the report

```bash
# Set baseline directory
export SGFP_BASELINE_DIR=sgfp_baseline_morning_20251109_080000

# Run doctor (will capture incident snapshot and compare)
./sgfp_doctor.sh <pod> -n default
```

### Manual Comparison

```bash
# Compare baseline with incident snapshot
./sgfp_analyze_metrics_diff.sh <baseline-dir> <incident-bundle-dir>
```

## Output Format

The metrics comparison output uses consistent prefixes:
- `[METRICS] [ISSUE]` - Problem detected (requires attention)
- `[METRICS] WARN` - Warning (may indicate issues)
- `[METRICS] [INFO]` - Informational message
- `[METRICS] [OK]` - No issues detected

## Related Files

- `sgfp_baseline_capture.sh` - Captures baseline snapshots
- `sgfp_analyze_metrics_diff.sh` - Analyzes metric differences
- `sgfp_compare_baseline.sh` - General baseline comparison
- `metrics_comparison.txt` - Detailed comparison output (in bundle)
- `incident_baseline/` - Incident metrics snapshot (in bundle)

## Best Practices

1. **Capture baselines regularly**: Run baseline capture each morning or before deployments
2. **Use labels**: Label baselines for easy identification (e.g., `--label morning`, `--label pre-deploy`)
3. **Compare during incidents**: Set `SGFP_BASELINE_DIR` before running doctor to enable automatic comparison
4. **Review all metrics**: Not all issues are detected automatically - review detailed metrics files manually
5. **Correlate with other diagnostics**: Use metrics comparison alongside other diagnostic checks

## Limitations

- Metrics collection depends on Prometheus endpoints being accessible
- Some metrics may not be available in all cluster configurations
- Comparison is point-in-time (does not show trends over time)
- Thresholds are configurable but may need tuning for specific environments
- Metrics may vary based on cluster size and workload patterns

## References

- [CoreDNS Metrics](https://coredns.io/plugins/metrics/)
- [AWS VPC CNI Metrics](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/metrics.md)
- [kube-proxy Metrics](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-proxy/)

