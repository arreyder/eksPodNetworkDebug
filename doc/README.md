# Diagnostic Checks Documentation

This directory contains detailed documentation for each diagnostic check performed by the toolkit.

## Available Checks

1. **[MTU Configuration](01-mtu-configuration.md)** - Detects MTU mismatches and fragmentation issues
2. **[kube-proxy iptables](02-kube-proxy-iptables.md)** - Validates kube-proxy configuration and service rules
3. **[Reverse Path Filtering](03-reverse-path-filtering.md)** - Validates rp_filter settings for pod ENI scenarios
4. **[ENI/Instance Limits](04-eni-instance-limits.md)** - Checks ENI and IP limits vs current usage
5. **[Security Group Validation](05-security-group-validation.md)** - Validates SGs on pod ENI vs expected SGs
6. **[Network Namespace Leaks](06-network-namespace-leaks.md)** - Detects orphaned network namespaces
7. **[IP Address Conflicts](07-ip-address-conflicts.md)** - Detects duplicate IP addresses
8. **[DNS Resolution](08-dns-resolution.md)** - Tests Kubernetes DNS resolution
9. **[Resource Exhaustion](09-resource-exhaustion.md)** - Monitors file descriptors and memory
10. **[SYN_SENT Detection](10-syn-sent-detection.md)** - Detects connection attempts that aren't completing
11. **[CNI Logs Analysis](11-cni-logs-analysis.md)** - Analyzes AWS VPC CNI logs for errors
12. **[Subnet IP Availability](12-subnet-ip-availability.md)** - Validates subnet IP availability
13. **[ENI Attachment Timing](13-eni-attachment-timing.md)** - Analyzes ENI attachment delays
14. **[Conntrack Usage](14-conntrack-usage.md)** - Monitors connection tracking usage
15. **[Socket Overruns](15-socket-overruns.md)** - Detects socket buffer overruns
16. **[Network Interface States](16-network-interface-states.md)** - Validates interface states
17. **[Route Table Drift](17-route-table-drift.md)** - Detects missing or incorrect routes
18. **[Health Probes](18-health-probes.md)** - Analyzes health probe configuration and failures
19. **[Network Policies](19-network-policies.md)** - Analyzes NetworkPolicy rules and potential traffic blocks
20. **[DNS / CoreDNS / NodeLocal DNSCache](20-dns-coredns-nodelocal.md)** - Analyzes DNS infrastructure, CoreDNS pods, and NodeLocal DNSCache
21. **[AMI / CNI / Kernel Drift](21-ami-cni-kernel-drift.md)** - Detects version mismatches and drift in Kubernetes components, AMI, and kernel
22. **[Custom Networking / ENIConfig](22-custom-networking-eniconfig.md)** - Validates ENIConfig resources, subnet → AZ mapping, and node assignments
23. **[NAT Gateway SNAT Port Exhaustion](23-nat-gateway-snat-exhaustion.md)** - Monitors NAT gateway connection counts and detects SNAT port exhaustion

## Document Structure

Each check documentation includes:

- **What We Check**: Description of the check and what data is analyzed
- **Why It Matters**: Explanation of why this check is important and common issues
- **How We Check It**: Technical details on how the check is performed
- **Recommended Actions**: Step-by-step guidance for fixing issues
- **Related Files**: List of diagnostic files relevant to this check
- **References**: Links to relevant documentation

## Contributing

When adding new checks, please create a corresponding documentation file following the same structure.

