# DNS Resolution

## What We Check

The toolkit tests DNS resolution to ensure Kubernetes service discovery and DNS are functioning correctly.

**Checks performed:**
- Tests Kubernetes DNS resolution (`kubernetes.default.svc.cluster.local`)
- Tests metadata service DNS (expected to fail, informational)
- Reports DNS failures with error details

## Why It Matters

**DNS resolution** is critical for:
- **Service discovery**: Pods need DNS to find services
- **Pod startup**: Applications often require DNS during startup
- **Health checks**: DNS failures can cause health check failures
- **Service communication**: Pods communicate via service DNS names

**Common issues:**
- CoreDNS pods not running or unhealthy
- NodeLocal DNSCache misconfiguration
- DNS service IP not routable
- Network policies blocking DNS traffic
- DNS timeout/rate limiting

## How We Check It

1. **Kubernetes DNS Test**: Attempts to resolve `kubernetes.default.svc.cluster.local`
2. **Metadata Service Test**: Attempts to resolve metadata service (expected to fail)
3. **Failure Detection**: Checks for DNS errors, timeouts, or NXDOMAIN responses

**Output examples:**
- `[OK] Kubernetes DNS resolution working`
- `[ISSUE] Kubernetes DNS resolution failed`
- `[INFO] Metadata service DNS: FAILED (expected - metadata service may not resolve via DNS)`

## Recommended Actions

### If DNS Resolution Fails

1. **Check CoreDNS pods**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns
   kubectl logs -n kube-system -l k8s-app=kube-dns
   ```

2. **Verify DNS service**:
   ```bash
   kubectl get svc -n kube-system kube-dns
   kubectl get endpoints -n kube-system kube-dns
   ```

3. **Test DNS from pod**:
   ```bash
   kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup kubernetes.default.svc.cluster.local
   ```

4. **Check Network Policies**:
   ```bash
   # Check if NetworkPolicies block DNS
   kubectl get networkpolicies -A
   # DNS uses UDP port 53
   ```

5. **Check NodeLocal DNSCache** (if enabled):
   ```bash
   kubectl get pods -n kube-system -l k8s-app=node-local-dns
   ```

### If DNS is Slow

1. **Check DNS query latency**:
   ```bash
   # From pod, test DNS latency
   time nslookup kubernetes.default.svc.cluster.local
   ```

2. **Review CoreDNS metrics**:
   ```bash
   kubectl port-forward -n kube-system <coredns-pod> 9153:9153
   curl http://localhost:9153/metrics | grep coredns_dns
   ```

3. **Consider NodeLocal DNSCache**:
   - Reduces DNS query latency
   - Reduces CoreDNS load
   - Improves DNS availability

### If DNS Timeouts

1. **Check DNS server availability**:
   ```bash
   # Test DNS server directly
   dig @<dns-service-ip> kubernetes.default.svc.cluster.local
   ```

2. **Review DNS rate limiting**:
   - Check CoreDNS configuration for rate limits
   - Review pod DNS query patterns

3. **Check for DNS amplification attacks**:
   - Review DNS query patterns
   - Check for excessive DNS queries

## Related Files

- `node_dns_tests.txt` - DNS resolution test results

## References

- [Kubernetes DNS](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)
- [CoreDNS](https://coredns.io/)
- [NodeLocal DNSCache](https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns/)

