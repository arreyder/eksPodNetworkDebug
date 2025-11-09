# DNS / CoreDNS / NodeLocal DNSCache Analysis

## What We Check

This check analyzes Kubernetes DNS infrastructure including CoreDNS pods, NodeLocal DNSCache, DNS service endpoints, and DNS resolution tests to ensure DNS is functioning correctly.

## Why It Matters

DNS infrastructure issues can cause:
- **Service discovery failures**: Pods cannot resolve service names
- **Pod startup delays**: Applications waiting for DNS resolution
- **Health check failures**: DNS timeouts cause probe failures
- **Application errors**: DNS failures break application functionality
- **High DNS latency**: Slow DNS queries impact application performance

Common causes:
- **CoreDNS pods not running**: CoreDNS pods crashed or not scheduled
- **CoreDNS scaling issues**: Too few CoreDNS pods for cluster size
- **NodeLocal DNSCache misconfiguration**: NodeLocal DNSCache not running on nodes
- **DNS service endpoints missing**: No CoreDNS pods backing DNS service
- **DNS service IP issues**: DNS service IP not routable or misconfigured
- **Network policies blocking DNS**: NetworkPolicies blocking DNS traffic (port 53)

## How We Check It

The analysis checks for:

1. **DNS Resolution Tests**
   - Tests Kubernetes DNS resolution (`kubernetes.default.svc.cluster.local`)
   - Reports DNS failures with error details

2. **CoreDNS Pods**
   - Counts CoreDNS pods in cluster
   - Checks CoreDNS pod status (Running, Ready)
   - Validates CoreDNS scaling (recommends 2+ for HA)
   - Reports unhealthy CoreDNS pods

3. **NodeLocal DNSCache**
   - Checks if NodeLocal DNSCache is enabled
   - Validates NodeLocal DNSCache pod on this node
   - Checks NodeLocal DNSCache pod status
   - Reports if NodeLocal DNSCache is enabled but not running on node

4. **DNS Service**
   - Checks DNS service endpoints (validates CoreDNS pods are backing service)
   - Reports DNS service IP
   - Validates DNS service has endpoints

5. **NodeLocal DNSCache Service**
   - Checks NodeLocal DNSCache service IP (if enabled)
   - Reports NodeLocal DNSCache service configuration

The analysis uses:
- `node_*/node_dns_tests.txt` - DNS resolution test results
- `node_*/node_coredns_pods.json` - CoreDNS pod status
- `node_*/node_nodelocal_dns_pods.json` - NodeLocal DNSCache pod status
- `node_*/node_dns_service.json` - DNS service configuration
- `node_*/node_dns_endpoints.json` - DNS service endpoints
- `node_*/node_nodelocal_dns_service.json` - NodeLocal DNSCache service (if enabled)
- `node_*/node_coredns_config.json` - CoreDNS configuration

## Recommended Actions

### If DNS Resolution Fails

1. **Check CoreDNS pods**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns
   kubectl logs -n kube-system -l k8s-app=kube-dns
   ```

2. **Check DNS service endpoints**:
   ```bash
   kubectl get endpoints -n kube-system kube-dns
   kubectl get svc -n kube-system kube-dns
   ```

3. **Test DNS from pod**:
   ```bash
   kubectl run -it --rm debug --image=busybox --restart=Never -- nslookup kubernetes.default.svc.cluster.local
   ```

4. **Check Network Policies** (may block DNS):
   ```bash
   kubectl get networkpolicies -A
   # DNS uses UDP port 53
   ```

5. **Check DNS service IP routing**:
   ```bash
   # Get DNS service IP
   DNS_IP=$(kubectl get svc -n kube-system kube-dns -o jsonpath='{.spec.clusterIP}')
   
   # Test DNS server directly
   dig @$DNS_IP kubernetes.default.svc.cluster.local
   ```

### If CoreDNS Pods Are Not Running

1. **Check CoreDNS pod status**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns
   kubectl describe pod -n kube-system -l k8s-app=kube-dns
   ```

2. **Check CoreDNS pod logs**:
   ```bash
   kubectl logs -n kube-system -l k8s-app=kube-dns
   ```

3. **Check CoreDNS deployment**:
   ```bash
   kubectl get deployment -n kube-system coredns
   kubectl describe deployment -n kube-system coredns
   ```

4. **Restart CoreDNS pods** (if needed):
   ```bash
   kubectl rollout restart deployment -n kube-system coredns
   ```

### If CoreDNS Scaling Is Insufficient

1. **Check current CoreDNS count**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns | wc -l
   ```

2. **Scale CoreDNS**:
   ```bash
   kubectl scale deployment -n kube-system coredns --replicas=2
   # Or use HPA for automatic scaling
   ```

3. **Consider NodeLocal DNSCache**:
   - Reduces CoreDNS load
   - Improves DNS latency
   - Provides local DNS caching

### If NodeLocal DNSCache Is Not Running on Node

1. **Check NodeLocal DNSCache pods**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=node-local-dns
   ```

2. **Check NodeLocal DNSCache DaemonSet**:
   ```bash
   kubectl get daemonset -n kube-system node-local-dns
   kubectl describe daemonset -n kube-system node-local-dns
   ```

3. **Check node labels** (NodeLocal DNSCache may use node selectors):
   ```bash
   kubectl get node <node-name> --show-labels
   ```

4. **Check NodeLocal DNSCache pod logs**:
   ```bash
   kubectl logs -n kube-system -l k8s-app=node-local-dns --tail=50
   ```

5. **Verify NodeLocal DNSCache configuration**:
   ```bash
   kubectl get configmap -n kube-system node-local-dns -o yaml
   ```

### If DNS Service Has No Endpoints

1. **Check DNS service**:
   ```bash
   kubectl get svc -n kube-system kube-dns
   kubectl get endpoints -n kube-system kube-dns
   ```

2. **Check CoreDNS pod labels**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns --show-labels
   ```

3. **Verify service selector matches pod labels**:
   ```bash
   kubectl get svc -n kube-system kube-dns -o jsonpath='{.spec.selector}'
   ```

4. **Check CoreDNS pod readiness**:
   ```bash
   kubectl get pods -n kube-system -l k8s-app=kube-dns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.status.containerStatuses[*].ready}{"\n"}{end}'
   ```

### General DNS Troubleshooting

1. **Test DNS resolution from multiple pods**:
   ```bash
   # Test from different pods to isolate issues
   kubectl run -it --rm debug1 --image=busybox --restart=Never -- nslookup kubernetes.default.svc.cluster.local
   kubectl run -it --rm debug2 --image=busybox --restart=Never -- nslookup kubernetes.default.svc.cluster.local
   ```

2. **Check DNS query latency**:
   ```bash
   # From pod, test DNS latency
   time nslookup kubernetes.default.svc.cluster.local
   ```

3. **Review CoreDNS metrics**:
   ```bash
   kubectl port-forward -n kube-system <coredns-pod> 9153:9153
   curl http://localhost:9153/metrics | grep coredns_dns
   ```

4. **Check CoreDNS configuration**:
   ```bash
   kubectl get configmap -n kube-system coredns -o yaml
   ```

5. **Review DNS-related logs**:
   ```bash
   kubectl logs -n kube-system -l k8s-app=kube-dns | grep -i error
   kubectl logs -n kube-system -l k8s-app=node-local-dns | grep -i error
   ```

6. **Check for DNS rate limiting**:
   ```bash
   # Review CoreDNS configuration for rate limits
   kubectl get configmap -n kube-system coredns -o yaml | grep -i rate
   ```

## Related Files

- `node_*/node_dns_tests.txt` - DNS resolution test results
- `node_*/node_coredns_pods.json` - CoreDNS pod status
- `node_*/node_nodelocal_dns_pods.json` - NodeLocal DNSCache pod status
- `node_*/node_dns_service.json` - DNS service configuration
- `node_*/node_dns_endpoints.json` - DNS service endpoints
- `node_*/node_nodelocal_dns_service.json` - NodeLocal DNSCache service (if enabled)
- `node_*/node_coredns_config.json` - CoreDNS configuration

## References

- [Kubernetes DNS](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)
- [CoreDNS](https://coredns.io/)
- [NodeLocal DNSCache](https://kubernetes.io/docs/tasks/administer-cluster/nodelocaldns/)
- [CoreDNS Configuration](https://coredns.io/plugins/)
- [DNS Troubleshooting](https://kubernetes.io/docs/tasks/administer-cluster/dns-debugging-resolution/)

