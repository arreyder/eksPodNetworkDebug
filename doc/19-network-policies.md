# NetworkPolicy Analysis

## What We Check

This check analyzes Kubernetes NetworkPolicies to determine if they apply to the pod and whether they might block required traffic such as DNS, health probes, metrics, or service communication.

## Why It Matters

NetworkPolicy misconfigurations can cause:
- **DNS failures**: Missing DNS egress rules prevent pods from resolving service names
- **Health probe failures**: Restrictive ingress rules block kubelet health checks
- **Service communication failures**: Ingress/egress rules block pod-to-pod or pod-to-service traffic
- **Metrics collection failures**: Missing metrics egress rules prevent observability
- **Application failures**: Overly restrictive policies block legitimate application traffic

Common causes:
- **Missing DNS egress**: NetworkPolicy blocks DNS (port 53) egress
- **Restrictive ingress**: NetworkPolicy blocks health probes from nodes
- **Selector mismatches**: NetworkPolicy podSelector doesn't match pod labels
- **Missing catch-all rules**: NetworkPolicy has no rules, blocking all traffic
- **Wrong namespace**: NetworkPolicy in wrong namespace doesn't apply

## How We Check It

The analysis checks for:

1. **Applicable NetworkPolicies**
   - Finds NetworkPolicies in the same namespace as the pod
   - Checks if podSelector matches pod labels (matchLabels)
   - Notes matchExpressions (not fully evaluated - limitation)

2. **Ingress Rules**
   - Checks if ingress rules allow traffic from node (for health probes)
   - Warns if ingress policy type exists but no rules (blocks all ingress)
   - Validates that health probes can reach the pod

3. **Egress Rules**
   - Checks for DNS egress rules (port 53 UDP/TCP)
   - Checks for metrics egress rules (common ports: 8080, 9090, 10250, 9100)
   - Warns if egress policy type exists but no rules (blocks all egress)
   - Checks for catch-all egress rules

4. **Policy Types**
   - Validates that policyTypes match actual rules
   - Checks for Ingress and Egress policy types

The analysis uses:
- `node_*/node_k8s_networkpolicies.json` - Kubernetes NetworkPolicies
- `pod_*/pod_full.json` - Pod spec with namespace and labels
- `node_*/node_all_ips.txt` - Node IPs (for health probe validation)

## Recommended Actions

### If NetworkPolicy Blocks DNS

1. **Check NetworkPolicy egress rules**:
   ```bash
   kubectl get networkpolicy <policy-name> -n <namespace> -o yaml
   ```

2. **Add DNS egress rule**:
   ```yaml
   egress:
   - to: []
     ports:
     - protocol: UDP
       port: 53
     - protocol: TCP
       port: 53
   ```

3. **Or add catch-all egress** (if appropriate):
   ```yaml
   egress:
   - {}  # Allow all egress
   ```

4. **Test DNS resolution**:
   ```bash
   kubectl exec <pod-name> -n <namespace> -- nslookup kubernetes.default.svc.cluster.local
   ```

### If NetworkPolicy Blocks Health Probes

1. **Check NetworkPolicy ingress rules**:
   ```bash
   kubectl describe networkpolicy <policy-name> -n <namespace>
   ```

2. **Add ingress rule for node IPs**:
   ```yaml
   ingress:
   - from:
     - ipBlock:
         cidr: <node-subnet-cidr>
     ports:
     - protocol: TCP
       port: <probe-port>
   ```

3. **Or allow from all sources** (if appropriate):
   ```yaml
   ingress:
   - {}  # Allow all ingress
   ```

4. **Test health probe**:
   ```bash
   # Get node IP
   NODE_IP=$(kubectl get node <node-name> -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
   
   # Test from node (if you have access)
   curl -v http://<pod-ip>:<probe-port><probe-path>
   ```

### If NetworkPolicy Selector Doesn't Match

1. **Check pod labels**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> --show-labels
   ```

2. **Check NetworkPolicy podSelector**:
   ```bash
   kubectl get networkpolicy <policy-name> -n <namespace> -o jsonpath='{.spec.podSelector}'
   ```

3. **Update podSelector** to match pod labels:
   ```yaml
   podSelector:
     matchLabels:
       app: my-app
       version: v1
   ```

4. **Or update pod labels** to match NetworkPolicy:
   ```bash
   kubectl label pod <pod-name> -n <namespace> app=my-app version=v1
   ```

### If NetworkPolicy Has No Rules

1. **Check NetworkPolicy**:
   ```bash
   kubectl get networkpolicy <policy-name> -n <namespace> -o yaml
   ```

2. **Add appropriate rules**:
   ```yaml
   spec:
     policyTypes:
     - Ingress
     - Egress
     ingress:
     - from:
       - namespaceSelector: {}
       ports:
       - protocol: TCP
         port: 8080
     egress:
     - to: []
       ports:
       - protocol: UDP
         port: 53
       - protocol: TCP
         port: 53
   ```

### General Troubleshooting

1. **List all NetworkPolicies**:
   ```bash
   kubectl get networkpolicies --all-namespaces
   ```

2. **Check which NetworkPolicies apply to pod**:
   ```bash
   # Get pod namespace and labels
   POD_NS=$(kubectl get pod <pod-name> -o jsonpath='{.metadata.namespace}')
   POD_LABELS=$(kubectl get pod <pod-name> -o jsonpath='{.metadata.labels}')
   
   # Check NetworkPolicies in same namespace
   kubectl get networkpolicies -n "$POD_NS"
   ```

3. **Test connectivity**:
   ```bash
   # Test DNS
   kubectl exec <pod-name> -n <namespace> -- nslookup kubernetes.default.svc.cluster.local
   
   # Test service connectivity
   kubectl exec <pod-name> -n <namespace> -- curl -v http://<service-name>.<namespace>.svc.cluster.local
   ```

4. **Review NetworkPolicy logs** (if using CNI with NetworkPolicy support):
   ```bash
   # Check CNI logs for NetworkPolicy events
   kubectl logs -n kube-system -l app=aws-node | grep -i networkpolicy
   ```

5. **Temporarily disable NetworkPolicy** (for testing):
   ```bash
   # Delete NetworkPolicy to test if it's causing issues
   kubectl delete networkpolicy <policy-name> -n <namespace>
   
   # Recreate after testing
   kubectl apply -f <networkpolicy.yaml>
   ```

## Limitations

- **matchExpressions**: The analysis notes when NetworkPolicies use matchExpressions but doesn't fully evaluate them (requires more complex logic)
- **namespaceSelector**: Full evaluation of namespaceSelector and podSelector combinations is simplified
- **ipBlock**: CIDR matching for ipBlock rules is simplified
- **Port ranges**: Port range matching (e.g., 8000-9000) is not fully evaluated

## Related Files

- `node_*/node_k8s_networkpolicies.json` - Kubernetes NetworkPolicies
- `pod_*/pod_full.json` - Pod spec with namespace and labels
- `node_*/node_all_ips.txt` - Node IPs (for health probe validation)
- `node_*/node_calico_networkpolicies.yaml` - Calico NetworkPolicies (if Calico)
- `node_*/node_bpf_programs.txt` - eBPF programs (if Cilium)

## References

- [Kubernetes NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [NetworkPolicy Best Practices](https://kubernetes.io/docs/concepts/services-networking/network-policies/#best-practices)
- [AWS VPC CNI Network Policies](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/network-policy-EN.md)

