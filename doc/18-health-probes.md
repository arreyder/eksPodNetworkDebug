# Health Probe Analysis

## What We Check

This check analyzes Kubernetes health probes (liveness, readiness, startup) to detect configuration issues, probe failures, and potential network blocks that prevent kubelet from reaching pod health check endpoints.

## Why It Matters

Health probe failures can cause:
- **Pod not Ready**: Readiness probe failures prevent pods from receiving traffic
- **Pod restarts**: Liveness probe failures cause pod restarts
- **Service disruption**: Pods marked as not ready are removed from service endpoints
- **Startup delays**: Startup probe failures delay pod initialization

Common causes:
- **Network blocks**: Security Groups or NetworkPolicies blocking kubelet → pod traffic
- **Port not listening**: Application not listening on probe port
- **Wrong path/scheme**: Incorrect HTTP path or scheme (HTTP vs HTTPS)
- **Probe timeout**: Probes timing out due to slow application response
- **Missing probes**: No health probes configured (may mask issues)

## How We Check It

The analysis checks for:

1. **Probe Configuration**
   - Extracts liveness, readiness, and startup probe configurations
   - Identifies probe type (HTTP GET, TCP socket, exec)
   - Extracts probe ports, paths, and schemes

2. **Port Listening Status**
   - Checks if readiness probe ports are listening (from pod connections)
   - Warns if probe port is not found in listening ports

3. **Pod Conditions**
   - Checks `Ready` condition status (False may indicate probe failures)
   - Checks `ContainersReady` condition status
   - Reports probe failure reasons

4. **Probe Failure Events**
   - Searches pod events for probe failure messages
   - Counts probe failure events

5. **Network Blocking Analysis**
   - Checks for NetworkPolicies that might block node → pod traffic
   - Reports node Security Groups (verify they allow probe traffic)
   - Notes that kubelet needs to reach pod on probe ports

The analysis uses:
- `pod_full.json` - Pod spec with probe configurations
- `pod_conditions.json` - Pod condition status
- `pod_events.txt` - Pod events (for probe failures)
- `pod_connections.txt` - Listening ports (to verify probe ports)
- `node_k8s_networkpolicies.json` - NetworkPolicies (for blocking analysis)
- `aws_*/all_instance_enis.json` - Node Security Groups

## Recommended Actions

### If Probe Port is Not Listening

1. **Check if application is running**:
   ```bash
   kubectl exec <pod-name> -n <namespace> -- ps aux
   ```

2. **Verify application is listening on probe port**:
   ```bash
   kubectl exec <pod-name> -n <namespace> -- netstat -tuln | grep <probe-port>
   # or
   kubectl exec <pod-name> -n <namespace> -- ss -tuln | grep <probe-port>
   ```

3. **Check application logs** for startup errors:
   ```bash
   kubectl logs <pod-name> -n <namespace>
   ```

4. **Verify probe configuration** matches application:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.spec.containers[*].readinessProbe}'
   ```

### If Pod Ready Condition is False

1. **Check probe failure reason**:
   ```bash
   kubectl describe pod <pod-name> -n <namespace> | grep -A 5 "Readiness\|Liveness"
   ```

2. **Check pod events** for probe failures:
   ```bash
   kubectl get events -n <namespace> --field-selector involvedObject.name=<pod-name> | grep -i probe
   ```

3. **Test probe endpoint manually** (from node):
   ```bash
   # Get pod IP
   POD_IP=$(kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.podIP}')
   
   # Test HTTP probe (if HTTP)
   curl -v http://$POD_IP:<probe-port><probe-path>
   
   # Test HTTPS probe (if HTTPS)
   curl -v -k https://$POD_IP:<probe-port><probe-path>
   
   # Test TCP probe (if TCP socket)
   nc -zv $POD_IP <probe-port>
   ```

4. **Check probe timeout/period settings**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.spec.containers[*].readinessProbe}' | jq
   ```

### If NetworkPolicies Might Block Probes

1. **List NetworkPolicies**:
   ```bash
   kubectl get networkpolicies -n <namespace>
   ```

2. **Check NetworkPolicy rules**:
   ```bash
   kubectl describe networkpolicy <policy-name> -n <namespace>
   ```

3. **Verify NetworkPolicy allows ingress from node**:
   - NetworkPolicies should allow ingress from node IPs or node selector
   - For pod ENI scenarios, node IPs may need explicit allow rules
   - Check if NetworkPolicy has `podSelector` that matches pod labels

4. **Test connectivity from node**:
   ```bash
   # Get node IP
   NODE_IP=$(kubectl get node <node-name> -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
   
   # Test from node (if you have node access)
   curl -v http://$POD_IP:<probe-port><probe-path>
   ```

### If Node Security Groups Block Probes

1. **Get node Security Groups**:
   ```bash
   aws ec2 describe-instances --instance-ids <instance-id> \
     --query 'Reservations[0].Instances[0].SecurityGroups[*].GroupId' \
     --output text
   ```

2. **Check Security Group rules**:
   ```bash
   aws ec2 describe-security-groups --group-ids <sg-id>
   ```

3. **Verify Security Group allows ingress**:
   - Node SG should allow ingress from node IP to pod IP on probe ports
   - For pod ENI scenarios, pod ENI SG may also need rules
   - Check if node SG allows all traffic within VPC (common pattern)

4. **Add Security Group rule** (if needed):
   ```bash
   aws ec2 authorize-security-group-ingress \
     --group-id <node-sg-id> \
     --protocol tcp \
     --port <probe-port> \
     --source-group <pod-sg-id>
   ```

### If Probes Are Missing

1. **Add readiness probe**:
   ```yaml
   readinessProbe:
     httpGet:
       path: /ready
       port: 8080
       scheme: HTTP
     initialDelaySeconds: 5
     periodSeconds: 10
     timeoutSeconds: 1
     failureThreshold: 3
   ```

2. **Add liveness probe** (if needed):
   ```yaml
   livenessProbe:
     httpGet:
       path: /health
       port: 8080
       scheme: HTTP
     initialDelaySeconds: 30
     periodSeconds: 10
     timeoutSeconds: 1
     failureThreshold: 3
   ```

3. **Add startup probe** (for slow-starting applications):
   ```yaml
   startupProbe:
     httpGet:
       path: /startup
       port: 8080
       scheme: HTTP
     initialDelaySeconds: 0
     periodSeconds: 10
     timeoutSeconds: 1
     failureThreshold: 30
   ```

### General Troubleshooting

1. **Check probe logs** (if available):
   ```bash
   kubectl logs <pod-name> -n <namespace> | grep -i "health\|ready\|probe"
   ```

2. **Verify probe timing**:
   - `initialDelaySeconds`: Time before first probe
   - `periodSeconds`: Time between probes
   - `timeoutSeconds`: Probe timeout
   - `failureThreshold`: Consecutive failures before marking unhealthy

3. **Test probe endpoint from pod** (if possible):
   ```bash
   kubectl exec <pod-name> -n <namespace> -- curl -v http://localhost:<probe-port><probe-path>
   ```

4. **Check for application errors**:
   ```bash
   kubectl logs <pod-name> -n <namespace> --tail=100
   ```

5. **Review probe configuration**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o yaml | grep -A 10 "readinessProbe\|livenessProbe"
   ```

## Related Files

- `pod_*/pod_full.json` - Pod spec with probe configurations
- `pod_*/pod_conditions.json` - Pod condition status (Ready, ContainersReady)
- `pod_*/pod_events.txt` - Pod events (for probe failures)
- `pod_*/pod_connections.txt` - Listening ports (to verify probe ports)
- `node_*/node_k8s_networkpolicies.json` - NetworkPolicies (for blocking analysis)
- `aws_*/all_instance_enis.json` - Node Security Groups

## References

- [Kubernetes Probes](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- [Pod Lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/)
- [NetworkPolicies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Security Groups for Pods](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)

