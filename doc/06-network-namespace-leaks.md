# Network Namespace Leaks

## What We Check

The toolkit detects orphaned or leaked network namespaces that remain after pods are deleted, which can indicate CNI cleanup issues.

**Checks performed:**
- Counts total network namespaces on node
- Identifies namespaces with no interfaces (orphaned)
- Checks namespace age (only flags as issue if older than 1 hour)
- Attempts to match pod's network namespace using container ID or pod UID
- Reports potential leaks with namespace age

## Why It Matters

**Network namespace leaks** can cause:
- **Resource exhaustion**: Each namespace consumes kernel resources
- **IP address leaks**: IPs remain allocated but unused
- **ENI leaks**: Branch ENIs may not be released
- **CNI cleanup failures**: Indicates CNI plugin issues
- **Performance degradation**: Too many namespaces slow down networking

**Common causes:**
- CNI plugin crashes during pod deletion
- Race conditions in CNI cleanup
- Kubernetes API delays (pod deleted before CNI cleanup)
- CNI plugin bugs in cleanup logic

## How We Check It

1. **Namespace Collection**: Lists all namespaces in `/var/run/netns`
2. **Interface Check**: For each namespace, checks if it has any network interfaces
3. **Age Calculation**: Calculates namespace age from creation time
4. **Leak Detection**: Flags namespaces as leaks if:
   - No interfaces present (empty namespace)
   - Older than 1 hour (avoids false positives from transient cleanup)
5. **Pod Matching**: Attempts to match pod's namespace using:
   - Container ID (hashed format)
   - Pod UID

**Output examples:**
- `[INFO] Found 13 network namespace(s) on node`
- `[ISSUE] Found 13 network namespace(s) with no interfaces and older than 1 hour (likely leaks)`
- `[WARN] Pod network namespace not found (pod may not have network setup yet or namespace name doesn't match UID)`

## Recommended Actions

### If Network Namespace Leaks Detected

1. **Identify leaked namespaces**:
   ```bash
   # On node, list network namespaces
   ip netns list
   
   # Check which are empty (no interfaces)
   for ns in $(ip netns list | awk '{print $1}'); do
     echo "=== $ns ==="
     ip netns exec $ns ip link show
   done
   ```

2. **Check CNI logs for cleanup errors**:
   ```bash
   # Look for DelNetwork errors
   grep -i "delnetwork\|cleanup\|delete" /var/log/aws-routed-eni/plugin.log
   ```

3. **Manual cleanup** (if safe):
   ```bash
   # WARNING: Only delete if you're sure the pod is gone
   # Check pod doesn't exist first
   kubectl get pod <pod-name> -n <namespace> 2>/dev/null || echo "Pod not found"
   
   # Delete namespace (if pod is confirmed deleted)
   ip netns delete <namespace-name>
   ```

4. **Investigate root cause**:
   - Review CNI plugin logs for errors
   - Check if specific pod types cause leaks
   - Look for patterns (specific namespaces, timing)

### If Pod Namespace Not Found

1. **Verify pod is running**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o wide
   ```

2. **Check if namespace uses hashed naming**:
   - AWS VPC CNI may use hashed namespace names
   - Container ID may not match namespace name exactly

3. **Verify network setup completed**:
   - Check pod events for network setup errors
   - Review CNI plugin logs for AddNetwork errors

### Preventing Leaks

1. **Monitor CNI plugin health**:
   ```bash
   kubectl get pods -n kube-system -l app=aws-node
   kubectl logs -n kube-system -l app=aws-node | grep -i error
   ```

2. **Update CNI plugin**:
   - Ensure using latest stable version
   - Check for known cleanup bugs in CNI version

3. **Configure CNI cleanup timeouts**:
   - Review CNI configuration for cleanup timeouts
   - Ensure timeouts are appropriate for your environment

4. **Monitor namespace count**:
   - Set up alerts for high namespace counts
   - Compare namespace count with pod count

## Related Files

- `node_netns_count.txt` - Total network namespace count
- `node_netns_list.txt` - List of network namespace names
- `node_netns_details.json` - Network namespace details (interfaces, IPs, timing)

## References

- [Linux Network Namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [AWS VPC CNI Cleanup](https://github.com/aws/amazon-vpc-cni-k8s)

