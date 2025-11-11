# Network Namespace Leaks

## What We Check

The toolkit detects orphaned or leaked network namespaces that remain after pods are deleted, which can indicate CNI cleanup issues.

**Checks performed:**
- Counts total network namespaces on node
- **Enhanced IP-based matching**: Collects actual IP addresses (IPv4 and IPv6) from each network namespace
- **Pod IP mapping**: Creates a map of all active pod IPs to `namespace/name` identifiers
- **Accurate matching**: Matches network namespace IPs against active pod IPs to identify truly orphaned namespaces
- **Process counting**: Counts processes within each namespace for additional context
- **Age-based filtering**: Only flags namespaces as orphaned if they're older than 1 hour (avoids false positives)
- Reports potential leaks with namespace IPs, age, and process count

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

1. **Namespace Collection**: Lists all namespaces in `/var/run/netns` (or `/host/var/run/netns` when accessed via temporary pod)
2. **IP Address Collection**: For each namespace, collects actual IPv4 and IPv6 addresses using `nsenter` to enter the host namespace, then `ip -n` to access the network namespace
3. **Pod IP Mapping**: Creates a map of all active pod IPs (excluding `Failed` and `Terminating` pods) to `namespace/name` format
4. **Process Counting**: Counts processes within each namespace using `ip netns pids`
5. **Age Calculation**: Calculates namespace age from file modification time
6. **IP-based Matching**: Matches each namespace's IP addresses against the pod IP map:
   - If namespace IP matches an active pod → namespace is active (not orphaned)
   - If namespace has no IPs AND no processes AND is older than 1 hour → likely orphaned
   - If namespace has IPs but no matching pod AND no processes AND is older than 1 hour → likely orphaned
7. **Leak Detection**: Flags namespaces as truly orphaned only if:
   - No matching pod found (IP doesn't match any active pod)
   - No processes running in the namespace
   - Older than 1 hour (avoids false positives from transient cleanup)

**Output examples:**
- `[INFO] Found 13 network namespace(s) on node`
- `[OK] cni-04b1c5aa-c3dc-db34-9c4f-3c27796f4201 -> default/be-innkeeper-7c49cfcb97-lsv45 (processes: 0)`
- `[INFO] Namespace matching summary: Matched to pods: 13, Orphaned (safe to delete): 0`
- `[ISSUE] Found 2 orphaned network namespace(s) (no matching pod, safe to delete after verification)`

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

### If Namespaces Show as Orphaned But Should Be Active

1. **Verify pod is actually running**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o wide
   ```

2. **Check if pod IP matches namespace IP**:
   ```bash
   # Get pod IP
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.podIP}'
   
   # Check namespace IP (from node)
   ip netns exec <namespace-name> ip addr show dev eth0
   ```

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

- `node_netns_list.txt` - List of network namespace names
- `node_netns_details.json` - Network namespace details including:
  - Namespace name
  - Interface count
  - IP addresses (IPv4 and IPv6 arrays)
  - Process count
  - Modification time (age)
  - Active status
- `node_pod_ip_map.txt` - Map of active pod IPv4 addresses to `namespace/name` format
- `node_pod_ipv6_map.txt` - Map of active pod IPv6 addresses to `namespace/name` format

## References

- [Linux Network Namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [AWS VPC CNI Cleanup](https://github.com/aws/amazon-vpc-cni-k8s)

