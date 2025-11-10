# Pod Events Analysis

## What We Check

The toolkit analyzes Kubernetes pod events to identify network-related issues and failures.

**Checks performed:**
- Collects all pod events from Kubernetes API
- Filters for network-related events (network, ENI, attach, security group, failed, error, timeout, not ready, pending)
- Reports network-related events that may indicate connectivity issues
- Counts total events vs network-related events

## Why It Matters

**Pod Events** provide real-time information about what's happening with the pod:
- **Network setup failures**: ENI attachment failures, security group assignment issues
- **Timeouts**: Network operations timing out
- **Readiness issues**: Pod not becoming ready due to network problems
- **Pending state**: Pod stuck in Pending due to IP/ENI allocation issues

**Common network-related events:**
- `Failed to attach network interface`
- `Error assigning security groups`
- `Network not ready`
- `Pod not ready: network setup incomplete`
- `Timeout waiting for network interface`

## How We Check It

1. **Event Collection**: Queries Kubernetes API for all events related to the pod
2. **Event Filtering**: Searches for network-related keywords in event messages
3. **Event Reporting**: Displays up to 10 most recent network-related events
4. **Event Counting**: Reports total event count vs network-related event count

**Output examples:**
- `[ISSUE] Network-related events found:`
- `  - Failed to attach network interface eni-xxx`
- `  - Error assigning security groups: InvalidGroup.NotFound`
- `[OK] No network-related events found (15 total events)`
- `[OK] No pod events found`

## Recommended Actions

### If Network-Related Events Found

1. **Review event details**:
   ```bash
   kubectl get events --field-selector involvedObject.name=<pod-name> -n <namespace> --sort-by='.lastTimestamp'
   ```

2. **Check for specific error types**:
   - **ENI attachment failures**: Check AWS permissions, ENI limits, subnet availability
   - **Security group errors**: Verify security group IDs exist and are in correct VPC
   - **Timeout errors**: Check CNI logs, ENI attachment timing, subnet IP availability
   - **Not ready errors**: Check readiness gate status, ENI attachment status

3. **Review CNI logs**: Check aws-node logs for detailed error messages
   ```bash
   kubectl logs -n kube-system -l app=aws-node | grep -i error
   ```

4. **Check CloudTrail**: Review CloudTrail for API errors/throttles related to ENI operations

### If Pod Stuck in Pending

1. **Check pod conditions**:
   ```bash
   kubectl describe pod <pod-name> -n <namespace>
   ```

2. **Check for IP allocation errors**: Look for events mentioning IP allocation failures
3. **Check subnet IP availability**: Verify subnets have available IPs
4. **Check ENI limits**: Verify instance hasn't reached ENI/IP limits

### If No Events Found

1. **Verify event collection**: Check if events are being collected correctly
2. **Check event retention**: Kubernetes events may be pruned after a certain time
3. **Review pod status directly**: Check pod conditions and status directly

## Related Files

- `pod_*/pod_events.txt` - All pod events from Kubernetes API
- `pod_*/pod_conditions.json` - Pod conditions (may reflect event causes)
- `pod_*/pod_wide.txt` - Pod status summary
- `node_*/cni_logs/plugin.log` - CNI plugin logs (may contain event-related errors)
- `node_*/cni_logs/ipamd.log` - IPAMD logs (may contain IP allocation errors)

## References

- [Kubernetes Events](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/event-v1/)
- [Pod Lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/)
- [Troubleshooting Pods](https://kubernetes.io/docs/tasks/debug/debug-application/debug-pods/)

