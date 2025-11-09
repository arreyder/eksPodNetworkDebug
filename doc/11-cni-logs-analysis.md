# CNI Logs Analysis

## What We Check

The toolkit collects and analyzes AWS VPC CNI logs to identify errors, warnings, and issues affecting pod networking.

**Checks performed:**
- Collects CNI logs from `/var/log/aws-routed-eni/`
- Analyzes logs for errors and warnings
- Creates error summaries for each log file
- Reports recent errors with examples
- Identifies pod-specific errors

## Why It Matters

**CNI logs** provide critical information about:
- **Pod network setup failures**: AddNetwork errors
- **Pod network cleanup failures**: DelNetwork errors
- **ENI attachment issues**: ENI attachment errors
- **IP assignment problems**: IP allocation failures
- **CNI plugin bugs**: Plugin errors and crashes

**Common issues:**
- Pod not found errors (race conditions)
- ENI attachment timeouts
- IP allocation failures
- CNI plugin crashes
- Permission errors

## How We Check It

1. **Log Collection**: Collects logs from `/var/log/aws-routed-eni/`:
   - `ipamd.log` - IP address management daemon
   - `plugin.log` - CNI plugin operations
   - `network-policy-agent.log` - Network policy agent
   - `ebpf-sdk.log` - eBPF SDK logs
   - `egress-v6-plugin.log` - IPv6 egress plugin

2. **Error Detection**: Searches for error and warning patterns:
   - Error level logs
   - Warning level logs
   - Exception/panic messages

3. **Error Summaries**: Creates `.errors` files with filtered errors

4. **Recent Errors**: Shows last 3 errors from each log file

**Output examples:**
- `[ISSUE] Found 173 error/warning lines in plugin.log`
- `[OK] No errors found in aws-node logs`
- `[INFO] Recent errors (last 3): ...`

## Recommended Actions

### If CNI Log Errors Detected

1. **Review specific error messages**:
   ```bash
   # View error summary
   cat <bundle>/node_*/cni_logs/plugin.log.errors
   
   # View full log
   cat <bundle>/node_*/cni_logs/plugin.log | grep -i error
   ```

2. **Identify error patterns**:
   - Look for common error messages
   - Check if errors are pod-specific or general
   - Identify timing patterns

3. **Common error types and fixes**:

   **"Pod not found" errors**:
   - Usually race conditions (pod deleted before CNI cleanup)
   - Generally safe to ignore if pod is actually deleted
   - May indicate CNI cleanup timing issues

   **"ENI attachment failed" errors**:
   - Check ENI limits (see ENI/Instance Limits doc)
   - Verify IAM permissions for ENI operations
   - Check AWS API throttling

   **"IP allocation failed" errors**:
   - Check subnet IP availability (see Subnet IP Availability)
   - Verify IPAMD is running
   - Check IPAMD warm pool configuration

   **"Permission denied" errors**:
   - Verify IAM role has required permissions
   - Check IRSA (IAM Roles for Service Accounts) configuration
   - Review CloudTrail for permission errors

### If High Error Count

1. **Check CNI plugin health**:
   ```bash
   kubectl get pods -n kube-system -l app=aws-node
   kubectl describe pod -n kube-system <aws-node-pod>
   ```

2. **Review CNI plugin version**:
   ```bash
   kubectl get daemonset -n kube-system aws-node -o jsonpath='{.spec.template.spec.containers[0].image}'
   ```

3. **Check for known issues**:
   - Review AWS VPC CNI release notes
   - Check GitHub issues for your CNI version
   - Consider upgrading CNI plugin

### If Pod-Specific Errors

1. **Use view-logs helper**:
   ```bash
   ./sgfp_view_logs.sh <bundle> --errors-only
   ```

2. **Review pod events**:
   ```bash
   kubectl describe pod <pod-name> -n <namespace>
   ```

3. **Check pod annotations**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o yaml | grep -A 10 annotations
   ```

## Related Files

- `node_*/cni_logs/ipamd.log` - IPAMD logs
- `node_*/cni_logs/plugin.log` - CNI plugin logs
- `node_*/cni_logs/*.errors` - Error summaries
- `aws_node_errors.log` - Filtered aws-node errors

## References

- [AWS VPC CNI Logging](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/troubleshooting.md)
- [AWS VPC CNI Troubleshooting](https://github.com/aws/amazon-vpc-cni-k8s/wiki/Troubleshooting)

