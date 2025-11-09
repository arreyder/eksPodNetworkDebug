# ENI Attachment Timing

## What We Check

The toolkit analyzes ENI attachment timing to detect delays or issues in pod ENI attachment that can cause pod startup delays.

**Checks performed:**
- Collects ENI attachment status and timing
- Checks readiness gate timing (PodReadyToStartContainers)
- Validates ENI is attached and in-use
- Reports attachment delays (>1 minute)

## Why It Matters

**ENI attachment delays** cause:
- **Pod startup delays**: Pods wait for ENI before starting
- **Slow pod scheduling**: New pods take longer to become ready
- **Application timeouts**: Applications may timeout during startup
- **Resource waste**: Pods consume resources while waiting

**Common causes:**
- ENI limits reached (see ENI/Instance Limits)
- AWS API throttling
- ENI attachment API delays
- CNI plugin issues
- IAM permission problems

## How We Check It

1. **ENI Status**: Checks ENI attachment status from AWS API
2. **Attachment Time**: Reads ENI attachment timestamp
3. **Readiness Gate**: Compares pod creation time with readiness gate time
4. **Delay Detection**: Flags delays >1 minute

**Output examples:**
- `[OK] ENI attached to trunk: eni-xxx (branch ENI, no Attachment.Status field)`
- `[OK] ENI status: in-use`
- `[OK] Readiness gate timing: 3s`
- `[ISSUE] Readiness gate took 120s (>1min, may indicate ENI attachment delay)`

## Recommended Actions

### If ENI Attachment Delayed

1. **Check ENI limits** (see ENI/Instance Limits doc):
   - Verify instance has available ENI capacity
   - Check trunk ENI branch ENI count

2. **Review CloudTrail for API issues**:
   ```bash
   # Check for ENI API throttling/errors
   ./sgfp_api_diag.sh
   ```

3. **Check CNI logs for errors**:
   ```bash
   # Look for ENI attachment errors
   grep -i "attach\|eni" <bundle>/node_*/cni_logs/plugin.log
   ```

4. **Verify IAM permissions**:
   - Check IAM role has `ec2:AttachNetworkInterface`
   - Verify IRSA configuration
   - Review CloudTrail for permission errors

### If Readiness Gate Delayed

1. **Review pod events**:
   ```bash
   kubectl describe pod <pod-name> -n <namespace>
   ```

2. **Check readiness gate condition**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.status.conditions[?(@.type=="PodReadyToStartContainers")]}'
   ```

3. **Verify CNI plugin is processing**:
   - Check CNI plugin logs
   - Verify CNI plugin is running
   - Check for CNI plugin errors

### Optimizing Attachment Time

1. **Use ENI trunking**:
   - Faster than individual ENI attachment
   - Reduces API calls

2. **Warm ENI pool**:
   - Pre-allocate ENIs
   - Reduces attachment time

3. **Monitor API throttling**:
   - Check CloudTrail for throttling
   - Consider increasing API limits
   - Use multiple AWS accounts if needed

## Related Files

- `pod_eni_attachment_status.txt` - ENI attachment status
- `pod_eni_attach_time.txt` - ENI attachment timestamp
- `pod_timing.txt` - Pod creation/start timestamps
- `pod_conditions.json` - Pod conditions including readiness gate

## References

- [AWS VPC CNI ENI Attachment](https://github.com/aws/amazon-vpc-cni-k8s)
- [Pod Readiness Gates](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-readiness-gate)

