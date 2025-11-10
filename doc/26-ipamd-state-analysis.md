# IPAMD State Analysis

## What We Check

The toolkit analyzes the IP Address Management Daemon (IPAMD) state to understand IP and ENI allocation behavior.

**Checks performed:**
- IPAMD warm pool configuration (warm IP target, warm ENI target)
- Branch ENI count on trunk ENI (from IPAMD introspection)
- Branch ENI limit warnings (approaching 50 per trunk limit)
- IPAMD data availability

## Why It Matters

**IPAMD** is the AWS VPC CNI component responsible for:
- Managing IP address allocation from subnets
- Managing ENI allocation and attachment
- Maintaining warm pools of IPs/ENIs for faster pod startup
- Tracking branch ENI allocations on trunk ENIs

**Common issues:**
- Warm pool too small (slow pod startup, frequent IP allocation delays)
- Warm pool too large (wastes IP addresses, may cause subnet exhaustion)
- Branch ENI limit reached (50 per trunk, prevents new pod ENI attachments)
- IPAMD introspection unavailable (cannot determine branch ENI count)

## How We Check It

1. **Warm Pool Configuration**: Reads IPAMD pool configuration from introspection endpoint
2. **Branch ENI Count**: Queries IPAMD introspection to count branch ENIs attached to trunk
3. **Limit Validation**: Checks if branch ENI count is approaching the 50 per trunk limit
4. **Data Availability**: Reports if IPAMD data is not available

**Output examples:**
- `[INFO] IPAMD warm pool: IPs=16, ENIs=2`
- `[INFO] Branch ENIs on trunk (from IPAMD): 45`
- `[WARN] Branch ENI count approaching limit (typical limit: 50)`
- `[INFO] Branch ENI count: Unable to determine from IPAMD (may need to check VPC-wide scan)`

## Recommended Actions

### If Warm Pool Too Small

1. **Increase warm pool size**:
   ```bash
   # Check current warm pool settings
   kubectl get daemonset aws-node -n kube-system -o jsonpath='{.spec.template.spec.containers[0].env}' | jq '.[] | select(.name | contains("WARM"))'
   
   # Update warm pool (via DaemonSet env vars)
   kubectl set env daemonset/aws-node -n kube-system WARM_IP_TARGET=16 WARM_ENI_TARGET=2
   ```

2. **Monitor pod startup times**: After increasing warm pool, monitor if pod startup times improve
3. **Balance with subnet size**: Ensure warm pool doesn't consume too many IPs from small subnets

### If Warm Pool Too Large

1. **Reduce warm pool size**:
   ```bash
   # Reduce warm pool to free up IPs
   kubectl set env daemonset/aws-node -n kube-system WARM_IP_TARGET=8 WARM_ENI_TARGET=1
   ```

2. **Monitor IP availability**: Check subnet IP availability after reducing warm pool
3. **Consider subnet size**: If subnets are small, use smaller warm pools

### If Branch ENI Count Approaching Limit

1. **Check trunk ENI branch ENI count**:
   ```bash
   # Get trunk ENI ID
   kubectl get node <node-name> -o jsonpath='{.metadata.annotations.vpc\.k8s\.aws/trunk-eni-id}'
   
   # Count branch ENIs (requires IPAMD introspection or AWS API)
   # This is typically done via the diagnostic toolkit
   ```

2. **Consider additional trunk ENIs**: If approaching limit, may need to add more trunk ENIs to the node
3. **Review pod density**: High pod density per node may require multiple trunk ENIs

### If IPAMD Data Not Available

1. **Check IPAMD introspection endpoint**: Verify IPAMD is exposing introspection data
2. **Check aws-node pod logs**: Review logs for IPAMD errors
3. **Verify aws-node version**: Ensure aws-node version supports introspection
4. **Use VPC-wide scan**: As fallback, use AWS API to scan for branch ENIs in VPC

## Related Files

- `pod_*/ipamd_pool.json` - IPAMD warm pool configuration
- `pod_*/ipamd_introspection.json` - IPAMD introspection data (ENI/IP state)
- `aws_*/trunk_eni.json` - Trunk ENI information
- `aws_*/_all_branch_enis_in_vpc.json` - All branch ENIs in VPC (fallback for counting)

## References

- [AWS VPC CNI Configuration](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/eni-and-ip-target.md)
- [IPAMD Warm Pool](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/eni-and-ip-target.md#warm-pool-targets)
- [Trunk ENI Branch ENI Limits](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)

