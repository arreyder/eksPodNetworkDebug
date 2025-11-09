# ENI / Instance Limits

## What We Check

The toolkit validates Elastic Network Interface (ENI) and IP address limits for EC2 instances to prevent pod scheduling failures due to network resource exhaustion.

**Checks performed:**
- Identifies instance type and looks up ENI/IP limits
- Compares current ENI usage vs instance limits
- Validates trunk ENI branch ENI count (approaching 50 limit)
- Estimates maximum pods capacity (without trunking)
- Warns when approaching or at limits

## Why It Matters

**ENI/IP limits** directly impact:
- **Maximum pods per node**: Limited by ENI count × IPs per ENI
- **Pod scheduling**: New pods cannot be scheduled if limits are reached
- **Pod ENI attachment**: Branch ENIs cannot be attached if trunk is full (50 limit)
- **Network capacity**: Determines how many pods can run on a node

**Common issues:**
- Instance hits ENI limit before CPU/RAM is full
- Trunk ENI reaches 50 branch ENI limit
- Small instance types cannot support desired pod density
- Pods stuck in Pending state due to ENI exhaustion

## How We Check It

1. **Instance Type Detection**: Reads instance type from AWS API
2. **Limit Lookup**: Maps instance type to ENI/IP limits:
   - Small instances (t3.small): 3 ENIs, 4 IPs per ENI
   - Medium instances (m5.large): 3 ENIs, 10 IPs per ENI
   - Large instances (m5.2xlarge): 4 ENIs, 15 IPs per ENI
   - Very large (m5.8xlarge+): 8 ENIs, 30 IPs per ENI
3. **Current Usage**: Counts ENIs attached to instance
4. **Trunk Analysis**: Counts branch ENIs attached to trunk ENI
5. **Max Pods Calculation**: `(ENIs × (IPs per ENI - 1)) + 2`

**Output examples:**
- `[INFO] Instance type: m8gd.2xlarge`
- `[INFO] Instance limits: 4 ENI(s), 15 IP(s) per ENI`
- `[INFO] Current ENIs on instance: 2 / 4`
- `[INFO] Estimated max pods (without trunking): ~58`
- `[WARN] Instance approaching ENI limit: 3 / 4 (1 remaining)`
- `[ISSUE] Trunk ENI at branch ENI limit: 50 / 50 - cannot attach more pod ENIs`

## Recommended Actions

### If Approaching ENI Limit

1. **Monitor ENI usage**:
   ```bash
   # Check current ENI count
   aws ec2 describe-network-interfaces \
     --filters "Name=attachment.instance-id,Values=<instance-id>" \
     --query 'length(NetworkInterfaces)'
   ```

2. **Consider larger instance types**:
   - Review instance type limits in AWS documentation
   - Upgrade to instance type with more ENIs if needed
   - Example: m5.large (3 ENIs) → m5.2xlarge (4 ENIs)

3. **Use ENI trunking** (if not already):
   - Enables up to 50 branch ENIs per trunk
   - Significantly increases pod capacity
   - Requires instance type support

### If Trunk ENI at Branch ENI Limit (50)

1. **Check branch ENI count**:
   ```bash
   # Count branch ENIs on trunk
   aws ec2 describe-network-interfaces \
     --filters "Name=parent-network-interface-id,Values=<trunk-eni-id>" \
     --query 'length(NetworkInterfaces)'
   ```

2. **Options**:
   - **Add more trunk ENIs** (if instance supports multiple trunks)
   - **Use larger instance types** (more trunk ENIs supported)
   - **Reduce pod density** (fewer pods per node)
   - **Scale out** (add more nodes)

### If Max Pods Calculation Shows Low Capacity

1. **Review pod density requirements**:
   - Calculate desired pods per node
   - Compare with estimated max pods

2. **Consider ENI trunking**:
   - Without trunking: Limited by ENI × IPs per ENI
   - With trunking: Up to 50 branch ENIs per trunk
   - Example: m5.2xlarge with trunking can support 50+ pods

3. **Instance type selection**:
   - Use [AWS ENI/IP limits documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html) to select appropriate instance type
   - Consider both ENI count and IPs per ENI

### Calculating Pod Capacity

**Without trunking:**
```
Max pods = (ENIs × (IPs per ENI - 1)) + 2
```
- The `-1` accounts for the primary IP on each ENI
- The `+2` accounts for host network pods (kube-proxy, CNI)

**With trunking:**
```
Max pods = (Trunk ENIs × 50) + 2
```
- Each trunk ENI can support up to 50 branch ENIs
- Each branch ENI typically has 1 IP (for pod)

## Related Files

- `aws_*/node_instance_type.txt` - Instance type
- `aws_*/all_instance_enis.json` - ENIs attached to instance
- `aws_*/trunk_eni_id.txt` - Trunk ENI ID
- `aws_*/_all_branch_enis_in_vpc.json` - Branch ENIs in VPC

## References

- [AWS ENI Limits](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-eni.html)
- [AWS VPC CNI Trunking](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/trunking.md)
- [EKS Best Practices - Networking](https://aws.github.io/aws-eks-best-practices/networking/)

