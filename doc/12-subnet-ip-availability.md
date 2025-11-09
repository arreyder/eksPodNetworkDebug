# Subnet IP Availability

## What We Check

The toolkit validates subnet IP address availability to prevent pod scheduling failures due to IP exhaustion.

**Checks performed:**
- Collects subnet information with available IP counts
- Identifies subnets with low IP availability (<10 IPs)
- Reports subnet CIDR blocks and availability zones
- Warns when subnets are approaching exhaustion

## Why It Matters

**Subnet IP exhaustion** causes:
- **Pod scheduling failures**: New pods cannot be scheduled
- **Pod stuck in Pending**: Pods wait indefinitely for IP assignment
- **CNI errors**: IP allocation failures in CNI logs
- **Cluster capacity issues**: Cannot scale workloads

**Common causes:**
- Subnets too small for workload
- Many small nodes (each node reserves IPs)
- IP warm pool too large
- IP leaks (IPs not released)
- Rapid pod churn

## How We Check It

1. **Subnet Collection**: Queries AWS API for all subnets in VPC
2. **IP Availability**: Reads `AvailableIpAddressCount` from AWS API
3. **Low IP Detection**: Flags subnets with <10 available IPs
4. **Reporting**: Shows subnet ID, available IPs, CIDR, and AZ

**Output examples:**
- `[OK] All subnets have adequate IP availability`
- `[ISSUE] Subnet subnet-xxx: 5 IPs available (CIDR: 10.4.192.0/18) - low availability`

## Recommended Actions

### If Subnet IP Availability Low

1. **Identify low-availability subnets**:
   ```bash
   # Check subnet IP availability
   aws ec2 describe-subnets \
     --subnet-ids <subnet-id> \
     --query 'Subnets[0].AvailableIpAddressCount'
   ```

2. **Calculate subnet capacity**:
   ```bash
   # Get subnet CIDR
   aws ec2 describe-subnets \
     --subnet-ids <subnet-id> \
     --query 'Subnets[0].CidrBlock'
   
   # Calculate total IPs in CIDR (excluding network/broadcast)
   # Example: /24 = 256 IPs, /18 = 16384 IPs
   ```

3. **Review IP usage**:
   - Count ENIs in subnet
   - Count pods using IPs
   - Check for IP leaks

4. **Options to resolve**:

   **Option 1: Enlarge subnets** (if possible):
   - Add more IP ranges to existing subnets
   - Requires VPC CIDR expansion

   **Option 2: Add more subnets**:
   - Create additional subnets in VPC
   - Update node groups to use new subnets

   **Option 3: Use prefix delegation** (IPv4):
   - Enables more IPs per ENI
   - Requires CNI configuration

   **Option 4: Reduce IP warm pool**:
   ```bash
   # Check current warm pool settings
   kubectl get configmap -n kube-system aws-node -o yaml | grep -i warm
   
   # Reduce warm pool (if too large)
   # Edit aws-node ConfigMap
   ```

   **Option 5: Use larger subnets**:
   - Migrate to larger CIDR blocks
   - Requires careful planning

### Preventing IP Exhaustion

1. **Monitor IP availability**:
   - Set up CloudWatch alarms for low IP counts
   - Monitor subnet IP usage trends

2. **Right-size subnets**:
   - Calculate required IPs based on:
     - Number of nodes
     - Pods per node
     - ENI trunking usage
   - Add 20-30% buffer for growth

3. **Optimize IP usage**:
   - Use ENI trunking (reduces IP usage)
   - Use prefix delegation (more IPs per ENI)
   - Reduce warm pool if too large

4. **Review IP allocation**:
   - Check for IP leaks
   - Verify IPs are released when pods deleted
   - Monitor IP allocation patterns

## Related Files

- `aws_*/subnets.json` - Subnet information with IP availability

## References

- [AWS VPC Subnets](https://docs.aws.amazon.com/vpc/latest/userguide/configure-subnets.html)
- [AWS VPC CNI IP Management](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/ip-management.md)
- [Prefix Delegation](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/prefix-delegation.md)

