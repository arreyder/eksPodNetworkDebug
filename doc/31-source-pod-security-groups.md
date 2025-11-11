# Source Pod Security Group Validation

## What We Check

The `sgfp_check_source_pod_sgs.sh` script checks security groups of source pods attempting to connect to identify mismatches with allowed security groups.

**Key checks:**
- Extracts allowed security groups for the target port from security group rules
- Identifies source pods attempting to connect (from conntrack data)
- Retrieves security groups from source pods (pod ENI or node security groups)
- Compares source pod security groups against allowed list
- Reports which source pods have matching security groups and which don't

## Why It Matters

When security group rules use SG-to-SG matching (referencing other security groups), the source pod's security groups must match one of the allowed security groups in the target pod's ingress rules.

Common issues:
- Source pods use node security groups that aren't in the allowed list
- Source pods use pod ENIs with security groups that don't match the allowed list
- Security group rules only allow specific security groups, not CIDR ranges
- Cross-node traffic is blocked because source pod security groups don't match

## How We Check It

1. **Extract allowed security groups** from `pod_branch_eni_sgs_rules.json` for the target port
2. **Get source IPs** from `pod_conntrack_connections.txt`
3. **Map source IPs to pods** using `node_pod_ip_map.txt`
4. **For each source pod:**
   - Check if pod has pod ENI (from pod annotations)
   - If pod ENI exists: Get security groups from the ENI
   - If no pod ENI: Get node security groups (from node's primary ENI or instance)
   - Compare against allowed security groups list
5. **Report matches and mismatches**

## Recommended Actions

### If source pods don't have matching security groups:

1. **For pods with pod ENIs:**
   - Add the pod ENI's security groups to the target pod's ingress rules
   - Or update the source pod's SecurityGroupPolicy to use matching security groups

2. **For pods using node security groups:**
   - Add the node's security groups to the target pod's ingress rules
   - This is the most common fix for cross-node traffic issues

3. **Alternative: Use CIDR ranges:**
   - Instead of security group references, add CIDR ranges covering the source IPs
   - Less secure but more flexible

### Example: Fixing node security group mismatch

If source pods use node security groups that aren't in the allowed list:

1. Run the script to identify which source pods have mismatches:
   ```bash
   ./sgfp_check_source_pod_sgs.sh <bundle-dir>
   ```

2. Get the node's security groups for each source pod:
   ```bash
   # Get node name
   NODE=$(kubectl get pod <source-pod> -o jsonpath='{.spec.nodeName}')
   
   # Get instance ID
   INSTANCE_ID=$(aws ec2 describe-instances \
     --filters "Name=private-dns-name,Values=${NODE}" \
     --query 'Reservations[0].Instances[0].InstanceId' \
     --output text)
   
   # Get security groups
   aws ec2 describe-instances --instance-ids $INSTANCE_ID \
     --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
     --output text
   ```

3. Add node security groups to target pod's ingress rules:
   ```bash
   aws ec2 authorize-security-group-ingress \
     --group-id <target-pod-sg> \
     --ip-permissions IpProtocol=tcp,FromPort=6000,ToPort=6000,UserIdGroupPairs=[{GroupId=<node-sg>}]
   ```

## Limitations

- **Pods deleted/recreated:** If source pods have been deleted/recreated since diagnostic collection, the script may not be able to retrieve their security groups. Run diagnostics while source pods are active for accurate results.
- **IP reassignment:** Pod IPs may have been reassigned, making it difficult to find the current ENI/instance.

## Related Files

- `pod_branch_eni_sgs_rules.json` - Full security group rules (including IpPermissions)
- `pod_conntrack_connections.txt` - Connection tracking data with source IPs
- `node_pod_ip_map.txt` - Mapping of IPs to pod names
- `pod_ip.txt` - Target pod IP address

## References

- [AWS Security Groups for Pods Documentation](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)
- [Security Group Rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)

