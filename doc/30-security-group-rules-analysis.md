# Security Group Rules Analysis

## What We Check

The `sgfp_check_sg_rules_for_cross_node.sh` script analyzes security group ingress rules to verify if cross-node source IPs are allowed for a specific port.

**Key checks:**
- Extracts allowed security groups for a specific port (e.g., port 6000) from the pod's ENI security group rules
- Identifies source IPs attempting to connect (from conntrack data)
- Checks if source IPs are allowed by CIDR ranges or security group references
- Reports which source IPs are blocked and which are allowed

## Why It Matters

When pods use Security Groups for Pods (SG-for-Pods), traffic between pods is controlled by security group rules. Cross-node traffic requires that:

1. **The target pod's security group** must have ingress rules allowing traffic from source pods
2. **Source IPs must match** either:
   - CIDR ranges in the ingress rules, OR
   - Security groups referenced in the ingress rules (SG-to-SG matching)

Common issues:
- Security group rules only allow specific security groups, not CIDR ranges
- Source pods use node security groups that aren't in the allowed list
- Source pods use pod ENIs with security groups that don't match the allowed list
- Cross-node traffic is blocked because source IPs don't match any allowed rules

## How We Check It

1. **Extract security group rules** from `pod_branch_eni_sgs_rules.json` (collected during diagnostics)
2. **Identify target port** from pod configuration or conntrack data
3. **Extract allowed security groups** for the port from ingress rules
4. **Get source IPs** from `pod_conntrack_connections.txt` (filtered for cross-node traffic)
5. **Check each source IP** against:
   - CIDR ranges in ingress rules
   - Security group references (requires checking source pod's security groups)

## Recommended Actions

### If source IPs are blocked:

1. **Check if source pods have pod ENIs:**
   ```bash
   kubectl get pod <source-pod> -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/pod-eni}'
   ```

2. **If source pods use pod ENIs:**
   - Verify their security groups are in the allowed list
   - Add their security groups to the target pod's ingress rules if needed

3. **If source pods use node security groups:**
   - Identify which nodes the source pods are on
   - Check the node's security groups
   - Add node security groups to the target pod's ingress rules if needed

4. **Alternative: Use CIDR ranges:**
   - Instead of security group references, add CIDR ranges covering the source IPs
   - This is less secure but more flexible

### Example: Adding node security groups to ingress rules

If source pods use node security groups that aren't in the allowed list:

1. Get the node's security groups:
   ```bash
   aws ec2 describe-instances --instance-ids <instance-id> \
     --query 'Reservations[0].Instances[0].SecurityGroups[].GroupId' \
     --output text
   ```

2. Add the node's security groups to the target pod's security group ingress rules:
   ```bash
   aws ec2 authorize-security-group-ingress \
     --group-id <target-pod-sg> \
     --ip-permissions IpProtocol=tcp,FromPort=6000,ToPort=6000,UserIdGroupPairs=[{GroupId=<node-sg>}]
   ```

## Related Files

- `pod_branch_eni_sgs_rules.json` - Full security group rules (including IpPermissions)
- `pod_conntrack_connections.txt` - Connection tracking data with source IPs
- `pod_ip.txt` - Target pod IP address
- `node_pod_ip_map.txt` - Mapping of IPs to pod names

## References

- [AWS Security Groups for Pods Documentation](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)
- [Security Group Rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)

