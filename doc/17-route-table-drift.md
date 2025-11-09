# Route Table Drift Analysis

## What We Check

This check analyzes the node's routing table to detect missing or incorrect routes that could cause network connectivity issues. Route table drift occurs when routes are missing, misconfigured, or inconsistent with expected VPC networking.

## Why It Matters

Route table drift can cause:
- **Loss of internet connectivity**: Missing default route (0.0.0.0/0) prevents nodes from reaching internet or VPC endpoints
- **Pod-to-pod communication failures**: Missing subnet routes prevent pods from communicating across subnets
- **Metadata service failures**: Missing route to AWS metadata service (169.254.169.254) breaks IRSA, node identity, and other AWS integrations
- **VPC routing issues**: Inconsistent routes can cause asymmetric routing or black holes
- **NACL/route table misconfiguration**: Changes to VPC route tables or NACLs can break connectivity

Common causes:
- VPC route table changes (accidental or intentional)
- Network interface misconfiguration
- Route table propagation delays
- Manual route deletion or modification
- NACL rule changes blocking routes

## How We Check It

The analysis checks for:

1. **Default Route (0.0.0.0/0)**
   - Verifies presence of default route for internet/VPC connectivity
   - Checks route gateway and interface

2. **Local Subnet Route**
   - Verifies route exists for node's primary interface subnet
   - Ensures local subnet connectivity

3. **Metadata Service Route**
   - Checks for route to AWS metadata service (169.254.169.254)
   - Critical for IRSA, node identity, and AWS integrations

4. **VPC Subnet Routes** (if subnet data available)
   - Compares collected subnet CIDRs against routes
   - Warns if subnet routes are missing (may use default route)

5. **Route Count**
   - Counts total routes (excluding local/broadcast/multicast/loopback)
   - Warns if very few routes found (may indicate routing issues)

The analysis uses:
- `node_routes_all.txt` - Full route table from `ip route show table all`
- `aws_*/subnets.json` - VPC subnet information (if available)

## Recommended Actions

### If Default Route is Missing

1. **Check VPC route tables**:
   ```bash
   aws ec2 describe-route-tables --filters "Name=vpc-id,Values=<vpc-id>"
   ```

2. **Verify internet gateway**:
   ```bash
   aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=<vpc-id>"
   ```

3. **Check NAT gateway** (for private subnets):
   ```bash
   aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=<vpc-id>"
   ```

4. **Verify route table association**:
   - Ensure subnet is associated with correct route table
   - Check route table has default route (0.0.0.0/0) pointing to IGW or NAT

5. **Restart node** (if route table is correct but node doesn't have route):
   - Routes should be automatically configured by AWS VPC CNI
   - Node restart may restore routes

### If Local Subnet Route is Missing

1. **Check network interface configuration**:
   ```bash
   ip addr show eth0
   ip route show dev eth0
   ```

2. **Verify VPC CNI is running**:
   ```bash
   kubectl get pods -n kube-system | grep aws-node
   ```

3. **Check CNI logs** for route configuration errors:
   ```bash
   kubectl logs -n kube-system -l app=aws-node | grep -i route
   ```

### If Metadata Service Route is Missing

1. **Check if default route exists** (metadata service may use default route):
   - If default route exists, metadata service should be reachable
   - If default route is missing, fix default route first

2. **Verify metadata service accessibility**:
   ```bash
   curl -s http://169.254.169.254/latest/meta-data/instance-id
   ```

3. **Check for explicit metadata route** (usually not needed):
   - Most VPCs use default route for metadata service
   - Explicit route may be needed for custom networking

### If Subnet Routes are Missing

1. **Verify VPC route table** has routes for all subnets:
   ```bash
   aws ec2 describe-route-tables --filters "Name=vpc-id,Values=<vpc-id>"
   ```

2. **Check route table associations**:
   - Ensure all subnets are associated with route tables
   - Verify route table has routes for all subnet CIDRs

3. **Review VPC CNI configuration**:
   - Check if custom networking is enabled
   - Verify ENIConfig resources match subnet CIDRs

### General Route Table Troubleshooting

1. **Compare routes across nodes**:
   - Routes should be consistent across nodes in same subnet
   - Differences may indicate node-specific issues

2. **Check for route conflicts**:
   - Multiple routes for same destination
   - Conflicting route priorities

3. **Verify route propagation**:
   - Routes should be automatically configured by AWS VPC CNI
   - Manual route changes may be overwritten

4. **Review recent changes**:
   - Check CloudTrail for route table modifications
   - Review recent infrastructure changes

5. **Test connectivity**:
   ```bash
   # Test internet connectivity
   ping -c 3 8.8.8.8
   
   # Test VPC connectivity
   ping -c 3 <other-node-ip>
   
   # Test metadata service
   curl -s http://169.254.169.254/latest/meta-data/instance-id
   ```

## Related Files

- `node_*/node_routes_all.txt` - Full route table from `ip route show table all`
- `aws_*/subnets.json` - VPC subnet information with CIDRs
- `node_*/node_arp_table.txt` - ARP table (for route validation)
- `node_*/node_interfaces_state.txt` - Interface states (for route interface validation)

## References

- [AWS VPC Route Tables](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html)
- [AWS VPC CNI Route Management](https://github.com/aws/amazon-vpc-cni-k8s)
- [Linux IP Route](https://man7.org/linux/man-pages/man8/ip-route.8.html)
- [AWS Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)

