# IP Address Conflicts

## What We Check

The toolkit detects duplicate IP addresses on the node, which can cause networking issues and connectivity problems.

**Checks performed:**
- Collects all IP addresses assigned to node interfaces
- Identifies duplicate IP addresses
- Reports conflicts with interface details

## Why It Matters

**IP address conflicts** can cause:
- **Connectivity failures**: Traffic routed to wrong interface
- **ARP conflicts**: Multiple interfaces respond to ARP requests
- **Routing issues**: Kernel routing confused by duplicate IPs
- **Service failures**: Services may bind to wrong interface
- **Security issues**: Traffic may be intercepted by wrong interface

**Common causes:**
- Manual IP assignment conflicts with CNI
- CNI plugin bugs assigning duplicate IPs
- Interface configuration errors
- Multiple CNI plugins conflicting
- ENI attachment issues

## How We Check It

1. **IP Collection**: Collects all IP addresses from all interfaces using `ip addr`
2. **Duplicate Detection**: Identifies IPs that appear on multiple interfaces
3. **Conflict Reporting**: Lists duplicate IPs with interface details

**Output examples:**
- `[OK] No IP address conflicts detected`
- `[ISSUE] Found duplicate IP address: 10.4.198.175 on interfaces eth0, veth12345`

## Recommended Actions

### If IP Conflicts Detected

1. **Identify conflicting interfaces**:
   ```bash
   # On node, check all IP addresses
   ip addr show
   
   # Find specific IP
   ip addr show | grep <conflicting-ip>
   ```

2. **Determine which interface should have the IP**:
   - Check CNI configuration for expected IP
   - Review pod ENI assignment
   - Verify trunk/branch ENI configuration

3. **Remove IP from wrong interface**:
   ```bash
   # WARNING: Only if you're certain which interface is wrong
   ip addr del <ip>/<prefix> dev <wrong-interface>
   ```

4. **Investigate root cause**:
   - Review CNI logs for IP assignment errors
   - Check if CNI plugin has bugs
   - Verify no manual IP configuration conflicts

### Preventing Conflicts

1. **Avoid manual IP configuration**:
   - Let CNI plugin manage all IP assignments
   - Don't manually configure IPs on interfaces

2. **Monitor CNI plugin**:
   - Check CNI logs for IP assignment errors
   - Verify CNI plugin is healthy

3. **Review CNI configuration**:
   - Ensure CNI configuration is correct
   - Check for conflicting CNI plugins

## Related Files

- `node_all_ips.txt` - All IP addresses on node
- `node_duplicate_ips.txt` - Duplicate IP addresses (if any)

## References

- [Linux IP Address Management](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)

