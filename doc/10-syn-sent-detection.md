# SYN_SENT Connection Detection

## What We Check

The toolkit detects connections in SYN_SENT state, where a pod has sent a SYN packet but is waiting for an ACK, indicating potential connectivity issues.

**Checks performed:**
- Identifies connections in SYN_SENT state from `/proc/net/tcp` and `ss`/`netstat` output
- Shows destination IPs and ports the pod is trying to connect to
- Identifies whether destinations are VPC/internal or external
- Reports connection attempts that aren't completing

## Why It Matters

**SYN_SENT connections** indicate:
- **Connection attempts failing**: Pod cannot establish connections
- **Firewall/security group blocks**: Traffic blocked before reaching destination
- **Network unreachable**: Destination not reachable
- **Port not listening**: Destination service not running
- **Routing issues**: Traffic not routed correctly

**Common causes:**
- Security group rules blocking traffic
- Network policies blocking egress
- Destination service down
- Network routing issues
- Firewall rules blocking traffic

## How We Check It

1. **Connection Collection**: Gathers connections from pod using:
   - `ss` command (preferred)
   - `netstat` command (fallback)
   - `/proc/net/tcp` (raw parsing, fallback)

2. **State Detection**: Identifies SYN_SENT state:
   - State code `02` in `/proc/net/tcp`
   - "SYN-SENT" or "SYN_SENT" in `ss`/`netstat` output

3. **Destination Analysis**: Identifies destination type:
   - VPC/internal (private IP ranges)
   - External (public IPs)

**Output examples:**
- `[ISSUE] Found 3 connection(s) in SYN_SENT state (pod sending SYN but waiting for ACK - potential connectivity issue)`
- `[INFO] Destinations: 10.4.100.50:443 (VPC/internal), 52.94.10.112:443 (external)`

## Recommended Actions

### If SYN_SENT Connections Detected

1. **Identify blocked destinations**:
   - Review the destination IPs and ports in the report
   - Determine what services these destinations provide

2. **Check Security Group rules**:
   ```bash
   # Check pod's Security Groups
   aws ec2 describe-network-interfaces \
     --network-interface-ids <pod-eni-id> \
     --query 'NetworkInterfaces[0].Groups'
   
   # Check SG egress rules
   aws ec2 describe-security-groups \
     --group-ids <sg-id> \
     --query 'SecurityGroups[0].IpPermissionsEgress'
   ```

3. **Verify destination is reachable**:
   ```bash
   # From pod, test connectivity
   kubectl exec <pod-name> -n <namespace> -- ping <destination-ip>
   kubectl exec <pod-name> -n <namespace> -- telnet <destination-ip> <port>
   ```

4. **Check Network Policies**:
   ```bash
   # Check if NetworkPolicies block egress
   kubectl get networkpolicies -n <namespace>
   kubectl describe networkpolicy <policy-name> -n <namespace>
   ```

5. **Verify destination service**:
   - Check if destination service is running
   - Verify destination port is listening
   - Test connectivity from other pods/nodes

### For VPC/Internal Destinations

1. **Check VPC routing**:
   ```bash
   # On node, check routes
   ip route show
   ip route get <destination-ip>
   ```

2. **Verify subnet configuration**:
   - Check if destination is in same VPC
   - Verify route tables are correct
   - Check for NACL rules blocking traffic

3. **Check destination Security Groups**:
   - Verify destination allows traffic from pod's SGs
   - Check destination SG ingress rules

### For External Destinations

1. **Check NAT Gateway**:
   - Verify NAT gateway is configured
   - Check NAT gateway route table
   - Verify NAT gateway is healthy

2. **Check Internet Gateway**:
   - Verify IGW is attached to VPC
   - Check route tables for 0.0.0.0/0 → IGW

3. **Verify egress rules**:
   - Check pod SG allows egress to 0.0.0.0/0
   - Verify no NetworkPolicies block egress

## Related Files

- `pod_connections.txt` - Pod network connections (including SYN_SENT)
- `pod_conntrack_connections.txt` - Conntrack connections filtered by pod IP

## References

- [TCP Connection States](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_states)
- [Linux /proc/net/tcp](https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt)

