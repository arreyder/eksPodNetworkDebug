# MTU Configuration Analysis

## What We Check

The toolkit analyzes Maximum Transmission Unit (MTU) configuration across network interfaces to detect mismatches and fragmentation issues.

**Checks performed:**
- Extracts MTU values from all non-loopback node interfaces
- Compares pod interface MTU with node interface MTU
- Detects multiple MTU values on non-loopback interfaces
- Checks kernel logs for fragmentation-related messages
- Identifies standard (1500) vs jumbo frame (9001) configurations

## Why It Matters

**MTU mismatches** can cause:
- **Fragmentation**: Large packets get fragmented, increasing overhead and latency
- **Packet drops**: Some networks drop fragmented packets, causing connection failures
- **Performance degradation**: Fragmentation adds CPU overhead and reduces throughput
- **gRPC/HTTP2 failures**: These protocols use large frames that fail if MTU is too small

**Common scenarios:**
- Pod ENI with different MTU than node interface
- Jumbo frames (9001) enabled on some interfaces but not others
- VPC with jumbo frames but pods configured for standard MTU (1500)
- Cross-AZ traffic where MTU differs between subnets

## How We Check It

1. **Node Interface MTU**: Extracts MTU from `ip -s link` output (excluding loopback)
2. **Pod Interface MTU**: Extracts MTU from pod's interface statistics
3. **Comparison**: Compares pod MTU with node MTU and flags mismatches
4. **Kernel Logs**: Searches `dmesg` for fragmentation-related messages:
   - "fragmentation needed"
   - "frag.*drop"
   - "mtu.*exceed"

**Output examples:**
- `[OK] Standard MTU (1500) on all non-loopback interfaces`
- `[ISSUE] MTU mismatch: pod (9001) != node (1500) - may cause fragmentation`
- `[WARN] Multiple MTU values found on node interfaces: 1500,9001`

## Recommended Actions

### If MTU Mismatch Detected

1. **Verify VPC MTU settings**:
   ```bash
   # Check if VPC supports jumbo frames
   aws ec2 describe-vpcs --vpc-ids <vpc-id> --query 'Vpcs[0].Tags'
   ```

2. **Check AWS VPC CNI configuration**:
   - Review CNI configuration for MTU settings
   - Ensure CNI MTU matches VPC MTU capability

3. **Align MTU values**:
   - If using jumbo frames: Ensure all interfaces (node, pod, VPC) use 9001
   - If using standard: Ensure all interfaces use 1500
   - Update CNI configuration if needed

4. **Test connectivity**:
   ```bash
   # From pod, test with different packet sizes
   ping -M do -s 1472 <destination>  # Standard MTU (1500 - 28)
   ping -M do -s 8972 <destination> # Jumbo frames (9001 - 28)
   ```

### If Multiple MTU Values Found

1. **Identify which interfaces have different MTUs**:
   - Review the interface breakdown in the report
   - Check if veth interfaces have different MTU than physical interfaces

2. **Standardize MTU**:
   - Configure all non-loopback interfaces to use the same MTU
   - Update CNI configuration to match

### If Fragmentation Messages in Kernel Logs

1. **Review fragmentation hints**:
   - Check the specific messages in `node_dmesg_network.txt`
   - Identify which interfaces are experiencing fragmentation

2. **Adjust MTU or packet sizes**:
   - Reduce application packet sizes if MTU cannot be increased
   - Increase MTU if VPC and all interfaces support it

## Related Files

- `node_interface_ip_stats.txt` - Node interface statistics with MTU
- `pod_interface_stats.txt` - Pod interface statistics with MTU
- `node_dmesg_network.txt` - Kernel messages including fragmentation hints

## References

- [AWS VPC Jumbo Frames](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/network_mtu.html)
- [AWS VPC CNI MTU Configuration](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/configuration.md)

