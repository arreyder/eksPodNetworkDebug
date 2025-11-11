# Packet Capture Analysis

## What We Check

The toolkit includes scripts to analyze packet capture files (from `tcpdump` or other packet capture tools) with pod IP mapping to identify communicating pods and traffic patterns.

**Key features:**
- Analyzes packet capture files (text format from `tcpdump` or binary `.pcap` files)
- Maps IP addresses to pod names using diagnostic bundle data
- Identifies source and destination pods
- Analyzes traffic patterns, connection states, and errors
- Provides pod-specific analysis for the target pod

## Why It Matters

Packet capture analysis helps diagnose network connectivity issues by:
- Identifying which pods are communicating
- Detecting connection failures (SYN without ACK, RST packets)
- Analyzing traffic patterns (local vs remote, protocol breakdown)
- Correlating packet-level issues with pod-level diagnostics

## How We Check It

### `sgfp_analyze_pcap.sh` - Basic Packet Capture Analysis

1. **Parse packet capture file** (supports text format from `tcpdump` or binary `.pcap`)
2. **Extract IP addresses** from packets
3. **Map IPs to pods** using `node_pod_ip_map.txt` from diagnostic bundle
4. **Analyze traffic patterns:**
   - Protocol breakdown (TCP, UDP, ICMP, etc.)
   - Top source and destination IPs (with pod mapping)
   - Connection state analysis (SYN, ESTABLISHED, RST, etc.)
   - Error analysis (SYN without ACK, RST packets)
5. **Pod-specific analysis** for the target pod

### `sgfp_analyze_pcap_with_pod_mapping.sh` - Enhanced Analysis

1. **Extract all IP addresses** from packet capture
2. **Map IPs to pod names** using diagnostic bundle
3. **Identify local vs remote traffic:**
   - Local: Same node (using `node_pod_ip_map.txt`)
   - Remote: Cross-node or external
4. **Provide summary:**
   - Communicating pods
   - Local vs remote traffic breakdown
   - Pod-to-pod communication matrix

## Recommended Actions

### If you see connection failures:

1. **Check for SYN without ACK:**
   - Indicates connection attempts that aren't completing
   - May indicate security group blocking, routing issues, or firewall rules

2. **Check for RST packets:**
   - Indicates connections being reset
   - May indicate application-level issues or security group blocking

3. **Check source/destination pods:**
   - Verify pods are on expected nodes
   - Check if traffic is local (same node) or cross-node
   - Cross-node traffic requires proper security group rules

4. **Correlate with diagnostic data:**
   - Check security group rules for cross-node traffic
   - Verify routing tables
   - Check for network policy blocks

### Example: Analyzing packet capture

```bash
# Basic analysis
./sgfp_analyze_pcap.sh capture.txt <bundle-dir>

# Enhanced analysis with pod mapping
./sgfp_analyze_pcap_with_pod_mapping.sh capture.txt <bundle-dir>
```

## Related Files

- `node_pod_ip_map.txt` - Mapping of IPs to pod names (for IP-to-pod mapping)
- `pod_ip.txt` - Target pod IP address
- `pod_conntrack_connections.txt` - Connection tracking data (for comparison)

## References

- [tcpdump Documentation](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Wireshark Documentation](https://www.wireshark.org/docs/)

