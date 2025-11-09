# Socket Overruns

## What We Check

The toolkit monitors socket overruns to detect when the kernel cannot keep up with network traffic, causing packet drops.

**Checks performed:**
- Collects socket statistics from `/proc/net/sockstat` and `/proc/net/snmp`
- Detects socket overruns (packet drops)
- Reports TCP attempt failures
- Monitors socket buffer issues

## Why It Matters

**Socket overruns** indicate:
- **Kernel overload**: Kernel cannot process packets fast enough
- **Packet drops**: Packets are dropped, causing retransmissions
- **Performance degradation**: Network performance suffers
- **Connection failures**: Connections may fail to establish

**Common causes:**
- High network traffic volume
- Small socket buffers
- CPU overload
- Network interface issues
- Application not reading data fast enough

## How We Check It

1. **Socket Statistics**: Reads `/proc/net/sockstat` for socket counts
2. **SNMP Statistics**: Reads `/proc/net/snmp` for TCP/UDP/IP statistics
3. **Overrun Detection**: Identifies TCP attempt failures and other overruns

**Output examples:**
- `[ISSUE] Socket overruns detected on node: TCP AttemptFail: 89`
- `[OK] No socket overruns detected`

## Recommended Actions

### If Socket Overruns Detected

1. **Check socket buffer sizes**:
   ```bash
   # On node, check buffer sizes
   sysctl net.core.rmem_max
   sysctl net.core.wmem_max
   sysctl net.ipv4.tcp_rmem
   sysctl net.ipv4.tcp_wmem
   ```

2. **Increase socket buffers**:
   ```bash
   # Temporary increase
   sysctl -w net.core.rmem_max=16777216
   sysctl -w net.core.wmem_max=16777216
   
   # Permanent increase (in /etc/sysctl.d/99-socket-buffers.conf)
   net.core.rmem_max = 16777216
   net.core.wmem_max = 16777216
   net.ipv4.tcp_rmem = 4096 87380 16777216
   net.ipv4.tcp_wmem = 4096 65536 16777216
   ```

3. **Review network traffic patterns**:
   - Check for traffic spikes
   - Identify high-traffic applications
   - Review network interface utilization

4. **Check CPU usage**:
   ```bash
   # Check if CPU is overloaded
   top
   # High CPU usage can cause socket overruns
   ```

### If TCP AttemptFail High

1. **Review connection patterns**:
   - Check for connection storms
   - Identify applications creating many connections
   - Review connection timeouts

2. **Optimize connection handling**:
   - Use connection pooling
   - Implement connection reuse
   - Reduce connection churn

3. **Check for network issues**:
   - Review network interface errors
   - Check for packet loss
   - Verify network connectivity

## Related Files

- `node_sockstat.txt` - Socket statistics
- `node_sockstat6.txt` - IPv6 socket statistics
- `node_snmp.txt` - SNMP-like network statistics
- `pod_sockstat.txt` - Pod socket statistics
- `pod_snmp.txt` - Pod socket overruns

## References

- [Linux Socket Buffers](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
- [TCP Tuning](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)

