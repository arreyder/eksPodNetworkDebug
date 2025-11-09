# Conntrack Usage

## What We Check

The toolkit monitors connection tracking (conntrack) usage to detect exhaustion that can cause DNS failures and sporadic network drops.

**Checks performed:**
- Collects conntrack count and maximum
- Calculates usage percentage
- Reports when approaching limits
- Collects full conntrack table for analysis

## Why It Matters

**Conntrack exhaustion** causes:
- **DNS failures**: DNS queries fail when conntrack is full
- **Sporadic network drops**: New connections cannot be tracked
- **Connection failures**: TCP connections fail to establish
- **Performance degradation**: Kernel struggles with full conntrack table

**Common causes:**
- Too many short-lived connections
- Connection leaks (connections not closed)
- High connection churn
- Conntrack table too small
- DDoS attacks

## How We Check It

1. **Conntrack Count**: Reads `/proc/sys/net/netfilter/nf_conntrack_count`
2. **Conntrack Max**: Reads `/proc/sys/net/netfilter/nf_conntrack_max`
3. **Usage Calculation**: Calculates percentage used
4. **Table Collection**: Collects full conntrack table for analysis

**Output examples:**
- `[OK] Conntrack usage: 621 / 262144 (~0%)`
- `[WARN] Conntrack usage high: 85%`
- `[ISSUE] Conntrack exhausted: 262144 / 262144 (100%)`

## Recommended Actions

### If Conntrack Usage High

1. **Check current usage**:
   ```bash
   # On node, check conntrack usage
   cat /proc/sys/net/netfilter/nf_conntrack_count
   cat /proc/sys/net/netfilter/nf_conntrack_max
   ```

2. **Identify connection patterns**:
   ```bash
   # Review conntrack table
   conntrack -L | head -100
   
   # Count by state
   conntrack -L | awk '{print $1}' | sort | uniq -c
   ```

3. **Increase conntrack size**:
   ```bash
   # Temporary increase
   sysctl -w net.netfilter.nf_conntrack_max=524288
   
   # Permanent increase (in /etc/sysctl.d/99-conntrack.conf)
   net.netfilter.nf_conntrack_max = 524288
   ```

4. **Reduce connection churn**:
   - Implement connection pooling
   - Reuse connections (HTTP keep-alive)
   - Close connections properly
   - Use connection timeouts

### If Conntrack Exhausted

1. **Immediate fix** (increase size):
   ```bash
   # Double the size
   sysctl -w net.netfilter.nf_conntrack_max=524288
   ```

2. **Review connection patterns**:
   - Check for connection leaks
   - Identify high connection churn applications
   - Review connection timeouts

3. **Optimize applications**:
   - Use connection pooling
   - Implement connection reuse
   - Reduce short-lived connections

### Preventing Exhaustion

1. **Set appropriate conntrack size**:
   - Base on expected connection count
   - Add 20-30% buffer
   - Monitor usage over time

2. **Monitor conntrack usage**:
   - Set up alerts for high usage
   - Track usage trends

3. **Optimize connection patterns**:
   - Use connection pooling
   - Implement connection reuse
   - Close connections properly

## Related Files

- `node_conntrack_mtu.txt` - Conntrack count and max
- `node_conntrack_table.txt` - Full conntrack table
- `pod_conntrack_connections.txt` - Conntrack connections filtered by pod IP

## References

- [Linux Conntrack](https://www.kernel.org/doc/Documentation/networking/nf_conntrack-sysctl.txt)
- [Conntrack Tuning](https://wiki.debian.org/nftables#Conntrack_tuning)

