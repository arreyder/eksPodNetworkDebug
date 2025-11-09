# Network Interface States

## What We Check

The toolkit validates network interface states to ensure all interfaces are in expected states (UP) and functioning correctly.

**Checks performed:**
- Collects state of all network interfaces
- Identifies interfaces in unexpected DOWN state
- Reports interface state issues

## Why It Matters

**Interface state issues** cause:
- **Connectivity failures**: DOWN interfaces cannot send/receive traffic
- **Pod networking failures**: Pod interfaces must be UP
- **ENI attachment issues**: ENIs must be in correct state
- **Routing problems**: DOWN interfaces break routing

**Common causes:**
- Interface configuration errors
- Driver issues
- ENI attachment failures
- Network interface errors

## How We Check It

1. **Interface Collection**: Collects all interfaces using `ip link show`
2. **State Validation**: Checks interface state (UP/DOWN)
3. **Issue Detection**: Flags interfaces in unexpected DOWN state

**Output examples:**
- `[OK] No interfaces in unexpected DOWN state`
- `[ISSUE] Interface eth1 is DOWN (expected UP)`

## Recommended Actions

### If Interface in DOWN State

1. **Check interface status**:
   ```bash
   # On node, check interface
   ip link show <interface>
   ip addr show <interface>
   ```

2. **Bring interface UP**:
   ```bash
   # Bring interface up
   ip link set <interface> up
   ```

3. **Check for errors**:
   ```bash
   # Check interface errors
   ip -s link show <interface>
   # Look for errors, drops, etc.
   ```

4. **Review interface configuration**:
   - Check if interface has IP address
   - Verify interface is configured correctly
   - Check for driver issues

### If Pod Interface DOWN

1. **Check pod network setup**:
   ```bash
   kubectl describe pod <pod-name> -n <namespace>
   ```

2. **Review CNI logs**:
   ```bash
   # Check for interface setup errors
   grep -i "interface\|link\|up\|down" <bundle>/node_*/cni_logs/plugin.log
   ```

3. **Verify ENI attachment**:
   - Check ENI is attached
   - Verify ENI is in-use
   - Review ENI attachment logs

## Related Files

- `node_interfaces_state.txt` - All interface states
- `node_interface_ip_stats.txt` - Interface statistics with state

## References

- [Linux Network Interfaces](https://www.kernel.org/doc/Documentation/networking/)

