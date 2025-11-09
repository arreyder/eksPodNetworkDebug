# Reverse Path Filtering (rp_filter)

## What We Check

The toolkit validates reverse path filtering (rp_filter) settings to ensure proper routing behavior, especially for pod ENI scenarios with asymmetric routing.

**Checks performed:**
- Collects rp_filter values for all network interfaces
- Validates rp_filter settings for pod ENI scenarios
- Flags security risks (rp_filter=0 disabled)
- Recommends appropriate settings based on pod ENI usage

## Why It Matters

**Reverse path filtering** controls source address validation:
- **rp_filter=0**: No source validation (disabled) - **Security risk** (allows spoofing)
- **rp_filter=1**: Strict mode (RFC 3704) - Validates return path matches forward path
- **rp_filter=2**: Loose mode - Validates return path exists (allows asymmetric routing)

**For pod ENI scenarios:**
- Pod ENIs use **asymmetric routing** (traffic may take different paths)
- Strict mode (rp_filter=1) **blocks** asymmetric routing
- Loose mode (rp_filter=2) **allows** asymmetric routing while maintaining security
- **Required** for pod ENI to work correctly

**Common issues:**
- rp_filter=1 blocks pod ENI traffic (asymmetric routing)
- rp_filter=0 creates security vulnerability (source spoofing)
- Inconsistent rp_filter settings across interfaces

## How We Check It

1. **Collection**: Reads `/proc/sys/net/ipv4/conf/*/rp_filter` for all interfaces
2. **Pod ENI Detection**: Checks if pod uses pod ENI (branch ENI)
3. **Validation**:
   - For pod ENI: Recommends rp_filter=2 (loose mode)
   - Flags rp_filter=1 as issue for pod ENI
   - Warns about rp_filter=0 (security risk)
4. **Reporting**: Shows which interfaces have which settings

**Output examples:**
- `[OK] Found 4 interface(s) with rp_filter=2 (loose mode) - appropriate for pod ENI`
- `[ISSUE] Found 4 interface(s) with rp_filter=0 (disabled) - security risk AND may cause asymmetric routing issues with pod ENI`
- `[INFO] Recommendation: Set rp_filter=2 (loose mode) for pod ENI scenarios`

## Recommended Actions

### If rp_filter=1 (Strict Mode) with Pod ENI

**This will block pod ENI traffic!** Fix immediately:

1. **Set rp_filter=2 (loose mode) for all interfaces**:
   ```bash
   # On node, set for all interfaces
   for iface in $(ls /proc/sys/net/ipv4/conf/); do
     echo 2 > /proc/sys/net/ipv4/conf/$iface/rp_filter
   done
   ```

2. **Make it persistent** (via systemd or init script):
   ```bash
   # Add to /etc/sysctl.d/99-pod-eni.conf
   net.ipv4.conf.all.rp_filter = 2
   net.ipv4.conf.default.rp_filter = 2
   ```

3. **Verify the change**:
   ```bash
   sysctl -a | grep rp_filter
   ```

### If rp_filter=0 (Disabled)

**Security risk!** Fix immediately:

1. **Set rp_filter=2 (loose mode)**:
   ```bash
   # For pod ENI scenarios
   for iface in $(ls /proc/sys/net/ipv4/conf/); do
     echo 2 > /proc/sys/net/ipv4/conf/$iface/rp_filter
   done
   ```

2. **For non-pod ENI scenarios**, use rp_filter=1:
   ```bash
   # Standard networking (no pod ENI)
   for iface in $(ls /proc/sys/net/ipv4/conf/); do
     echo 1 > /proc/sys/net/ipv4/conf/$iface/rp_filter
   done
   ```

### Making Changes Persistent

**Option 1: sysctl configuration** (recommended):
```bash
# Create /etc/sysctl.d/99-pod-eni.conf
cat > /etc/sysctl.d/99-pod-eni.conf <<EOF
# Allow asymmetric routing for pod ENI
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF

# Apply immediately
sysctl -p /etc/sysctl.d/99-pod-eni.conf
```

**Option 2: EKS node user-data**:
```bash
# Add to node user-data script
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf.default.rp_filter=2
```

**Option 3: DaemonSet** (if you can't modify node configuration):
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: rp-filter-fix
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: fix
        image: busybox
        command: ["sh", "-c", "echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter && sleep infinity"]
        securityContext:
          privileged: true
```

## Related Files

- `node_rp_filter.txt` - rp_filter settings per interface

## References

- [RFC 3704 - Ingress Filtering](https://tools.ietf.org/html/rfc3704)
- [AWS VPC CNI Pod ENI Requirements](https://github.com/aws/amazon-vpc-cni-k8s)
- [Linux rp_filter Documentation](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)

