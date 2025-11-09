# kube-proxy iptables Analysis

## What We Check

The toolkit validates kube-proxy configuration and iptables rules to ensure Kubernetes service networking is functioning correctly.

**Checks performed:**
- Detects kube-proxy mode (iptables vs IPVS)
- Validates kube-proxy chains exist (KUBE-SERVICES, KUBE-NODEPORTS, KUBE-MARK-MASQ)
- Checks if chains are active (processing traffic)
- Verifies masquerade rules are present
- Identifies pod-specific service rules

## Why It Matters

**kube-proxy** is responsible for:
- **Service IP routing**: Routes ClusterIP traffic to pod endpoints
- **Load balancing**: Distributes traffic across service endpoints
- **NAT/Masquerade**: Translates service IPs to pod IPs
- **NodePort services**: Exposes services on node ports

**Common issues:**
- kube-proxy not running or crashed
- iptables rules missing or corrupted
- Masquerade rules missing (service traffic fails)
- IPVS mode misconfiguration
- Service rules not created for pods

## How We Check It

1. **Mode Detection**: Searches for kube-proxy chains:
   - `KUBE-IPVS` chains → IPVS mode
   - `KUBE-SERVICES` chains → iptables mode

2. **Chain Validation**: Checks for required chains:
   - `KUBE-SERVICES` (in both filter and NAT tables)
   - `KUBE-NODEPORTS` (for NodePort services)
   - `KUBE-MARK-MASQ` (for masquerading)

3. **Activity Check**: Validates chains are processing traffic:
   - Checks packet counts in iptables rules
   - Warns if chains have zero packet counts

4. **Masquerade Rules**: Searches for masquerade rules:
   - `MASQUERADE` target
   - `KUBE-MARK-MASQ` references

5. **Pod Service Rules**: Searches for rules matching pod IP:
   - DNAT rules for service endpoints
   - Service endpoint rules (KUBE-SEP-*)

**Output examples:**
- `[OK] kube-proxy mode: iptables`
- `[OK] KUBE-SERVICES chain active (2 rule(s) with traffic, sample: 2675K packets)`
- `[OK] Found 3 iptables rule(s) for pod IP 10.4.198.175 (service rules present)`
- `[WARN] KUBE-SERVICES chain has no packet counts (kube-proxy may not be processing traffic)`

## Recommended Actions

### If kube-proxy Chains Not Found

1. **Check kube-proxy pod status**:
   ```bash
   kubectl get pods -n kube-system | grep kube-proxy
   kubectl logs -n kube-system <kube-proxy-pod>
   ```

2. **Verify kube-proxy is running**:
   ```bash
   # Check if kube-proxy daemonset is running
   kubectl get daemonset -n kube-system kube-proxy
   ```

3. **Restart kube-proxy if needed**:
   ```bash
   kubectl rollout restart daemonset/kube-proxy -n kube-system
   ```

### If Chains Have No Packet Counts

1. **Verify kube-proxy is processing traffic**:
   - Check kube-proxy logs for errors
   - Verify kube-proxy has correct permissions

2. **Check iptables rules are being created**:
   ```bash
   # On node, check if rules are being updated
   iptables -t nat -L KUBE-SERVICES -v -n
   ```

3. **Verify service endpoints exist**:
   ```bash
   kubectl get endpoints <service-name> -n <namespace>
   ```

### If Masquerade Rules Missing

1. **Check kube-proxy configuration**:
   - Verify `--masquerade-all` or masquerade settings
   - Check kube-proxy ConfigMap

2. **Verify iptables modules are loaded**:
   ```bash
   lsmod | grep iptable
   ```

### If Pod Service Rules Not Found

1. **Verify pod is part of a service**:
   ```bash
   kubectl get svc -A -o wide | grep <pod-ip>
   ```

2. **Check service selectors match pod labels**:
   ```bash
   kubectl get svc <service-name> -n <namespace> -o yaml
   kubectl get pod <pod-name> -n <namespace> --show-labels
   ```

3. **Verify service endpoints include pod**:
   ```bash
   kubectl get endpoints <service-name> -n <namespace>
   ```

## Related Files

- `node_iptables_filter.txt` - iptables filter table rules
- `node_iptables_nat.txt` - iptables NAT table rules

## References

- [kube-proxy Modes](https://kubernetes.io/docs/concepts/services-networking/service/#proxy-mode-ipvs)
- [iptables Mode](https://kubernetes.io/docs/concepts/services-networking/service/#proxy-mode-iptables)
- [Troubleshooting kube-proxy](https://kubernetes.io/docs/tasks/debug/debug-cluster/troubleshoot/)

