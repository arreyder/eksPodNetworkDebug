# Network Traffic Capture

## What We Check

The `sgfp_pod_tcpdump.sh` script automates capturing network traffic from a pod's network namespace using `tcpdump`.

**Key features:**
- Finds the node where the pod is running
- Creates a debug pod on the same node with `sysadmin` profile
- Extracts network namespace name from diagnostic reports (if available)
- Provides instructions for running tcpdump in the pod's network namespace
- Automatically installs tcpdump if needed

## Why It Matters

Capturing network traffic from a pod's network namespace helps diagnose:
- Connection failures (SYN without ACK)
- Connection resets (RST packets)
- Traffic patterns (what's communicating with the pod)
- Protocol-level issues
- Security group blocking (packets being dropped)

## How We Check It

1. **Find the pod's node** using `kubectl`
2. **Create debug pod** on the same node using `kubectl debug` with `sysadmin` profile
3. **Extract network namespace name** from diagnostic reports:
   - Uses `node_netns_details.json` to find namespace by pod IP
   - Falls back to manual instructions if not found
4. **Provide tcpdump commands:**
   - Option 1: Capture from within pod's network namespace (recommended)
   - Option 2: Capture on veth interface from host namespace
5. **Auto-install tcpdump** if needed (using `yum`, `apt-get`, or `apk`)

## Usage

### Basic capture (port 6000):
```bash
./sgfp_pod_tcpdump.sh be-conductor default
```

### Custom tcpdump arguments:
```bash
./sgfp_pod_tcpdump.sh be-conductor default "-i any -n -v port 6000"
```

### Capture all traffic:
```bash
./sgfp_pod_tcpdump.sh be-conductor default "-i any -n -v"
```

### Using Make:
```bash
make pod-tcpdump POD=be-conductor NS=default
make pod-tcpdump POD=be-conductor NS=default ARGS="-i any -n -v port 6000"
```

## Recommended Actions

### If you need to capture traffic:

1. **Run diagnostics first:**
   ```bash
   ./sgfp_doctor.sh be-conductor -n default
   ```
   This will output the tcpdump command at the end.

2. **Use the provided command:**
   ```bash
   ./sgfp_pod_tcpdump.sh be-conductor default
   ```

3. **Follow the instructions:**
   - The script will create a debug pod
   - Enter the host namespace: `nsenter --target 1 --mount --uts --ipc --net --pid sh`
   - Install tcpdump if needed: `yum install -y tcpdump` (or `apt-get`/`apk`)
   - Run tcpdump in the pod's network namespace: `ip netns exec <namespace> tcpdump <args>`

4. **Save the capture:**
   ```bash
   # From within the debug pod
   ip netns exec <namespace> tcpdump -i any -n -v -w /tmp/capture.pcap
   
   # Copy from debug pod
   kubectl cp <debug-pod>:/tmp/capture.pcap ./capture.pcap
   ```

5. **Analyze the capture:**
   ```bash
   # Convert to text format
   tcpdump -r capture.pcap > capture.txt
   
   # Analyze with diagnostic bundle
   ./sgfp_analyze_pcap.sh capture.txt <bundle-dir>
   ```

## Related Files

- `node_netns_details.json` - Network namespace details (for finding namespace by pod IP)
- `pod_ip.txt` - Pod IP address
- `pod_veth_interface.txt` - Veth interface name (for host namespace capture)

## References

- [tcpdump Documentation](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [kubectl debug Documentation](https://kubernetes.io/docs/reference/kubectl/kubectl-debug/)
- [nsenter Documentation](https://man7.org/linux/man-pages/man1/nsenter.1.html)

