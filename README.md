
# SG-for-Pods / AWS VPC CNI Diagnostics Toolkit (Linux)

This toolkit collects comprehensive diagnostics for AWS EKS pods using Security Groups for Pods (SGFP). It gathers **pod**, **node**, and **AWS ENI** data into a single bundle, optionally pulls **CloudTrail ENI API** activity (for throttles/errors), and generates a **markdown report** plus a **post-analyzer** summary.

## Features

- **Comprehensive Pod Diagnostics**: Collects pod annotations, conditions, network namespace routes/rules, interface statistics, socket statistics, and reachability tests
- **Security Group Validation**: Automatically validates actual SGs on pod ENI against expected SGs from pod, deployment, replicaset, or namespace annotations
- **SG Details**: Shows Security Group IDs, names, and descriptions for easy identification
- **Node Diagnostics**: Collects conntrack usage, interface error statistics, socket overruns, and AWS VPC CNI logs (automatically via temporary debug pod)
- **CNI Log Analysis**: Automatically collects and analyzes CNI logs from `/var/log/aws-routed-eni/` including ipamd, plugin, network-policy-agent, and eBPF SDK logs
- **Connectivity Analysis**: Advanced analysis for pod connectivity issues after large churns, including ENI attachment timing, subnet IP availability, and CNI log errors
- **AWS ENI State**: Captures trunk and branch ENI information, subnet IP availability
- **API Diagnostics**: Analyzes CloudTrail events for ENI-related throttles and errors (with dry-run detection)
- **Log Files Summary**: Report includes concise summary of all log files with error counts and file paths
- **View Related Logs Helper**: Helper script to easily view pod-specific log lines from collected bundles
- **Node Debug Pod**: Helper script to create debug pods on nodes (supports pod name or node name)
- **All-in-One Doctor Script**: Single command to collect, analyze, and report
- **Consistent Output Format**: Uses `[PREFIX]` format for clear, parseable output

## Requirements

- Linux
- `kubectl`, `jq`, `awk`, `grep`
- `aws` CLI configured (and `AWS_REGION` set, e.g., `export AWS_REGION=us-west-2`)
- Permissions: `ec2:DescribeNetworkInterfaces`, optionally CloudTrail `lookup-events`

## Quick Start

### Option 1: All-in-One (Recommended)

```bash
export AWS_REGION=us-west-2

# Run everything: collect, API diag, report, analyze, and display
./sgfp_doctor.sh <pod-name> -n default --minutes 60
```

### Option 2: Step-by-Step

```bash
export AWS_REGION=us-west-2

# 1) Collect a bundle for a pod (namespace default)
./sgfp_collect.sh -n default <pod-name>

# 2) (Optional) CloudTrail ENI API diagnostics for last 60 minutes
WINDOW_MINUTES=60 ./sgfp_api_diag.sh

# 3) Generate a report for the bundle
B=$(ls -dt sgfp_bundle_<pod-name>_* | head -1)
./sgfp_report.sh "$B"

# 4) Post analyze the bundle
./sgfp_post_analyze.sh "$B"
```

### Using Make Targets

```bash
# All-in-one
make doctor POD=<pod> NS=default

# Or step-by-step
make collect POD=<pod> NS=default
make api WINDOW_MINUTES=60
make report BUNDLE=<dir>
make analyze BUNDLE=<dir>

# Clean up all diagnostic output directories
make clean
```

## What gets collected

Bundle structure (example):

```
sgfp_bundle_<pod>_<timestamp>/
  pod_<pod>/
    pod_annotations.json
    pod_conditions.json
    pod_ip.txt
    node_name.txt
    pod_netns_routes_rules.txt
    pod_reachability.txt
    pod_veth_interface.txt                 # veth interface name
    pod_interface_stats.txt                # Interface statistics with errors
    pod_sockstat.txt                       # Pod socket statistics
    pod_sockstat6.txt                      # Pod IPv6 socket statistics
    pod_snmp.txt                           # Pod socket overruns
    pod_timing.txt                         # Pod creation/start timestamps
    pod_events.txt                         # Pod events
    pod_full.json                          # Full pod JSON
    pod_container_statuses.json            # Container statuses
    pod_connections.txt                     # Pod network connections (listening ports and established)
    pod_conntrack_connections.txt          # Conntrack connections filtered by pod IP
    ipamd_introspection.json               # IPAMD introspection data
    ipamd_pool.json                        # IPAMD pool state
    ipamd_networkutils.json                # IPAMD network utils config
    aws_node_errors.log                    # Filtered aws-node errors
    pod_branch_eni_id.txt
    pod_branch_eni_describe.json
    pod_branch_eni_sgs.txt              # Actual SGs on pod ENI
    pod_branch_eni_sgs_details.json     # SG IDs, names, descriptions
    pod_parent_trunk_eni.txt
    pod_expected_sgs.txt                 # Expected SGs from pod annotation
    deployment_expected_sgs.txt          # Expected SGs from deployment annotation
    replicaset_expected_sgs.txt          # Expected SGs from replicaset annotation
    namespace_expected_sgs.txt           # Expected SGs from namespace annotation
    deployment_annotations.json
    replicaset_annotations.json
    namespace_annotations.json
    aws_node_full.log
  node_<node>/
    node_conntrack_mtu.txt
    node_conntrack_table.txt              # Full conntrack table (for connection analysis)
    node_pod_ips.txt                      # All pod IPs on this node (for same-node identification)
    aws_node_full.log
    node_interface_dev_stats.txt          # Interface error statistics
    node_interface_ip_stats.txt            # ip -s link statistics
    node_sockstat.txt                      # Socket statistics
    node_sockstat6.txt                     # IPv6 socket statistics
    node_snmp.txt                          # Socket overruns
    node_netns_count.txt                   # Network namespace count
    node_netns_list.txt                    # List of network namespaces
    node_netns_details.json                # Network namespace details (interfaces, IPs, timing)
    node_interfaces_state.txt              # All interface states
    node_all_ips.txt                       # All IP addresses on node
    node_duplicate_ips.txt                 # Duplicate IP addresses (if any)
    node_dns_tests.txt                     # DNS resolution tests
    node_file_descriptors.txt              # File descriptor usage
    node_memory_info.txt                   # Memory information
    node_k8s_networkpolicies.json          # Kubernetes NetworkPolicies
    node_calico_networkpolicies.yaml       # Calico network policies (if Calico)
    node_bpf_programs.txt                  # eBPF programs (if Cilium)
    node_dmesg_network.txt                 # Network-related kernel messages
    node_arp_table.txt                     # ARP table
    node_iptables_filter.txt               # iptables filter rules
    node_iptables_nat.txt                  # iptables NAT rules
    node_routes_all.txt                    # Route table (all tables)
    node_veth_interfaces.txt               # veth interfaces
    node_syslog_network.txt                # Network-related syslog entries
    cni_logs/                              # AWS VPC CNI logs
      ipamd.log
      plugin.log
      network-policy-agent.log
      ebpf-sdk.log
      egress-v6-plugin.log
      ipamd-latest-rotated.log
      *.errors                              # Error summaries for each log
  aws_<node>/
    vpc_id.txt
    node_instance_id.txt
    trunk_eni_id.txt
    trunk_eni.json
    all_instance_enis.json
    _all_branch_enis_in_vpc.json         # best-effort, may be empty
    subnets.json                          # Subnet IP availability
  report.md                              # generated by sgfp_report.sh
```

CloudTrail API diag folder:

```
sgfp_api_diag_<timestamp>/
  events_eni.json
  flat_events.json
  eni_errors.tsv                        # Real errors/throttles (excludes dry-runs)
  eni_dryruns.tsv                        # Dry-run operations (informational)
  eni_all_issues.tsv                     # All events with error codes
  error_codes_summary.txt                # Summary of all error codes
  throttle_by_action.txt
  throttle_by_caller.txt
  calls_by_user.txt                       # API calls by user/caller ARN
  top_api_calls.txt
```

## Scripts

### `sgfp_doctor.sh` - All-in-One Orchestrator
Runs all diagnostics in sequence: collect → API diag → report → analyze → display report.

```bash
./sgfp_doctor.sh <pod> -n <namespace> [--minutes N] [--days D] [--region R] [--skip-api] [--api-dir DIR]
```

### `sgfp_collect.sh` - Collection Orchestrator
Collects pod, node, and AWS diagnostics into a bundle.

```bash
./sgfp_collect.sh -n <namespace> <pod-name>
```

**Features:**
- Automatically detects available shell in pod (`sh`, `/bin/sh`, `/bin/bash`, `bash`)
- Gracefully handles missing network tools (`ip`, `ping`)
- Collects Security Groups from pod ENI via AWS API
- Collects expected SGs from pod, deployment, replicaset, and namespace annotations
- Traverses Kubernetes owner references (Pod → ReplicaSet → Deployment)

### `sgfp_pod_diag.sh` - Pod Diagnostics
Collects pod-specific information including annotations, conditions, network namespace routes/rules.

### `sgfp_node_diag.sh` - Node Diagnostics
Collects node-level diagnostics: conntrack usage, interface error statistics, socket overruns, and AWS VPC CNI logs.

**Features:**
- **Automatic CNI Log Collection**: Collects CNI logs from `/var/log/aws-routed-eni/` via temporary debug pod when not running on node (pod is automatically cleaned up)
- **Conntrack Collection**: Collects full conntrack table via temporary pod if needed (for connection analysis)
- **Pod IP Collection**: Collects all pod IPs on the node (for same-node vs cross-node connection identification)
- Collects interface error statistics from `/proc/net/dev` and `ip -s link`
- Collects socket statistics including overruns from `/proc/net/sockstat` and `/proc/net/snmp`
- Creates error summaries for each CNI log file
- Analyzes network namespaces for leaks (orphaned namespaces with no interfaces, only flags as issue if older than 1 hour)
- Detects IP address conflicts (duplicate IPs on node)
- Tests DNS resolution (Kubernetes DNS, metadata service)
- Checks for resource exhaustion (file descriptors, memory pressure)
- Collects network policy rules (Kubernetes and CNI-specific: Calico, Cilium)
- Checks network interface states (interfaces in unexpected DOWN state)
- Collects kernel logs (dmesg), ARP table, iptables rules (filter and NAT), and route tables (all tables)

### `sgfp_aws_diag.sh` - AWS ENI Diagnostics
Collects AWS ENI information: instance ID, VPC ID, trunk ENI, branch ENIs.

### `sgfp_api_diag.sh` - CloudTrail API Diagnostics
Analyzes CloudTrail events for ENI-related API calls, throttles, and errors.

```bash
WINDOW_MINUTES=60 ./sgfp_api_diag.sh
```

**Features:**
- Distinguishes real errors/throttles from dry-run operations
- Categorizes events: `eni_errors.tsv` (real issues), `eni_dryruns.tsv` (informational)
- Provides summaries by action, caller, and error codes

### `sgfp_report.sh` - Report Generator
Generates a markdown report from the collected bundle.

**Features:**
- Shows Security Group IDs, names, and descriptions
- Validates actual SGs against expected SGs (from annotations)
- **Network Connections**:
  - Pod network connections (listening ports and established connections from pod's perspective)
  - Conntrack connections with direction labels (INBOUND/OUTBOUND)
  - Same-node vs cross-node vs external connection identification
  - Connection states (ESTABLISHED, CLOSE, TIME_WAIT, etc.)
- **Log Files Summary**: Concise list of all log files with error counts and file paths
- **Node CNI Logs**: Shows CNI log errors with recent examples in the Node State section
- **View Related Logs**: Provides helper script commands to view pod-specific log lines
- Uses consistent `[OK]`, `[ISSUE]`, `[INFO]` format

### `sgfp_post_analyze.sh` - Quick Analysis
Provides a quick summary of potential issues found in the bundle.

**Features:**
- Validates Security Groups (actual vs expected)
- Checks pod status, readiness gates, routing tables
- Uses consistent `[OK]`, `[ISSUE]`, `[INFO]` format

### `sgfp_analyze_connectivity.sh` - Connectivity Analysis
Advanced analysis for diagnosing pod connectivity issues, especially after large pod churns.

**Features:**
- Analyzes ENI attachment state and timing
- Checks IPAMD state and branch ENI limits
- Validates subnet IP availability
- Analyzes pod events for network-related issues
- Analyzes CNI logs (both aws-node and node-level CNI logs)
- Checks readiness gate timing
- Detects stuck/orphaned network namespaces
- Analyzes network namespace creation timing (delays after pod creation)
- Detects IP address conflicts
- Tests DNS resolution
- Checks for resource exhaustion (file descriptors, memory pressure)
- Validates network interface states

### `sgfp_node_debug.sh` - Node Debug Pod
Creates a debug pod on a node for interactive troubleshooting.

```bash
# Debug node where a pod is running
./sgfp_node_debug.sh <pod-name> -n <namespace>

# Debug node directly
./sgfp_node_debug.sh <node-name>

# With custom image
./sgfp_node_debug.sh <pod-name> -n <namespace> <image>
```

**Features:**
- Automatically detects if argument is a pod name or node name
- Uses `kubectl debug node/` for proper node debugging
- Defaults to `ubuntu` image

### `sgfp_view_logs.sh` - View Related Logs
Helper script to view pod-specific log lines from a diagnostic bundle.

```bash
# View all pod-related log lines
./sgfp_view_logs.sh <bundle-dir>

# View only errors/warnings
./sgfp_view_logs.sh <bundle-dir> --errors-only

# View all log lines (not filtered)
./sgfp_view_logs.sh <bundle-dir> --all-logs
```

**Features:**
- Automatically extracts pod identifiers (pod name, container ID, ENI ID, IP, UID) from bundle
- Searches all log files (aws-node logs, CNI logs) for pod-related lines
- Three modes: default (pod-related), errors-only, or all-logs
- Shows which search patterns are being used

## Security Group Validation

The toolkit automatically validates Security Groups by:

1. **Collecting actual SGs** from the pod's ENI via AWS API
2. **Collecting expected SGs** from Kubernetes annotations (in priority order):
   - Pod annotation: `vpc.amazonaws.com/security-groups`
   - Deployment annotation: `vpc.amazonaws.com/security-groups`
   - ReplicaSet annotation: `vpc.amazonaws.com/security-groups`
   - Namespace annotation: `vpc.amazonaws.com/security-groups`
3. **Comparing** actual vs expected and reporting mismatches

The report shows:
- Actual SGs with names and descriptions
- Expected SGs (if specified)
- Validation status: Match, Mismatch, or No expected SGs specified

## Output Format

All scripts use a consistent `[PREFIX]` output format:
- `[OK]` - Successful check
- `[ISSUE]` - Problem detected
- `[INFO]` - Informational message
- `[WARN]` - Warning
- `[ERROR]` - Error condition

Script-specific prefixes:
- `[DOCTOR]` - Doctor script
- `[NODE]` - Node diagnostics
- `[AWS]` - AWS diagnostics
- `[API]` - API diagnostics
- `[ANALYZE]` - Post-analyze script
- `[REPORT]` - Report generator

## Make Targets

```bash
make collect POD=<pod> NS=default      # Collect diagnostics
make api WINDOW_MINUTES=60             # API diagnostics
make report BUNDLE=<dir>               # Generate report
make analyze BUNDLE=<dir>              # Post-analyze
make analyze-connectivity BUNDLE=<dir> # Connectivity analysis
make doctor POD=<pod> NS=default       # All-in-one
make node-debug TARGET=<pod|node>      # Create debug pod on node
make view-logs BUNDLE=<dir>            # View pod-related log lines
make clean                             # Remove all diagnostic output directories
make clean-debug-pods NS=<namespace>   # Clean up debug pods interactively
```

## Notes

- The collectors are **best-effort**. Missing permissions or components are handled gracefully; files still get created (possibly empty) so later steps won't crash.
- **Shell Detection**: Scripts automatically detect available shells in pods (`sh`, `/bin/sh`, `/bin/bash`, `bash`) for better compatibility.
- **Network Tools**: Missing network tools (`ip`, `ping`) in pods are handled gracefully with informative messages.
- **ICMP Reachability**: ICMP may be blocked; `pod_reachability.txt` is informational only.
- **Security Groups**: SG names and descriptions require `ec2:DescribeSecurityGroups` permission. The toolkit automatically fetches this information when available.
- **Dry-Run Operations**: API diagnostics distinguish between real errors/throttles and successful dry-run validations.
- **CNI Log Collection**: When node diagnostics are run, the toolkit automatically creates a temporary privileged pod on the node to collect CNI logs from `/var/log/aws-routed-eni/` and conntrack data. The pod is automatically cleaned up after collection.
- **Connection Analysis**: 
  - Pod connections show listening ports and established connections from the pod's perspective
  - Conntrack connections show both directions (INBOUND TO pod and OUTBOUND FROM pod) with connection states
  - Connections are identified as same-node (pod on same node), cross-node (pod on different node in VPC), or external (outside VPC)
  - This helps diagnose if connectivity issues are local to the node or cross-node networking problems
- **Log Files Summary**: The report includes a concise summary of all log files with error counts and file paths, making it easy to identify which logs need attention
- **View Related Logs Helper**: The `sgfp_view_logs.sh` script automatically extracts pod identifiers and searches all log files for pod-related lines, with options to view only errors or all logs
- **Network Namespace Matching**: Attempts to match pod's network namespace using container ID (with fallback to pod UID) to handle AWS CNI's hashed namespace naming scheme
- **Leak Detection**: Only flags empty network namespaces as issues if they're older than 1 hour (to avoid false positives from transient cleanup states)
- **Node Debug Pod**: The `sgfp_node_debug.sh` script can accept either a pod name (will find the node) or a node name directly.
- **Output Directories**: All diagnostic output directories (`sgfp_bundle_*`, `sgfp_diag_*`, `sgfp_api_diag_*`) are automatically ignored by git (see `.gitignore`).

## Requirements

- Linux
- `kubectl`, `jq`, `awk`, `grep`
- `aws` CLI configured (and `AWS_REGION` set, e.g., `export AWS_REGION=us-west-2`)
- Permissions:
  - `ec2:DescribeNetworkInterfaces` (required)
  - `ec2:DescribeSecurityGroups` (for SG names/descriptions)
  - CloudTrail `lookup-events` (optional, for API diagnostics)
