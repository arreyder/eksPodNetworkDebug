# AWS VPC CNI ConfigMap Settings

## What We Check

The toolkit collects and reports all AWS VPC CNI configuration settings from the `amazon-vpc-cni` ConfigMap in the `kube-system` namespace. These settings control IP allocation, ENI management, and CNI behavior.

**Settings collected:**
- `branch-eni-cooldown` - Cooldown period for branch ENIs after detachment
- `warm-ip-target` - Target number of warm IPs to maintain per node
- `minimum-ip-target` - Minimum IPs to maintain per node
- `warm-prefix-target` - Target for prefix delegation (IPv6/IPv4 prefix delegation)
- `enable-network-policy-controller` - Whether the network policy controller is enabled

## Why It Matters

**AWS VPC CNI ConfigMap settings** directly impact:
- **IP allocation performance**: Warm IP targets affect how quickly pods get IPs
- **IP exhaustion**: Minimum IP targets can prevent IP exhaustion but consume more IPs
- **ENI reuse timing**: Branch ENI cooldown affects when ENIs can be reused after pod deletion
- **Network policy enforcement**: Network policy controller enables Kubernetes NetworkPolicy support

**Common issues:**
- **Low warm IP target**: Pods experience delays getting IPs (default: 1)
- **High minimum IP target**: Wastes IPs but prevents exhaustion (default: 0)
- **Short branch ENI cooldown**: ENIs reused too quickly, causing cleanup issues (minimum: 30s)
- **Missing prefix delegation**: Not using IPv6 or IPv4 prefix delegation when available

**Impact:**
- Pods stuck in Pending state (IP allocation delays)
- IP exhaustion during high pod churn
- ENI attachment failures (cooldown too short)
- Network policy rules not enforced (controller disabled)

## How We Check It

1. **ConfigMap Collection**: Queries the `amazon-vpc-cni` ConfigMap in `kube-system` namespace
   - Extracts all configuration settings
   - Reports configured values or defaults

2. **Default Values**: Displays default values when settings are not configured:
   - `branch-eni-cooldown`: 30s (minimum enforced by vpc-resource-controller)
   - `warm-ip-target`: 1
   - `minimum-ip-target`: 0
   - `warm-prefix-target`: 1 (prefix delegation only)
   - `enable-network-policy-controller`: false

3. **Reporting**: All settings are displayed in the "AWS VPC CNI Configuration" section of the report

## Recommended Actions

### If Warm IP Target Too Low

1. **Check current setting**:
   ```bash
   kubectl get configmap -n kube-system amazon-vpc-cni -o yaml | grep warm-ip-target
   ```

2. **Increase warm IP target** (if pods experience IP allocation delays):
   ```bash
   kubectl edit configmap -n kube-system amazon-vpc-cni
   # Add or update: warm-ip-target: "2" (or higher)
   ```

3. **Consider instance type**: Larger instances can support more warm IPs

### If Minimum IP Target Too Low (IP Exhaustion)

1. **Check current setting**:
   ```bash
   kubectl get configmap -n kube-system amazon-vpc-cni -o yaml | grep minimum-ip-target
   ```

2. **Increase minimum IP target** (to prevent IP exhaustion):
   ```bash
   kubectl edit configmap -n kube-system amazon-vpc-cni
   # Add or update: minimum-ip-target: "3" (or higher based on pod churn)
   ```

3. **Balance with subnet size**: Higher minimum = more IPs consumed but better availability

### If Branch ENI Cooldown Too Short

1. **Check current setting**:
   ```bash
   kubectl get configmap -n kube-system amazon-vpc-cni -o yaml | grep branch-eni-cooldown
   ```

2. **Increase cooldown** (if experiencing ENI cleanup issues):
   ```bash
   kubectl edit configmap -n kube-system amazon-vpc-cni
   # Add or update: branch-eni-cooldown: "60" (minimum: 30s)
   ```

3. **Note**: Minimum is 30s (enforced by vpc-resource-controller)

### If Network Policy Controller Disabled

1. **Check current setting**:
   ```bash
   kubectl get configmap -n kube-system amazon-vpc-cni -o yaml | grep enable-network-policy-controller
   ```

2. **Enable network policy controller** (if using Kubernetes NetworkPolicies):
   ```bash
   kubectl edit configmap -n kube-system amazon-vpc-cni
   # Add or update: enable-network-policy-controller: "true"
   ```

3. **Restart aws-node pods** (if needed):
   ```bash
   kubectl rollout restart daemonset -n kube-system aws-node
   ```

### If Prefix Delegation Not Configured

1. **Check current setting**:
   ```bash
   kubectl get configmap -n kube-system amazon-vpc-cni -o yaml | grep warm-prefix-target
   ```

2. **Enable prefix delegation** (for IPv6 or IPv4 prefix delegation):
   ```bash
   kubectl edit configmap -n kube-system amazon-vpc-cni
   # Add or update: warm-prefix-target: "1" (or higher)
   ```

3. **Verify subnet supports prefix delegation**: Requires /64 IPv6 prefixes or /28 IPv4 prefixes

## Related Files

- `node_*/node_aws_vpc_cni_config.json` - Full ConfigMap contents
- `node_*/node_aws_node_env.json` - aws-node daemonset environment variables (fallback)

## References

- [AWS VPC CNI Configuration](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/eni-and-ip-target.md)
- [Branch ENI Cooldown PR](https://github.com/aws/amazon-vpc-resource-controller-k8s/pull/342)
- [AWS VPC CNI IP Management](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/ip-management.md)
- [Prefix Delegation](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/prefix-delegation.md)
- [Network Policy Controller](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/network-policy-EN.md)

