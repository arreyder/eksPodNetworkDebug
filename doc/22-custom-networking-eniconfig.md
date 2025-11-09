# Custom Networking / ENIConfig

## What We Check

The toolkit validates ENIConfig (Custom Networking) resources to ensure proper subnet → AZ mapping, node assignments, and configuration consistency.

**Checks performed:**
- Collects ENIConfig CRD resources from Kubernetes
- Validates subnet CIDR → AZ mapping against actual AWS subnets
- Checks node ENIConfig assignments (from annotations/labels)
- Verifies ENIConfig subnet existence in VPC
- Flags configuration mismatches and missing resources

## Why It Matters

**ENIConfig (Custom Networking)** allows AWS VPC CNI to use different subnets for pods than the node's primary subnet, enabling:
- **Custom IP ranges**: Pods can use IPs from different CIDR blocks
- **Security group isolation**: Different security groups per ENIConfig
- **Multi-AZ flexibility**: Pods can be placed in specific AZs regardless of node location

**Common issues:**
- **Subnet → AZ mismatch**: ENIConfig references subnet in wrong AZ
- **Missing ENIConfig**: Node assigned to ENIConfig that doesn't exist
- **Invalid subnet**: ENIConfig references subnet that doesn't exist or is in different VPC
- **Name confusion**: ENIConfig name doesn't match AZ (causes confusion)
- **Node assignment errors**: Node assigned to wrong ENIConfig or ENIConfig not found

**Impact:**
- Pods cannot be scheduled (ENI attachment fails)
- Pods get wrong IP ranges or security groups
- Network connectivity issues (wrong subnet routing)
- Only some AZs or nodes failing (ENIConfig misconfiguration)

## How We Check It

1. **ENIConfig Collection**: Queries Kubernetes for ENIConfig CRD resources
   - Tries cluster-scoped first, then `kube-system` namespace
   - Handles alternative CRD naming (`eniconfig` vs `eniconfigs`)

2. **Subnet Validation**: For each ENIConfig:
   - Extracts subnet ID from `spec.subnet`
   - Validates subnet exists in VPC (from AWS subnet data)
   - Compares ENIConfig name with subnet AZ (common pattern: name = AZ)
   - Flags missing or invalid subnets

3. **Node Assignment Check**:
   - Reads node annotations (`k8s.amazonaws.com/eniConfig` or `vpc.amazonaws.com/eniConfig`)
   - Falls back to node labels if annotations not found
   - Verifies assigned ENIConfig exists in cluster
   - Flags missing or invalid assignments

4. **Configuration Display**:
   - Shows ENIConfig name, subnet ID, CIDR, and AZ
   - Displays security groups and tags if specified
   - Reports node ENIConfig assignment status

**Output examples:**
- `[OK] No ENIConfig resources found (custom networking not enabled - using default VPC CNI)`
- `[INFO] Found 3 ENIConfig resource(s) (custom networking enabled)`
- `[INFO] ENIConfig 'us-west-2a': Subnet subnet-xxx (CIDR: 10.4.192.0/18, AZ: us-west-2a)`
- `[ISSUE] ENIConfig 'us-west-2a': Subnet 'subnet-xxx' not found in VPC (may be in different VPC or deleted)`
- `[ISSUE] Node assigned to ENIConfig 'us-west-2a' but this ENIConfig does not exist`
- `[WARN] ENIConfig name 'us-west-2a' does not match subnet AZ 'us-west-2b' (may cause confusion)`

## Recommended Actions

### If ENIConfig Subnet Not Found

1. **Verify subnet exists in VPC**:
   ```bash
   # Check if subnet exists
   aws ec2 describe-subnets --subnet-ids <subnet-id>
   
   # List all subnets in VPC
   aws ec2 describe-subnets --filters "Name=vpc-id,Values=<vpc-id>"
   ```

2. **Check ENIConfig subnet specification**:
   ```bash
   # View ENIConfig resources
   kubectl get eniconfig -o yaml
   
   # Check specific ENIConfig
   kubectl get eniconfig <name> -o yaml
   ```

3. **Verify VPC ID matches**:
   - Ensure ENIConfig subnet is in the same VPC as the cluster
   - Check if subnet was deleted or moved to different VPC

### If Node ENIConfig Assignment Invalid

1. **Check node annotations/labels**:
   ```bash
   # View node annotations
   kubectl get node <node-name> -o jsonpath='{.metadata.annotations}'
   
   # View node labels
   kubectl get node <node-name> -o jsonpath='{.metadata.labels}'
   ```

2. **Verify ENIConfig exists**:
   ```bash
   # List all ENIConfigs
   kubectl get eniconfig
   
   # Check if specific ENIConfig exists
   kubectl get eniconfig <name>
   ```

3. **Fix node assignment**:
   - Update node annotation: `kubectl annotate node <node-name> k8s.amazonaws.com/eniConfig=<eniconfig-name>`
   - Or update node label: `kubectl label node <node-name> k8s.amazonaws.com/eniConfig=<eniconfig-name>`
   - Ensure ENIConfig name matches exactly (case-sensitive)

### If ENIConfig Name Doesn't Match AZ

1. **Verify naming convention**:
   - Common pattern: ENIConfig name = AZ name (e.g., `us-west-2a`)
   - Check if naming is intentional (may use custom naming)

2. **Consider renaming**:
   - Rename ENIConfig to match AZ for clarity
   - Or document naming convention if intentional

### If Custom Networking Not Enabled

1. **Check if custom networking is needed**:
   - Default VPC CNI uses node's subnet for pods
   - Custom networking only needed for specific IP ranges or security groups

2. **Enable custom networking** (if needed):
   - Create ENIConfig resources for each AZ/subnet
   - Configure node groups to use ENIConfigs
   - See AWS documentation for setup instructions

## Related Files

- `node_*/node_eniconfigs.json` - ENIConfig CRD resources
- `node_*/node_annotations.json` - Node annotations (may contain ENIConfig references)
- `node_*/node_labels.json` - Node labels (may contain ENIConfig references)
- `aws_*/subnets.json` - Subnet information (for validation)

## References

- [AWS VPC CNI Custom Networking](https://docs.aws.amazon.com/eks/latest/userguide/cni-custom-network.html)
- [ENIConfig CRD Specification](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/eni-config.md)
- [Kubernetes Custom Resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)

