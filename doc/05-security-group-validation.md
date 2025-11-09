# Security Group Validation

## What We Check

The toolkit automatically validates Security Groups (SGs) attached to pod ENIs against expected SGs specified in Kubernetes annotations.

**Checks performed:**
- Collects actual SGs from pod ENI via AWS API
- Collects expected SGs from annotations (pod, deployment, replicaset, namespace)
- Compares actual vs expected SGs
- Shows SG IDs, names, and descriptions for easy identification
- Reports mismatches, missing SGs, and unexpected SGs

## Why It Matters

**Security Groups** control network traffic to/from pods:
- **Ingress rules**: Control what traffic can reach the pod
- **Egress rules**: Control what traffic the pod can send
- **Pod-to-pod communication**: SGs must allow traffic between pods
- **Service discovery**: SGs must allow DNS and service traffic
- **Health probes**: Node/kubelet must be able to reach pod health check ports

**Common issues:**
- Expected SGs not attached (pod cannot receive expected traffic)
- Unexpected SGs attached (security risk, pod exposed to unintended traffic)
- SG rules too restrictive (blocks required traffic like DNS, health probes)
- SG rules missing (allows unintended traffic)

## How We Check It

1. **Actual SGs Collection**: Queries AWS API for SGs attached to pod ENI
2. **Expected SGs Collection**: Extracts from annotations in priority order:
   - Pod annotation: `vpc.amazonaws.com/security-groups`
   - Deployment annotation: `vpc.amazonaws.com/security-groups`
   - ReplicaSet annotation: `vpc.amazonaws.com/security-groups`
   - Namespace annotation: `vpc.amazonaws.com/security-groups`
3. **SG Details**: Fetches SG names and descriptions via AWS API
4. **Comparison**: Compares actual vs expected and identifies:
   - Missing SGs (expected but not attached)
   - Unexpected SGs (attached but not expected)
   - Matches (correctly attached)

**Output examples:**
- `[OK] Security Groups match: 3 SG(s)`
- `[ISSUE] Security Group mismatch: expected 2 SG(s), found 3 SG(s)`
- `[INFO] Missing SG: sg-0123456789abcdef0 (expected but not attached)`
- `[INFO] Unexpected SG: sg-0987654321fedcba0 (attached but not expected)`

## Recommended Actions

### If SGs Don't Match

1. **Verify annotation is correct**:
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/security-groups}'
   kubectl get deployment <deployment> -n <namespace> -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/security-groups}'
   ```

2. **Check if annotation format is correct**:
   - Should be comma-separated SG IDs: `sg-xxx,sg-yyy`
   - Or JSON array: `["sg-xxx","sg-yyy"]`

3. **Verify AWS VPC CNI is processing annotations**:
   ```bash
   kubectl logs -n kube-system -l app=aws-node | grep -i "security.*group"
   ```

4. **Check pod ENI attachment**:
   - Verify pod ENI is attached correctly
   - Check if CNI has permissions to attach SGs

### If Missing Expected SGs

1. **Verify SG exists and is accessible**:
   ```bash
   aws ec2 describe-security-groups --group-ids <sg-id>
   ```

2. **Check SG attachment permissions**:
   - Verify IAM role has `ec2:ModifyNetworkInterfaceAttribute`
   - Check if SG is in same VPC as pod

3. **Review CNI logs for errors**:
   ```bash
   kubectl logs -n kube-system -l app=aws-node | grep -i "security.*group\|eni"
   ```

### If Unexpected SGs Attached

1. **Identify source of unexpected SGs**:
   - Check if another annotation is overriding
   - Verify namespace-level annotations
   - Review deployment/replicaset annotations

2. **Remove unexpected SGs**:
   - Update annotations to remove unwanted SGs
   - Restart pod to apply changes

### If Traffic Blocked Despite Correct SGs

1. **Verify SG rules allow required traffic**:
   ```bash
   aws ec2 describe-security-groups --group-ids <sg-id> --query 'SecurityGroups[0].IpPermissions'
   ```

2. **Check for required rules**:
   - **DNS (UDP 53)**: Required for service discovery
   - **Health probe ports**: Node/kubelet must reach pod
   - **Pod-to-pod communication**: SGs must allow traffic between pods
   - **Service traffic**: ClusterIP/NodePort traffic

3. **Verify node SG allows pod traffic**:
   - Node SG must allow traffic to pod SGs
   - Check node SG egress rules

## Related Files

- `pod_branch_eni_sgs.txt` - Actual SGs on pod ENI
- `pod_branch_eni_sgs_details.json` - SG details (IDs, names, descriptions)
- `pod_expected_sgs.txt` - Expected SGs from pod annotation
- `deployment_expected_sgs.txt` - Expected SGs from deployment annotation
- `replicaset_expected_sgs.txt` - Expected SGs from replicaset annotation
- `namespace_expected_sgs.txt` - Expected SGs from namespace annotation

## References

- [AWS Security Groups for Pods](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)
- [AWS VPC CNI Security Groups](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/security-groups-for-pods.md)

