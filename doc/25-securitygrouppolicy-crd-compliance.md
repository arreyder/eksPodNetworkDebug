# SecurityGroupPolicy CRD Compliance

## What We Check

The toolkit automatically validates SecurityGroupPolicy CRD resources to ensure compliance with AWS EKS limits and best practices.

**Checks performed:**
- Collects all SecurityGroupPolicy resources (namespace-scoped and cluster-scoped)
- Matches SecurityGroupPolicy resources to the pod using `podSelector` (matchLabels)
- Counts security groups in each matching SecurityGroupPolicy
- Validates compliance with the 5 security groups per policy limit
- Detects when multiple SecurityGroupPolicy resources are used (allows up to 10 total SGs)
- Reports violations and provides recommendations

## Why It Matters

**SecurityGroupPolicy CRD** is the recommended way to assign security groups to pods in AWS EKS (replacing annotation-based assignment). However, there are important limits:

- **5 security groups per SecurityGroupPolicy**: Each SecurityGroupPolicy custom resource can specify up to 5 security groups
- **10 security groups total**: If you need more than 5 security groups, you can use multiple SecurityGroupPolicy resources, but the total across all matching policies should not exceed 10
- **PodSelector matching**: SecurityGroupPolicy uses `podSelector` (similar to NetworkPolicy) to match pods based on labels

**Common issues:**
- SecurityGroupPolicy with more than 5 security groups (violates CRD limit, will be rejected or cause errors)
- Multiple SecurityGroupPolicy resources matching the same pod with total SGs exceeding 10 (may cause unexpected behavior)
- PodSelector not matching the pod (SecurityGroupPolicy won't apply, pod may not get expected security groups)

## How We Check It

1. **Collection**: Queries Kubernetes API for all SecurityGroupPolicy resources in the pod's namespace and cluster-wide
2. **PodSelector Matching**: Extracts pod labels and matches them against each SecurityGroupPolicy's `podSelector.matchLabels`
3. **Security Group Counting**: Counts security groups in `spec.securityGroups.groupIds` array for each matching policy
4. **Compliance Validation**: 
   - Flags violations if any SecurityGroupPolicy has more than 5 security groups
   - Warns if multiple policies match and total SGs exceed 10
   - Reports total security groups across all matching policies
5. **Deduplication**: Tracks processed policies to avoid counting the same policy twice (namespace-scoped vs cluster-scoped)

**Output examples:**
- `[OK] SecurityGroupPolicy 'be-innkeeper-sgp-191744d1' (namespace: default): 3 SG(s) - compliant`
- `[ISSUE] SecurityGroupPolicy 'my-policy' has 7 security groups (exceeds limit of 5 per policy)`
- `[INFO] Found 2 SecurityGroupPolicy resource(s) matching this pod`
- `[WARN] Total security groups (12) exceeds recommended limit of 10 (across all policies)`

## Recommended Actions

### If SecurityGroupPolicy Has More Than 5 Security Groups

1. **Split into multiple policies**: Create two or more SecurityGroupPolicy resources, each with up to 5 security groups
   ```yaml
   # Policy 1: First 5 security groups
   apiVersion: vpcresources.k8s.aws/v1beta1
   kind: SecurityGroupPolicy
   metadata:
     name: my-policy-part1
   spec:
     podSelector:
       matchLabels:
         app: my-app
     securityGroups:
       groupIds:
         - sg-xxx
         - sg-yyy
         - sg-zzz
         - sg-aaa
         - sg-bbb
   
   # Policy 2: Remaining security groups
   apiVersion: vpcresources.k8s.aws/v1beta1
   kind: SecurityGroupPolicy
   metadata:
     name: my-policy-part2
   spec:
     podSelector:
       matchLabels:
         app: my-app
     securityGroups:
       groupIds:
         - sg-ccc
         - sg-ddd
   ```

2. **Verify podSelector matches**: Ensure the `podSelector.matchLabels` in both policies match the pod's labels
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.metadata.labels}' | jq .
   ```

3. **Test the configuration**: Apply the policies and verify the pod receives all expected security groups
   ```bash
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.metadata.annotations.vpc\.amazonaws\.com/pod-eni}' | jq .
   ```

### If Multiple Policies Match and Total SGs Exceed 10

1. **Review security group requirements**: Determine if all security groups are necessary
2. **Consolidate security groups**: Consider combining rules from multiple security groups into fewer groups
3. **Use security group rules**: Instead of multiple security groups, use more specific rules within fewer groups
4. **Split workloads**: If possible, split the workload into multiple pods with different security group requirements

### If SecurityGroupPolicy Doesn't Match Pod

1. **Verify podSelector**: Check that the `podSelector.matchLabels` matches the pod's labels
   ```bash
   kubectl get securitygrouppolicy <policy-name> -n <namespace> -o jsonpath='{.spec.podSelector}' | jq .
   kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.metadata.labels}' | jq .
   ```

2. **Check namespace**: Ensure the SecurityGroupPolicy is in the same namespace as the pod (or is cluster-scoped)
3. **Verify CRD is installed**: Confirm the SecurityGroupPolicy CRD is available
   ```bash
   kubectl api-resources | grep -i securitygrouppolicy
   ```

### If Pod Uses Annotations Instead of SecurityGroupPolicy

If the pod is using annotation-based security groups (`vpc.amazonaws.com/security-groups`), the toolkit will report:
- `[INFO] No SecurityGroupPolicy resources found matching this pod`
- `[INFO] Pod may be using annotation-based security groups`

This is acceptable, but consider migrating to SecurityGroupPolicy CRD for better management and compliance checking.

## Related Files

- `pod_*/pod_securitygrouppolicies.json` - SecurityGroupPolicy resources in pod's namespace
- `pod_*/pod_securitygrouppolicies_all.json` - All SecurityGroupPolicy resources (cluster-wide)
- `pod_*/pod_full.json` - Pod spec with labels for matching
- `pod_*/pod_annotations.json` - Pod annotations (may contain annotation-based SGs)

## References

- [AWS EKS Security Groups for Pods](https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html)
- [SecurityGroupPolicy CRD](https://github.com/aws/amazon-vpc-resource-controller-k8s)
- [AWS EKS Best Practices: Security Groups for Pods](https://docs.aws.amazon.com/eks/latest/best-practices/sgpp.html)

