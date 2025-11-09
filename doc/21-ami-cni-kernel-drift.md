# AMI / CNI / Kernel Drift Analysis

## What We Check

This check analyzes version information for Kubernetes components, OS image (AMI), kernel, and CNI components to detect version mismatches and drift that can cause network connectivity issues.

**Checks performed:**
- Collects Kubernetes version from node
- Collects OS image (AMI) information
- Collects kernel version
- Collects aws-node (CNI) version
- Collects kube-proxy version
- Collects container runtime version
- Compares versions for mismatches
- Flags non-EKS-optimized AMIs
- Identifies outdated components

## Why It Matters

**Version drift** can cause:
- **Network connectivity failures**: Incompatible CNI versions may not work with certain Kubernetes versions
- **Feature incompatibilities**: New Kubernetes features may require updated CNI/kube-proxy versions
- **Security vulnerabilities**: Outdated components may have known security issues
- **Performance issues**: Older versions may have performance bugs or lack optimizations
- **Pod scheduling failures**: Version mismatches can cause pods to fail to start or network setup to fail

**Common issues:**
- kube-proxy version doesn't match Kubernetes version
- aws-node (CNI) version is outdated
- Non-EKS-optimized AMI used (may have incompatible kernel/CNI versions)
- Kernel version too old for CNI features
- Container runtime version mismatches

## How We Check It

The analysis checks for:

1. **Kubernetes Version**
   - Extracts version from node info
   - Flags very old versions (< 1.20)

2. **OS Image (AMI)**
   - Extracts OS image from node info
   - Checks if it's an EKS-optimized AMI
   - Flags non-EKS-optimized AMIs

3. **Kernel Version**
   - Extracts kernel version from node info
   - Flags very old kernels (< 5.4)

4. **aws-node (CNI) Version**
   - Extracts version from DaemonSet image tag
   - Flags very old versions (< 1.10)

5. **kube-proxy Version**
   - Extracts version from DaemonSet image tag
   - Compares with Kubernetes version
   - Flags version mismatches

6. **Container Runtime Version**
   - Extracts container runtime version from node info
   - Reports version for reference

The analysis uses:
- `node_*/node_info.json` - Full node information
- `node_*/node_k8s_version.txt` - Kubernetes version
- `node_*/node_os_image.txt` - OS image (AMI)
- `node_*/node_kernel_version.txt` - Kernel version
- `node_*/node_aws_node_daemonset.json` - aws-node DaemonSet
- `node_*/node_aws_node_version.txt` - aws-node version
- `node_*/node_kube_proxy_daemonset.json` - kube-proxy DaemonSet
- `node_*/node_kube_proxy_version.txt` - kube-proxy version
- `node_*/node_container_runtime_version.txt` - Container runtime version

## Recommended Actions

### If kube-proxy Version Doesn't Match Kubernetes Version

1. **Check current versions**:
   ```bash
   kubectl get node <node-name> -o jsonpath='{.status.nodeInfo.kubeletVersion}'
   kubectl get daemonset -n kube-system kube-proxy -o jsonpath='{.spec.template.spec.containers[0].image}'
   ```

2. **Update kube-proxy**:
   ```bash
   # Get the correct kube-proxy image for your Kubernetes version
   # EKS uses: 602401143452.dkr.ecr.us-west-2.amazonaws.com/eks/kube-proxy:v<k8s-version>
   
   kubectl set image daemonset/kube-proxy \
     kube-proxy=602401143452.dkr.ecr.us-west-2.amazonaws.com/eks/kube-proxy:v<k8s-version> \
     -n kube-system
   ```

3. **Verify update**:
   ```bash
   kubectl get daemonset -n kube-system kube-proxy -o jsonpath='{.spec.template.spec.containers[0].image}'
   ```

### If aws-node (CNI) Version Is Outdated

1. **Check current version**:
   ```bash
   kubectl get daemonset -n kube-system aws-node -o jsonpath='{.spec.template.spec.containers[0].image}'
   ```

2. **Check latest available version**:
   ```bash
   # Check AWS VPC CNI releases: https://github.com/aws/amazon-vpc-cni-k8s/releases
   # Or check ECR: aws ecr describe-images --repository-name amazon-k8s-cni --region us-west-2
   ```

3. **Update aws-node**:
   ```bash
   # Update to latest version (check compatibility with your Kubernetes version first)
   kubectl set image daemonset/aws-node \
     aws-node=602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon-k8s-cni:v<version> \
     -n kube-system
   ```

4. **Verify update**:
   ```bash
   kubectl get daemonset -n kube-system aws-node -o jsonpath='{.spec.template.spec.containers[0].image}'
   kubectl get pods -n kube-system -l app=aws-node
   ```

### If Non-EKS-Optimized AMI Is Detected

1. **Check current AMI**:
   ```bash
   kubectl get node <node-name> -o jsonpath='{.status.nodeInfo.osImage}'
   ```

2. **Identify EKS-optimized AMI for your region**:
   ```bash
   # List EKS-optimized AMIs
   aws ec2 describe-images \
     --owners 602401143452 \
     --filters "Name=name,Values=amazon-eks-node-*" \
     --query 'Images[*].[Name,ImageId,CreationDate]' \
     --output table \
     --region <region>
   ```

3. **Update node group to use EKS-optimized AMI**:
   - Update node group launch template or configuration
   - Use EKS-optimized AMI ID for your Kubernetes version
   - Roll out new nodes gradually

4. **Verify AMI**:
   ```bash
   kubectl get node <node-name> -o jsonpath='{.status.nodeInfo.osImage}'
   ```

### If Kernel Version Is Too Old

1. **Check current kernel**:
   ```bash
   kubectl get node <node-name> -o jsonpath='{.status.nodeInfo.kernelVersion}'
   ```

2. **Update to EKS-optimized AMI**:
   - EKS-optimized AMIs include compatible kernel versions
   - Update node group to use latest EKS-optimized AMI

3. **Verify kernel**:
   ```bash
   kubectl get node <node-name> -o jsonpath='{.status.nodeInfo.kernelVersion}'
   ```

### General Version Management

1. **Keep components in sync**:
   - Use EKS-optimized AMIs (includes compatible versions)
   - Update aws-node and kube-proxy when upgrading Kubernetes
   - Test upgrades in non-production first

2. **Check version compatibility**:
   - Review AWS EKS documentation for version compatibility
   - Check CNI release notes for Kubernetes version requirements
   - Verify kube-proxy version matches Kubernetes version

3. **Monitor for updates**:
   - Subscribe to EKS release announcements
   - Monitor CNI releases: https://github.com/aws/amazon-vpc-cni-k8s/releases
   - Review EKS upgrade guides before upgrading

4. **Version consistency across nodes**:
   ```bash
   # Check versions across all nodes
   kubectl get nodes -o custom-columns=NAME:.metadata.name,K8S:.status.nodeInfo.kubeletVersion,OS:.status.nodeInfo.osImage
   
   # Check aws-node versions
   kubectl get pods -n kube-system -l app=aws-node -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,IMAGE:.spec.containers[0].image
   
   # Check kube-proxy versions
   kubectl get pods -n kube-system -l k8s-app=kube-proxy -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,IMAGE:.spec.containers[0].image
   ```

## Related Files

- `node_*/node_info.json` - Full node information
- `node_*/node_k8s_version.txt` - Kubernetes version
- `node_*/node_os_image.txt` - OS image (AMI)
- `node_*/node_kernel_version.txt` - Kernel version
- `node_*/node_aws_node_daemonset.json` - aws-node DaemonSet configuration
- `node_*/node_aws_node_version.txt` - aws-node version
- `node_*/node_kube_proxy_daemonset.json` - kube-proxy DaemonSet configuration
- `node_*/node_kube_proxy_version.txt` - kube-proxy version
- `node_*/node_container_runtime_version.txt` - Container runtime version
- `node_*/node_labels.json` - Node labels

## References

- [EKS Optimized AMIs](https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html)
- [AWS VPC CNI Releases](https://github.com/aws/amazon-vpc-cni-k8s/releases)
- [EKS Upgrade Guide](https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html)
- [Kubernetes Version Skew Policy](https://kubernetes.io/docs/setup/release/version-skew-policy/)
- [EKS Component Versions](https://docs.aws.amazon.com/eks/latest/userguide/update-cluster.html#update-existing-cluster)

