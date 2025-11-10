# CloudTrail API Diagnostics

## What We Check

The toolkit analyzes AWS CloudTrail events to identify ENI-related API errors, throttles, and issues.

**Checks performed:**
- Queries CloudTrail for ENI-related API calls (CreateNetworkInterface, AttachNetworkInterface, DeleteNetworkInterface, ModifyNetworkInterfaceAttribute, etc.)
- Distinguishes between dry-run operations and real API calls
- Identifies real errors and throttles (excluding dry-runs)
- Groups throttles by API action
- Summarizes API calls by user/caller identity
- Reports total events analyzed vs dry-runs

## Why It Matters

**CloudTrail API Diagnostics** helps identify:
- **API throttling**: AWS API rate limits being hit, causing ENI operations to fail
- **Permission errors**: IAM policy issues preventing ENI operations
- **Invalid parameter errors**: Configuration issues (e.g., deleting ENI in use, invalid security group)
- **Dry-run operations**: Normal validation operations (not actual issues)

**Common issues:**
- `Throttling` errors on ENI API calls (rate limits)
- `AccessDenied` errors (IAM permission issues)
- `InvalidParameterValue` errors (e.g., "Network interface is currently in use")
- High API call volume from specific callers (may indicate retry storms)

## How We Check It

1. **CloudTrail Query**: Queries CloudTrail for ENI-related API events within the specified time window
2. **Dry-Run Detection**: Identifies and excludes dry-run operations (normal validation)
3. **Error Classification**: Separates real errors/throttles from dry-runs
4. **Error Grouping**: Groups errors by API action and caller identity
5. **Summary Reporting**: Provides counts and summaries of errors, throttles, and API calls

**Output examples:**
- `[ISSUE] Found 5 real error/throttle event(s) in CloudTrail`
- `  - DeleteNetworkInterface: Client.InvalidParameterValue (Network interface 'eni-xxx' is currently in use.)`
- `[INFO] Throttles by action:`
- `  - 3 AttachNetworkInterface`
- `[INFO] API calls by user/caller:`
- `  - 1152 arn:aws:sts::xxx:assumed-role/AWSServiceRoleForAmazonEKS/AmazonEKS`
- `[INFO] Total ENI API events analyzed: 1161 (dry-runs: 1152)`

## Recommended Actions

### If API Throttling Detected

1. **Review throttle patterns**:
   ```bash
   # Check throttle_by_action.txt in API diagnostics directory
   cat sgfp_api_diag_*/throttle_by_action.txt
   ```

2. **Identify throttled actions**: Common throttled actions include:
   - `AttachNetworkInterface` - High pod churn
   - `CreateNetworkInterface` - Rapid ENI creation
   - `DeleteNetworkInterface` - Cleanup operations

3. **Mitigation strategies**:
   - **Reduce pod churn**: Avoid rapid pod creation/deletion
   - **Increase warm pool**: Reduce need for frequent ENI creation
   - **Use pod ENI (trunking)**: Reduces ENI creation/deletion operations
   - **Add retry logic**: Ensure applications handle throttling gracefully

4. **Monitor throttle rate**: Track throttle frequency over time

### If Permission Errors Detected

1. **Review error details**:
   ```bash
   # Check eni_errors.tsv in API diagnostics directory
   cat sgfp_api_diag_*/eni_errors.tsv
   ```

2. **Verify IAM permissions**: Ensure IAM roles have required permissions:
   - `ec2:CreateNetworkInterface`
   - `ec2:AttachNetworkInterface`
   - `ec2:DeleteNetworkInterface`
   - `ec2:ModifyNetworkInterfaceAttribute`
   - `ec2:DescribeNetworkInterfaces`

3. **Check IAM role assignments**:
   ```bash
   # Check aws-node service account
   kubectl get sa aws-node -n kube-system -o yaml
   
   # Check IAM role trust policy
   aws iam get-role --role-name <role-name>
   ```

4. **Review IAM policies**: Ensure policies allow required ENI operations

### If Invalid Parameter Errors

1. **Review specific errors**: Check error messages for details
2. **Common invalid parameter errors**:
   - **"Network interface is currently in use"**: ENI deletion attempted while still attached
   - **"Invalid security group"**: Security group doesn't exist or in wrong VPC
   - **"Invalid subnet"**: Subnet doesn't exist or in wrong VPC

3. **Fix configuration issues**: Correct invalid parameters in pod/deployment configurations

### If High API Call Volume

1. **Review calls by user/caller**:
   ```bash
   # Check calls_by_user.txt in API diagnostics directory
   cat sgfp_api_diag_*/calls_by_user.txt
   ```

2. **Identify high-volume callers**: May indicate:
   - Retry storms (application retrying failed operations)
   - Misconfigured applications (creating/deleting ENIs unnecessarily)
   - Cleanup operations (normal after large pod churn)

3. **Optimize API usage**: Reduce unnecessary API calls, implement backoff/retry logic

## Related Files

- `sgfp_api_diag_*/eni_errors.tsv` - Real errors/throttles (excludes dry-runs)
- `sgfp_api_diag_*/eni_dryruns.tsv` - Dry-run operations (normal validation)
- `sgfp_api_diag_*/throttle_by_action.txt` - Throttles grouped by API action
- `sgfp_api_diag_*/calls_by_user.txt` - API calls grouped by caller identity
- `sgfp_api_diag_*/flat_events.json` - All ENI API events (for detailed analysis)

## References

- [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/)
- [EC2 API Throttling](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/throttling.html)
- [IAM Permissions for VPC CNI](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/docs/iam-policy.md)
- [AWS Service Quotas](https://docs.aws.amazon.com/servicequotas/)

