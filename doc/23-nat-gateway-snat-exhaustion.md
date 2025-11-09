# NAT Gateway SNAT Port Exhaustion

## What We Check

The toolkit monitors NAT gateway connection counts via CloudWatch metrics to detect SNAT (Source Network Address Translation) port exhaustion, which can cause internet egress failures.

**Checks performed:**
- Collects NAT gateway information from VPC
- Queries CloudWatch for `ActiveConnectionCount` metrics (last 1 hour)
- Detects when NAT gateways are approaching or exceeding connection limits
- Warns at 80% of limit (~45,000 connections)
- Flags when at limit (~55,000 connections)

## Why It Matters

**NAT Gateway SNAT Port Exhaustion** causes:
- **Internet egress failures**: Pods cannot connect to external services
- **Connection timeouts**: New connections fail to establish
- **Unstable internet access**: Intermittent connectivity issues
- **Application failures**: Services that depend on external APIs fail

**NAT Gateway Limits:**
- **~55,000 concurrent connections** per NAT gateway
- Each connection uses one SNAT port
- High connection churn (short-lived connections) exhausts ports faster
- Multiple pods sharing one NAT gateway increases contention

**Common causes:**
- **High connection churn**: Many short-lived connections (no connection pooling)
- **Too few NAT gateways**: Single NAT gateway for entire VPC
- **High traffic volume**: Many pods making external connections simultaneously
- **No VPC endpoints**: All AWS service traffic goes through NAT gateway
- **Connection leaks**: Applications not closing connections properly

## How We Check It

1. **NAT Gateway Discovery**: Queries EC2 API for NAT gateways in VPC
   - Filters for `available` state only
   - Collects NAT gateway ID, subnet, state, and public IP

2. **CloudWatch Metrics Collection**: For each NAT gateway:
   - Queries `AWS/NATGateway` namespace
   - Metric: `ActiveConnectionCount` (indicator of SNAT port usage)
   - Time range: Last 1 hour
   - Statistics: Maximum and Average
   - Period: 5 minutes (300 seconds)

3. **Exhaustion Detection**:
   - **At Limit**: `ActiveConnectionCount >= 55,000` → `[ISSUE]`
   - **Approaching Limit**: `ActiveConnectionCount >= 45,000` (80%) → `[WARN]`
   - **Normal**: `ActiveConnectionCount < 45,000` → `[OK]`

4. **Reporting**: Shows:
   - NAT gateway ID, subnet, and state
   - Maximum and average active connections (last hour)
   - Connection usage percentage
   - Warnings when approaching/exceeding limits

**Output examples:**
- `[INFO] Found 2 NAT gateway(s) in VPC`
- `[INFO] NAT Gateway: nat-xxx (Subnet: subnet-xxx, State: available)`
- `[OK] Connection usage: ~15% of limit (Maximum: 8,250 / 55,000)`
- `[WARN] NAT gateway approaching connection limit (47,500 / 55,000, ~86%) - may experience SNAT port exhaustion`
- `[ISSUE] NAT gateway at connection limit (55,000 / 55,000) - SNAT port exhaustion likely`

## Recommended Actions

### If NAT Gateway at Connection Limit

1. **Add more NAT gateways** (distribute traffic):
   ```bash
   # Create additional NAT gateways in different AZs
   aws ec2 create-nat-gateway \
     --subnet-id <subnet-id> \
     --allocation-id <eip-allocation-id>
   ```
   - Distribute traffic across multiple NAT gateways
   - Use route tables to route different subnets to different NAT gateways
   - Reduces connection contention per gateway

2. **Use VPC endpoints** (reduces NAT gateway traffic):
   ```bash
   # Create VPC endpoints for AWS services (S3, DynamoDB, etc.)
   aws ec2 create-vpc-endpoint \
     --vpc-id <vpc-id> \
     --service-name com.amazonaws.<region>.s3 \
     --route-table-ids <route-table-id>
   ```
   - VPC endpoints bypass NAT gateway for AWS service traffic
   - Reduces NAT gateway connection count
   - Lower latency and cost

3. **Implement connection pooling/reuse**:
   - Use HTTP connection pooling (keep-alive)
   - Reuse database connections (connection pools)
   - Avoid creating new connections for each request
   - Reduces connection churn

4. **Use private endpoints** for external services:
   - Use AWS PrivateLink for third-party services
   - Reduces NAT gateway traffic
   - Improves security and performance

### If Approaching Connection Limit

1. **Monitor connection trends**:
   ```bash
   # Check CloudWatch metrics over time
   aws cloudwatch get-metric-statistics \
     --namespace AWS/NATGateway \
     --metric-name ActiveConnectionCount \
     --dimensions Name=NatGatewayId,Value=<nat-id> \
     --start-time <start-time> \
     --end-time <end-time> \
     --period 300 \
     --statistics Maximum,Average
   ```

2. **Identify high-traffic sources**:
   - Review application logs for connection patterns
   - Identify pods/services making many external connections
   - Check for connection leaks (connections not being closed)

3. **Optimize applications**:
   - Implement connection pooling
   - Reduce connection churn
   - Use async/await patterns to reuse connections
   - Close connections properly

### If No NAT Gateways Found

1. **Verify VPC configuration**:
   ```bash
   # Check if VPC uses Internet Gateway instead
   aws ec2 describe-internet-gateways \
     --filters "Name=attachment.vpc-id,Values=<vpc-id>"
   ```
   - Public subnets use Internet Gateway (no NAT needed)
   - Private subnets require NAT gateway for internet access

2. **Check if internet access is needed**:
   - Some clusters may not need internet access
   - VPC endpoints can provide AWS service access without internet

## Related Files

- `aws_*/nat_gateways.json` - NAT gateway information (ID, subnet, state, public IP)
- `aws_*/nat_<nat-id>_metrics.json` - CloudWatch metrics for each NAT gateway

## References

- [AWS NAT Gateway Limits](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html#nat-gateway-limits)
- [CloudWatch NAT Gateway Metrics](https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-cloudwatch.html)
- [VPC Endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints.html)
- [Troubleshooting NAT Gateway Issues](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway.html#nat-gateway-troubleshooting)

