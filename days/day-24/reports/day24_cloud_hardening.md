# Day 24 — AWS Cloud Security Hardening Checklist
**NovaCrest Capital Group | Post-Incident Cloud Hardening**
**Author:** V. Willis, CISSP

---

## 1. IAM Hardening

### Access Key Hygiene
```bash
# Audit all active access keys (find long-lived/unused keys)
aws iam generate-credential-report
aws iam get-credential-report --query 'Content' --output text | \
    base64 -d | csvkit | head -20

# Delete keys not used in 90 days
# Key rotation policy: maximum 90 days
aws configservice put-config-rule --config-rule '{
    "ConfigRuleName": "access-keys-rotated",
    "Source": {"Owner": "AWS", "SourceIdentifier": "ACCESS_KEYS_ROTATED"},
    "InputParameters": "{\"maxAccessKeyAge\":\"90\"}"
}'

# Disable root account access keys (should be NONE)
aws iam list-access-keys --user-name root
# If any exist: immediately delete
```

### MFA Enforcement
```bash
# Require MFA for all IAM users via SCP (Service Control Policy)
# Apply to entire organization root:
cat > require-mfa-scp.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyAllExceptListedIfNoMFA",
    "Effect": "Deny",
    "NotAction": [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken"
    ],
    "Resource": "*",
    "Condition": {
      "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
    }
  }]
}
EOF
aws organizations create-policy --content file://require-mfa-scp.json \
    --name "RequireMFA" --type SERVICE_CONTROL_POLICY
```

### IAM Monitoring Rules
```bash
# Alert on new IAM user creation
aws cloudwatch put-metric-alarm \
    --alarm-name "IAM-CreateUser" \
    --alarm-description "Alert when new IAM user created" \
    --metric-name "IAMUserCreation" \
    --namespace "CloudTrailMetrics" \
    --statistic Sum \
    --period 300 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --alarm-actions arn:aws:sns:us-east-1:123456789012:security-alerts

# Create CloudWatch filter for IAM changes
aws logs put-metric-filter \
    --log-group-name CloudTrail/novacrest-logs \
    --filter-name IAMPolicyChanges \
    --filter-pattern '{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) ||
        ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) ||
        ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) ||
        ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) ||
        ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) ||
        ($.eventName=SetDefaultPolicyVersion) || ($.eventName=AttachRolePolicy) ||
        ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) ||
        ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) ||
        ($.eventName=DetachGroupPolicy) }' \
    --metric-transformations metricName=IAMPolicyChanges,metricNamespace=CloudTrailMetrics,metricValue=1
```

---

## 2. CloudTrail Hardening

### Multi-Trail Configuration (Cannot Be Disabled by Single Action)
```bash
# Trail 1: S3 delivery (already existed — saved investigation)
# Trail 2: CloudWatch Logs delivery (was stopped by attacker)
# Trail 3: Add CloudWatch cross-account delivery to security account

# Create immutable CloudTrail with S3 Object Lock
aws s3api put-object-lock-configuration \
    --bucket novacrest-cloudtrail-logs \
    --object-lock-configuration Mode=GOVERNANCE,Days=365

# Enable CloudTrail log validation (detect tampering)
aws cloudtrail update-trail \
    --name novacrest-main-trail \
    --enable-log-file-validation

# Verify integrity of log files
aws cloudtrail validate-logs \
    --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/novacrest-main-trail \
    --start-time 2026-06-14T00:00:00Z

# Alert on StopLogging — P1 Critical (< 5 min response required)
# CloudWatch filter:
FILTER='{ ($.eventName = StopLogging) || ($.eventName = DeleteTrail) ||
           ($.eventName = UpdateTrail) }'
```

### Data Events (S3 + Lambda)
```bash
# Enable S3 data events in CloudTrail for all buckets
aws cloudtrail put-event-selectors \
    --trail-name novacrest-main-trail \
    --event-selectors '[{
        "ReadWriteType": "All",
        "IncludeManagementEvents": true,
        "DataResources": [{
            "Type": "AWS::S3::Object",
            "Values": ["arn:aws:s3:::novacrest-trading-data/",
                       "arn:aws:s3:::novacrest-ml-models/"]
        }]
    }]'
# With data events: EVERY GetObject is logged (required for exfil detection)
```

---

## 3. GuardDuty Hardening

```bash
# Delegate GuardDuty administration to security account
# (Security account cannot be disabled from member accounts)
aws guardduty enable-organization-admin-account \
    --admin-account-id 111111111111  # Security account

# Enable all GuardDuty finding types including:
#   - CryptoCurrency:EC2/BitcoinTool.B!DNS
#   - Persistence:IAMUser/UserPermissions
#   - UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration

# Protect GuardDuty from disable via SCP
cat > protect-guardduty-scp.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyGuardDutyChanges",
    "Effect": "Deny",
    "Action": [
      "guardduty:DeleteDetector",
      "guardduty:DisassociateFromMasterAccount",
      "guardduty:StopMonitoringMembers",
      "guardduty:UpdateDetector"
    ],
    "Resource": "*",
    "Condition": {
      "StringNotEquals": {
        "aws:PrincipalAccount": "111111111111"  // Only security account can modify
      }
    }
  }]
}
EOF
```

---

## 4. Secrets Manager Hardening

```bash
# Enable automatic rotation for all secrets
aws secretsmanager rotate-secret \
    --secret-id novacrest/bloomberg/api-key \
    --rotation-rules AutomaticallyAfterDays=30

# Restrict GetSecretValue to specific roles only (not all admin)
aws secretsmanager put-resource-policy \
    --secret-id novacrest/bloomberg/api-key \
    --resource-policy '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/bloomberg-service-role"},
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*"
        },{
            "Effect": "Deny",
            "Principal": "*",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:PrincipalArn": "arn:aws:iam::123456789012:role/bloomberg-service-role"
                }
            }
        }]
    }'

# Alert on GetSecretValue from unexpected role/IP
aws cloudwatch put-metric-filter \
    --log-group-name CloudTrail/novacrest-logs \
    --filter-name SecretsManagerAccess \
    --filter-pattern '{ $.eventSource = "secretsmanager.amazonaws.com" &&
        $.eventName = "GetSecretValue" }'
```

---

## 5. S3 Bucket Hardening

```bash
# Block all public access on all buckets
aws s3control put-public-access-block \
    --account-id 123456789012 \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,\
    BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable S3 server access logging on sensitive buckets
aws s3api put-bucket-logging \
    --bucket novacrest-trading-data \
    --bucket-logging-status '{
        "LoggingEnabled": {
            "TargetBucket": "novacrest-s3-access-logs",
            "TargetPrefix": "trading-data/"
        }
    }'

# Restrict GetObject to VPC endpoints only (no internet access)
aws s3api put-bucket-policy \
    --bucket novacrest-trading-data \
    --policy '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::novacrest-trading-data/*",
            "Condition": {
                "StringNotEquals": {
                    "aws:SourceVpc": "vpc-12345678"
                }
            }
        }]
    }'
```

---

## 6. Detective Controls Checklist

```
CLOUDTRAIL
  ☐ CloudTrail enabled in all regions (use --is-multi-region-trail)
  ☐ S3 data events enabled for sensitive buckets
  ☐ Log file validation enabled (--enable-log-file-validation)
  ☐ S3 bucket with Object Lock for tamper resistance
  ☐ Secondary delivery trail to security account
  ☐ Alerts: StopLogging, DeleteTrail (P1 Critical)

GUARDDUTY
  ☐ Enabled in all accounts via AWS Organizations
  ☐ Delegated to security account (cannot be disabled by member)
  ☐ SCP blocks UpdateDetector/DeleteDetector from non-security accounts
  ☐ Findings exported to SIEM (Splunk/Sentinel) via EventBridge

IAM
  ☐ MFA enforced via SCP for all human users
  ☐ No root account access keys
  ☐ Root account MFA enabled
  ☐ Access key rotation policy: 90 days (AWS Config rule)
  ☐ Alerts: CreateUser, AttachPolicy, CreateRole, CreateAccessKey (P1)
  ☐ IAM Access Analyzer enabled (detects cross-account access)
  ☐ AWS Config: iam-no-inline-policy-check, iam-root-access-key-check

SECRETS MANAGER
  ☐ Automatic rotation enabled on all secrets (≤ 30 days)
  ☐ Resource policies restrict GetSecretValue to specific roles
  ☐ Alert on GetSecretValue from unexpected principal
  ☐ Secrets tagged with owner, data-classification, rotation-date

EC2
  ☐ Service Control Policy: restrict allowed instance types
  ☐ Alert on GPU instance launch (p3.*, p4.*, g4.*, g5.*)
  ☐ AWS Config: ec2-instance-detailed-monitoring-enabled
  ☐ VPC Flow Logs enabled (detect mining traffic to pool endpoints)

S3
  ☐ Block public access at account level
  ☐ S3 server access logging on sensitive buckets
  ☐ Bucket policies restrict access to VPC endpoints only
  ☐ AWS Macie enabled (detects PII and sensitive data in S3)
  ☐ Alert on unusual GetObject volume (> 100 MB in 10 minutes)
```

---

*Day 24 — AWS Cloud Security Hardening Checklist*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
