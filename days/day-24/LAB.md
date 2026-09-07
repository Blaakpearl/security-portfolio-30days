# Day 24 — LAB.md
## Cloud Infrastructure Hunt Lab Guide
**NovaCrest Capital Group | Threat Hunt Track**

---

## Step 1: CloudTrail Log Collection

```bash
# Ensure CloudTrail is enabled with management events (should already be on)
aws cloudtrail describe-trails --region us-east-1

# Download CloudTrail logs for hunt window (June 14–21)
aws s3 sync s3://novacrest-cloudtrail-logs/AWSLogs/123456789012/CloudTrail/us-east-1/ \
    /tmp/cloudtrail/ \
    --exclude "*" \
    --include "*2026061*" \
    --include "*2026062[01]*"

# Count log files
ls /tmp/cloudtrail/ | wc -l

# Decompress all .gz files
find /tmp/cloudtrail/ -name "*.gz" -exec gunzip {} \;

# Merge all JSON files into one for analysis
jq -s '[.[] | .Records[]]' /tmp/cloudtrail/*.json > /tmp/all_cloudtrail_events.json
echo "Total events: $(jq length /tmp/all_cloudtrail_events.json)"
```

---

## Step 2: Filter for Suspicious Source IPs

```bash
# Filter all events from attacker IP (198.51.100.99)
jq '[.[] | select(.sourceIPAddress == "198.51.100.99")]' \
    /tmp/all_cloudtrail_events.json > /tmp/attacker_events.json

echo "Attacker events: $(jq length /tmp/attacker_events.json)"

# List unique event names (what did attacker DO?)
jq '[.[].eventName] | unique | sort[]' /tmp/attacker_events.json

# List unique resources accessed
jq '[.[].resources // [] | .[].ARN] | unique[] | select(. != null)' \
    /tmp/attacker_events.json
```

---

## Step 3: IAM Enumeration Detection

```bash
# Find all IAM read/list calls from external IPs
jq '[.[] | select(
    (.sourceIPAddress | test("^(10\\.|172\\.16\\.|192\\.168\\.)") | not) and
    (.eventSource == "iam.amazonaws.com") and
    (.eventName | test("^(List|Get|Describe)"))
)]' /tmp/all_cloudtrail_events.json

# Find IAM modification calls (CreateUser, CreateRole, PutPolicy, etc.)
jq '[.[] | select(
    .eventSource == "iam.amazonaws.com" and
    (.eventName | test("^(Create|Put|Attach|Add|Delete|Detach|Remove|Update)"))
)]' /tmp/all_cloudtrail_events.json | jq 'sort_by(.eventTime)'
```

---

## Step 4: GuardDuty Alert Review

```bash
# List all GuardDuty findings in the hunt window
aws guardduty list-findings \
    --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
    --finding-criteria '{
        "Criterion": {
            "updatedAt": {
                "GreaterThanOrEqual": 1718323200000,
                "LessThan": 1718928000000
            }
        }
    }' \
    --query 'FindingIds' --output json

# Get details for each finding
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty get-findings \
    --detector-id $DETECTOR_ID \
    --finding-ids $(aws guardduty list-findings --detector-id $DETECTOR_ID \
        --query 'FindingIds[]' --output text | tr '\t' ' ') \
    | jq '.Findings[] | {id: .Id, type: .Type, severity: .Severity,
           title: .Title, description: .Description}'
```

---

## Step 5: Pacu — Cloud Exploitation Framework (Red Team Context)

Pacu is an AWS exploitation framework used to simulate attacker enumeration.
**For the hunt lab:** we use Pacu in read-only/enumeration mode to understand
what an attacker with the `trading-api-deploy` key would have seen.

```bash
# Install Pacu
pip install pacu --break-system-packages

# Launch Pacu
pacu

# Set compromised credentials (use test/lab credentials — NOT prod)
Pacu (session) > set_keys
Access Key ID: AKIA[TEST_KEY_ID]
Secret Key: [TEST_SECRET_KEY]

# Enumerate IAM permissions (read-only)
Pacu (session) > run iam__enum_permissions
Pacu (session) > run iam__enum_users_roles_policies_groups

# Enumerate S3 buckets
Pacu (session) > run s3__enum

# Enumerate EC2 instances
Pacu (session) > run ec2__enum

# Enumerate Secrets Manager (lists only — no GetSecretValue in this mode)
Pacu (session) > run secretsmanager__enum

# Generate enumeration report
Pacu (session) > data
```

**What Pacu shows an attacker with admin key can see:**
- All IAM users, roles, policies, and groups
- All S3 buckets and their ACLs
- All EC2 instances, security groups, VPCs
- All Secrets Manager secret names (not values without explicit call)
- All Lambda functions and their environment variables
- All RDS instances and their configuration

---

## Step 6: Run Hunt Scripts

```bash
# CloudTrail hunt (all 6 hypotheses, demo mode)
python3 scripts/cloudtrail_hunter.py --demo --verbose

# IAM backdoor detection specifically
python3 scripts/iam_backdoor_detector.py --demo --verbose

# Load results into Splunk
python3 scripts/cloudtrail_hunter.py --demo --json | \
    curl -k -H "Authorization: Splunk $HEC_TOKEN" \
         -H "Content-Type: application/json" \
         -d @- https://localhost:8088/services/collector/event
```

---

## Step 7: AWS Config — Continuous Compliance Checks

```bash
# Enable AWS Config for IAM compliance rules
aws configservice put-config-rule --config-rule '{
    "ConfigRuleName": "iam-root-access-key-check",
    "Source": {
        "Owner": "AWS",
        "SourceIdentifier": "IAM_ROOT_ACCESS_KEY_CHECK"
    }
}'

aws configservice put-config-rule --config-rule '{
    "ConfigRuleName": "iam-no-inline-policy-check",
    "Source": {
        "Owner": "AWS",
        "SourceIdentifier": "IAM_NO_INLINE_POLICY_CHECK"
    }
}'

aws configservice put-config-rule --config-rule '{
    "ConfigRuleName": "guardduty-enabled-centralized",
    "Source": {
        "Owner": "AWS",
        "SourceIdentifier": "GUARDDUTY_ENABLED_CENTRALIZED"
    }
}'

# List non-compliant resources
aws configservice describe-compliance-by-config-rule \
    --compliance-types NON_COMPLIANT \
    --query 'ComplianceByConfigRules[].{Rule:ConfigRuleName,Status:Compliance.ComplianceType}'
```

---

*Day 24 Lab Guide | Cloud Infrastructure Threat Hunt*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
