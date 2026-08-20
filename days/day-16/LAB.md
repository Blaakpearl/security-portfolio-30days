# Day 16 — LAB.md
## Initial Access Simulation Lab Setup Guide
**NovaCrest Capital Group | Purple Team Week 3**

---

## Overview

Day 16 runs two parallel lab environments:

- **Lab A — Credential Exploitation:** Simulates AWS CLI and database client
  usage against a controlled lab account using the credential patterns
  discovered during Day 15 GitHub scanning.
- **Lab B — Phishing Simulation:** Crafts and analyzes spearphishing email
  artifacts; assesses email gateway controls without sending real email.

Both labs can run on a single VM. No production NovaCrest credentials or
systems are used at any point.

---

## Prerequisites

### Software
```bash
# Python 3.10+
python3 --version

# AWS CLI (for Lab A credential simulation)
sudo apt-get install -y awscli
# or: pip install awscli

# PostgreSQL client (for Lab A DB simulation)
sudo apt-get install -y postgresql-client

# MySQL client (for Lab A DB simulation)
sudo apt-get install -y mysql-client

# Python libraries
pip install boto3 psycopg2-binary pymysql requests jinja2
```

### Lab AWS Account (Path A)
You need a **personal test AWS account** (not NovaCrest's) to practice
credential enumeration safely. AWS Free Tier is sufficient.

```bash
# Create a test IAM user with limited permissions for simulation
# In your personal AWS console:
# IAM → Users → Create User → "pentest-lab-user"
# Attach: ReadOnlyAccess (AWS managed policy)
# Create access key → save to ~/.day16-lab-creds

cat > ~/.day16-lab-creds << 'EOF'
export AWS_ACCESS_KEY_ID="AKIA_YOUR_TEST_KEY"
export AWS_SECRET_ACCESS_KEY="your_test_secret"
export AWS_DEFAULT_REGION="us-east-1"
EOF

source ~/.day16-lab-creds
```

### Lab Database (Path A)
Run a local PostgreSQL instance to simulate database login attempts:

```bash
# Install and start PostgreSQL locally
sudo apt-get install -y postgresql postgresql-contrib
sudo systemctl start postgresql

# Create lab database and user (mirrors NovaCrest exposure)
sudo -u postgres psql << 'EOF'
CREATE USER trading_api WITH PASSWORD 'trading_db_pass_2024';
CREATE DATABASE tradingdb OWNER trading_api;
GRANT ALL PRIVILEGES ON DATABASE tradingdb TO trading_api;
EOF

# Verify connection (simulate attacker login with exposed credential)
psql -h 127.0.0.1 -U trading_api -d tradingdb
# Password: trading_db_pass_2024 (from Day 15 GitHub finding)
```

---

## Lab A — Credential Exploitation Setup

### Step 1: Configure AWS CLI with Lab Credentials
```bash
source ~/.day16-lab-creds

# Verify credential works
aws sts get-caller-identity
# Expected output: Account ID, UserID, ARN of test user
```

### Step 2: Run Credential Exploitation Simulator
```bash
# Full simulation (no live AWS calls — demo mode)
python3 scripts/credential_exploitation_simulator.py --demo --verbose

# Live mode (uses your personal lab AWS account)
python3 scripts/credential_exploitation_simulator.py \
    --mode live \
    --aws-key $AWS_ACCESS_KEY_ID \
    --aws-secret $AWS_SECRET_ACCESS_KEY \
    --region us-east-1

# Database simulation only
python3 scripts/credential_exploitation_simulator.py \
    --mode db-only \
    --db-host 127.0.0.1 \
    --db-user trading_api \
    --db-pass "trading_db_pass_2024"
```

### Step 3: Review CloudTrail Events Generated
```bash
# After running live mode, check what CloudTrail captured
aws cloudtrail lookup-events \
    --lookup-attributes AttributeKey=Username,AttributeValue=pentest-lab-user \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ) \
    --query 'Events[*].{Time:EventTime,Event:EventName,Source:EventSource}' \
    --output table
```

---

## Lab B — Phishing Simulation Setup

### Step 1: Generate Phishing Email Artifacts
```bash
# Generate both phishing variants (no email sent)
python3 scripts/phishing_email_crafter.py \
    --target-name "John Smith" \
    --target-email "j.smith@novacrest.com" \
    --target-title "CTO" \
    --sender-domain "novacrest-security.com" \
    --variant both \
    --output /tmp/phishing-artifacts/

# Review generated artifacts
ls /tmp/phishing-artifacts/
# → link_variant.eml
# → attachment_variant.eml
# → phishing_report.json
```

### Step 2: Analyze Email Against SPF/DKIM/DMARC
```bash
# Check SPF record for spoofed domain
dig TXT novacrest.com | grep spf

# Check DMARC policy
dig TXT _dmarc.novacrest.com

# Check DKIM selector (if known)
dig TXT default._domainkey.novacrest.com

# Analyze with Python script
python3 scripts/phishing_email_crafter.py --analyze-dns novacrest.com
```

### Step 3: Email Gateway Control Assessment
```bash
# Generate email gateway test matrix
python3 scripts/phishing_email_crafter.py \
    --gateway-assessment \
    --controls "spf,dkim,dmarc,sandbox,url-filter,attachment-scan" \
    --output /tmp/gateway_assessment.json

cat /tmp/gateway_assessment.json | python3 -m json.tool
```

---

## Detection Validation Exercises

### Exercise 1: CloudTrail Alert on Exposed Key Use
```bash
# Simulate using the GitHub-exposed key pattern (use lab key)
aws s3 ls                          # List all buckets
aws iam get-user                   # Who am I?
aws iam list-attached-user-policies --user-name pentest-lab-user
aws ec2 describe-instances --region us-east-1
aws rds describe-db-instances

# Expected detection: CloudTrail → SIEM alert for
#   - ListBuckets from unknown IP
#   - GetCallerIdentity from unknown IP
#   - IAM enumeration from unknown IP
```

### Exercise 2: Database Authentication Alert
```bash
# Simulate attacker database login (lab PostgreSQL)
psql -h 127.0.0.1 -U trading_api -d tradingdb \
    -c "SELECT table_name FROM information_schema.tables;"

# Expected detection: PostgreSQL auth log → SIEM
#   - Connection from external IP to port 5432
#   - Successful authentication (attacker had correct password)
#   - Immediate SELECT on information_schema (enumeration pattern)
```

### Exercise 3: Email Gateway Control Test
```bash
# Pipe generated .eml through local mail tools for header analysis
python3 -c "
import email
with open('/tmp/phishing-artifacts/link_variant.eml') as f:
    msg = email.message_from_file(f)
    print('From:', msg['From'])
    print('Subject:', msg['Subject'])
    print('X-Mailer:', msg.get('X-Mailer', 'Not set'))
    print('Return-Path:', msg.get('Return-Path', 'Not set'))
"
```

---

## Cleanup
```bash
# Remove lab credentials
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
rm -f ~/.day16-lab-creds

# Remove phishing artifacts
rm -rf /tmp/phishing-artifacts/

# Stop local PostgreSQL (if started for lab)
sudo systemctl stop postgresql

# Deactivate Python environment
deactivate
```

---

*Day 16 Lab Guide | Week 3 Purple Team Adversary Simulation*
*NovaCrest Capital Group Engagement | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
