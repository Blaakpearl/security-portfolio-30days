# Day 02 — Lab Guide: Credential Exposure Hunt
### Track: Threat Hunting | Duration: ~2.5 hours | Difficulty: Intermediate

---

## 🛠 Tools Required

| Tool | Purpose | Install / Access |
|------|---------|-----------------|
| **HaveIBeenPwned API** | Validate email exposure in known breaches | Free key at haveibeenpwned.com/API/Key |
| **Python 3** | API queries, data parsing, report generation | Pre-installed on Kali/Ubuntu |
| **Splunk Free / SIEM** | Log analysis — authentication hunt queries | splunk.com/free-trial or Splunk Cloud |
| **KQL (Azure Monitor)** | Azure AD sign-in log queries | portal.azure.com → Log Analytics |
| **jq** | JSON parsing on command line | `sudo apt install jq` |
| **curl** | HTTP API requests | Pre-installed |
| **DeHashed** | Enriched breach data lookup | dehashed.com (paid) — free alternatives noted |

---

## 🖥 Environment Setup

```bash
# 1. Create your working directory
mkdir -p ~/security-labs/day-02/artifacts
cd ~/security-labs/day-02

# 2. Set your HIBP API key (get free key at haveibeenpwned.com/API/Key)
export HIBP_API_KEY="your-hibp-api-key-here"

# 3. Install Python dependencies
pip install requests pandas tabulate --break-system-packages

# 4. Create a test email list (use your own domain or fictional examples)
cat > artifacts/email_list.txt << 'EOF'
test.user@yourdomain.com
admin@yourdomain.com
john.smith@yourdomain.com
jane.doe@yourdomain.com
it.admin@yourdomain.com
cfo@yourdomain.com
hr.manager@yourdomain.com
helpdesk@yourdomain.com
soc.analyst@yourdomain.com
ceo@yourdomain.com
EOF

echo "[+] Environment ready"
echo "[+] Email list created: $(wc -l < artifacts/email_list.txt) accounts"
```

---

## 📋 Pre-Lab Checklist

- [ ] HIBP API key obtained and set as `$HIBP_API_KEY`
- [ ] Working directory created at `~/security-labs/day-02/`
- [ ] `email_list.txt` populated with test/authorized target emails
- [ ] Python 3 with `requests` and `pandas` installed
- [ ] Access to a SIEM (Splunk/Azure) for Steps 3 & 4 (or review query logic if no SIEM available)

---

## STEP 1 — HaveIBeenPwned API: Bulk Exposure Validation

**Objective:** Query the HIBP API for every account in your exposure list and map
which breach datasets each account appears in, including what data types were leaked.

### 1a. Single Account Query (understand the API first)

```bash
# Test a single query against the HIBP API
EMAIL="test.user@yourdomain.com"

curl -s \
  -H "hibp-api-key: $HIBP_API_KEY" \
  -H "user-agent: SecurityPortfolio-Day02" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/${EMAIL}?truncateResponse=false" \
  | jq '.'
```

**Expected Output:**
```json
[
  {
    "Name": "LinkedIn",
    "Title": "LinkedIn",
    "BreachDate": "2012-05-05",
    "PwnCount": 164611595,
    "DataClasses": ["Email addresses", "Passwords"],
    "IsVerified": true
  },
  {
    "Name": "Adobe",
    "Title": "Adobe",
    "BreachDate": "2013-10-04",
    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"]
  }
]
```

**✅ Checkpoint 1:** You should see breach names and data classes returned.
The critical field is `DataClasses` — if it includes `"Passwords"`, the risk is HIGH.

---

### 1b. Python Script — Bulk HIBP Query with Risk Scoring

```python
# Save as: hibp_bulk_query.py
# Run with: python3 hibp_bulk_query.py

import requests
import json
import time
import os
from datetime import datetime

API_KEY = os.environ.get("HIBP_API_KEY", "your-key-here")
HEADERS = {
    "hibp-api-key": API_KEY,
    "user-agent": "SecurityPortfolio-Blaakpearl-Day02"
}

# High-risk data types that indicate password exposure
HIGH_RISK_DATA = {"Passwords", "Password hints", "Auth tokens"}
CRITICAL_ACCOUNTS = {"ceo", "cfo", "admin", "it.admin", "helpdesk"}  # customize

def query_hibp(email: str) -> list:
    """Query HIBP API for a single email. Returns list of breaches."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
        elif r.status_code == 404:
            return []  # Not found in any breach — good news
        elif r.status_code == 429:
            print(f"  [!] Rate limited — sleeping 2s...")
            time.sleep(2)
            return query_hibp(email)  # Retry
        else:
            print(f"  [!] Unexpected status {r.status_code} for {email}")
            return []
    except Exception as e:
        print(f"  [!] Error querying {email}: {e}")
        return []

def risk_score(email: str, breaches: list) -> str:
    """Score account risk: CRITICAL / HIGH / MEDIUM / LOW / CLEAN"""
    if not breaches:
        return "CLEAN"
    
    username = email.split("@")[0].lower()
    has_password = any(
        data_class in HIGH_RISK_DATA
        for b in breaches
        for data_class in b.get("DataClasses", [])
    )
    is_privileged = any(keyword in username for keyword in CRITICAL_ACCOUNTS)
    breach_count = len(breaches)
    
    if is_privileged and has_password:
        return "CRITICAL"
    elif has_password and breach_count >= 3:
        return "HIGH"
    elif has_password:
        return "HIGH"
    elif breach_count >= 3:
        return "MEDIUM"
    else:
        return "LOW"

def main():
    print(f"\n{'='*60}")
    print(f"  HIBP Credential Exposure Hunt — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}\n")
    
    # Load email list
    with open("artifacts/email_list.txt") as f:
        emails = [e.strip() for e in f if e.strip() and not e.startswith("#")]
    
    print(f"[*] Querying {len(emails)} accounts against HIBP API...")
    print(f"[*] Rate limit: 1 request/1.5s (HIBP API requirement)\n")
    
    results = []
    
    for email in emails:
        print(f"  Checking: {email}", end=" ... ")
        breaches = query_hibp(email)
        risk = risk_score(email, breaches)
        
        # Extract key data
        breach_names = [b["Name"] for b in breaches]
        data_types = list(set(
            dt for b in breaches for dt in b.get("DataClasses", [])
        ))
        password_exposed = any(
            dt in HIGH_RISK_DATA for dt in data_types
        )
        
        result = {
            "email": email,
            "breach_count": len(breaches),
            "breaches": breach_names,
            "data_types": data_types,
            "password_exposed": password_exposed,
            "risk": risk
        }
        results.append(result)
        
        status = f"[{risk}] — {len(breaches)} breaches"
        print(status)
        
        time.sleep(1.5)  # HIBP rate limit compliance
    
    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}
    results.sort(key=lambda x: risk_order.get(x["risk"], 5))
    
    # Save JSON results
    with open("artifacts/hibp_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Print summary table
    print(f"\n{'='*60}")
    print(f"  EXPOSURE SUMMARY")
    print(f"{'='*60}")
    print(f"{'Email':<35} {'Risk':<10} {'Breaches':>8} {'Passwords?'}")
    print(f"{'-'*35} {'-'*10} {'-'*8} {'-'*10}")
    
    for r in results:
        pwd = "⚠️  YES" if r["password_exposed"] else "No"
        print(f"{r['email']:<35} {r['risk']:<10} {r['breach_count']:>8} {pwd}")
    
    # Stats
    critical = sum(1 for r in results if r["risk"] == "CRITICAL")
    high     = sum(1 for r in results if r["risk"] == "HIGH")
    exposed  = sum(1 for r in results if r["breach_count"] > 0)
    
    print(f"\n[+] Total accounts checked:    {len(results)}")
    print(f"[!] Accounts in breach data:   {exposed}")
    print(f"[!!!] CRITICAL risk accounts:  {critical}")
    print(f"[!]  HIGH risk accounts:       {high}")
    print(f"\n[+] Full results: artifacts/hibp_results.json")

if __name__ == "__main__":
    main()
```

```bash
# Run the script
python3 hibp_bulk_query.py
```

**Expected Output:**
```
============================================================
  HIBP Credential Exposure Hunt — 2025-01-16 09:14
============================================================

[*] Querying 10 accounts against HIBP API...

  Checking: ceo@yourdomain.com ... [CRITICAL] — 5 breaches
  Checking: cfo@yourdomain.com ... [HIGH] — 3 breaches
  Checking: it.admin@yourdomain.com ... [CRITICAL] — 4 breaches
  Checking: admin@yourdomain.com ... [HIGH] — 2 breaches
  ...

============================================================
  EXPOSURE SUMMARY
============================================================
Email                               Risk       Breaches Passwords?
----------------------------------- ---------- -------- ----------
ceo@yourdomain.com                  CRITICAL          5 ⚠️  YES
it.admin@yourdomain.com             CRITICAL          4 ⚠️  YES
cfo@yourdomain.com                  HIGH              3 ⚠️  YES
```

**✅ Checkpoint 2:** You should have `artifacts/hibp_results.json` populated.
CRITICAL accounts must go to the top of your remediation list immediately.

---

## STEP 2 — Breach Data Enrichment & Password Hash Analysis

**Objective:** For accounts with password exposure, determine whether the leaked
passwords are plaintext or hashed — and if hashed, whether they're weak algorithms
that have likely already been cracked.

### 2a. Identify Password Storage Quality by Breach Source

```bash
# Query HIBP Breaches API to get password storage method per breach
curl -s \
  -H "hibp-api-key: $HIBP_API_KEY" \
  -H "user-agent: SecurityPortfolio-Day02" \
  "https://haveibeenpwned.com/api/v3/breach/LinkedIn" \
  | jq '{name: .Name, date: .BreachDate, pwn_count: .PwnCount, 
         description: .Description, data_classes: .DataClasses}'
```

### 2b. Risk Matrix — Password Algorithm Risk Tiers

```bash
cat > artifacts/breach_algorithm_risk.md << 'EOF'
# Password Algorithm Risk Assessment

## Tier 1 — CRITICAL (Treat as plaintext)
- **Plaintext** — no hashing at all
- **MD5** — cracked in seconds; rainbow tables exist for all common passwords
- **SHA-1 (unsalted)** — equivalent to plaintext for common passwords
- **DES / 3DES** — legacy, trivially broken

Breaches using these: LinkedIn (2012), Adobe (2013), RockYou (2009)

## Tier 2 — HIGH (Likely cracked within hours-days)
- **SHA-256 (unsalted)** — fast hash, cracked with modern GPUs quickly
- **MD5(MD5(password))** — double hashing doesn't help much
- **SHA-1 + salt** — better but still weak

## Tier 3 — MEDIUM (May be cracked, assume compromised)
- **bcrypt (cost factor < 10)** — slow hash but low cost factor = faster cracking
- **SHA-512 (unsalted)** — still fast hashing

## Tier 4 — LOW (Harder to crack but still assume exposure)
- **bcrypt (cost factor >= 10)** — strong, but assume cracked for common passwords
- **scrypt / Argon2** — modern algorithms; low risk but not zero

## Decision Rule for This Hunt:
Regardless of algorithm tier, treat ALL password exposures as COMPROMISED
if the breach is > 6 months old. Cracking infrastructure has grown exponentially.
EOF

echo "[+] Risk tier reference saved"
```

---

## STEP 3 — Internal Log Hunt: Has It Been Weaponized?

**Objective:** Search authentication logs for signs that exposed credentials have
already been used against your environment.

### 3a. Splunk — Authentication Anomaly Hunting

```splunk
| SPL Query 1: Password Spray Detection
| Hunt for one password attempted against many accounts in short time window

index=windows_security EventCode=4625
| bin _time span=10m
| stats dc(user) as unique_users, count as attempts, values(src_ip) as sources
    by _time, src_ip
| where unique_users > 10 AND attempts > 20
| eval spray_score = (unique_users / attempts) * 100
| where spray_score > 40
| sort - spray_score
| table _time, src_ip, unique_users, attempts, spray_score, sources
| rename spray_score as "Spray Confidence %"
```

```splunk
| SPL Query 2: Impossible Travel Detection
| Login from two geographically impossible locations within short window

index=o365_audit OR index=azure_signin
| eval login_time=_time
| sort user, login_time
| streamstats current=f last(src_ip) as prev_ip, 
              last(login_time) as prev_time,
              last(country) as prev_country by user
| eval time_diff_hours = round((login_time - prev_time) / 3600, 2)
| where country != prev_country AND time_diff_hours < 4
| eval alert = "IMPOSSIBLE TRAVEL: " + prev_country + " → " + country 
               + " in " + time_diff_hours + " hrs"
| table _time, user, src_ip, prev_ip, country, prev_country, 
        time_diff_hours, alert
| sort - _time
```

```splunk
| SPL Query 3: New Device First Login for Breached Accounts
| Alert when a breached account logs in from a device never seen before

| inputlookup breached_accounts.csv
| rename email as user
| join type=inner user [
    search index=azure_signin
    | stats earliest(_time) as first_seen by user, device_id, device_os
    | where first_seen > relative_time(now(), "-7d")
  ]
| eval alert = "NEW DEVICE LOGIN — breached account: " + user
| table user, device_id, device_os, first_seen, alert
```

```splunk
| SPL Query 4: Mailbox Forwarding Rule Created (Post-Compromise)
| Attackers often add forwarding rules immediately after gaining access

index=o365_audit Operation="Set-Mailbox" OR Operation="New-InboxRule"
| where match(Parameters, "ForwardTo|RedirectTo|ForwardingSmtpAddress")
| eval risk = "HIGH — Forwarding rule created post-breach window"
| table _time, UserId, ClientIP, Operation, Parameters, risk
| sort - _time
```

**✅ Checkpoint 3:** Save these queries to `artifacts/splunk_hunt_queries.spl`
Run each query and document: number of results, any true positive findings.

---

### 3b. KQL — Azure AD / Microsoft Sentinel Queries

```kql
// KQL Query 1: Sign-in failures for breached accounts
// Load your breached account list first

let breached_accounts = dynamic([
    "ceo@yourdomain.com",
    "cfo@yourdomain.com",
    "it.admin@yourdomain.com"
    // add from your hibp_results.json
]);
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in (breached_accounts)
| where ResultType != 0  // failed logins only
| summarize 
    FailureCount = count(),
    UniqueIPs = dcount(IPAddress),
    Countries = make_set(LocationDetails.countryOrRegion),
    ErrorCodes = make_set(ResultType)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailureCount > 5
| order by FailureCount desc
```

```kql
// KQL Query 2: Successful logins to breached accounts — review these manually
let breached_accounts = dynamic(["ceo@yourdomain.com","cfo@yourdomain.com"]);
SigninLogs
| where TimeGenerated > ago(48h)  // Last 48hrs = breach window
| where UserPrincipalName in (breached_accounts)
| where ResultType == 0  // SUCCESSFUL logins only
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location = strcat(LocationDetails.city, ", ", LocationDetails.countryOrRegion),
    AppDisplayName,
    DeviceDetail,
    ConditionalAccessStatus,
    MfaDetail = AuthenticationDetails
| order by TimeGenerated desc
```

```kql
// KQL Query 3: Credential stuffing pattern — many accounts, few IPs
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    TotalAttempts = count(),
    AccountList = make_set(UserPrincipalName, 20)
    by IPAddress, bin(TimeGenerated, 30m)
| where TargetedAccounts > 5
| extend StuffingConfidence = iff(TargetedAccounts > 20, "HIGH", "MEDIUM")
| order by TargetedAccounts desc
```

```kql
// KQL Query 4: MFA bypass attempts on breached accounts
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName in (dynamic(["ceo@yourdomain.com","it.admin@yourdomain.com"]))
| where AuthenticationRequirement == "singleFactorAuthentication"
    or ConditionalAccessStatus == "notApplied"
| project TimeGenerated, UserPrincipalName, IPAddress, 
          AppDisplayName, ConditionalAccessStatus, ResultType
| order by TimeGenerated desc
```

```bash
# Save all KQL queries to artifacts
cat > artifacts/kql_hunt_queries.kql << 'KQLEOF'
// ============================================================
// Blaakpearl Security Portfolio — Day 02
// KQL Queries: Credential Exposure Hunt
// Azure Monitor / Microsoft Sentinel
// ============================================================

// [QUERY 1] Failed logins for breached accounts
// [QUERY 2] Successful logins — breached accounts (review manually)
// [QUERY 3] Credential stuffing pattern detection
// [QUERY 4] MFA bypass on breached accounts

// [Copy full queries from LAB.md above]
KQLEOF

echo "[+] KQL queries saved to artifacts/kql_hunt_queries.kql"
```

---

## STEP 4 — Sigma Rule: Credential Stuffing Detection

**Objective:** Write a production-quality Sigma rule for ongoing detection that
can be deployed to any SIEM platform.

```bash
cat > artifacts/sigma_credential_stuffing.yml << 'SIGMAEOF'
title: Credential Stuffing — High Volume Failed Logins Multiple Accounts
id: a7f3c821-9b2e-4d1f-88ac-3e5b7c9d0f12
status: experimental
description: |
    Detects credential stuffing attacks where a single source IP attempts
    authentication against many different user accounts in a short time window.
    Indicative of automated combolist-based attacks or password spray campaigns.
    
    Tuning required per environment — adjust thresholds based on baseline.

author: Blaakpearl
date: 2025/01/16
modified: 2025/01/16

references:
    - https://attack.mitre.org/techniques/T1110/004/
    - https://haveibeenpwned.com
    - https://owasp.org/www-community/attacks/Credential_stuffing

tags:
    - attack.credential_access
    - attack.t1110
    - attack.t1110.003
    - attack.t1110.004
    - attack.initial_access
    - attack.t1078

logsource:
    category: authentication
    product: windows
    service: security

detection:
    selection:
        EventID: 4625          # Failed logon
        LogonType:
            - 3                # Network logon
            - 8                # NetworkCleartext
    
    timeframe: 10m
    
    condition: |
        selection
        | stats count() as attempt_count, dc(TargetUserName) as unique_accounts
          by IpAddress
        | where unique_accounts >= 10 and attempt_count >= 20

falsepositives:
    - Misconfigured service accounts with incorrect credentials
    - IT helpdesk bulk password reset operations
    - Penetration testing (verify against change calendar)
    - Vulnerability scanners without authentication

level: high

fields:
    - IpAddress
    - TargetUserName
    - WorkstationName
    - LogonType

enrichment:
    - ip_reputation_lookup: IpAddress
    - geo_lookup: IpAddress
    - threat_intel_lookup: IpAddress

response_playbook:
    immediate:
        - Block source IP at perimeter firewall
        - Alert SOC L1 analyst for review
        - Pull full authentication log for affected accounts
    investigate:
        - Check if any attempts succeeded (EventID 4624)
        - Correlate with HIBP breach data for targeted accounts
        - Review for impossible travel on successful authentications
    contain:
        - Force password reset for all targeted accounts
        - Enable MFA if not already enforced
        - Add source IP to threat intel watchlist
SIGMAEOF

echo "[+] Sigma rule saved to artifacts/sigma_credential_stuffing.yml"
```

---

## STEP 5 — Remediation Priority Matrix

**Objective:** Produce the prioritized account list that goes to IT for immediate action.

```python
# Save as: build_remediation_matrix.py
# Run with: python3 build_remediation_matrix.py

import json
from datetime import datetime

with open("artifacts/hibp_results.json") as f:
    results = json.load(f)

print(f"\n# CREDENTIAL EXPOSURE — REMEDIATION PRIORITY MATRIX")
print(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
print(f"# Analyst: Blaakpearl\n")

ACTIONS = {
    "CRITICAL": [
        "IMMEDIATE forced password reset (within 2 hours)",
        "Terminate all active sessions (revoke refresh tokens)",
        "Escalate to account owner's manager + CISO",
        "Enable MFA if not present — block login until enrolled",
        "Review last 30 days of activity in audit logs",
        "Check for new inbox rules / forwarding rules",
    ],
    "HIGH": [
        "Forced password reset within 24 hours",
        "Verify MFA enrollment status",
        "Review sign-in logs for last 7 days",
        "Check for suspicious app consents",
    ],
    "MEDIUM": [
        "Prompt password change at next login",
        "Confirm MFA is enabled",
        "Send security awareness notification",
    ],
    "LOW": [
        "Include in next scheduled password rotation cycle",
        "Send informational breach notification to user",
    ],
    "CLEAN": [
        "No action required — monitor",
    ]
}

risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}
sorted_results = sorted(results, key=lambda x: risk_order.get(x["risk"], 5))

for r in sorted_results:
    if r["risk"] == "CLEAN":
        continue
    print(f"{'='*60}")
    print(f"Account:  {r['email']}")
    print(f"Risk:     {r['risk']}")
    print(f"Breaches: {r['breach_count']} ({', '.join(r['breaches'][:3])}{'...' if len(r['breaches'])>3 else ''})")
    print(f"Data:     {', '.join(r['data_types'][:4])}")
    print(f"Passwords Exposed: {'YES ⚠️' if r['password_exposed'] else 'No'}")
    print(f"\nRequired Actions:")
    for i, action in enumerate(ACTIONS[r["risk"]], 1):
        print(f"  {i}. {action}")
    print()

# Summary stats
total      = len(results)
critical   = sum(1 for r in results if r["risk"] == "CRITICAL")
high       = sum(1 for r in results if r["risk"] == "HIGH")
medium     = sum(1 for r in results if r["risk"] == "MEDIUM")
exposed    = sum(1 for r in results if r["breach_count"] > 0)
pwd_exp    = sum(1 for r in results if r["password_exposed"])

print(f"{'='*60}")
print(f"SUMMARY:")
print(f"  Accounts checked:          {total}")
print(f"  In breach data:            {exposed} ({round(exposed/total*100)}%)")
print(f"  Password exposed:          {pwd_exp}")
print(f"  CRITICAL priority:         {critical}")
print(f"  HIGH priority:             {high}")
print(f"  MEDIUM priority:           {medium}")
```

```bash
python3 build_remediation_matrix.py | tee artifacts/remediation_matrix.txt
echo "[+] Remediation matrix saved"
```

**✅ Checkpoint 4:** Your matrix is the deliverable that goes to IT Security
and the CISO. Sort it by risk tier — CRITICAL accounts need a phone call,
not an email.

---

## STEP 6 — Leadership 5-Minute Brief

```bash
cat > artifacts/leadership_brief.md << 'EOF'
# 5-Minute Leadership Brief — Credential Exposure Incident

**Date:** 2025-01-16  **Analyst:** Blaakpearl  **Priority:** HIGH

---

## What Happened
A batch of employee credentials was discovered in a criminal breach compilation
circulating on dark web forums. This data originates from third-party platform
breaches (LinkedIn, Adobe, Dropbox) — NOT from a breach of our own systems.
The data was uploaded approximately 48 hours ago.

## Why It Matters
65% of users reuse passwords across personal and work accounts. If any employee
used the same password leaked in a third-party breach for their corporate account,
an attacker could log in right now with valid credentials — bypassing most controls.

## What We Found
| Severity | Accounts | Immediate Risk |
|----------|----------|----------------|
| CRITICAL | X | Privileged accounts with password exposure |
| HIGH     | X | Standard accounts with password exposure |
| MEDIUM   | X | Accounts in breach data, no password confirmed |

## What We're Doing — Right Now
1. Forcing password resets on all CRITICAL and HIGH accounts today
2. Reviewing authentication logs for signs of early exploitation
3. Verifying MFA is enforced on all at-risk accounts

## What We Need From Leadership
- Approval to force password resets without prior user notice (CRITICAL accounts)
- Authorization to revoke and re-issue active sessions for affected accounts
- Communication plan for affected employees

## Current Status: No confirmed exploitation detected — acting preventively.
EOF

echo "[+] Leadership brief saved to artifacts/leadership_brief.md"
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** How many accounts have password data exposed (not just email)?
- [ ] 🚩 **Flag 2:** Which breach source appears most frequently across your account list?
- [ ] 🚩 **Flag 3:** What Splunk EventCode indicates a successful Windows logon?
- [ ] 🚩 **Flag 4:** What is the MITRE technique ID for credential stuffing specifically?
- [ ] 🚩 **Flag 5:** In your KQL query, what `ResultType` value means a successful login?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `email_list.txt` | Target account list used in lab |
| `hibp_results.json` | Full HIBP API query results |
| `breach_algorithm_risk.md` | Password algorithm risk tier reference |
| `splunk_hunt_queries.spl` | All 4 Splunk detection queries |
| `kql_hunt_queries.kql` | All 4 Azure AD / Sentinel KQL queries |
| `sigma_credential_stuffing.yml` | Production Sigma detection rule |
| `remediation_matrix.txt` | Prioritized account remediation list |
| `leadership_brief.md` | 5-minute executive brief |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| HIBP returns 401 Unauthorized | Check `$HIBP_API_KEY` is set; verify key at haveibeenpwned.com/API/Key |
| HIBP returns 429 Too Many Requests | Add `time.sleep(1.5)` between requests — HIBP rate limit is ~1 req/1.5s |
| No Splunk/Azure access for Steps 3-4 | Review the query logic and document what you would look for — still valid portfolio work |
| `requests` module not found | Run `pip install requests --break-system-packages` |
| jq not found | `sudo apt install jq` or `brew install jq` |

---

*Next: [REPORT.md](REPORT.md) — Professional incident report from these findings*
