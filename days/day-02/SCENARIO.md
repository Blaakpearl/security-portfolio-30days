# Day 02 — Credential Exposure Hunt
### Track: Threat Hunting | Difficulty: Intermediate | Phase: Initial Access / Credential Access

---

## 🎯 Threat Brief

It's 07:42 on a Tuesday morning. Your threat intelligence platform fires an alert:
a credential monitoring service has flagged **NovaCrest Capital Group** employee
email addresses appearing in a freshly parsed dark web breach compilation —
**"COMBOLIST-FIN-2025-Q1"** — uploaded to a Russian-language cybercrime forum
48 hours ago.

The compilation contains 2.3 million records scraped from 14 separate data breaches
spanning 2021–2024. Your organization's email domain appears **312 times**.

You have a finite window. Nation-state and criminal actors operating credential
stuffing infrastructure typically begin automated login attempts within
**6–72 hours** of a new compilation drop. The clock is running.

**Your mission:** validate the exposure, determine which accounts are at active risk,
correlate against internal authentication logs to detect any early exploitation,
and brief leadership with a remediation priority list before end of business.

---

## 🕵️ Threat Actor Profile

| Attribute          | Details                                                                     |
|--------------------|-----------------------------------------------------------------------------|
| **Actor Type**     | Multiple — credential stuffing bots + targeted human operators              |
| **Motivation**     | Financial theft, insider access, lateral movement pivot                     |
| **Sophistication** | Low (automated bots) to High (APT operators cherry-picking exec accounts)   |
| **TTPs**           | T1589.001, T1078, T1110, T1110.003, T1110.004                              |
| **Tools Used**     | Sentry MBA, SilverBullet, OpenBullet2 (credential stuffing frameworks)      |
| **Timeline**       | Automated attacks begin 6–72 hrs post-dump; human operators within 1 week  |
| **Prior Activity** | Same actor group linked to successful BEC at 3 financial firms in Q4 2024  |

---

## 🏢 Incident Context — NovaCrest Capital Group

```
Breach Source:     COMBOLIST-FIN-2025-Q1 (third-party breach aggregation)
Records Exposed:   312 @novacrest-capital.com email addresses
Data Included:     Email address + plaintext or MD5/bcrypt hashed passwords
Breach Origin:     Mix of third-party SaaS platforms (LinkedIn, Adobe, Canva, Dropbox)
Discovery Source:  Flare.io / dark web monitoring alert
Time Since Upload: 48 hours
Risk Window:       ACTIVE — credential stuffing attempts likely imminent or underway
```

**The hard truth about credential reuse:**

Research consistently shows **65% of users reuse passwords** across personal and
work accounts. Even though these credentials were leaked from third-party platforms,
a significant percentage of affected employees may be using the same password —
or a minor variation — for their corporate Microsoft 365 / VPN / email accounts.

---

## 🔍 The Three-Layer Investigation

```
┌────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — EXTERNAL EXPOSURE VALIDATION                             │
│  • Query HaveIBeenPwned API for each affected email                 │
│  • Enumerate breach sources and data types exposed per account      │
│  • Identify executive / privileged accounts in the exposure list    │
├────────────────────────────────────────────────────────────────────┤
│  LAYER 2 — INTERNAL LOG CORRELATION (Has it been weaponized?)       │
│  • Search Azure AD / Entra sign-in logs for affected accounts       │
│  • Hunt for impossible travel, new device fingerprints             │
│  • Correlate Microsoft 365 audit logs — mailbox access, forwarding  │
│  • Check VPN authentication logs for affected usernames            │
├────────────────────────────────────────────────────────────────────┤
│  LAYER 3 — DETECTION RULE DEPLOYMENT                                │
│  • Write Splunk/KQL detection rules for credential stuffing         │
│  • Implement velocity-based login anomaly alerting                 │
│  • Deploy conditional access policy for at-risk accounts           │
└────────────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Detection Challenge

Credential stuffing is one of the **hardest attacks to detect** because:

- Attackers use **residential proxy networks** — each attempt appears from a unique
  legitimate-looking IP address, defeating IP blocklisting
- **Slow-and-low** attacks deliberately spread attempts over hours/days to stay
  below rate-limit thresholds
- Successful logins with valid credentials look **identical to legitimate user logins**
  in basic authentication logs
- **Password spray** (one password tried against many accounts) evades per-account
  lockout policies

Detection requires **behavioral baselines** — identifying what *normal* login
patterns look like and alerting on deviations: unusual geography, new device
fingerprints, impossible travel, off-hours access, and first-time application consent.

---

## 📚 Learning Objectives

1. Use the HaveIBeenPwned (HIBP) API to programmatically validate credential exposure at scale
2. Correlate breach data against internal authentication logs (Azure AD / Splunk)
3. Write detection logic for credential stuffing, password spray, and impossible travel
4. Prioritize remediation by account sensitivity and breach data type
5. Produce an executive-ready breach exposure report with a clear action matrix
6. Deploy a Sigma detection rule for ongoing monitoring

---

## ✅ Success Criteria

- [ ] Query HIBP API for at least 10 test email addresses and parse results
- [ ] Identify which accounts have plaintext vs hashed password exposure
- [ ] Write a Splunk query that detects password spray (1 password, many accounts)
- [ ] Write a KQL query that detects impossible travel in Azure AD sign-in logs
- [ ] Produce a prioritized remediation matrix sorted by account risk tier
- [ ] Save a Sigma rule for credential stuffing detection to `artifacts/`
- [ ] Brief document: what to tell leadership in under 5 minutes

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1589.001** | Gather Victim Identity — Credentials | Reconnaissance | Breach data sourcing |
| **T1078** | Valid Accounts | Defense Evasion / Initial Access | Using stolen creds to log in |
| **T1078.004** | Cloud Accounts | Defense Evasion | M365 / Azure AD account abuse |
| **T1110** | Brute Force | Credential Access | Credential stuffing framework |
| **T1110.003** | Password Spraying | Credential Access | Single password vs many accounts |
| **T1110.004** | Credential Stuffing | Credential Access | Combolist-based automated attacks |
| **T1556** | Modify Authentication Process | Defense Evasion | MFA bypass techniques |
| **T1098** | Account Manipulation | Persistence | Adding forwarding rules post-compromise |

---

*Next: [LAB.md](LAB.md) — Step-by-step credential exposure hunt guide*
