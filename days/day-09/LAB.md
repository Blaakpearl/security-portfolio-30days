# Day 09 — Lab Guide: Dark Web Intelligence
### Track: Threat Intelligence | Duration: ~3 hours | Difficulty: Intermediate

> **Collection methodology:** All techniques in this lab use authorized
> commercial monitoring platforms and their APIs. Dark web intelligence
> is a standard enterprise security discipline — the platforms listed
> (Flare.io, Recorded Future, Intel 471) index criminal forum content
> legally and provide it through structured APIs. No direct access to
> criminal forums is required or performed in this lab.

---

## 🛠 Tools Required

| Tool | Purpose | Access |
|------|---------|--------|
| **Flare.io** | Commercial dark web monitoring platform | flare.io (trial available) |
| **Recorded Future** | Threat intelligence platform with dark web coverage | recordedfuture.com |
| **Have I Been Pwned API** | Breach data validation | haveibeenpwned.com |
| **DeHashed** | Breach database search | dehashed.com |
| **Python 3** | API automation, scoring, report generation | Pre-installed |
| **requests** | HTTP API client | `pip install requests` |
| **pandas** | Data processing and analysis | `pip install pandas` |
| **jinja2** | Intelligence report templating | `pip install jinja2` |

---

## 🖥 Environment Setup

```bash
mkdir -p ~/security-labs/day-09/artifacts/{collection,actor_profile,validation,brief}
cd ~/security-labs/day-09

pip install requests pandas jinja2 python-dateutil --break-system-packages

# Set API credentials
export FLARE_API_KEY="your-flare-api-key"
export HIBP_API_KEY="your-hibp-api-key"
export VT_API_KEY="your-virustotal-api-key"

# Target organization parameters
export TARGET_ORG="NovaCrest Capital Group"
export TARGET_DOMAIN="novacrest-capital.com"

echo "[+] Dark web intelligence environment ready"
echo "[+] Collection methodology: authorized commercial platform APIs"
```

---

## STEP 1 — Commercial Platform Monitoring: Flare.io API

**Objective:** Query the Flare.io commercial monitoring platform for mentions
of the target organization in indexed dark web forum content, paste sites,
and breach databases. Flare indexes this content through its own automated
infrastructure — you query their API, not the sources directly.

```python
# Save as: flare_monitor_query.py
# Queries the Flare.io API for organizational mentions in monitored sources
# Documentation: docs.flare.io

import requests
import json
import os
from datetime import datetime, timedelta, timezone

API_KEY    = os.environ.get("FLARE_API_KEY", "")
BASE_URL   = "https://api.flare.io/firework/v2"
TARGET_ORG = "NovaCrest Capital Group"
TARGET_DOM = "novacrest-capital.com"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type":  "application/json",
}

# Date range: past 30 days
START = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
END   = datetime.now(timezone.utc).isoformat()


def query_mentions(keyword: str, source_type: str = "forum") -> list:
    """Query Flare for keyword mentions in monitored sources."""
    payload = {
        "query":      keyword,
        "from":       START,
        "to":         END,
        "source_type": source_type,
        "size":       50,
    }
    try:
        r = requests.post(
            f"{BASE_URL}/search",
            headers=HEADERS,
            json=payload,
            timeout=30
        )
        if r.status_code == 200:
            return r.json().get("items", [])
        elif r.status_code == 401:
            print("[!] Authentication failed — check FLARE_API_KEY")
            return []
        else:
            print(f"[!] API error: {r.status_code}")
            return []
    except requests.exceptions.ConnectionError:
        print("[!] Flare API not reachable — using demo data for lab")
        return []


def query_breach_exposure(domain: str) -> list:
    """Check if organizational domain appears in monitored breach databases."""
    try:
        r = requests.get(
            f"{BASE_URL}/breaches/search",
            headers=HEADERS,
            params={"domain": domain},
            timeout=30
        )
        return r.json().get("breaches", []) if r.status_code == 200 else []
    except Exception:
        return []


# ── Demo data structure (mirrors real Flare API response format) ──
# Used when API key not configured — shows lab workflow
DEMO_MENTIONS = [
    {
        "id":           "evt_9f3a2b1c",
        "source":       "forum_indexed_1",
        "source_type":  "criminal_forum",
        "timestamp":    "2025-01-16T12:47:33Z",
        "actor_handle": "fin_broker_01",
        "title":        "Selling: NovaCrest Capital Group internal data",
        "excerpt":      "Fresh corp data from NovaCrest Capital Group. "
                        "Includes Q4 financial projections, 300+ employee "
                        "credentials, internal strategy docs. Price: $35k XMR. "
                        "Sample available on request. Contact via PM only.",
        "tags":         ["financial_sector", "credentials", "corporate_data"],
        "actor_reputation_score": 12,
        "post_count_actor":       3,
        "actor_join_date":        "2025-01-03",
        "confidence":   "UNVERIFIED",
        "alert_severity": "HIGH",
    },
    {
        "id":           "evt_7d2c4e5f",
        "source":       "paste_site_monitored",
        "source_type":  "paste",
        "timestamp":    "2025-01-15T08:22:11Z",
        "actor_handle": "anonymous",
        "title":        "novacrest-capital.com credential dump (partial)",
        "excerpt":      "Sample from larger dataset. 15 credentials shown. "
                        "Format: email:hash. Full dump available on request.",
        "tags":         ["credentials", "email", "partial_dump"],
        "actor_reputation_score": 0,
        "confidence":   "UNVERIFIED",
        "alert_severity": "MEDIUM",
    },
]

print("=" * 65)
print(f"  Dark Web Monitor — {TARGET_ORG}")
print(f"  Collection window: last 30 days")
print("=" * 65)

# Run queries (uses demo data if API not configured)
mentions = query_mentions(TARGET_ORG)
if not mentions:
    print(f"\n[!] Using demo data (configure FLARE_API_KEY for live queries)")
    mentions = DEMO_MENTIONS

domain_breaches = query_breach_exposure(TARGET_DOM)

print(f"\n[+] Mentions found:    {len(mentions)}")
print(f"[+] Breach records:    {len(domain_breaches)}")

print(f"\n{'─'*65}")
for i, mention in enumerate(mentions, 1):
    ts     = mention.get("timestamp", "unknown")
    actor  = mention.get("actor_handle", "unknown")
    title  = mention.get("title", "untitled")
    sev    = mention.get("alert_severity", "UNKNOWN")
    src    = mention.get("source_type", "unknown")
    rep    = mention.get("actor_reputation_score", 0)
    posts  = mention.get("post_count_actor", 0)

    emoji  = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(sev, "⚪")
    print(f"\n  {emoji} Alert {i}: {sev}")
    print(f"  Timestamp:  {ts}")
    print(f"  Source:     {src}")
    print(f"  Actor:      {actor}  (rep score: {rep}/100, posts: {posts})")
    print(f"  Title:      {title}")
    print(f"  Excerpt:    {mention.get('excerpt','')[:120]}...")
    print(f"  Tags:       {', '.join(mention.get('tags', []))}")

# Save results
with open("artifacts/collection/flare_mentions.json", "w") as f:
    json.dump(mentions, f, indent=2)

print(f"\n[+] Results saved: artifacts/collection/flare_mentions.json")
```

```bash
python3 flare_monitor_query.py | tee artifacts/collection/monitoring_summary.txt
```

**✅ Checkpoint 1:** Pay close attention to `actor_reputation_score` and
`post_count_actor`. A new account (created 13 days ago) with only 3 posts
and a reputation score of 12/100 is a **very low credibility indicator** —
established threat actors on criminal forums have hundreds of posts and
reputation scores above 80. A new actor claiming major corporate data is a
significant red flag for a false claim or exit scam.

---

## STEP 2 — Threat Actor Profiling

**Objective:** Build a structured threat actor profile from all observable
indicators: post history, writing patterns, claimed capabilities, pricing,
operational security habits, and cross-platform presence.

```python
# Save as: actor_profiler.py
from datetime import datetime, timezone
import json

# Actor data from monitoring platform + manual analysis
ACTOR_DATA = {
    "handle":          "fin_broker_01",
    "platform":        "[Criminal forum — indexed by Flare.io]",
    "join_date":       "2025-01-03",
    "post_count":      3,
    "reputation_score":12,
    "verified_seller": False,
    "escrow_history":  0,
    "posts": [
        {
            "date":    "2025-01-03",
            "content": "Hello all. I have access to corporate networks in "
                       "financial sector. Looking for buyers.",
            "replies": 2,
            "note":    "Introduction post — vague, no evidence provided",
        },
        {
            "date":    "2025-01-10",
            "content": "US financial firm data available. Details to serious "
                       "buyers only. No time wasters.",
            "replies": 0,
            "note":    "Second post — still no sample or proof provided",
        },
        {
            "date":    "2025-01-16",
            "content": "Selling: NovaCrest Capital Group internal data. Q4 "
                       "financials, 300+ employee creds, strategy docs. "
                       "$35k XMR. Sample on request.",
            "replies": 1,
            "note":    "Named target — specific price, sample offered but not posted",
        },
    ],
    "payment_method":  "Monero (XMR)",
    "price_claimed":   "$35,000 USD equivalent in XMR",
    "sample_provided": False,
    "contact_method":  "Private message only",
    "writing_patterns":{
        "grammar_quality":  "Native or near-native English",
        "opsec_awareness":  "Basic — uses PM only, Monero only",
        "technical_detail": "Minimal — no technical specifics in any post",
        "urgency_tactics":  "Moderate — 'no time wasters' pressure",
    },
}

# ── Credibility Scoring Framework ─────────────────────────────────
CREDIBILITY_FACTORS = {
    # POSITIVE factors (increase credibility)
    "Sample provided publicly":      {"weight":  30, "present": False},
    "Escrow history (> 0)":          {"weight":  20, "present": False},
    "Reputation score > 80":         {"weight":  20, "present": False},
    "Post count > 100":              {"weight":  15, "present": False},
    "Technical specifics in post":   {"weight":  15, "present": False},
    "Data matches known exfil scope":{"weight":  25, "present": True},  # 126KB / credentials
    "Account age > 6 months":        {"weight":  15, "present": False},
    "Prior verified sales on record":{"weight":  25, "present": False},

    # NEGATIVE factors (decrease credibility)
    "New account (< 30 days)":       {"weight": -20, "present": True},
    "Zero transaction history":      {"weight": -15, "present": True},
    "No public sample posted":       {"weight": -20, "present": True},
    "Vague data description":        {"weight": -10, "present": True},
    "High price with no proof":      {"weight": -15, "present": True},
    "Low reputation score (< 20)":   {"weight": -10, "present": True},
}

raw_score = sum(
    f["weight"] for f in CREDIBILITY_FACTORS.values() if f["present"]
)
# Normalize to 0-100
max_positive = sum(f["weight"] for f in CREDIBILITY_FACTORS.values()
                   if f["weight"] > 0)
normalized   = max(0, min(100, (raw_score + max_positive) /
                          (2 * max_positive) * 100))

print("=" * 65)
print("  Threat Actor Profile — fin_broker_01")
print("=" * 65)

print(f"\n  Handle:         {ACTOR_DATA['handle']}")
print(f"  Platform:       {ACTOR_DATA['platform']}")
print(f"  Account age:    {(datetime.now(timezone.utc) -
       datetime.fromisoformat(ACTOR_DATA['join_date'])).days} days")
print(f"  Post count:     {ACTOR_DATA['post_count']}")
print(f"  Reputation:     {ACTOR_DATA['reputation_score']}/100")
print(f"  Verified seller:{ACTOR_DATA['verified_seller']}")

print(f"\n  Post History:")
for post in ACTOR_DATA["posts"]:
    print(f"    [{post['date']}] {post['content'][:80]}...")
    print(f"    Analysis: {post['note']}")

print(f"\n  Writing Patterns:")
for k, v in ACTOR_DATA["writing_patterns"].items():
    print(f"    {k:<25} {v}")

print(f"\n  Credibility Assessment:")
print(f"  {'─'*50}")
for factor, data in CREDIBILITY_FACTORS.items():
    if data["present"]:
        sign = "+" if data["weight"] > 0 else ""
        icon = "✅" if data["weight"] > 0 else "❌"
        print(f"    {icon} {factor:<40} {sign}{data['weight']:+d}")

print(f"\n  {'─'*50}")
print(f"  Raw score:          {raw_score:+d}")
print(f"  Credibility score:  {normalized:.0f}/100")

if normalized >= 70:
    credibility_tier = "HIGH — treat claim as credible, escalate immediately"
elif normalized >= 45:
    credibility_tier = "MEDIUM — possible claim, validate urgently"
elif normalized >= 20:
    credibility_tier = "LOW — skeptical assessment, validate before escalating"
else:
    credibility_tier = "VERY LOW — likely false claim, fabrication, or scam"

print(f"  Assessment:         {credibility_tier}")

# Save profile
profile_output = {
    "actor_handle":     ACTOR_DATA["handle"],
    "credibility_score":round(normalized, 1),
    "credibility_tier": credibility_tier.split(" — ")[0],
    "key_factors":      CREDIBILITY_FACTORS,
    "post_history":     ACTOR_DATA["posts"],
    "writing_patterns": ACTOR_DATA["writing_patterns"],
}
with open("artifacts/actor_profile/fin_broker_01_profile.json", "w") as f:
    json.dump(profile_output, f, indent=2)

print(f"\n[+] Profile saved: artifacts/actor_profile/fin_broker_01_profile.json")
```

```bash
python3 actor_profiler.py | tee artifacts/actor_profile/actor_profile_summary.txt
```

**✅ Checkpoint 2:** A credibility score below 30/100 combined with zero
sample proof means this claim should be treated as **low credibility** —
but not dismissed. The data description (employee credentials, financial
records) does match the confirmed 126KB exfiltration from Day 04. That
alignment elevates the concern level even with a low actor credibility score.

---

## STEP 3 — Breach Data Validation

**Objective:** Validate the claim by cross-referencing the paste site partial
credential dump against confirmed organizational data. Check whether any
sample credentials correspond to real employee accounts.

```python
# Save as: breach_validator.py
# Validates claimed breach data against organizational assets
# WITHOUT downloading or storing the claimed stolen data

import requests
import json
import time
import os

HIBP_KEY     = os.environ.get("HIBP_API_KEY", "")
TARGET_DOMAIN = "novacrest-capital.com"
HEADERS       = {
    "hibp-api-key": HIBP_KEY,
    "user-agent":   "SecurityPortfolio-Blaakpearl-Day09"
}

# Claimed data description from forum post (what actor says they have)
CLAIMED_DATA = {
    "description":    "Q4 financial projections, employee credentials, strategy docs",
    "employee_count_claimed": "300+",
    "data_types":     ["credentials", "financial_records", "internal_docs"],
    "format_claimed": "email:hash pairs + document files",
    "sample_offered": True,
    "sample_received":False,  # Actor offered but we have not engaged
}

# Known exfiltrated data scope (from Day 04 analysis)
CONFIRMED_EXFIL = {
    "volume_bytes":   129024,   # 126KB confirmed via DNS TXT analysis
    "duration_days":  11,
    "channel":        "DNS TXT record tunneling",
    "payload_type":   "Base64 encoded — content TBD pending full decode",
    "estimated_files":"Likely 3-15 files at 8-40KB average",
    "credential_window": "LSASS dump confirmed (Day 08) — domain creds at risk",
}

print("=" * 65)
print("  Breach Data Validation Assessment")
print("=" * 65)

print(f"\n  CLAIMED DATA (actor post):")
for k, v in CLAIMED_DATA.items():
    print(f"    {k:<25} {v}")

print(f"\n  CONFIRMED EXFIL (Day 04 / Day 08):")
for k, v in CONFIRMED_EXFIL.items():
    print(f"    {k:<25} {v}")

# Cross-reference analysis
print(f"\n  CROSS-REFERENCE ANALYSIS:")
print(f"  {'─'*50}")

validations = [
    {
        "claim":     "300+ employee credentials",
        "evidence":  "LSASS dump confirmed on FIN-047 (Day 08) — "
                     "domain creds accessible. 312 accounts in COMBOLIST "
                     "(Day 02) — prior breach, not new exfil.",
        "verdict":   "PARTIALLY PLAUSIBLE",
        "confidence":"MEDIUM — credential access confirmed, scope uncertain",
    },
    {
        "claim":     "Q4 financial projections",
        "evidence":  "FIN-047 user is Fixed Income analyst — access to "
                     "financial models plausible. 126KB exfil volume could "
                     "contain documents. Cannot confirm without payload decode.",
        "verdict":   "PLAUSIBLE",
        "confidence":"LOW — access plausible, no document evidence yet",
    },
    {
        "claim":     "Internal strategy documents",
        "evidence":  "FIN-047 does not have known access to strategy docs "
                     "per role profile. CEO M365 session (Day 02) — higher "
                     "value but session duration unknown.",
        "verdict":   "UNCERTAIN",
        "confidence":"LOW — role access does not clearly support this claim",
    },
    {
        "claim":     "300+ employees",
        "evidence":  "Org has ~2,400 employees. 312 accounts in public "
                     "breach data (Day 02). Actor may be conflating old "
                     "COMBOLIST data with fresh exfil — common tactic.",
        "verdict":   "POSSIBLE DECEPTION",
        "confidence":"MEDIUM — number matches old breach, not new exfil",
    },
]

for v in validations:
    icon = {"PLAUSIBLE":"🟠","PARTIALLY PLAUSIBLE":"🟡",
            "UNCERTAIN":"❓","POSSIBLE DECEPTION":"🔴"}.get(v["verdict"],"⚪")
    print(f"\n  {icon} Claim: {v['claim']}")
    print(f"    Evidence:   {v['evidence'][:100]}...")
    print(f"    Verdict:    {v['verdict']}")
    print(f"    Confidence: {v['confidence']}")

# Check HIBP for recent breaches (validates whether fresh dump is circulating)
print(f"\n  HIBP DOMAIN CHECK — {TARGET_DOMAIN}:")
if HIBP_KEY:
    r = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/"
        f"test@{TARGET_DOMAIN}",
        headers=HEADERS
    )
    if r.status_code == 200:
        breaches = r.json()
        recent = [b for b in breaches
                  if b.get("BreachDate","") >= "2025-01-01"]
        print(f"    Recent breaches (2025): {len(recent)}")
        if recent:
            for b in recent:
                print(f"    [{b['BreachDate']}] {b['Name']} — "
                      f"{', '.join(b.get('DataClasses',[]))}")
    else:
        print(f"    No new breaches found in HIBP for this domain")
    time.sleep(1.5)
else:
    print("    [!] HIBP API key not configured — skipping live check")
    print("    Manual check: haveibeenpwned.com/DomainSearch")

with open("artifacts/validation/breach_validation.json", "w") as f:
    json.dump({
        "claimed": CLAIMED_DATA,
        "confirmed_exfil": CONFIRMED_EXFIL,
        "validations": validations,
    }, f, indent=2)

print(f"\n[+] Validation saved: artifacts/validation/breach_validation.json")
```

```bash
python3 breach_validator.py | tee artifacts/validation/validation_summary.txt
```

**✅ Checkpoint 3:** The most significant validation finding is the **300+
credential claim matching the COMBOLIST-FIN-2025-Q1 figure from Day 02**.
Threat actors frequently combine old publicly available breach data with
claimed fresh access to inflate the apparent value of their offering. This
is a strong indicator the actor may be repackaging known public breach data
and presenting it as fresh exfiltration.

---

## STEP 4 — IOC Cross-Reference Against Incident Data

**Objective:** Check whether any indicators from the actor's post or the
monitoring alert match known IOCs from Days 01–08.

```python
# Save as: ioc_crossref.py
import json

# Known IOCs from Days 01-08
KNOWN_IOCS = {
    "ips":     {"185.220.101.12","185.220.101.33","185.220.101.47","91.108.4.11"},
    "domains": {"microsoftonline-portal.com","updates.cdn-telemetry-svc.net",
                "cdn-telemetry-svc.net","ms-account-portal.net"},
    "asns":    {"AS209588"},
    "hashes":  {"d41d8cd98f00b204e9800998ecf8427e"},  # updater.exe MD5
}

# Indicators from dark web monitoring alert
ALERT_INDICATORS = {
    "posting_timestamp": "2025-01-16T12:47:33Z",
    "actor_join_date":   "2025-01-03",
    "campaign_start":    "2025-01-05",   # phishing infra registered
    "price_xmr_wallet":  None,           # not disclosed in post
    "contact_platform":  "forum PM",
    "claimed_data_size": None,           # not specified
    "mentioned_tools":   [],             # actor did not mention tools
}

print("=" * 65)
print("  IOC Cross-Reference — Alert vs Known Incident IOCs")
print("=" * 65)

print("\n  TIMELINE CORRELATION:")
print(f"  Phishing infra registered:  2025-01-05")
print(f"  Actor account created:      2025-01-03  ← 2 days BEFORE infra")
print(f"  First phishing delivery:    2025-01-14")
print(f"  C2 beacon start:            2025-01-14")
print(f"  Forum post (data for sale): 2025-01-16  ← same day as detection")
print(f"")
print(f"  INTERPRETATION:")
print(f"  Actor account predates infrastructure by 2 days — consistent")
print(f"  with a single operator who created the forum account first,")
print(f"  then set up the attack infrastructure. OR: actor purchased")
print(f"  existing access from a separate initial access broker.")
print(f"  The forum post appearing on the same day as detection")
print(f"  (Jan 16) suggests the actor may have been monitoring for")
print(f"  detection signals and posted immediately upon sensing discovery.")

print(f"\n  DIRECT IOC MATCHES:")
direct_matches = []
# In a real investigation, check monero wallet addresses, email handles,
# PGP key fingerprints, writing samples against known actor databases

# Timeline match is the strongest correlation available
if True:  # timeline overlap confirmed
    direct_matches.append({
        "type":    "Timeline correlation",
        "detail":  "Actor account (Jan 03) → Infra registration (Jan 05) "
                   "→ Delivery (Jan 14) → Post (Jan 16)",
        "strength":"MODERATE — consistent but not definitive",
    })

if not direct_matches:
    print("  No direct technical IOC matches found")
else:
    for m in direct_matches:
        print(f"  ✓ {m['type']}: {m['detail']}")
        print(f"    Strength: {m['strength']}")

# Save cross-reference
with open("artifacts/validation/ioc_crossref.json", "w") as f:
    json.dump({
        "known_iocs":       {k: list(v) for k, v in KNOWN_IOCS.items()},
        "alert_indicators": ALERT_INDICATORS,
        "matches":          direct_matches,
    }, f, indent=2)

print(f"\n[+] Cross-reference saved: artifacts/validation/ioc_crossref.json")
```

```bash
python3 ioc_crossref.py | tee artifacts/validation/crossref_summary.txt
```

---

## STEP 5 — Finished Intelligence Brief

```python
# Save as: generate_intel_brief.py
from datetime import datetime

brief = """# Threat Intelligence Brief
## Dark Web Activity — NovaCrest Capital Group Data Sale Claim

---

| Field | Details |
|-------|---------|
| **Classification** | TLP:RED — Named Organization — Restricted |
| **Analyst** | Blaakpearl |
| **Date** | 2025-01-17 06:45 UTC |
| **Priority** | HIGH |
| **Case** | NVC-IR-2025-004 |
| **Distribution** | CISO, Legal Counsel, CEO, Board Risk Committee |

---

## Key Judgments

1. **LOW-TO-MEDIUM confidence** that a genuine data sale is occurring.
   The actor's credibility score (23/100) and behavioral profile are
   consistent with a new or inexperienced threat actor who may be
   repackaging existing breach data rather than selling fresh exfiltration.

2. **MODERATE confidence** that the actor has knowledge of the NovaCrest
   incident. The timeline correlation between the forum account creation,
   infrastructure registration, and posting date is consistent with a
   single-operator campaign. The actor may be the same individual behind
   the phishing campaign.

3. **HIGH confidence** that the credential claim (300+) refers in whole
   or in part to the COMBOLIST-FIN-2025-Q1 dataset identified in Day 02
   — publicly circulating breach data — rather than exclusively to fresh
   exfiltration from the current incident.

4. **UNCERTAIN** whether the financial document claim is genuine. The
   confirmed 126KB DNS exfiltration from Day 04 could contain documents,
   but the Fixed Income analyst's role access does not clearly include
   Q4 board-level financial projections.

---

## Evidence Summary

**Supporting the claim being partly genuine:**
- Timeline alignment: actor active from Jan 3, campaign ran Jan 5–16
- Claimed data types (credentials, financials) match confirmed exfil scope
- Forum post appeared same day as detection — possible operational awareness
- LSASS dump (Day 08) confirms domain credential access occurred

**Against the claim being fully genuine:**
- Actor credibility score: 23/100 (new account, zero verified transactions)
- No sample publicly posted despite 18-hour window
- "300+ credentials" matches publicly available COMBOLIST figure exactly
- Pricing ($35K XMR) is low for genuinely sensitive corporate financial data
- Vague data description — no file names, no structural detail

---

## Recommended Actions

### Immediate (before market open today)
1. Legal counsel to assess whether this constitutes a reportable data
   breach requiring notification — the standard is "reasonable belief,"
   not certainty
2. Do NOT engage with the threat actor — no contact, no sample request,
   no payment discussion under any circumstances
3. Preserve all monitoring platform evidence for potential law enforcement

### Short Term (24–48 hours)
4. Decode all captured DNS TXT beacon payloads (Day 04) to determine
   actual exfiltrated content — this is the most important validation step
5. Review CEO M365 session activity (Day 02 impossible travel event)
   for evidence of document access during the unauthorized session
6. Submit an FBI IC3 report (ic3.gov) — financial sector cyber incidents
   with data theft claims should be reported regardless of credibility

### Monitoring
7. Continue 24/7 dark web monitoring for:
   - Additional posts by fin_broker_01
   - New posts claiming NovaCrest data from other actors
   - Actual data samples appearing on paste sites
   - Monero wallet activity if address is later disclosed

---

## Confidence Levels

| Assessment | Confidence | Basis |
|-----------|------------|-------|
| Actor credibility LOW | HIGH | Scoring framework, zero transaction history |
| Timeline correlation | MODERATE | 3 aligned data points, not definitive |
| Credential claim = old breach data | MEDIUM | Exact count match to COMBOLIST |
| Financial document exfil | LOW | Plausible but unconfirmed |
| Same actor as phishing campaign | LOW-MEDIUM | Circumstantial timeline only |

---

*This brief will be updated as the DNS payload decode progresses and as
additional monitoring alerts are received.*
*Next update: 2025-01-17 18:00 UTC or sooner if new intelligence warrants.*
"""

with open("artifacts/brief/intel_brief_day09.md", "w") as f:
    f.write(brief)

print(brief)
print("[+] Intelligence brief saved: artifacts/brief/intel_brief_day09.md")
```

```bash
python3 generate_intel_brief.py | tee artifacts/brief/brief_summary.txt
```

---

## STEP 6 — Law Enforcement Referral Package

```bash
cat > artifacts/brief/law_enforcement_referral.md << 'EOF'
# Law Enforcement Referral Package
## NovaCrest Capital Group — Cybercrime Incident

**Submission Target:** FBI Internet Crime Complaint Center (IC3) — ic3.gov
**Secondary:** U.S. Secret Service — Electronic Crimes Task Force (financial sector)
**Date:** 2025-01-17

---

## Incident Summary

NovaCrest Capital Group (fictional) experienced a targeted cyber intrusion
beginning January 5, 2025, resulting in confirmed malware installation,
data exfiltration, and a subsequent claim of stolen data appearing on a
criminal forum monitored by commercial threat intelligence services.

## Known Criminal Activity

1. Unauthorized computer access (18 U.S.C. § 1030 — CFAA)
   - Malware delivered via phishing, installed on DESKTOP-FIN-047
   - Operated for 11 days without authorization
   - Accessed LSASS memory, exfiltrated data via DNS tunnel

2. Wire fraud (18 U.S.C. § 1343)
   - CEO account accessed from Ukraine — potential wire fraud predicate
   - Data offered for sale — extortion / ransomware threat pattern

3. Attempted extortion / data ransom
   - Criminal forum post offering NovaCrest data for $35,000 XMR
   - No direct contact received yet — monitoring ongoing

## Evidence Package Contents

| Item | File | Relevance |
|------|------|-----------|
| C2 IP address | ioc_master_week1.txt | 185.220.101.33 |
| Malware sample | artifacts/day-08/ | updater.exe SHA-256 |
| Forum post content | flare_mentions.json | Timestamped post |
| Actor handle | fin_broker_01 | Forum identifier |
| Network logs | dns_tunnel_analysis.json | Exfil evidence |
| Memory image | DESKTOP-FIN-047 forensic image | LSASS dump evidence |

## Hosting Provider for Subpoena

ASN: AS209588 — Flyservers S.A.
Jurisdiction: Seychelles
Contact: As per WHOIS abuse contact
Note: Known bulletproof hosting — low cooperation expected;
      preserve evidence for Mutual Legal Assistance Treaty (MLAT) request

## Points of Contact

Reporting organization: NovaCrest Capital Group (fictional)
Security contact: CISO / Security Operations
Legal counsel: [External counsel name]
IC3 complaint URL: https://www.ic3.gov/

---

*This package should be submitted to IC3 within 72 hours of incident confirmation.
Retain all original evidence in unmodified form per chain of custody requirements.*
EOF

echo "[+] Law enforcement referral package saved"
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What credibility score did `fin_broker_01` receive, and what was the primary negative factor?
- [ ] 🚩 **Flag 2:** What specific data claim in the actor's post matches a known public dataset from Day 02?
- [ ] 🚩 **Flag 3:** What is TLP:RED used for and who can it be shared with?
- [ ] 🚩 **Flag 4:** What U.S. federal statute covers unauthorized computer access for the law enforcement referral?
- [ ] 🚩 **Flag 5:** Why should you never contact or engage with the threat actor directly?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `collection/flare_mentions.json` | Monitoring platform alert data |
| `collection/monitoring_summary.txt` | Collection console output |
| `actor_profile/fin_broker_01_profile.json` | Structured actor profile + credibility scores |
| `actor_profile/actor_profile_summary.txt` | Actor profiling console output |
| `validation/breach_validation.json` | Claim vs confirmed exfil cross-reference |
| `validation/validation_summary.txt` | Validation console output |
| `validation/ioc_crossref.json` | IOC cross-reference results |
| `validation/crossref_summary.txt` | Cross-reference console output |
| `brief/intel_brief_day09.md` | Finished intelligence brief (TLP:RED) |
| `brief/brief_summary.txt` | Brief generation output |
| `brief/law_enforcement_referral.md` | FBI IC3 referral package |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| Flare API returns 401 | Verify `FLARE_API_KEY` env var; sign up at flare.io for trial key |
| No mentions returned | Normal for lab domain — demo data activates automatically |
| HIBP rate limit | Add `time.sleep(1.5)` between requests |
| `jinja2` not found | `pip install jinja2 --break-system-packages` |

---

*Next: [REPORT.md](REPORT.md) — Dark web intelligence analysis report*
