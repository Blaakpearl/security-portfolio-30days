# Day 11 — Lab Guide: Geo-IP & Attribution
### Track: OSINT | Duration: ~3 hours | Difficulty: Advanced

---

## 🛠 Tools Required

| Tool | Purpose | Access |
|------|---------|--------|
| **Shodan** | Infrastructure enumeration and historical data | shodan.io |
| **Censys** | Certificate and service search | censys.io |
| **BGP.he.net** | BGP routing and ASN analysis | bgp.he.net |
| **crt.sh** | Certificate transparency log search | crt.sh |
| **MaxMind GeoIP2** | Geographic IP attribution | maxmind.com |
| **VirusTotal** | Infrastructure relationship graphing | virustotal.com |
| **MITRE ATT&CK Groups** | Known threat actor TTP database | attack.mitre.org/groups |
| **Python 3** | Timing analysis, confidence scoring | Pre-installed |
| **whois** | Registration data | Pre-installed |

---

## 🖥 Environment Setup

```bash
mkdir -p ~/security-labs/day-11/artifacts/{infrastructure,timing,ttp_comparison}
cd ~/security-labs/day-11

pip install requests pandas python-dateutil pytz --break-system-packages

export SHODAN_API_KEY="your-key"
export VT_API_KEY="your-key"

echo "[+] Attribution analysis environment ready"
echo "[+] Methodology: evidence-graded, confidence-explicit assessment"
```

---

## STEP 1 — Full Infrastructure Cluster Mapping

**Objective:** Consolidate and expand the infrastructure picture from Days
01, 03, and 04 into a complete cluster map, identifying the full scope of
attacker-controlled or attacker-adjacent infrastructure.

```python
# Save as: infrastructure_cluster_map.py
import json
from collections import defaultdict

# Known infrastructure from Days 01, 03, 04, 09
KNOWN_INFRASTRUCTURE = {
    "ips": [
        {"ip": "185.220.101.12", "role": "Phishing hosting",       "day": "03"},
        {"ip": "185.220.101.33", "role": "C2 server",              "day": "04"},
        {"ip": "185.220.101.47", "role": "Credential stuffing",    "day": "02"},
    ],
    "domains": [
        {"domain": "microsoftonline-portal.com",       "role": "Primary phishing", "day": "03"},
        {"domain": "ms-account-portal.net",             "role": "Related phishing", "day": "03"},
        {"domain": "updates.cdn-telemetry-svc.net",     "role": "C2 domain",        "day": "04"},
    ],
    "asns": [
        {"asn": "AS209588", "org": "Flyservers S.A.", "country": "Seychelles"},
    ],
}

print("=" * 65)
print("  Infrastructure Cluster Map — Consolidated View")
print("=" * 65)

# All IPs fall within same /24 — confirm subnet clustering
subnet_analysis = defaultdict(list)
for item in KNOWN_INFRASTRUCTURE["ips"]:
    subnet = ".".join(item["ip"].split(".")[:3]) + ".0/24"
    subnet_analysis[subnet].append(item)

print(f"\n  Subnet Clustering Analysis:")
for subnet, ips in subnet_analysis.items():
    print(f"    {subnet}  ({len(ips)} known IPs)")
    for item in ips:
        print(f"      {item['ip']:<18} {item['role']:<25} (Day {item['day']})")

print(f"\n  ASN Concentration:")
for asn in KNOWN_INFRASTRUCTURE["asns"]:
    print(f"    {asn['asn']} — {asn['org']} ({asn['country']})")
    print(f"    All {len(KNOWN_INFRASTRUCTURE['ips'])} known IPs fall under this ASN")

print(f"\n  Registrar Pattern:")
print(f"    All 12 phishing domains: Namecheap, WhoisGuard privacy protection")
print(f"    C2 domain: Same registrar pattern (Day 04 finding)")

# Infrastructure reuse assessment
print(f"\n  INFRASTRUCTURE COHESION ASSESSMENT:")
print(f"    Single ASN for all identified IPs:        YES — strong clustering signal")
print(f"    Single registrar for all domains:         YES — strong clustering signal")
print(f"    Single /24 subnet for phishing + C2:      YES — likely same operator")
print(f"    Consistent privacy protection pattern:    YES — consistent OPSEC discipline")
print(f"")
print(f"    Interpretation: High confidence this represents a SINGLE operator's")
print(f"    infrastructure, not multiple unrelated actors coincidentally")
print(f"    overlapping. However, this confirms operational cohesion, NOT")
print(f"    the operator's identity, nationality, or group affiliation.")

with open("artifacts/infrastructure/cluster_map.json", "w") as f:
    json.dump(KNOWN_INFRASTRUCTURE, f, indent=2)

print(f"\n[+] Cluster map saved: artifacts/infrastructure/cluster_map.json")
```

```bash
python3 infrastructure_cluster_map.py | tee artifacts/infrastructure/cluster_summary.txt
```

**✅ Checkpoint 1:** Note the careful distinction being drawn — infrastructure
clustering tells you these are likely the SAME operator's assets, not WHO that
operator is. This distinction is the core discipline of good attribution work.

---

## STEP 2 — Hosting Provider Selection Pattern Analysis

**Objective:** Analyze why the attacker chose Flyservers S.A. specifically —
hosting provider selection carries weak but real attribution signal, as
different threat actor categories have documented provider preferences.

```python
# Save as: hosting_pattern_analysis.py
import json

# Reference data: documented bulletproof hosting provider associations
# (based on public threat intelligence reporting patterns)
PROVIDER_INTELLIGENCE = {
    "Flyservers S.A.": {
        "country":       "Seychelles",
        "asn":           "AS209588",
        "known_for":     "General-purpose bulletproof hosting",
        "documented_associations": [
            "Various financially-motivated criminal groups",
            "Phishing-as-a-service operations",
            "No strong single-actor association documented publicly",
        ],
        "cost_tier":     "Low-to-medium (accessible to non-state actors)",
        "cooperation_with_le": "Minimal — known for ignoring abuse reports",
    },
    "Reference: Known nation-state infrastructure patterns": {
        "note": "For comparison only — NOT claiming NovaCrest attacker match",
        "typical_indicators": [
            "Often uses compromised legitimate infrastructure over bulletproof hosting",
            "Higher operational security — less reliance on 'known bad' ASNs",
            "Longer-term infrastructure investment vs disposable domains",
        ],
    },
    "Reference: Typical financially-motivated criminal patterns": {
        "note": "For comparison only",
        "typical_indicators": [
            "Cost-sensitive infrastructure choices — bulletproof hosting common",
            "Disposable, rapidly-rotated domains",
            "Commodity or lightly-modified tooling (cost/speed over stealth)",
            "Monetization-focused secondary activity (data sale, ransomware)",
        ],
    },
}

print("=" * 65)
print("  Hosting Provider Selection Pattern Analysis")
print("=" * 65)

print(f"\n  Provider Used: Flyservers S.A. (AS209588)")
fp = PROVIDER_INTELLIGENCE["Flyservers S.A."]
for k, v in fp.items():
    if isinstance(v, list):
        print(f"    {k}:")
        for item in v:
            print(f"      - {item}")
    else:
        print(f"    {k}: {v}")

print(f"\n  COMPARISON — Actor Category Fit Assessment:")
print(f"  {'─'*55}")

criminal_indicators = PROVIDER_INTELLIGENCE[
    "Reference: Typical financially-motivated criminal patterns"]["typical_indicators"]
nation_state_indicators = PROVIDER_INTELLIGENCE[
    "Reference: Known nation-state infrastructure patterns"]["typical_indicators"]

observed_behaviors = {
    "Cost-sensitive bulletproof hosting":      True,   # confirmed - Flyservers
    "Disposable, rapidly-rotated domains":     True,   # 12 domains, quick registration
    "Commodity/modified tooling":              True,   # Day 08 - CS-like but modified
    "Monetization-focused secondary activity": True,   # Day 09 - data sale attempt
    "Compromised legitimate infrastructure":   False,  # used dedicated bulletproof hosting
    "Long-term infrastructure investment":     False,  # infra built same-day as campaign
}

criminal_match = sum(1 for k in [
    "Cost-sensitive bulletproof hosting",
    "Disposable, rapidly-rotated domains",
    "Commodity/modified tooling",
    "Monetization-focused secondary activity",
] if observed_behaviors[k])

nation_state_match = sum(1 for k in [
    "Compromised legitimate infrastructure",
    "Long-term infrastructure investment",
] if observed_behaviors[k])

print(f"    Financially-motivated criminal pattern match: {criminal_match}/4 indicators")
print(f"    Nation-state pattern match:                   {nation_state_match}/2 indicators")

print(f"\n  ASSESSMENT (Moderate Confidence):")
print(f"    The observed infrastructure and monetization pattern is MORE")
print(f"    CONSISTENT with a financially-motivated criminal actor than a")
print(f"    nation-state operation. This assessment is based on:")
print(f"      • Cost-sensitive bulletproof hosting choice")
print(f"      • Rapid, disposable domain infrastructure")
print(f"      • Direct monetization attempt (Day 09 forum sale)")
print(f"      • Financial sector targeting consistent with criminal profit motive")
print(f"")
print(f"    This does NOT rule out a nation-state actor using criminal")
print(f"    infrastructure as a false-flag technique — this remains a")
print(f"    documented alternative hypothesis (see Step 5).")

with open("artifacts/infrastructure/hosting_pattern_analysis.json", "w") as f:
    json.dump({
        "provider": "Flyservers S.A.",
        "observed_behaviors": observed_behaviors,
        "criminal_match_score": f"{criminal_match}/4",
        "nation_state_match_score": f"{nation_state_match}/2",
    }, f, indent=2)

print(f"\n[+] Analysis saved: artifacts/infrastructure/hosting_pattern_analysis.json")
```

```bash
python3 hosting_pattern_analysis.py | tee artifacts/infrastructure/hosting_summary.txt
```

---

## STEP 3 — Operational Timing Analysis

**Objective:** Analyze the timestamps of attacker activity across the entire
incident to infer likely working hours and, cautiously, a probable time zone
range. This is one of the weaker attribution signals and must be presented
with appropriate humility.

```python
# Save as: timing_analysis.py
from datetime import datetime, timezone
import json
from collections import defaultdict

# All confirmed attacker activity timestamps (UTC) from Days 01-10
ACTIVITY_TIMESTAMPS = [
    {"event": "Phishing domain registered",     "utc": "2025-01-05T14:32:00Z"},
    {"event": "C2 domain registered",           "utc": "2025-01-05T16:00:00Z"},
    {"event": "Certificate issued",             "utc": "2025-01-05T18:00:00Z"},
    {"event": "Additional domains registered",  "utc": "2025-01-05T18:30:00Z"},
    {"event": "DNS configured",                 "utc": "2025-01-05T20:00:00Z"},
    {"event": "Dark web account created",       "utc": "2025-01-03T00:00:00Z"},  # date only, time unknown
    {"event": "Phishing delivered",             "utc": "2025-01-14T09:00:00Z"},
    {"event": "First C2 beacon",                "utc": "2025-01-14T09:12:00Z"},
    {"event": "DNS exfil channel activated",    "utc": "2025-01-14T14:00:00Z"},
    {"event": "CEO account accessed",           "utc": "2025-01-15T22:14:00Z"},
    {"event": "Credential stuffing attempt",    "utc": "2025-01-15T23:47:00Z"},
    {"event": "Forum data sale post",           "utc": "2025-01-16T12:47:00Z"},
]

print("=" * 65)
print("  Operational Timing Analysis")
print("=" * 65)

hour_distribution = defaultdict(int)
for activity in ACTIVITY_TIMESTAMPS:
    dt = datetime.fromisoformat(activity["utc"].replace("Z", "+00:00"))
    hour_distribution[dt.hour] += 1
    print(f"  [{dt.strftime('%Y-%m-%d %H:%M UTC')}] {activity['event']}")

print(f"\n  UTC Hour Distribution (activity count by hour):")
for hour in sorted(hour_distribution.keys()):
    bar = "█" * hour_distribution[hour]
    print(f"    {hour:02d}:00 UTC  {bar} ({hour_distribution[hour]})")

# Time zone inference — CAUTIOUS interpretation
print(f"\n  TIME ZONE INFERENCE (Low-Medium Confidence):")
print(f"  {'─'*55}")
earliest_hour = min(hour_distribution.keys())
latest_hour   = max(hour_distribution.keys())
print(f"    Activity observed: {earliest_hour:02d}:00 - {latest_hour:02d}:00 UTC")
print(f"")
print(f"    If activity reflects a standard 9am-9pm local working pattern,")
print(f"    this UTC range is consistent with a local time zone offset")
print(f"    of approximately UTC+2 to UTC+5 (covering Eastern Europe,")
print(f"    Middle East, or Western/Central Asia) OR could equally reflect")
print(f"    an actor deliberately operating during off-hours for their")
print(f"    true time zone specifically to obscure this exact inference.")
print(f"")
print(f"    CAVEATS (must be stated explicitly):")
print(f"      • Sample size is small (12 events) — statistically weak")
print(f"      • Automated events (beacons, scheduled tasks) do not reflect")
print(f"        human working hours at all — only manual actions do")
print(f"      • A sophisticated actor MAY deliberately operate during")
print(f"        atypical hours specifically to defeat this analysis")
print(f"      • This inference should be treated as a weak supporting")
print(f"        signal only, never as a standalone attribution basis")

# Filter to LIKELY human-driven events only (exclude automated beacon activity)
human_events = [a for a in ACTIVITY_TIMESTAMPS if "beacon" not in a["event"].lower()
                and "exfil channel" not in a["event"].lower()]

print(f"\n  Refined Analysis (human-driven events only, n={len(human_events)}):")
for activity in human_events:
    dt = datetime.fromisoformat(activity["utc"].replace("Z", "+00:00"))
    print(f"    [{dt.strftime('%H:%M UTC')}] {activity['event']}")

with open("artifacts/timing/timing_analysis.json", "w") as f:
    json.dump({
        "all_events": ACTIVITY_TIMESTAMPS,
        "hour_distribution": dict(hour_distribution),
        "human_driven_events": human_events,
        "confidence": "LOW-MEDIUM — weak supporting signal only",
    }, f, indent=2)

print(f"\n[+] Timing analysis saved: artifacts/timing/timing_analysis.json")
```

```bash
python3 timing_analysis.py | tee artifacts/timing/timing_summary.txt
```

**✅ Checkpoint 2:** Notice the explicit caveats built into this analysis.
Timing-based attribution is one of the weakest and most frequently misused
signals in threat intelligence — an analyst who presents it without heavy
caveats is not being rigorous.

---

## STEP 4 — TTP Comparison Against Known Threat Actor Profiles

**Objective:** Compare the confirmed TTPs from this incident against the
MITRE ATT&CK Groups database to identify overlapping or divergent patterns
with documented threat actors — without overclaiming a match.

```python
# Save as: ttp_comparison.py
import json

# Confirmed TTPs from this incident (Days 01-10)
INCIDENT_TTPS = {
    "T1566.001",  # Spearphishing Attachment
    "T1583.001",  # Acquire Infrastructure: Domains
    "T1078.004",  # Valid Accounts: Cloud Accounts
    "T1539",      # Steal Web Session Cookie (MFA bypass)
    "T1071.004",  # DNS C2
    "T1573.002",  # Asymmetric Crypto C2
    "T1048.001",  # Exfiltration Over DNS
    "T1053.005",  # Scheduled Task
    "T1547.001",  # Registry Run Keys
    "T1546.003",  # WMI Event Subscription
    "T1055.012",  # Process Hollowing
    "T1003.001",  # LSASS Memory
    "T1027",      # Obfuscated Files
}

# Reference TTP profiles for comparison — illustrative, based on publicly
# documented ATT&CK Group technique associations (attack.mitre.org/groups)
REFERENCE_PROFILES = {
    "Generic Financially-Motivated Criminal Cluster": {
        "typical_ttps": {"T1566.001","T1078.004","T1071.004","T1048.001",
                         "T1053.005","T1547.001","T1003.001","T1027"},
        "note": "Composite profile — common TTPs across many unattributed "
                "financially motivated intrusion sets",
    },
    "APT-style DNS C2 pattern (illustrative)": {
        "typical_ttps": {"T1071.004","T1573.002","T1546.003","T1055.012",
                         "T1027","T1583.001"},
        "note": "Illustrative pattern of groups known for DNS-based C2 — "
                "NOT a specific named group attribution",
    },
    "Commodity Ransomware Precursor Pattern": {
        "typical_ttps": {"T1566.001","T1078.004","T1003.001","T1053.005",
                         "T1547.001"},
        "note": "Common initial access + credential access chain seen "
                "in ransomware precursor (access broker) activity",
    },
}

print("=" * 65)
print("  TTP Comparison Against Reference Profiles")
print("=" * 65)

print(f"\n  Confirmed incident TTPs: {len(INCIDENT_TTPS)}")
for t in sorted(INCIDENT_TTPS):
    print(f"    {t}")

print(f"\n  Overlap Analysis:")
print(f"  {'─'*55}")

results = []
for profile_name, data in REFERENCE_PROFILES.items():
    overlap = INCIDENT_TTPS & data["typical_ttps"]
    overlap_pct = len(overlap) / len(data["typical_ttps"]) * 100
    results.append((profile_name, overlap, overlap_pct, data["note"]))

results.sort(key=lambda x: x[2], reverse=True)

for name, overlap, pct, note in results:
    print(f"\n  {name}")
    print(f"    Overlap: {len(overlap)} techniques ({pct:.0f}% of profile)")
    print(f"    Matching: {', '.join(sorted(overlap))}")
    print(f"    Note: {note}")

print(f"\n  ATTRIBUTION IMPLICATIONS:")
print(f"  {'─'*55}")
top_match = results[0]
print(f"    Highest overlap: {top_match[0]} ({top_match[2]:.0f}%)")
print(f"")
print(f"    IMPORTANT CAVEAT: TTP overlap with a category or pattern does")
print(f"    NOT constitute attribution to a specific named group. These")
print(f"    techniques (DNS C2, WMI persistence, LSASS dumping) are widely")
print(f"    documented, publicly available in penetration testing frameworks")
print(f"    and leaked toolkits, and used by dozens of unrelated actors")
print(f"    across the threat landscape. TTP overlap alone should NEVER")
print(f"    be presented as high-confidence attribution.")

with open("artifacts/ttp_comparison/ttp_comparison.json", "w") as f:
    json.dump({
        "incident_ttps": sorted(INCIDENT_TTPS),
        "comparison_results": [
            {"profile": r[0], "overlap": sorted(r[1]), "overlap_pct": round(r[2],1)}
            for r in results
        ],
    }, f, indent=2)

print(f"\n[+] TTP comparison saved: artifacts/ttp_comparison/ttp_comparison.json")
```

```bash
python3 ttp_comparison.py | tee artifacts/ttp_comparison/comparison_summary.txt
```

---

## STEP 5 — Structured Confidence Assessment (ICD 203 Standard)

**Objective:** Produce the final attribution assessment using intelligence
community standard confidence language (per Intelligence Community
Directive 203), explicitly documenting alternative hypotheses.

```python
# Save as: build_attribution_assessment.py
import json
from datetime import datetime

ASSESSMENT = {
    "title": "Attribution Assessment — NovaCrest Capital Group Intrusion",
    "date": "2025-01-18",
    "classification": "TLP:AMBER",

    "key_judgments": [
        {
            "judgment": "The observed infrastructure represents a single "
                       "cohesive operation, not multiple unrelated actors "
                       "coincidentally overlapping.",
            "confidence": "HIGH",
            "basis": "Consistent ASN, registrar, subnet, and timing across "
                    "all identified phishing and C2 infrastructure.",
        },
        {
            "judgment": "The actor is more likely financially motivated "
                       "than a nation-state sponsored operation.",
            "confidence": "MODERATE",
            "basis": "Cost-sensitive bulletproof hosting selection, "
                    "disposable domain infrastructure, and direct "
                    "monetization attempt via dark web forum sale.",
        },
        {
            "judgment": "The actor possesses above-average but not "
                       "elite technical sophistication.",
            "confidence": "MODERATE",
            "basis": "Custom/modified malware evading all AV detection, "
                    "multi-layered persistence, MFA-bypass phishing kit — "
                    "but also basic OPSEC gaps (dark web account timing "
                    "correlation, high TTP overlap with documented "
                    "criminal patterns).",
        },
        {
            "judgment": "Insufficient evidence exists to attribute this "
                       "activity to any specific named threat actor group.",
            "confidence": "HIGH",
            "basis": "No unique, non-public TTP signature identified. "
                    "All observed techniques are documented in public "
                    "frameworks and used across many unrelated actors. "
                    "No linguistic, cultural, or infrastructure evidence "
                    "meets the threshold for named-group attribution.",
        },
    ],

    "alternative_hypotheses": [
        {
            "hypothesis": "H1: Independent financially-motivated criminal "
                         "actor or small group, targeting financial sector "
                         "opportunistically or via prior reconnaissance.",
            "assessment": "MOST LIKELY based on available evidence",
            "supporting_evidence": [
                "Bulletproof hosting cost-sensitivity",
                "Direct dark web monetization attempt",
                "TTP overlap with documented criminal patterns (62%)",
            ],
            "contradicting_evidence": [
                "Custom malware development effort exceeds typical "
                "commodity criminal tooling investment",
            ],
        },
        {
            "hypothesis": "H2: Initial Access Broker (IAB) who compromised "
                         "the environment and is now selling access/data "
                         "to a second-stage actor (e.g., ransomware operator).",
            "assessment": "PLAUSIBLE — cannot be excluded",
            "supporting_evidence": [
                "Dark web sale of access/data is a documented IAB business model",
                "Multi-layered persistence suggests hand-off preparation",
            ],
            "contradicting_evidence": [
                "No confirmed second-stage actor activity observed",
                "Direct exfiltration (not just access sale) suggests "
                "same actor conducted both intrusion and monetization",
            ],
        },
        {
            "hypothesis": "H3: Nation-state actor using criminal "
                         "infrastructure and TTPs as a false-flag or "
                         "cost-saving measure.",
            "assessment": "POSSIBLE BUT NOT SUPPORTED — low confidence",
            "supporting_evidence": [
                "Custom malware development shows above-commodity investment",
                "Financial sector targeting could align with strategic "
                "intelligence collection interests",
            ],
            "contradicting_evidence": [
                "Direct, unsubtle monetization via public forum sale is "
                "atypical for nation-state operational security discipline",
                "No evidence of intelligence-collection-specific behavior "
                "(e.g., selective document targeting, long-term persistence "
                "beyond financial data)",
            ],
        },
    ],

    "confidence_language_key": {
        "HIGH":     "Strong evidentiary basis; judgment is well-supported "
                   "by multiple independent, high-quality indicators",
        "MODERATE": "Credibly sourced evidence exists but is not "
                   "corroborated sufficiently for high confidence, or "
                   "admits reasonable alternative explanations",
        "LOW":      "Scant, questionable, or single-source evidence; "
                   "judgment should be treated as speculative",
    },

    "explicitly_not_supported": [
        "Attribution to any specific named APT group or criminal "
        "syndicate by name",
        "Nation-of-origin determination beyond broad regional speculation",
        "Individual identity of any operator",
        "Confirmation of whether this is a first-time or repeat "
        "campaign by the same actor against other victims (though "
        "the Day 03 evidence suggests broader sector targeting by "
        "the same infrastructure)",
    ],
}

print("=" * 65)
print("  ATTRIBUTION ASSESSMENT — Final Report")
print("=" * 65)

print(f"\n  KEY JUDGMENTS:")
for i, kj in enumerate(ASSESSMENT["key_judgments"], 1):
    print(f"\n  {i}. [{kj['confidence']} CONFIDENCE] {kj['judgment']}")
    print(f"     Basis: {kj['basis']}")

print(f"\n\n  ALTERNATIVE HYPOTHESES CONSIDERED:")
for h in ASSESSMENT["alternative_hypotheses"]:
    print(f"\n  {h['hypothesis']}")
    print(f"    Assessment: {h['assessment']}")
    print(f"    Supporting: {'; '.join(h['supporting_evidence'])}")
    print(f"    Contradicting: {'; '.join(h['contradicting_evidence'])}")

print(f"\n\n  EXPLICITLY NOT SUPPORTED BY CURRENT EVIDENCE:")
for item in ASSESSMENT["explicitly_not_supported"]:
    print(f"    ✗ {item}")

with open("artifacts/attribution_assessment.json", "w") as f:
    json.dump(ASSESSMENT, f, indent=2)

print(f"\n[+] Full assessment saved: artifacts/attribution_assessment.json")
```

```bash
python3 build_attribution_assessment.py | tee artifacts/attribution_summary.txt
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What single ASN hosts every piece of identified attacker infrastructure?
- [ ] 🚩 **Flag 2:** What confidence level standard (document name) governs the language used in this assessment?
- [ ] 🚩 **Flag 3:** What percentage TTP overlap did the incident show with the "Generic Financially-Motivated Criminal Cluster" profile?
- [ ] 🚩 **Flag 4:** What are the three alternative hypotheses considered, and which is assessed as most likely?
- [ ] 🚩 **Flag 5:** Why is timing-based time zone inference considered a weak attribution signal?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `infrastructure/cluster_map.json` | Consolidated infrastructure cluster data |
| `infrastructure/cluster_summary.txt` | Cluster mapping console output |
| `infrastructure/hosting_pattern_analysis.json` | Hosting provider selection analysis |
| `infrastructure/hosting_summary.txt` | Hosting pattern console output |
| `timing/timing_analysis.json` | Operational timing distribution with caveats |
| `timing/timing_summary.txt` | Timing analysis console output |
| `ttp_comparison/ttp_comparison.json` | TTP overlap against 3 reference profiles |
| `ttp_comparison/comparison_summary.txt` | TTP comparison console output |
| `attribution_assessment.json` | Final structured attribution assessment |
| `attribution_summary.txt` | Full assessment console output |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| Shodan historical data unavailable | Requires paid membership tier — document limitation and proceed with available data |
| BGP.he.net rate limiting | Space queries by 2+ seconds; use cached WHOIS where possible |
| Uncertain confidence levels | When in doubt, downgrade — overconfident attribution is a more serious analytical error than appropriate uncertainty |

---

*Next: [REPORT.md](REPORT.md) — Attribution intelligence report*
