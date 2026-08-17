# Day 13 — Lab Guide: MITRE ATT&CK Mapping & Coverage Gap Analysis
### Track: Threat Intelligence | Duration: ~3.5 hours | Difficulty: Advanced

---

## 🛠 Tools Required

| Tool | Purpose | Access |
|------|---------|--------|
| **MITRE ATT&CK Groups** | Reference threat actor technique data | attack.mitre.org/groups |
| **ATT&CK Navigator** | Heat map visualization | mitre-attack.github.io/attack-navigator |
| **Python 3** | Gap analysis automation, layer generation | Pre-installed |
| **D3FEND** | Defensive technique mapping reference | d3fend.mitre.org |
| **pandas** | Coverage matrix data processing | `pip install pandas` |

---

## 🖥 Environment Setup

```bash
mkdir -p ~/security-labs/day-13/artifacts/{reference_profile,coverage_analysis,navigator,roadmap}
cd ~/security-labs/day-13

pip install pandas requests --break-system-packages

echo "[+] ATT&CK mapping environment ready"
echo "[+] Reference profile: APT29 (defensive benchmarking, not attribution)"
```

---

## STEP 1 — Build the Reference Threat Actor Profile

**Objective:** Enumerate APT29's publicly documented technique set from the
MITRE ATT&CK Groups database. This is public information — no special
access required.

```python
# Save as: build_reference_profile.py
# APT29 technique data sourced from MITRE ATT&CK Groups (G0016)
# https://attack.mitre.org/groups/G0016/
# Used here strictly for DEFENSIVE BENCHMARKING — not attribution

import json

# Representative subset of APT29's publicly documented techniques
# (Full profile at attack.mitre.org contains 60+ techniques; this lab
# uses a representative cross-tactic sample for the exercise)
APT29_PROFILE = {
    "group_id":   "G0016",
    "group_name": "APT29",
    "aliases":    ["Cozy Bear", "Midnight Blizzard", "NOBELIUM", "The Dukes"],
    "source":     "MITRE ATT&CK — attack.mitre.org/groups/G0016/",
    "usage_note": "Reference profile for defensive benchmarking only. "
                 "Day 11 attribution assessment does NOT support "
                 "attribution of the NovaCrest incident to this group.",

    "techniques": [
        {"id":"T1595",     "name":"Active Scanning",                      "tactic":"reconnaissance"},
        {"id":"T1589",     "name":"Gather Victim Identity Information",   "tactic":"reconnaissance"},
        {"id":"T1583.001", "name":"Acquire Infrastructure: Domains",      "tactic":"resource-development"},
        {"id":"T1587.001", "name":"Develop Capabilities: Malware",        "tactic":"resource-development"},
        {"id":"T1586.002", "name":"Compromise Accounts: Email Accounts",  "tactic":"resource-development"},
        {"id":"T1566.001", "name":"Spearphishing Attachment",             "tactic":"initial-access"},
        {"id":"T1566.002", "name":"Spearphishing Link",                   "tactic":"initial-access"},
        {"id":"T1078",     "name":"Valid Accounts",                       "tactic":"initial-access"},
        {"id":"T1195.002", "name":"Supply Chain Compromise: Software",    "tactic":"initial-access"},
        {"id":"T1059.001", "name":"PowerShell",                           "tactic":"execution"},
        {"id":"T1059.003", "name":"Windows Command Shell",                "tactic":"execution"},
        {"id":"T1053.005", "name":"Scheduled Task",                       "tactic":"persistence"},
        {"id":"T1098",     "name":"Account Manipulation",                 "tactic":"persistence"},
        {"id":"T1547.001", "name":"Registry Run Keys",                    "tactic":"persistence"},
        {"id":"T1546.003", "name":"WMI Event Subscription",               "tactic":"persistence"},
        {"id":"T1136",     "name":"Create Account",                       "tactic":"persistence"},
        {"id":"T1055",     "name":"Process Injection",                    "tactic":"defense-evasion"},
        {"id":"T1027",     "name":"Obfuscated Files or Information",      "tactic":"defense-evasion"},
        {"id":"T1070.004", "name":"File Deletion",                       "tactic":"defense-evasion"},
        {"id":"T1550.001", "name":"Application Access Token",            "tactic":"defense-evasion"},
        {"id":"T1036.005", "name":"Match Legitimate Name",               "tactic":"defense-evasion"},
        {"id":"T1003.001", "name":"LSASS Memory",                        "tactic":"credential-access"},
        {"id":"T1110.003", "name":"Password Spraying",                   "tactic":"credential-access"},
        {"id":"T1552.001", "name":"Credentials In Files",                "tactic":"credential-access"},
        {"id":"T1539",     "name":"Steal Web Session Cookie",            "tactic":"credential-access"},
        {"id":"T1082",     "name":"System Information Discovery",        "tactic":"discovery"},
        {"id":"T1069.002", "name":"Domain Groups Discovery",             "tactic":"discovery"},
        {"id":"T1018",     "name":"Remote System Discovery",             "tactic":"discovery"},
        {"id":"T1021.001", "name":"Remote Desktop Protocol",             "tactic":"lateral-movement"},
        {"id":"T1021.006", "name":"Windows Remote Management",           "tactic":"lateral-movement"},
        {"id":"T1550.002", "name":"Pass the Hash",                       "tactic":"lateral-movement"},
        {"id":"T1114.002", "name":"Remote Email Collection",             "tactic":"collection"},
        {"id":"T1560.001", "name":"Archive via Utility",                 "tactic":"collection"},
        {"id":"T1071.001", "name":"Web Protocols",                       "tactic":"command-and-control"},
        {"id":"T1071.004", "name":"DNS",                                 "tactic":"command-and-control"},
        {"id":"T1573.002", "name":"Asymmetric Cryptography",             "tactic":"command-and-control"},
        {"id":"T1090.002", "name":"External Proxy",                      "tactic":"command-and-control"},
        {"id":"T1041",     "name":"Exfiltration Over C2 Channel",        "tactic":"exfiltration"},
        {"id":"T1048.001", "name":"Exfiltration Over Alternative Protocol: DNS", "tactic":"exfiltration"},
    ],
}

print("=" * 65)
print(f"  Reference Threat Actor Profile — {APT29_PROFILE['group_name']}")
print("=" * 65)
print(f"\n  Group ID:  {APT29_PROFILE['group_id']}")
print(f"  Aliases:   {', '.join(APT29_PROFILE['aliases'])}")
print(f"  Source:    {APT29_PROFILE['source']}")
print(f"\n  ⚠ {APT29_PROFILE['usage_note']}")
print(f"\n  Total techniques in profile: {len(APT29_PROFILE['techniques'])}")

from collections import Counter
tactic_counts = Counter(t["tactic"] for t in APT29_PROFILE["techniques"])
print(f"\n  Tactic Distribution:")
for tactic, count in sorted(tactic_counts.items()):
    print(f"    {tactic:<25} {count:>2} technique(s)")

with open("artifacts/reference_profile/apt29_profile.json", "w") as f:
    json.dump(APT29_PROFILE, f, indent=2)

print(f"\n[+] Reference profile saved: artifacts/reference_profile/apt29_profile.json")
```

```bash
python3 build_reference_profile.py | tee artifacts/reference_profile/profile_summary.txt
```

---

## STEP 2 — Catalog Current Detection Coverage

**Objective:** Build a complete inventory of every detection rule NovaCrest
currently has deployed, drawing from the confirmed Sigma/KQL rules across
Days 02, 04, and 06.

```python
# Save as: catalog_current_coverage.py
import json

# Current detection rules deployed (confirmed from Days 02, 04, 06, 07)
CURRENT_COVERAGE = {
    "T1110.004": {"rule": "sigma_credential_stuffing.yml",        "day": "02", "level": "high",     "status": "DEPLOYED"},
    "T1078.004": {"rule": "kql_impossible_travel.kql",             "day": "02", "level": "high",     "status": "DEPLOYED"},
    "T1566.001": {"rule": "sigma_phishing_campaign.yml",           "day": "03", "level": "high",     "status": "DEPLOYED"},
    "T1583.001": {"rule": "sigma_phishing_campaign.yml (shared)",  "day": "03", "level": "high",     "status": "DEPLOYED"},
    "T1071.004": {"rule": "sigma_c2_beacon_dns.yml",               "day": "04", "level": "high",     "status": "DEPLOYED"},
    "T1048.001": {"rule": "sigma_dns_tunneling.yml",               "day": "04", "level": "high",     "status": "DEPLOYED"},
    "T1053.005": {"rule": "sigma_scheduled_task_persistence.yml",  "day": "06", "level": "high",     "status": "DEPLOYED"},
    "T1547.001": {"rule": "sigma_registry_run_key_persistence.yml","day": "06", "level": "medium",   "status": "DEPLOYED"},
    "T1546.003": {"rule": "sigma_wmi_subscription_persistence.yml","day": "06", "level": "critical", "status": "DEPLOYED"},
}

print("=" * 65)
print("  Current Detection Coverage Catalog — NovaCrest Capital Group")
print("=" * 65)

print(f"\n  Total rules deployed: {len(CURRENT_COVERAGE)}")
print(f"\n  {'Technique':<12} {'Level':<10} {'Rule File':<45} Day")
print("  " + "─" * 75)
for tid, data in CURRENT_COVERAGE.items():
    print(f"  {tid:<12} {data['level'].upper():<10} {data['rule']:<45} {data['day']}")

with open("artifacts/coverage_analysis/current_coverage.json", "w") as f:
    json.dump(CURRENT_COVERAGE, f, indent=2)

print(f"\n[+] Coverage catalog saved: artifacts/coverage_analysis/current_coverage.json")
```

```bash
python3 catalog_current_coverage.py | tee artifacts/coverage_analysis/coverage_summary.txt
```

---

## STEP 3 — Gap Analysis: Cross-Reference Profile Against Coverage

**Objective:** Determine which of APT29's reference techniques have full,
partial, or zero detection coverage in the current NovaCrest environment.

```python
# Save as: gap_analysis.py
import json

with open("artifacts/reference_profile/apt29_profile.json") as f:
    profile = json.load(f)

with open("artifacts/coverage_analysis/current_coverage.json") as f:
    coverage = json.load(f)

# Techniques that are conceptually related to covered ones but not exact
# matches — these count as PARTIAL coverage
PARTIAL_MATCHES = {
    "T1078":      "Covered rule targets T1078.004 (Cloud) specifically — "
                  "base T1078 (general Valid Accounts) has partial overlap "
                  "but not full parent-technique coverage",
    "T1566.002":  "Covered rule (sigma_phishing_campaign.yml) targets "
                  "T1566.001 patterns but also catches some T1566.002 "
                  "link-based indicators — partial overlap",
    "T1055":      "No direct rule, but Day 08/12 forensic methodology "
                  "(malfind-based detection) could be operationalized — "
                  "capability partially exists, not yet a deployed rule",
}

results = []
for tech in profile["techniques"]:
    tid = tech["id"]
    if tid in coverage:
        status = "COVERED"
        detail = coverage[tid]["rule"]
    elif tid in PARTIAL_MATCHES:
        status = "PARTIAL"
        detail = PARTIAL_MATCHES[tid]
    else:
        status = "GAP"
        detail = "No detection rule currently deployed"

    results.append({
        "id":     tid,
        "name":   tech["name"],
        "tactic": tech["tactic"],
        "status": status,
        "detail": detail,
    })

print("=" * 70)
print("  Gap Analysis — APT29 Reference Profile vs Current Coverage")
print("=" * 70)

covered = [r for r in results if r["status"] == "COVERED"]
partial = [r for r in results if r["status"] == "PARTIAL"]
gaps    = [r for r in results if r["status"] == "GAP"]

total = len(results)
print(f"\n  Total techniques assessed: {total}")
print(f"  ✅ COVERED:  {len(covered):>2}  ({len(covered)/total*100:.0f}%)")
print(f"  🟡 PARTIAL:  {len(partial):>2}  ({len(partial)/total*100:.0f}%)")
print(f"  ❌ GAP:      {len(gaps):>2}  ({len(gaps)/total*100:.0f}%)")

print(f"\n  {'─'*70}")
print(f"  COVERED TECHNIQUES:")
for r in covered:
    print(f"    ✅ {r['id']:<12} {r['name']:<40} [{r['tactic']}]")

print(f"\n  PARTIAL COVERAGE:")
for r in partial:
    print(f"    🟡 {r['id']:<12} {r['name']:<40} [{r['tactic']}]")
    print(f"       {r['detail']}")

print(f"\n  COVERAGE GAPS:")
for r in gaps:
    print(f"    ❌ {r['id']:<12} {r['name']:<40} [{r['tactic']}]")

# Gap breakdown by tactic — reveals which phases are weakest
from collections import Counter
gap_tactics = Counter(r["tactic"] for r in gaps)
print(f"\n  GAPS BY TACTIC (weakest phases):")
for tactic, count in sorted(gap_tactics.items(), key=lambda x: -x[1]):
    print(f"    {tactic:<25} {count} gap(s)")

with open("artifacts/coverage_analysis/gap_analysis_results.json", "w") as f:
    json.dump({
        "total": total,
        "covered": len(covered), "partial": len(partial), "gaps": len(gaps),
        "coverage_pct": round(len(covered)/total*100, 1),
        "results": results,
    }, f, indent=2)

print(f"\n[+] Full gap analysis saved: artifacts/coverage_analysis/gap_analysis_results.json")
```

```bash
python3 gap_analysis.py | tee artifacts/coverage_analysis/gap_analysis_summary.txt
```

**✅ Checkpoint 1:** Note which tactics show the most gaps — this directly
informs where detection engineering effort should be prioritized. Discovery
and Lateral Movement tactics frequently show the largest gaps in
organizations that have focused detection engineering primarily on Initial
Access and Command & Control (a common but incomplete pattern).

---

## STEP 4 — Generate ATT&CK Navigator Heat Map

**Objective:** Produce a visual, three-tier heat map layer that can be
imported into ATT&CK Navigator to communicate coverage status at a glance.

```python
# Save as: generate_heatmap_layer.py
import json

with open("artifacts/coverage_analysis/gap_analysis_results.json") as f:
    gap_data = json.load(f)

STATUS_COLORS = {
    "COVERED": "#00ff88",   # green
    "PARTIAL": "#ffb700",   # amber
    "GAP":     "#ff4757",   # red
}

STATUS_SCORES = {
    "COVERED": 100,
    "PARTIAL": 50,
    "GAP":     0,
}

layer = {
    "name":        "NovaCrest Detection Coverage vs APT29 Reference Profile",
    "versions":    {"attack": "14", "navigator": "4.9"},
    "domain":      "enterprise-attack",
    "description": (
        "Defensive coverage benchmarking layer — NOT an attribution claim. "
        "Maps NovaCrest Capital Group's current detection rule coverage "
        "against the publicly documented APT29 technique profile (MITRE "
        "ATT&CK Group G0016) for the purpose of identifying detection gaps "
        "and prioritizing detection engineering work. "
        "Analyst: Blaakpearl | Day 13 | 2025-01-19"
    ),
    "filters":     {"platforms": ["Windows", "Azure AD", "Office 365"]},
    "sorting":     0,
    "layout":      {"layout": "side", "showID": True, "showName": True},
    "hideDisabled": False,
    "techniques":  [],
    "gradient":    {"colors": ["#ff4757", "#ffb700", "#00ff88"],
                    "minValue": 0, "maxValue": 100},
    "legendItems": [
        {"label": "✅ Covered — detection rule deployed",  "color": "#00ff88"},
        {"label": "🟡 Partial — some overlapping coverage", "color": "#ffb700"},
        {"label": "❌ Gap — no detection rule",             "color": "#ff4757"},
    ],
    "showTacticRowBackground": True,
    "tacticRowBackground":     "#0f1318",
}

for r in gap_data["results"]:
    layer["techniques"].append({
        "techniqueID": r["id"],
        "score":       STATUS_SCORES[r["status"]],
        "color":       STATUS_COLORS[r["status"]],
        "comment":     f"{r['status']}: {r['detail'][:100]}",
        "enabled":     True,
    })

with open("artifacts/navigator/coverage_heatmap_layer.json", "w") as f:
    json.dump(layer, f, indent=2)

print("=" * 60)
print("  ATT&CK Navigator Heat Map Layer Generated")
print("=" * 60)
print(f"\n  Techniques mapped: {len(layer['techniques'])}")
print(f"  Coverage:  {gap_data['coverage_pct']}%")
print(f"\n  Import at: https://mitre-attack.github.io/attack-navigator/")
print(f"  File: artifacts/navigator/coverage_heatmap_layer.json")
```

```bash
python3 generate_heatmap_layer.py | tee artifacts/navigator/heatmap_summary.txt
```

---

## STEP 5 — Risk-Based Gap Prioritization

**Objective:** Not all gaps are equal. Prioritize the coverage gaps using
a structured risk framework considering exploitability, business impact,
and implementation effort.

```python
# Save as: prioritize_gaps.py
import json

with open("artifacts/coverage_analysis/gap_analysis_results.json") as f:
    gap_data = json.load(f)

gaps = [r for r in gap_data["results"] if r["status"] == "GAP"]

# Risk scoring factors (1-5 scale each)
RISK_FACTORS = {
    "T1595":     {"exploitability": 2, "business_impact": 2, "implementation_effort": 2},
    "T1589":     {"exploitability": 3, "business_impact": 2, "implementation_effort": 3},
    "T1587.001": {"exploitability": 1, "business_impact": 3, "implementation_effort": 5},
    "T1586.002": {"exploitability": 3, "business_impact": 4, "implementation_effort": 3},
    "T1195.002": {"exploitability": 2, "business_impact": 5, "implementation_effort": 5},
    "T1059.003": {"exploitability": 4, "business_impact": 4, "implementation_effort": 2},
    "T1098":     {"exploitability": 4, "business_impact": 5, "implementation_effort": 3},
    "T1136":     {"exploitability": 3, "business_impact": 4, "implementation_effort": 2},
    "T1070.004": {"exploitability": 3, "business_impact": 3, "implementation_effort": 2},
    "T1550.001": {"exploitability": 4, "business_impact": 4, "implementation_effort": 3},
    "T1003.001": {"exploitability": 5, "business_impact": 5, "implementation_effort": 3},
    "T1110.003": {"exploitability": 4, "business_impact": 4, "implementation_effort": 2},
    "T1552.001": {"exploitability": 3, "business_impact": 4, "implementation_effort": 2},
    "T1539":     {"exploitability": 5, "business_impact": 5, "implementation_effort": 4},
    "T1082":     {"exploitability": 2, "business_impact": 1, "implementation_effort": 1},
    "T1069.002": {"exploitability": 3, "business_impact": 3, "implementation_effort": 2},
    "T1018":     {"exploitability": 3, "business_impact": 3, "implementation_effort": 2},
    "T1021.001": {"exploitability": 4, "business_impact": 4, "implementation_effort": 2},
    "T1021.006": {"exploitability": 4, "business_impact": 4, "implementation_effort": 2},
    "T1550.002": {"exploitability": 5, "business_impact": 5, "implementation_effort": 3},
    "T1114.002": {"exploitability": 3, "business_impact": 4, "implementation_effort": 3},
    "T1560.001": {"exploitability": 2, "business_impact": 3, "implementation_effort": 2},
    "T1071.001": {"exploitability": 3, "business_impact": 3, "implementation_effort": 3},
    "T1090.002": {"exploitability": 3, "business_impact": 3, "implementation_effort": 3},
    "T1041":     {"exploitability": 4, "business_impact": 4, "implementation_effort": 2},
}

print("=" * 70)
print("  Risk-Based Gap Prioritization")
print("=" * 70)

prioritized = []
for r in gaps:
    factors = RISK_FACTORS.get(r["id"], {"exploitability":3,"business_impact":3,"implementation_effort":3})
    # Priority score: high exploitability + high impact + LOW effort = highest priority
    priority_score = (factors["exploitability"] * 2 +
                      factors["business_impact"] * 2 -
                      factors["implementation_effort"])
    prioritized.append({
        **r,
        "exploitability":       factors["exploitability"],
        "business_impact":      factors["business_impact"],
        "implementation_effort":factors["implementation_effort"],
        "priority_score":       priority_score,
    })

prioritized.sort(key=lambda x: x["priority_score"], reverse=True)

print(f"\n  {'Rank':<5}{'Technique':<12}{'Priority':<9}{'Effort':<8}Name")
print("  " + "─" * 70)
for i, p in enumerate(prioritized, 1):
    tier = "🔴 P1" if i <= 6 else ("🟠 P2" if i <= 14 else "🟡 P3")
    print(f"  {i:<5}{p['id']:<12}{p['priority_score']:<9}{p['implementation_effort']:<8}{p['name'][:35]} {tier}")

with open("artifacts/roadmap/prioritized_gaps.json", "w") as f:
    json.dump(prioritized, f, indent=2)

print(f"\n[+] Prioritized gap list saved: artifacts/roadmap/prioritized_gaps.json")
```

```bash
python3 prioritize_gaps.py | tee artifacts/roadmap/prioritization_summary.txt
```

---

## STEP 6 — 90-Day Detection Engineering Roadmap

```python
# Save as: build_roadmap.py
import json

with open("artifacts/roadmap/prioritized_gaps.json") as f:
    prioritized = json.load(f)

p1 = prioritized[:6]
p2 = prioritized[6:14]
p3 = prioritized[14:]

roadmap_md = f"""# 90-Day Detection Engineering Roadmap
## NovaCrest Capital Group — APT29 Coverage Gap Remediation

**Prepared by:** Blaakpearl | **Date:** 2025-01-19
**Reference:** Day 13 gap analysis — {len(prioritized)} gaps identified

---

## Phase 1 — Days 1-30 (Quick Wins + Critical Risk)

Focus: Highest priority score (exploitability × impact, low effort)

| Technique | Name | Priority | Effort |
|-----------|------|:--------:|:------:|
"""
for p in p1:
    roadmap_md += f"| {p['id']} | {p['name'][:40]} | {p['priority_score']} | {p['implementation_effort']}/5 |\n"

roadmap_md += f"""
**Milestone:** All Phase 1 rules deployed and validated via purple team
exercise by Day 30. Expected coverage increase: +{len(p1)} techniques.

---

## Phase 2 — Days 31-60 (Foundational Detection Engineering)

Focus: Moderate priority, may require new data source onboarding

| Technique | Name | Priority | Effort |
|-----------|------|:--------:|:------:|
"""
for p in p2:
    roadmap_md += f"| {p['id']} | {p['name'][:40]} | {p['priority_score']} | {p['implementation_effort']}/5 |\n"

roadmap_md += f"""
**Milestone:** Data source gaps closed (e.g., enhanced logging enablement),
Phase 2 rules deployed by Day 60. Expected coverage increase: +{len(p2)} techniques.

---

## Phase 3 — Days 61-90 (Comprehensive Coverage + Maturity)

Focus: Remaining gaps, lower individual priority but completes the picture

| Technique | Name | Priority | Effort |
|-----------|------|:--------:|:------:|
"""
for p in p3:
    roadmap_md += f"| {p['id']} | {p['name'][:40]} | {p['priority_score']} | {p['implementation_effort']}/5 |\n"

roadmap_md += f"""
**Milestone:** Full APT29 reference profile coverage achieved or explicitly
risk-accepted with documented rationale by Day 90.

---

## Success Metrics

| Metric | Baseline (Day 13) | Day 30 Target | Day 60 Target | Day 90 Target |
|--------|:-----------------:|:-------------:|:-------------:|:-------------:|
| Techniques covered | 9/38 (24%) | {9+len(p1)}/38 | {9+len(p1)+len(p2)}/38 | 38/38 (100%*) |
| Detection rules deployed | 8 | {8+len(p1)} | {8+len(p1)+len(p2)} | {8+len(prioritized)} |

*100% coverage target may include explicitly risk-accepted gaps with
documented compensating controls where full detection is not feasible.

---

## Governance

- **Weekly:** Detection engineering standup — review in-flight rule development
- **Bi-weekly:** Purple team validation of newly deployed rules (per Day 06 methodology)
- **Monthly:** Coverage percentage reported to CISO and board risk committee
- **Day 90:** Full re-run of this gap analysis to measure actual vs. planned progress
"""

with open("artifacts/roadmap/90_day_roadmap.md", "w") as f:
    f.write(roadmap_md)

print(roadmap_md)
print(f"\n[+] Roadmap saved: artifacts/roadmap/90_day_roadmap.md")
```

```bash
python3 build_roadmap.py | tee artifacts/roadmap/roadmap_summary.txt
```

---

## 🚩 Capture the Flag Checkpoints

- [ ] 🚩 **Flag 1:** What percentage of the APT29 reference profile does NovaCrest currently have COVERED status for?
- [ ] 🚩 **Flag 2:** Which ATT&CK tactic shows the highest number of coverage gaps?
- [ ] 🚩 **Flag 3:** What are the three factors used in the risk-based gap prioritization formula?
- [ ] 🚩 **Flag 4:** Why is using APT29 as a reference profile explicitly NOT an attribution claim?
- [ ] 🚩 **Flag 5:** What three colors are used in the ATT&CK Navigator heat map, and what does each represent?

---

## 📁 Artifacts to Commit

| File | Contents |
|------|---------|
| `reference_profile/apt29_profile.json` | APT29 reference technique profile (38 techniques) |
| `reference_profile/profile_summary.txt` | Profile console output |
| `coverage_analysis/current_coverage.json` | Current 9-rule detection catalog |
| `coverage_analysis/coverage_summary.txt` | Coverage catalog console output |
| `coverage_analysis/gap_analysis_results.json` | Full covered/partial/gap classification |
| `coverage_analysis/gap_analysis_summary.txt` | Gap analysis console output |
| `navigator/coverage_heatmap_layer.json` | ATT&CK Navigator 3-tier heat map layer |
| `navigator/heatmap_summary.txt` | Heat map generation output |
| `roadmap/prioritized_gaps.json` | Risk-scored, ranked gap list |
| `roadmap/prioritization_summary.txt` | Prioritization console output |
| `roadmap/90_day_roadmap.md` | Full phased detection engineering roadmap |
| `roadmap/roadmap_summary.txt` | Roadmap generation output |

---

## 🔧 Troubleshooting

| Issue | Fix |
|-------|-----|
| Uncertain about a technique's exploitability score | Default to middle score (3) rather than guessing extremes |
| Navigator layer won't import | Validate JSON syntax with `python3 -m json.tool file.json` |
| Roadmap seems too aggressive | Adjust phase boundaries based on actual team capacity — 90 days is illustrative |

---

*Next: [REPORT.md](REPORT.md) — Defensive coverage assessment report*
