# Day 28 — REPORT.md
## OSINT Investigation Report
**NovaCrest Capital Group | OSINT Track**
**Author:** V. Willis, CISSP
**Date:** 2026-06-28

---

## Summary

| Finding | Value |
|---------|-------|
| Investigation seed | C2 IP 198.51.100.99 |
| Infrastructure nodes | 6 domains + 2 C2 IPs + 1 ASN |
| Confirmed victims | 4 (3 prior + NovaCrest) |
| Potential 5th victim | `capitalupdates.org` domain (unconfirmed) |
| Second C2 discovered | 198.51.100.101 (ASN pivot — not previously known) |
| Campaign cadence | ~50 days between attacks |
| Infra prep lead time | 8 days (domain reg → phishing) |
| Actor OPSEC score | 5.8/10 — Moderate-Advanced |
| Key OPSEC weakness | Static IP 3+ months; predictable cert timing |
| Total demanded (4 victims) | ~$12M USD equivalent |
| Paid | 1 of 4 victims (US Hedge Fund, May 2026) |
| Leak site | Active — NovaCrest deadline June 22 |
| Next campaign estimate | ~August 2026 |

---

## The Single Most Actionable Finding

The Let's Encrypt certificate timing is the most operationally useful
finding in this investigation. Across all four known victims, the actor
issued a new cert exactly 2 days after domain registration and 6 days
before phishing delivery — without exception.

If a financial sector CT log monitor spots a new Let's Encrypt cert for
a `[finance-term]-[action-term].[tld]` domain resolving to AS209588,
that is 6 days of warning before the next phishing email lands.

That monitoring query is `O-4` in `osint_hunt.kql`. It should be running
now, and the alert should go to FS-ISAC immediately when it fires.

---

## What This Day Adds

Day 28 closes the intelligence loop on the NovaCrest breach narrative.
Day 26 asked "who is this?" Day 28 asks "what is their entire operation?"
The answer: a professional, financially-focused ransomware group with four
confirmed victims in four months, an escalating target profile, a consistent
operational playbook, and a predictable next-campaign window.

That predictability is both their operational efficiency and their greatest
weakness — it turns their playbook into an early warning system for the
sector.

---

## Git Commit

```bash
cd security-portfolio-30days
git checkout main && git pull origin main

mkdir -p days/day-28/{scripts,queries,reports,artifacts}
cp -r /path/to/outputs/day28/* days/day-28/

git add days/day-28/

git commit -m "feat: Add Day 28 — OSINT Investigation Report (Maltego, i2, Shodan)

Track: OSINT | Tools: Maltego, i2 Analyst's Notebook, Shodan, SpiderFoot
          Censys, crt.sh, DNSDB, Ransomwatch

FIN-NC-001 infrastructure OSINT investigation:
  - 6 domains + 2 C2 IPs + AS209588 (Flyservers NL) mapped
  - 4 confirmed victims; potential 5th victim domain identified
  - Second C2 node (198.51.100.101) discovered via ASN pivot
  - Campaign cadence: ~50 days | Infra prep: 8 days lead time
  - Let's Encrypt cert timing = 6-day early warning indicator
  - Actor OPSEC: 5.8/10 — static IP + naming pattern = fingerprint
  - Ransom formula: 0.1% of AUM (consistent across all 4 victims)
  - 1 of 4 prior victims paid; 2 had data published
  - Next campaign estimated August 2026 — early warning checklist produced
  - Executive brief for board/C-suite distribution
  - Infrastructure graph: 18 nodes, 22 edges (Maltego/i2 compatible)

Deliverables:
  SCENARIO.md, LAB.md, REPORT.md
  scripts/infrastructure_mapper.py  (ASN pivot, passive DNS, OPSEC scoring)
  scripts/campaign_tracker.py       (4-victim timeline, pattern analysis, prediction)
  queries/osint_hunt.spl            (8 SPL: infra match, CT signals, leak monitoring)
  queries/osint_hunt.kql            (7 KQL: infra match, campaign analysis, prediction)
  reports/day28_investigation_report.md (full OSINT investigation with link chart)
  reports/day28_executive_brief.md  (board/C-suite brief in plain language)
  artifacts/infrastructure_graph.json (18 nodes, 22 edges, Maltego/i2 format)"

git push origin main
```

---

*Day 28 — OSINT Investigation Report | NovaCrest Capital Group*
*V. Willis, CISSP | github.com/Blaakpearl/Blaakpearl*
