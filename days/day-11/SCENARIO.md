# Day 11 — Geo-IP & Attribution
### Track: OSINT | Difficulty: Advanced | Phase: Attribution Analysis

---

## 🎯 Threat Brief

It is Day 17 of the NovaCrest Capital Group incident. The technical picture
is nearly complete: phishing infrastructure, C2 beacon, persistence mechanisms,
malware sample, dark web sale claim, and a resolved lateral movement question.
What remains unanswered is the question every executive and board member will
ask: **who did this?**

Attribution in cybersecurity is notoriously difficult and frequently
overstated by vendors seeking headlines. Today's exercise is deliberately
disciplined: you will build a geographic and infrastructure attribution
assessment using only technical evidence, explicitly documenting confidence
levels and alternative hypotheses rather than producing a confident but
unsupported "APT29 did this" conclusion.

**Your mission:** trace the attacker's infrastructure choices — hosting
providers, ASN patterns, registration behaviors, and operational timing —
to build the most defensible attribution assessment possible, while being
explicit about what the evidence does NOT support.

---

## 🌍 The Attribution Challenge

Attribution is one of the hardest problems in cybersecurity because
sophisticated attackers deliberately manipulate the evidence used for
attribution:

```
┌────────────────────────────────────────────────────────────────────┐
│  WHY ATTRIBUTION IS HARD                                             │
│                                                                      │
│  False Flags:        Attackers plant misleading language strings,   │
│                       use infrastructure in third countries, or      │
│                       mimic known group TTPs to misdirect analysts  │
│                                                                      │
│  Shared Infrastructure: Bulletproof hosting providers serve dozens   │
│                       of unrelated criminal groups — same ASN does   │
│                       not mean same actor                            │
│                                                                      │
│  VPN/Proxy Chains:    Registration and access often routed through   │
│                       multiple hops, obscuring true origin           │
│                                                                      │
│  Tool Reuse:          Commodity tools (Cobalt Strike, Sliver) and    │
│                       leaked/shared toolkits are used by many        │
│                       unrelated groups — TTP overlap ≠ same actor    │
│                                                                      │
│  Operational Timing:  Time zone inference from activity patterns     │
│                       is suggestive but never conclusive alone       │
└────────────────────────────────────────────────────────────────────┘
```

The discipline of good attribution work is **not** confidently naming a
group. It is building a structured, evidence-graded assessment that states
clearly what is known, what is inferred, what is uncertain, and what
alternative explanations remain viable.

---

## 🔍 The Evidence Available

```
Infrastructure Evidence (Days 01, 03, 04):
  • ASN AS209588 — Flyservers S.A., Seychelles (bulletproof hosting)
  • 12-domain phishing cluster, Namecheap registrar, WhoisGuard privacy
  • C2 IP 185.220.101.33 — same /24 subnet as phishing infrastructure
  • Registration timing: all infrastructure built January 5, 2025

Behavioral Evidence (Days 02, 04, 06, 08):
  • Reverse-proxy MFA-bypass phishing kit (custom/modified)
  • DNS-based C2 with 60.3s beacon interval, low jitter
  • WMI persistence + Registry Run key + Scheduled Task (multi-layered)
  • LSASS credential dumping via MiniDumpWriteDump
  • Zero AV detection at delivery — custom or heavily modified tooling

Operational Timing Evidence:
  • Infrastructure built: Jan 5, 2025, 14:32–20:00 UTC
  • Phishing delivered: Jan 14, 2025, ~09:00 UTC
  • Forum post (data sale): Jan 16, 2025, 12:47 UTC
  • Dark web account created: Jan 3, 2025 (Day 09)
```

---

## 📚 Learning Objectives

1. Perform IP/ASN pivoting to map the full scope of attacker-controlled infrastructure
2. Analyze BGP routing and hosting provider selection patterns for attribution signal
3. Cluster infrastructure using passive DNS, WHOIS history, and certificate reuse
4. Apply operational timing analysis to infer likely time zone of operation
5. Cross-reference TTPs against known threat actor profiles using ATT&CK Groups data
6. Build a confidence-graded attribution assessment following intelligence community standards
7. Explicitly document alternative hypotheses and evidence gaps

---

## ✅ Success Criteria

- [ ] Full infrastructure cluster mapped via IP/ASN/certificate pivoting
- [ ] Hosting provider selection pattern analyzed for attribution signal
- [ ] Operational timing analysis completed with time zone inference
- [ ] TTP comparison against at least 3 known threat actor profiles
- [ ] Attribution assessment uses structured confidence language (per ICD 203 standards)
- [ ] At least 2 alternative hypotheses documented and evaluated
- [ ] Final assessment explicitly states what is NOT supported by evidence

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| **T1583** | Acquire Infrastructure | Resource Development | Full cluster analysis |
| **T1583.001** | Domains | Resource Development | Registration pattern analysis |
| **T1584** | Compromise Infrastructure | Resource Development | Hosting provider selection |
| **T1590** | Gather Victim Network Information | Reconnaissance | Analyst-perspective (defender) |
| **T1596** | Search Open Technical Databases | Reconnaissance | Analyst-perspective (defender) |

---

*Next: [LAB.md](LAB.md) — Step-by-step attribution analysis lab guide*
