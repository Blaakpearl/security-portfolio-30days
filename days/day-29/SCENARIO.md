# Day 29 — SCENARIO.md
## AI Agent Integration: Autonomous Security Analysis Pipeline
**NovaCrest Capital Group | Security Operations**
**Classification:** TLP:AMBER — Security Operations Use
**Track:** Full Stack
**Tools:** Claude API · Python · LangChain · Splunk · MITRE ATT&CK

---

## The Capability Gap

Twenty-eight days of the NovaCrest investigation produced a body of work
that would take a traditional team of analysts weeks to produce manually:
forensic timelines, IOC bundles, threat actor profiles, detection rules,
OSINT link graphs, executive briefs, and risk registers. Day 29 addresses
the next evolution: what if a significant portion of that analytical pipeline
could run autonomously — with an AI agent as the analyst, not just the tool?

The honest answer is nuanced. AI agents in 2026 can credibly automate:
- IOC triage and enrichment (pivot, score, normalize)
- Alert summarization and first-pass triage
- SIEM query generation for a given ATT&CK technique
- Draft threat intelligence reports from structured data
- IOC-to-STIX conversion
- Natural language → detection rule translation

They cannot yet reliably replace:
- Human judgment on ambiguous forensic evidence
- Novel TTP identification without prior training data
- Legal and regulatory decision-making
- Attribution with accountability
- Adversarial red-teaming creativity

Day 29 builds an **AI-augmented security analyst pipeline** that automates
the credible subset — freeing human analysts for the judgment work that
machines cannot do.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   AI Security Analyst Pipeline                   │
│                     NovaCrest SOC Integration                    │
└─────────────────────────────────────────────────────────────────┘

  INGESTION LAYER
  ├── Splunk alerts (via Webhook → FastAPI endpoint)
  ├── CloudTrail events (direct S3 poll)
  ├── Zeek conn/dns/ssl logs (Kafka consumer)
  └── STIX feeds (TAXII pull, FS-ISAC)

  AGENT LAYER (Claude API — claude-sonnet-4-6)
  ├── Alert Triage Agent
  │   → Receives raw alert, enriches IOCs, scores severity
  │   → Output: structured triage report + recommended action
  │
  ├── IOC Enrichment Agent
  │   → Pivots IOCs via VT/OTX/Shodan tool calls
  │   → Output: enriched IOC set, STIX indicator objects
  │
  ├── Threat Hunt Query Agent
  │   → Given ATT&CK technique, generates SIEM queries
  │   → Output: Splunk SPL + Sentinel KQL + Elastic EQL
  │
  ├── Report Drafting Agent
  │   → Given structured findings, drafts analyst report
  │   → Output: markdown report in NovaCrest template
  │
  └── SOAR Action Agent
      → Recommends containment actions (human-approved)
      → Output: runbook steps, not direct execution

  OUTPUT LAYER
  ├── Structured triage tickets (Jira/ServiceNow)
  ├── Draft reports (pushed to security team Slack)
  ├── STIX bundles (pushed to OpenCTI)
  └── Human review queue (all agent outputs reviewed before action)
```

---

## Design Principles

### 1. Human-in-the-Loop
No agent takes direct action on production systems. Every output goes to
a human review queue. The agent recommends, the analyst decides.

### 2. Explainability
Every agent output includes a `reasoning` field explaining why the
conclusion was reached, what data was used, and what the agent is
uncertain about. No black-box scores.

### 3. Audit Trail
Every agent invocation is logged with: input hash, model version,
output, confidence, human reviewer, and final disposition.

### 4. Failure Gracefully
If the agent produces low-confidence output, it flags for human review
rather than guessing. Uncertainty is a first-class output.

### 5. Tool-Augmented
Agents use real tools (VT API, Shodan, MITRE ATT&CK TAXII) rather than
hallucinating from training data. Tool calls are logged and auditable.

---

## Agents Built Today

| Agent | Input | Output | Automation Value |
|-------|-------|--------|-----------------|
| `triage_agent.py` | Raw SIEM alert JSON | Structured triage report | Replaces 15-min manual triage per alert |
| `ioc_enricher.py` | List of IOCs | Enriched STIX indicators | Replaces 30-min manual VT/OTX pivoting |
| `hunt_query_gen.py` | ATT&CK technique ID | SPL + KQL + EQL queries | Replaces 45-min query authoring session |
| `report_drafter.py` | Findings JSON | Draft markdown report | Replaces 2-hr initial report writing |

**Combined time savings per incident:** ~3.5 hours of mechanical analyst work
automated per major alert, freeing humans for judgment and decision-making.

---

## Deliverables

| File | Description |
|------|-------------|
| `SCENARIO.md` | This document |
| `LAB.md` | Claude API setup, LangChain agent config, pipeline integration |
| `REPORT.md` | Architecture summary and capability demonstration |
| `scripts/triage_agent.py` | AI-powered alert triage agent |
| `scripts/ioc_enricher.py` | Automated IOC enrichment pipeline |
| `scripts/hunt_query_gen.py` | ATT&CK-to-SIEM query generator |
| `scripts/report_drafter.py` | AI report drafting agent |
| `queries/agent_validation.spl` | Splunk SPL: agent output validation queries |
| `queries/agent_validation.kql` | Sentinel KQL: agent performance monitoring |
| `reports/day29_agent_report.md` | Full pipeline design and demo output |
| `artifacts/pipeline_config.json` | Agent pipeline configuration |

---

*Day 29 Scenario | AI Agent Integration*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
