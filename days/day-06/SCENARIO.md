# Day 06 — Endpoint Persistence Hunt
### Track: Purple Team | Difficulty: Intermediate | Phase: Persistence Detection

---

## 🎯 Threat Brief

It is Day 12 of the NovaCrest Capital Group incident. DESKTOP-FIN-047 has been
isolated and a forensic image captured. But the IR team faces a hard question:
**if the attacker was in the environment for 11 days, did they establish
persistence beyond the C2 beacon itself?**

A beacon running for 11 days requires the malware process to survive reboots.
If the threat actor deployed scheduled tasks, registry run keys, or WMI event
subscriptions, they can re-establish access even after the workstation is
rebuilt and re-imaged. Worse: if lateral movement occurred during those 11
days, persistence mechanisms may exist on hosts not yet identified.

Today's exercise is a structured **Purple Team detection validation**: the red
side deploys three common Windows persistence mechanisms in an isolated lab VM.
The blue side must detect all three within a 2-hour window using Velociraptor,
OSQuery, Sysmon, and Autoruns differential analysis. Every detection gap found
today becomes a Sigma rule deployed to the production SIEM.

**The goal is not to catch a simulated attacker. The goal is to prove your
detection capability — or expose the gaps before a real attacker does.**

---

## 🔴 Red Side — What Gets Deployed (Isolated Lab Only)

> All persistence mechanisms are deployed and removed within an isolated
> Windows 11 lab VM. No production connectivity. Purpose: create realistic
> forensic artefacts for the blue side to detect and document.

Three mechanisms deployed in sequence with 20-minute spacing:

```
T+00:00  Mechanism 1 — Scheduled Task
         Task name mimics legitimate Windows maintenance task
         Executes PowerShell payload every 60 minutes
         Requires no user interaction after creation

T+20:00  Mechanism 2 — Registry Run Key
         Written to HKCU\...\CurrentVersion\Run
         Executes at every user logon
         Requires only standard user privileges — no admin needed

T+40:00  Mechanism 3 — WMI Event Subscription
         Permanent WMI filter + consumer + binding
         Triggers on system uptime event at boot
         Most stealthy — survives most remediation procedures
```

---

## 🔵 Blue Side — Detection Objectives

```
┌──────────────────────────────────────────────────────────────────┐
│  DETECTION CHALLENGE                                              │
│                                                                   │
│  Mechanism 1 — Scheduled Task                                     │
│    Detect via: Windows Event 4698, Sysmon Event 1                │
│    Hunt tool:  OSQuery scheduled_tasks table                     │
│    Rule:       sigma_scheduled_task_persistence.yml              │
│                                                                   │
│  Mechanism 2 — Registry Run Key                                   │
│    Detect via: Sysmon Event 12/13, Autoruns differential         │
│    Hunt tool:  Velociraptor Windows.Registry.RunKeys             │
│    Rule:       sigma_registry_run_key_persistence.yml            │
│                                                                   │
│  Mechanism 3 — WMI Event Subscription                            │
│    Detect via: Sysmon Events 19/20/21, WMI namespace query      │
│    Hunt tool:  OSQuery wmi_event_filters + wmi_cli_event_consumers│
│    Rule:       sigma_wmi_subscription_persistence.yml            │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🏢 Exercise Parameters

```
Environment:     Isolated Windows 11 lab VM — zero production connectivity
Red objective:   Deploy 3 mechanisms with 20-minute spacing
Blue objective:  Detect all 3 within 2-hour total SLA window
Scoring:         MTTD (mean time to detect) per mechanism + Sigma rule quality
Success:         All 3 detected + 3 production Sigma rules written
Partial:         Any missed mechanism = gap documented + rule written anyway
```

---

## ⚠️ Why These Three Mechanisms

These are not exotic techniques. They are the persistence mechanisms used in
the majority of real-world intrusions documented in threat intelligence reports
because they work — they are reliable, they blend with legitimate system
activity, and most environments have incomplete detection coverage for at
least one of them.

- **Scheduled tasks** blend with hundreds of legitimate Windows and third-party
  tasks — signal-to-noise is high without behavioral baselining
- **Registry Run keys** are populated by every installer on the system —
  defenders need a whitelist of known-good entries before anomalies surface
- **WMI subscriptions** are used by almost no legitimate end-user processes,
  are invisible in Task Manager and basic Autoruns output, and survive reboots
  silently — making them the preferred choice for sophisticated actors who
  expect the endpoint to be rebooted during investigation

---

## 📚 Learning Objectives

1. Take an Autoruns baseline before any changes and run differential analysis
2. Use Sysmon Events 12, 13, 19, 20, 21 to detect registry and WMI activity
3. Use OSQuery to enumerate live system state — scheduled tasks and WMI tables
4. Use Velociraptor to collect the Windows.Registry.RunKeys forensic artifact
5. Enumerate the WMI `root\subscription` namespace directly via PowerShell
6. Write three production Sigma rules — one per persistence mechanism
7. Score the exercise: record MTTD per mechanism and document detection gaps

---

## ✅ Success Criteria

- [ ] Autoruns baseline taken before deployment and differential run after
- [ ] Scheduled task detected — Event 4698 or OSQuery — time recorded
- [ ] Registry run key detected — Sysmon Event 13 or Autoruns diff — time recorded
- [ ] WMI subscription detected — Events 19/20/21 or PowerShell enum — time recorded
- [ ] Velociraptor artifact used for at least one detection
- [ ] OSQuery query written and executed for at least one mechanism
- [ ] Three Sigma rules written to `artifacts/` folder
- [ ] Purple team debrief completed — MTTD, gaps, improvements documented

---

## 🔗 MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Mechanism |
|---|---|---|---|
| **T1053.005** | Scheduled Task | Persistence | Mechanism 1 |
| **T1547.001** | Registry Run Keys / Startup Folder | Persistence | Mechanism 2 |
| **T1546.003** | WMI Event Subscription | Persistence | Mechanism 3 |
| **T1059.001** | PowerShell | Execution | All payloads |
| **T1036.005** | Masquerading: Match Legitimate Name | Defense Evasion | Task / key naming |
| **T1112** | Modify Registry | Defense Evasion | Mechanism 2 |

---

*Next: [LAB.md](LAB.md) — Step-by-step purple team detection lab guide*
