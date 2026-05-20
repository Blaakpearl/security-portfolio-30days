"""
Timeline Builder — Build markdown forensic timelines from event lists.
"""
import json, sys
from datetime import datetime

def build_markdown_timeline(events: list) -> str:
    events_sorted = sorted(events, key=lambda e: e.get("timestamp",""))
    lines = ["# Forensic Timeline\n", "| Timestamp | Event | Source | Significance |",
             "|-----------|-------|--------|--------------|"]
    for e in events_sorted:
        sig = e.get("significance","medium")
        emoji = {"high":"🔴","medium":"🟡","low":"🟢"}.get(sig,"⚪")
        lines.append(f"| `{e.get('timestamp','')}` | {e.get('event','')} | {e.get('source','')} | {emoji} {sig.upper()} |")
    return "\n".join(lines)

if __name__ == "__main__":
    sample = [
        {"timestamp":"2025-01-15T08:23:11Z","event":"Phishing email opened","source":"Exchange","significance":"high"},
        {"timestamp":"2025-01-15T08:24:05Z","event":"Macro execution detected","source":"Defender","significance":"high"},
        {"timestamp":"2025-01-15T08:25:30Z","event":"PowerShell download cradle","source":"Sysmon EID 1","significance":"high"},
    ]
    print(build_markdown_timeline(sample))
