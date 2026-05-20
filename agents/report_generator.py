"""
Report Generator Agent
Produces GitHub-ready markdown portfolio reports from security findings.
"""

import anthropic
from datetime import date
from typing import Optional

client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are a professional security analyst producing portfolio-quality reports.

Generate a structured markdown security report with these sections:
1. Executive Summary (3-4 sentences, non-technical)
2. Technical Findings (detailed, with evidence)
3. MITRE ATT&CK Mappings (table format)
4. Risk Assessment (CVSS + DREAD scores where applicable)
5. Recommendations (prioritized, actionable)
6. Artifacts & IOCs (if applicable)

Write in professional security analyst voice. Use markdown headers, tables, and code blocks.
Be specific and technical. This is a portfolio piece demonstrating real skill."""


def generate_report(
    query: str,
    results: dict,
    day_number: Optional[int] = None,
    routing: Optional[dict] = None,
    title: Optional[str] = None,
) -> str:
    """Generate a full markdown report from investigation findings."""

    day_str = f"Day {str(day_number).zfill(2)} — " if day_number else ""
    report_title = title or routing.get("task_summary", "Security Investigation Report") if routing else "Security Investigation Report"

    prompt = f"""Generate a complete security analyst report for this investigation.

Title: {day_str}{report_title}
Date: {date.today().isoformat()}
Analyst: Blaakpearl

Original Query: {query}

Investigation Results:
{str(results)}

{'MITRE Techniques Found: ' + str(results.get('mitre', {}).get('techniques', [])) if 'mitre' in results else ''}

Produce a full, professional markdown report."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def generate_scenario(day_number: int, title: str, track: str, description: str) -> str:
    """Generate a SCENARIO.md for a given day."""
    prompt = f"""Write a detailed threat scenario for a security portfolio lab.

Day: {day_number}
Title: {title}
Track: {track}
Brief: {description}

Include: threat actor profile, target environment, attack vector, detection challenge, 
business context, and learning objectives. Write as a professional security brief."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system="You are a senior security trainer writing realistic threat scenarios for professional development.",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def generate_lab(day_number: int, title: str, tools: list, objectives: str) -> str:
    """Generate a LAB.md with step-by-step instructions."""
    prompt = f"""Write a detailed hands-on lab guide for a security portfolio exercise.

Day: {day_number}
Title: {title}
Tools: {', '.join(tools)}
Objectives: {objectives}

Include: prerequisites, environment setup, numbered step-by-step instructions with 
exact commands, expected outputs, common errors, and capture-the-flag style checkpoints.
Use code blocks for all commands."""

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system="You are a senior security engineer writing precise, reproducible lab guides.",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


if __name__ == "__main__":
    sample_results = {
        "threat_hunt": "Found DNS beaconing to 185.220.101.45 at regular 60s intervals",
        "mitre": {"techniques": [{"id": "T1071.004", "name": "DNS", "tactic": "Command and Control"}]}
    }
    report = generate_report(
        query="Investigate DNS beaconing on host DESKTOP-001",
        results=sample_results,
        day_number=4,
        title="Network Traffic Anomalies"
    )
    print(report)
