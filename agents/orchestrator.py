"""
Blaakpearl Security Portfolio — AI Agent Orchestrator
Powered by Claude (Anthropic API)

Routes security research queries to specialist agents and synthesizes outputs.
"""

import anthropic
import json
from typing import Optional

client = anthropic.Anthropic()  # set ANTHROPIC_API_KEY env var

SYSTEM_PROMPT = """You are the Orchestrator for a security research AI agent system.
Your role is to:
1. Analyze the incoming security research query
2. Determine which specialist agent(s) should handle it
3. Return a JSON routing decision with agent selection and task breakdown

Available agents: osint, threat_hunt, threat_intel, forensics, purple_team, mitre_mapper, report_generator

Respond ONLY with JSON in this format:
{
  "primary_agent": "agent_name",
  "supporting_agents": ["agent1", "agent2"],
  "task_summary": "one sentence task description",
  "priority": "high|medium|low",
  "mitre_mapping_required": true|false,
  "report_required": true|false
}"""


def orchestrate(query: str, context: Optional[dict] = None) -> dict:
    """Route a security query to the appropriate specialist agents."""
    messages = [{"role": "user", "content": query}]
    if context:
        messages[0]["content"] = f"Context: {json.dumps(context)}\n\nQuery: {query}"

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=messages,
    )

    raw = response.content[0].text.strip()
    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())


def run_pipeline(query: str, day_number: Optional[int] = None) -> str:
    """
    Full pipeline: orchestrate → specialist agents → MITRE mapper → report.
    Returns a GitHub-ready markdown report.
    """
    from osint_agent import osint_research
    from threat_hunt_agent import generate_hunt_queries
    from forensics_agent import analyze_artifacts
    from mitre_mapper_agent import map_to_attack
    from report_generator import generate_report

    print(f"[Orchestrator] Routing query: {query[:80]}...")
    routing = orchestrate(query)
    print(f"[Orchestrator] Primary agent: {routing['primary_agent']}")

    results = {}

    # Run primary agent
    agent = routing["primary_agent"]
    if agent == "osint":
        results["osint"] = osint_research(query)
    elif agent == "threat_hunt":
        results["threat_hunt"] = generate_hunt_queries(query)
    elif agent == "forensics":
        results["forensics"] = analyze_artifacts(query)

    # MITRE mapping
    if routing.get("mitre_mapping_required"):
        results["mitre"] = map_to_attack(results, query)

    # Generate report
    if routing.get("report_required"):
        report_md = generate_report(
            query=query,
            results=results,
            day_number=day_number,
            routing=routing
        )
        return report_md

    return json.dumps(results, indent=2)


if __name__ == "__main__":
    # Example usage
    query = "Investigate suspicious DNS beaconing from host 10.1.2.45 to external resolver"
    result = orchestrate(query)
    print(json.dumps(result, indent=2))
