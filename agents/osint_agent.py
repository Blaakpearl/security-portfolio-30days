"""
OSINT Agent — Passive intelligence gathering via Claude API.
"""
import anthropic, json

client = anthropic.Anthropic()

SYSTEM = """You are an expert OSINT analyst. Given a target or query, produce a structured
intelligence collection plan and synthesize findings.

Respond ONLY with JSON:
{
  "target": "...",
  "collection_plan": ["step1", "step2"],
  "findings": {
    "domains": [], "ips": [], "emails": [], "persons": [],
    "infrastructure": [], "social_profiles": []
  },
  "iocs": [],
  "confidence": "high|medium|low",
  "next_steps": ["..."]
}"""

def osint_research(query: str) -> dict:
    r = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=1000,
        system=SYSTEM, messages=[{"role":"user","content":query}])
    raw = r.content[0].text.strip()
    if raw.startswith("```"): raw = raw.split("```")[1]; raw = raw[4:] if raw.startswith("json") else raw
    return json.loads(raw.strip())

if __name__ == "__main__":
    print(json.dumps(osint_research("Map external attack surface for example-corp.com"), indent=2))
