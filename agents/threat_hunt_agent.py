"""
Threat Hunt Agent — Generates hunt hypotheses and detection queries.
"""
import anthropic, json

client = anthropic.Anthropic()

SYSTEM = """You are a senior threat hunter. Generate hunt hypotheses and detection queries.

Respond ONLY with JSON:
{
  "hypothesis": "...",
  "hunt_queries": {
    "splunk": "...", "kql": "...", "zeek": "..."
  },
  "sigma_rule": "...",
  "indicators": [],
  "false_positive_notes": "...",
  "mitre_techniques": []
}"""

def generate_hunt_queries(query: str) -> dict:
    r = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=1000,
        system=SYSTEM, messages=[{"role":"user","content":query}])
    raw = r.content[0].text.strip()
    if raw.startswith("```"): raw = raw.split("```")[1]; raw = raw[4:] if raw.startswith("json") else raw
    return json.loads(raw.strip())

if __name__ == "__main__":
    print(json.dumps(generate_hunt_queries("Hunt for DNS beaconing with regular 60s intervals"), indent=2))
