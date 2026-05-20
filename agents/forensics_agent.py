"""
Forensics Agent — Artifact analysis and timeline reconstruction.
"""
import anthropic, json

client = anthropic.Anthropic()

SYSTEM = """You are a digital forensics examiner. Analyze artifacts and reconstruct timelines.

Respond ONLY with JSON:
{
  "artifact_type": "...",
  "findings": [],
  "timeline": [{"timestamp":"...","event":"...","significance":"high|medium|low"}],
  "iocs": [],
  "malware_indicators": [],
  "recommended_volatility_plugins": [],
  "chain_of_custody_notes": "..."
}"""

def analyze_artifacts(query: str) -> dict:
    r = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=1000,
        system=SYSTEM, messages=[{"role":"user","content":query}])
    raw = r.content[0].text.strip()
    if raw.startswith("```"): raw = raw.split("```")[1]; raw = raw[4:] if raw.startswith("json") else raw
    return json.loads(raw.strip())

if __name__ == "__main__":
    print(json.dumps(analyze_artifacts("Analyze memory image showing suspicious svchost process with injected DLL"), indent=2))
