"""
MITRE ATT&CK Mapper Agent
Maps security findings to ATT&CK techniques and generates Navigator layers.
"""

import anthropic
import json
from typing import Union

client = anthropic.Anthropic()

SYSTEM_PROMPT = """You are a MITRE ATT&CK expert. Map security findings to ATT&CK techniques.

For each finding, identify:
- Technique ID (e.g. T1566.001)
- Technique name
- Tactic (e.g. Initial Access)
- Confidence (high/medium/low)
- Detection notes

Respond ONLY with JSON:
{
  "techniques": [
    {
      "id": "T1566.001",
      "name": "Spearphishing Attachment",
      "tactic": "Initial Access",
      "confidence": "high",
      "detection": "Monitor email gateway for attachment-based delivery"
    }
  ],
  "navigator_layer": {
    "name": "Analysis Layer",
    "domain": "enterprise-attack",
    "techniques": [{"techniqueID": "T1566.001", "score": 100, "color": "#ff4757"}]
  }
}"""


def map_to_attack(findings: Union[dict, str], context: str = "") -> dict:
    """Map findings dict or text description to MITRE ATT&CK techniques."""
    if isinstance(findings, dict):
        content = f"Context: {context}\n\nFindings:\n{json.dumps(findings, indent=2)}"
    else:
        content = f"Context: {context}\n\nFindings:\n{findings}"

    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": content}],
    )

    raw = response.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw.strip())


def export_navigator_layer(techniques: list, name: str = "Portfolio Layer") -> str:
    """Export ATT&CK Navigator layer JSON for import at attack.mitre.org/navigator."""
    layer = {
        "name": name,
        "versions": {"attack": "14", "navigator": "4.9"},
        "domain": "enterprise-attack",
        "description": f"Blaakpearl Security Portfolio — {name}",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Cloud"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": t.get("id", ""),
                "score": 100,
                "color": _tactic_color(t.get("tactic", "")),
                "comment": t.get("detection", ""),
                "enabled": True,
            }
            for t in techniques
        ],
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0f1318",
    }
    return json.dumps(layer, indent=2)


def _tactic_color(tactic: str) -> str:
    colors = {
        "Initial Access": "#ff4757",
        "Execution": "#ff6b81",
        "Persistence": "#ffa502",
        "Privilege Escalation": "#ffb700",
        "Defense Evasion": "#eccc68",
        "Credential Access": "#a29bfe",
        "Discovery": "#00d4ff",
        "Lateral Movement": "#55efc4",
        "Collection": "#81ecec",
        "Command and Control": "#fd79a8",
        "Exfiltration": "#e17055",
        "Impact": "#d63031",
    }
    return colors.get(tactic, "#636e72")


if __name__ == "__main__":
    sample = "Attacker used spearphishing email with malicious attachment to gain initial access, then used scheduled task for persistence."
    result = map_to_attack(sample, "Day 3 phishing investigation")
    print(json.dumps(result, indent=2))
