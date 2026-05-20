"""
OSINT Pipeline — Chain multiple OSINT lookups and correlate results.
Requires: ANTHROPIC_API_KEY env var set.
"""
import json
from agents.osint_agent import osint_research

def run_pipeline(targets: list) -> dict:
    """Run OSINT research on a list of targets and correlate findings."""
    all_results = {}
    ioc_master = []
    for target in targets:
        print(f"[OSINT Pipeline] Researching: {target}")
        result = osint_research(f"Perform OSINT research on: {target}")
        all_results[target] = result
        ioc_master.extend(result.get("iocs", []))
    return {"targets": all_results, "consolidated_iocs": list(set(ioc_master))}

if __name__ == "__main__":
    targets = ["example-threat-actor-domain.com", "185.220.101.0/24"]
    results = run_pipeline(targets)
    print(json.dumps(results, indent=2))
