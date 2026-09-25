# Day 29 — LAB.md
## AI Agent Integration Lab Guide
**NovaCrest Capital Group | Full Stack Track**

---

## Phase 1: Claude API Setup

```bash
# Install Anthropic Python SDK
pip install anthropic --break-system-packages

# Set API key (use environment variable — never hardcode)
export ANTHROPIC_API_KEY="your_key_here"

# Basic API call test
python3 - << 'EOF'
import anthropic

client = anthropic.Anthropic()

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[
        {
            "role": "user",
            "content": "What ATT&CK technique does 'vssadmin delete shadows /all /quiet' map to?"
        }
    ]
)
print(message.content[0].text)
EOF
```

---

## Phase 2: Tool-Augmented Agent Pattern

```python
# Tool-use pattern: agent calls external APIs during reasoning

import anthropic
import json

client = anthropic.Anthropic()

# Define tools the agent can call
TOOLS = [
    {
        "name": "virustotal_ip_lookup",
        "description": "Look up an IP address in VirusTotal to get reputation, ASN, and related domains",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "IPv4 address to look up"
                }
            },
            "required": ["ip_address"]
        }
    },
    {
        "name": "attck_technique_lookup",
        "description": "Get MITRE ATT&CK technique details including mitigations and detections",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "ATT&CK technique ID (e.g. T1566.001)"
                }
            },
            "required": ["technique_id"]
        }
    },
    {
        "name": "generate_siem_query",
        "description": "Generate a Splunk SPL query to detect a specific ATT&CK technique",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string"},
                "siem_platform": {
                    "type": "string",
                    "enum": ["splunk", "sentinel", "elastic"]
                },
                "log_source": {"type": "string"}
            },
            "required": ["technique_id", "siem_platform"]
        }
    }
]


def run_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool call and return the result."""
    if tool_name == "virustotal_ip_lookup":
        # In production: call VT API
        # In demo: return simulated data
        ip = tool_input["ip_address"]
        if ip == "198.51.100.99":
            return json.dumps({
                "malicious_detections": 47,
                "asn": "AS209588",
                "asn_name": "Flyservers S.A.",
                "country": "NL",
                "related_domains": ["trading-updates.novacrest-secure.com"],
                "tags": ["c2", "bulletproof-hosting"],
                "verdict": "MALICIOUS"
            })
        return json.dumps({"verdict": "CLEAN", "detections": 0})

    elif tool_name == "attck_technique_lookup":
        tid = tool_input["technique_id"]
        return json.dumps({
            "id": tid,
            "name": "Spearphishing Attachment" if "T1566.001" in tid else "Unknown",
            "tactic": "Initial Access",
            "mitigation": "User training; email gateway filtering; macro policy",
            "detection": "Monitor Office apps spawning cmd/PowerShell; email gateway logs"
        })

    elif tool_name == "generate_siem_query":
        return json.dumps({
            "query": f"index=sysmon EventCode=1 "
                     f"ParentImage IN (\"*WINWORD*\",\"*EXCEL*\") "
                     f"Image IN (\"*cmd.exe*\",\"*powershell.exe*\")",
            "platform": tool_input["siem_platform"]
        })

    return json.dumps({"error": f"Unknown tool: {tool_name}"})


def run_agent_with_tools(prompt: str, system: str = "") -> str:
    """Run an agentic loop with tool use."""
    messages = [{"role": "user", "content": prompt}]
    sys_prompt = system or "You are an expert cybersecurity analyst. Use the tools available to enrich your analysis."

    while True:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=sys_prompt,
            tools=TOOLS,
            messages=messages
        )

        # Collect tool calls
        tool_uses = [b for b in response.content if b.type == "tool_use"]

        if not tool_uses:
            # No more tool calls — final response
            text_blocks = [b for b in response.content if b.type == "text"]
            return text_blocks[0].text if text_blocks else ""

        # Execute tool calls and add results
        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        for tool_use in tool_uses:
            result = run_tool(tool_use.name, tool_use.input)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": result
            })
        messages.append({"role": "user", "content": tool_results})
```

---

## Phase 3: LangChain Agent Setup

```bash
pip install langchain langchain-anthropic --break-system-packages
```

```python
from langchain_anthropic import ChatAnthropic
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate

# Define LangChain tools
@tool
def virustotal_lookup(ip_or_hash: str) -> str:
    """Look up an IP address or file hash in VirusTotal."""
    # Real implementation: call VT API
    return f"VT result for {ip_or_hash}: 47 malicious detections, AS209588 (Flyservers)"

@tool
def attck_lookup(technique_id: str) -> str:
    """Get MITRE ATT&CK technique details."""
    return f"T1566.001: Spearphishing Attachment | Tactic: Initial Access | Detection: Monitor Office macro execution"

@tool
def shodan_lookup(ip: str) -> str:
    """Get Shodan banner and port data for an IP."""
    return f"Shodan {ip}: ports=[22,80,443,8443], server=nginx/1.24.0, JARM=1dd28f00..., ASN=AS209588"

# Create the agent
llm = ChatAnthropic(model="claude-sonnet-4-6")
tools = [virustotal_lookup, attck_lookup, shodan_lookup]

prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a senior cybersecurity analyst at NovaCrest Capital Group.
    Your job is to triage security alerts, enrich IOCs, and produce structured
    analysis reports. Always:
    1. Use tools to enrich IOCs before making conclusions
    2. Map findings to MITRE ATT&CK
    3. Include confidence levels
    4. Flag what you're uncertain about
    5. Recommend specific next steps
    """),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}")
])

agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

# Run the agent
result = agent_executor.invoke({
    "input": "Triage this alert: Source IP 198.51.100.99 established HTTPS connection to WS-FIN-04 at 09:14 UTC. JA3 hash: a0e9f5d64349fb13191bc781f81f42e1"
})
print(result["output"])
```

---

## Phase 4: FastAPI Alert Ingestion Endpoint

```bash
pip install fastapi uvicorn --break-system-packages
```

```python
# api/alert_ingest.py — Splunk webhook receiver → AI triage
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import anthropic
import json
import logging

app = FastAPI(title="NovaCrest AI Security Analyst", version="1.0")
client = anthropic.Anthropic()
log = logging.getLogger("alert_ingest")


class SplunkAlert(BaseModel):
    alert_name: str
    source_ip: str
    dest_ip: str
    event_time: str
    raw_event: str
    severity: str


@app.post("/api/v1/alert")
async def receive_alert(alert: SplunkAlert, background_tasks: BackgroundTasks):
    """Receive Splunk webhook alert and queue for AI triage."""
    background_tasks.add_task(triage_alert_async, alert)
    return {"status": "queued", "alert_name": alert.alert_name}


async def triage_alert_async(alert: SplunkAlert):
    """Background task: run AI triage on alert."""
    prompt = f"""
    Triage this security alert from the NovaCrest SIEM:

    Alert Name: {alert.alert_name}
    Source IP: {alert.source_ip}
    Destination IP: {alert.dest_ip}
    Time: {alert.event_time}
    Severity: {alert.severity}
    Raw Event: {alert.raw_event}

    Known context:
    - NovaCrest internal network: 10.0.0.0/8
    - Confirmed attacker IP: 198.51.100.99
    - Known Sliver JA3: a0e9f5d64349fb13191bc781f81f42e1

    Provide:
    1. SEVERITY ASSESSMENT (Critical/High/Medium/Low) with reasoning
    2. ATT&CK technique mapping
    3. Confidence level (0-100%)
    4. Immediate recommended action
    5. What additional data would confirm or refute your assessment
    """

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}]
    )

    triage_result = response.content[0].text
    log.info(f"Alert triaged: {alert.alert_name}\n{triage_result}")
    # In production: push to Jira ticket, Slack, or SOC queue


# Run: uvicorn api.alert_ingest:app --host 0.0.0.0 --port 8001
```

---

## Phase 5: Evaluating Agent Quality

```bash
# Run the built-in evaluation suite
python3 scripts/triage_agent.py --demo --eval

# Expected output:
# ┌─────────────────────────────────────────────────┐
# │ AGENT EVALUATION RESULTS                        │
# │ Triage Agent — NovaCrest Demo                   │
# ├─────────────────────────────────────────────────┤
# │ Test cases: 5                                   │
# │ Correct severity: 5/5 (100%)                    │
# │ Correct ATT&CK: 4/5 (80%)                       │
# │ Actionable output: 5/5 (100%)                   │
# │ Mean latency: 2.3s                              │
# │ Mean tokens: 847                                │
# └─────────────────────────────────────────────────┘
```

---

*Day 29 Lab Guide | AI Agent Integration*
*NovaCrest Capital Group | V. Willis, CISSP*
*github.com/Blaakpearl/Blaakpearl*
