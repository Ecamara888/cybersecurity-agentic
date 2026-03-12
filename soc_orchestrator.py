"""
SOC Orchestrator — Master Cybersecurity Analyst
================================================
Coordinates all specialized security agents to perform a full-spectrum
security assessment. Each agent can also be run standalone.

Architecture:
    soc_orchestrator.py          ← you are here (master coordinator)
    ├── cloud_security_agent.py  ← cloud infra, IAM, network, compliance
    ├── threat_intel_agent.py    ← IOC hunting, CVE research, threat modeling
    ├── incident_response_agent.py ← log analysis, forensics, containment
    └── vuln_scanner_agent.py    ← SAST, dependency audit, secrets detection

Usage:
    python soc_orchestrator.py [target_path] [--mode full|quick|cloud|threat|ir|vuln]

Modes:
    full   — Run all agents (default)
    quick  — Vuln scan + threat intel only
    cloud  — Cloud security audit only
    threat — Threat intelligence only
    ir     — Incident response only
    vuln   — Vulnerability scan only
"""

import sys
import anyio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    AgentDefinition,
    ResultMessage,
    SystemMessage,
)

# Import agent definitions from standalone modules
from cloud_security_agent import AGENT_DEFINITION as CLOUD_SECURITY_DEF  # noqa: E402
from threat_intel_agent import AGENT_DEFINITION as THREAT_INTEL_DEF  # noqa: E402
from incident_response_agent import AGENT_DEFINITION as INCIDENT_RESPONSE_DEF  # noqa: E402
from vuln_scanner_agent import AGENT_DEFINITION as VULN_SCANNER_DEF  # noqa: E402

# Final report writer — consolidates output from all agents
REPORT_WRITER_DEF = AgentDefinition(
    description=(
        "Security Report Writer. Consolidates findings from all security agents into "
        "a comprehensive executive and technical security report. Produces a prioritized "
        "remediation roadmap, risk score, and compliance posture summary."
    ),
    prompt="""You are a Security Report Writer. Create a full security assessment report:

---
# Security Assessment Report

**Date:** [today]
**Classification:** CONFIDENTIAL

## Executive Summary
- Overall Risk Score: X/100
- Critical Findings: N
- High Findings: N
- Medium Findings: N
- Low Findings: N
- Top 3 Immediate Actions Required

## Findings Summary Table
| ID | Title | Severity | Category | Status |
|----|-------|----------|----------|--------|

## Critical & High Findings (Full Detail)
For each: Title, Description, Evidence, Business Impact, Remediation Steps, Effort

## Cloud Security Findings
[From cloud-security-engineer]

## Vulnerability Findings
[From vuln-scanner]

## Threat Intelligence
[From threat-intel-analyst]

## Incident Response Findings
[From incident-responder]

## Compliance Posture
| Framework | Controls Checked | Pass | Fail | Coverage |
|-----------|-----------------|------|------|----------|

## Remediation Roadmap
### Immediate (0-24 hours)
### Short Term (1-7 days)
### Medium Term (7-30 days)
### Long Term (30-90 days)

## Risk Metrics
- Attack surface score
- Data exposure risk
- Compliance gap severity
- Incident readiness score

---

Write this report to `security_assessment_report.md` and print the executive summary.""",
    tools=["Read", "Write", "Glob"],
)


def build_agents_for_mode(mode: str) -> dict:
    """Return the appropriate agent set for the selected mode."""
    all_agents = {
        "cloud-security-engineer": CLOUD_SECURITY_DEF,
        "threat-intel-analyst": THREAT_INTEL_DEF,
        "incident-responder": INCIDENT_RESPONSE_DEF,
        "vuln-scanner": VULN_SCANNER_DEF,
        "report-writer": REPORT_WRITER_DEF,
    }
    mode_map = {
        "full": all_agents,
        "quick": {
            "vuln-scanner": VULN_SCANNER_DEF,
            "threat-intel-analyst": THREAT_INTEL_DEF,
            "report-writer": REPORT_WRITER_DEF,
        },
        "cloud": {
            "cloud-security-engineer": CLOUD_SECURITY_DEF,
            "report-writer": REPORT_WRITER_DEF,
        },
        "threat": {
            "threat-intel-analyst": THREAT_INTEL_DEF,
            "report-writer": REPORT_WRITER_DEF,
        },
        "ir": {
            "incident-responder": INCIDENT_RESPONSE_DEF,
            "report-writer": REPORT_WRITER_DEF,
        },
        "vuln": {
            "vuln-scanner": VULN_SCANNER_DEF,
            "report-writer": REPORT_WRITER_DEF,
        },
    }
    return mode_map.get(mode, all_agents)


def build_prompt(mode: str, target: str) -> str:
    prompts = {
        "full": f"""You are the SOC Orchestrator conducting a FULL security assessment on: {target}

Execute ALL agents in this sequence and collect their findings:

1. **cloud-security-engineer** — Audit cloud infrastructure, IAM policies, network configs,
   and compliance posture. Collect all findings.

2. **threat-intel-analyst** — Hunt for IOCs, research CVE exposure, and build a MITRE
   ATT&CK threat model. Collect all findings.

3. **vuln-scanner** — Run SAST analysis, dependency audit, and secrets detection.
   Collect all findings.

4. **incident-responder** — Analyze logs and artifacts for signs of compromise,
   build attack timeline, and create containment playbook. Collect all findings.

5. **report-writer** — Pass ALL findings from agents 1-4 to this agent and generate
   the final `security_assessment_report.md`.

Be thorough. Pass complete findings between agents. The final report must cover all domains.""",

        "quick": f"""You are the SOC Orchestrator conducting a QUICK security scan on: {target}

1. **vuln-scanner** — Scan for code vulnerabilities, bad dependencies, and exposed secrets.
2. **threat-intel-analyst** — Hunt for IOCs and CVE exposures.
3. **report-writer** — Consolidate findings into `security_assessment_report.md`.""",

        "cloud": f"""You are the SOC Orchestrator conducting a CLOUD SECURITY AUDIT on: {target}

1. **cloud-security-engineer** — Full cloud security audit (IAM, network, compliance).
2. **report-writer** — Write findings to `security_assessment_report.md`.""",

        "threat": f"""You are the SOC Orchestrator conducting THREAT INTELLIGENCE analysis on: {target}

1. **threat-intel-analyst** — Full IOC hunting, CVE research, threat modeling.
2. **report-writer** — Write findings to `security_assessment_report.md`.""",

        "ir": f"""You are the SOC Orchestrator conducting an INCIDENT RESPONSE investigation on: {target}

1. **incident-responder** — Log analysis, forensics, containment planning.
2. **report-writer** — Write findings to `security_assessment_report.md`.""",

        "vuln": f"""You are the SOC Orchestrator conducting a VULNERABILITY SCAN on: {target}

1. **vuln-scanner** — SAST, dependency audit, secrets detection.
2. **report-writer** — Write findings to `security_assessment_report.md`.""",
    }
    return prompts.get(mode, prompts["full"])


async def run_soc_orchestrator(target_path: str = ".", mode: str = "full"):
    """
    Master SOC Orchestrator — runs all security agents together.

    Args:
        target_path: Directory to analyze
        mode: Assessment mode (full|quick|cloud|threat|ir|vuln)
    """
    agents = build_agents_for_mode(mode)
    prompt = build_prompt(mode, target_path)

    print("=" * 60)
    print("  SOC ORCHESTRATOR — Cybersecurity Assessment Platform")
    print("=" * 60)
    print(f"  Target : {target_path}")
    print(f"  Mode   : {mode.upper()}")
    print(f"  Agents : {', '.join(a for a in agents if a != 'report-writer')}")
    print("=" * 60)
    print()

    async for message in query(
        prompt=prompt,
        options=ClaudeAgentOptions(
            cwd=target_path,
            allowed_tools=["Read", "Glob", "Grep", "Bash", "Agent"],
            permission_mode="acceptEdits",
            max_turns=80,
            agents=agents,
        ),
    ):
        if isinstance(message, SystemMessage) and message.subtype == "init":
            print(f"Session ID: {message.session_id}\n")
        elif isinstance(message, ResultMessage):
            print("\n" + "=" * 60)
            print("  ASSESSMENT COMPLETE")
            print("=" * 60)
            print(message.result)
            print("\nFull report saved to: security_assessment_report.md")


if __name__ == "__main__":
    target = "."
    mode = "full"

    args = sys.argv[1:]
    for arg in args:
        if arg.startswith("--mode="):
            mode = arg.split("=", 1)[1]
        elif not arg.startswith("--"):
            target = arg

    valid_modes = {"full", "quick", "cloud", "threat", "ir", "vuln"}
    if mode not in valid_modes:
        print(f"Invalid mode '{mode}'. Choose from: {', '.join(sorted(valid_modes))}")
        sys.exit(1)

    anyio.run(run_soc_orchestrator, target, mode)
