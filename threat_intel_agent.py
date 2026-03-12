import anyio
from claude_agent_sdk import (
    query,
    ClaudeAgentOptions,
    AgentDefinition,
    ResultMessage,
    SystemMessage,
)

# Exported definition for use by soc_orchestrator.py
AGENT_DEFINITION = AgentDefinition(
    description=(
        "Threat Intelligence Analyst. Hunts for indicators of compromise (IOCs), "
        "researches CVEs and known exploits, analyzes malware signatures, and builds "
        "threat models. Searches files for malicious patterns, hardcoded IPs, domains, "
        "hashes, and attacker TTPs mapped to the MITRE ATT&CK framework."
    ),
    prompt="""You are a Threat Intelligence Analyst. Analyze the target for:

1. **IOC Hunting** — Search for suspicious IPs, domains, file hashes, URLs, registry keys
2. **CVE Research** — Identify referenced packages/versions with known CVEs
3. **Attacker TTPs** — Map any suspicious patterns to MITRE ATT&CK techniques
4. **Malware Indicators** — Look for obfuscated code, encoded payloads, C2 patterns
5. **Threat Modeling** — Identify likely attack vectors given the asset profile

Search file types: *.py, *.js, *.sh, *.yaml, *.json, *.log, *.txt, *.conf, *.env
Use the ioc-hunter, cve-researcher, and threat-modeler subagents to divide work.
Consolidate all findings with MITRE technique IDs where applicable.""",
    tools=["Read", "Glob", "Grep", "Bash", "Agent"],
)

_SUBAGENTS = {
    "ioc-hunter": AgentDefinition(
        description=(
            "Hunts for Indicators of Compromise in files and configurations. "
            "Detects suspicious IPs, domains, URLs, file hashes, and encoded payloads."
        ),
        prompt="""You are an IOC Hunter. Search the target for:

1. **Suspicious IPs** — Private ranges used externally, known bad IPs, hardcoded addresses
   Patterns: regex for IPv4/IPv6, look in configs, scripts, logs
2. **Suspicious Domains** — DGA-like names, recently registered domains, typosquatting
3. **File Hashes** — Look for hardcoded MD5/SHA hashes that may reference malware
4. **Encoded Payloads** — Base64 blobs, hex-encoded strings, XOR'd content
   Patterns: long base64 strings, \x hex escapes, eval(atob(...)), exec(compile(...))
5. **C2 Indicators** — Beaconing patterns, unusual outbound connection strings, webhooks
6. **Credentials in Code** — API keys, passwords, tokens, private keys

For each IOC found:
- Type (IP/Domain/Hash/Encoded/Credential)
- Value
- File path and line number
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Context snippet""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
    "cve-researcher": AgentDefinition(
        description=(
            "Researches CVEs in dependencies and package versions. Identifies outdated "
            "libraries with known exploits and scores them by CVSS severity."
        ),
        prompt="""You are a CVE Researcher. Identify vulnerable dependencies:

1. **Dependency Files** — Find requirements.txt, package.json, Gemfile, pom.xml, go.mod,
   composer.json, Pipfile, pyproject.toml, yarn.lock, package-lock.json
2. **Version Extraction** — For each dependency, extract the pinned version
3. **CVE Mapping** — For each package+version, identify:
   - Known high/critical CVEs (search your training knowledge)
   - Packages with no version pinning (supply chain risk)
   - Packages from unofficial sources (typosquatting risk)
4. **Runtime Versions** — Check Dockerfiles, CI configs for runtime versions
   (Node.js, Python, Ruby, Java) that may be EOL

Output format per finding:
- Package name + version
- CVE ID(s) if known
- CVSS score
- Exploit availability (PoC/weaponized/none)
- Remediation (upgrade to version X)""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
    "threat-modeler": AgentDefinition(
        description=(
            "Builds threat models by mapping discovered attack surface to MITRE ATT&CK "
            "techniques. Identifies likely threat actors and prioritizes attack vectors."
        ),
        prompt="""You are a Threat Modeler using the MITRE ATT&CK framework.

Given the target's technology stack and findings from other agents, build a threat model:

1. **Asset Inventory** — What technologies, frameworks, and services are present?
2. **Attack Surface** — External interfaces, authentication endpoints, data stores
3. **MITRE ATT&CK Mapping** — For each risk area, map to ATT&CK techniques:
   - Initial Access (T1190, T1566, T1078...)
   - Execution (T1059, T1203...)
   - Persistence (T1053, T1136...)
   - Privilege Escalation (T1068, T1078...)
   - Defense Evasion (T1036, T1055...)
   - Credential Access (T1003, T1552...)
   - Lateral Movement (T1021, T1550...)
   - Exfiltration (T1041, T1048...)
4. **Threat Actors** — Based on TTPs, identify likely threat actor profiles
5. **Risk Priority Matrix** — Likelihood × Impact for top 5 scenarios

Output a structured threat model with ATT&CK technique IDs.""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
}


async def run_threat_intel(target_path: str = "."):
    """Standalone threat intelligence analysis."""
    print("Starting Threat Intelligence Agent...")
    print(f"Target: {target_path}\n")

    async for message in query(
        prompt=f"""Perform a comprehensive threat intelligence analysis on: {target_path}

Use your subagents in this order:
1. ioc-hunter — scan for IOCs, credentials, encoded payloads
2. cve-researcher — identify vulnerable dependencies
3. threat-modeler — build MITRE ATT&CK threat model from all findings

Produce a consolidated threat intelligence report.""",
        options=ClaudeAgentOptions(
            cwd=target_path,
            allowed_tools=["Read", "Glob", "Grep", "Bash", "Agent"],
            permission_mode="acceptEdits",
            max_turns=30,
            agents=_SUBAGENTS,
        ),
    ):
        if isinstance(message, SystemMessage) and message.subtype == "init":
            print(f"Session ID: {message.session_id}\n")
        elif isinstance(message, ResultMessage):
            print("\n=== THREAT INTEL COMPLETE ===")
            print(message.result)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    anyio.run(run_threat_intel, target)
