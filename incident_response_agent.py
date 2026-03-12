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
        "Incident Response Specialist. Analyzes security logs, reconstructs attack "
        "timelines, performs digital forensics on files and configurations, and "
        "develops containment and remediation playbooks. Handles breach investigations, "
        "anomaly detection in logs, and post-incident reporting."
    ),
    prompt="""You are an Incident Response Specialist. Investigate the target for:

1. **Log Analysis** — Parse security, application, and system logs for anomalies
2. **Attack Timeline** — Reconstruct the sequence of events if an incident occurred
3. **Forensic Artifacts** — Identify modified files, suspicious processes, persistence mechanisms
4. **Containment Plan** — Recommend immediate containment actions
5. **Remediation Steps** — Provide step-by-step recovery procedures

Use log-analyzer, forensics-investigator, and containment-planner subagents.
Focus on evidence preservation and chain of custody in your analysis.""",
    tools=["Read", "Glob", "Grep", "Bash", "Agent"],
)

_SUBAGENTS = {
    "log-analyzer": AgentDefinition(
        description=(
            "Security log analyst. Parses application, system, and security logs to "
            "identify anomalies, authentication failures, privilege escalations, "
            "and indicators of compromise."
        ),
        prompt="""You are a Security Log Analyst. Parse and analyze logs:

1. **Authentication Events** — Failed logins, brute force patterns, impossible travel
   Look for: too many 401/403, login from multiple IPs, off-hours access
2. **Privilege Escalation** — sudo usage, role assumption, permission changes
3. **Data Access Anomalies** — Bulk downloads, unusual query patterns, after-hours access
4. **Error Spikes** — Sudden increases in 500 errors, timeouts (may indicate attack)
5. **Network Anomalies** — Unexpected outbound connections, port scans, data exfil volume
6. **Injection Attempts** — SQLi, XSS, path traversal in HTTP logs

Search for: *.log, *.json (log format), access.log, error.log, auth.log, syslog
Time-sort events and flag anomalies with timestamps.

Output format:
- Timestamp range
- Event type
- Severity
- Source IP/User
- Description
- Related log lines (with file:line reference)""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
    "forensics-investigator": AgentDefinition(
        description=(
            "Digital forensics specialist. Examines file system artifacts, modified "
            "timestamps, suspicious files, and persistence mechanisms to reconstruct "
            "what happened during a security incident."
        ),
        prompt="""You are a Digital Forensics Investigator. Examine artifacts:

1. **Recently Modified Files** — Find files changed in suspicious timeframes
   Command hints: find . -newer reference_file, stat, ls -lt
2. **Hidden Files & Directories** — Dot-files, unusual names, steganography
3. **Persistence Mechanisms** — Cron jobs, startup scripts, scheduled tasks, hooks
   Look in: .bashrc, .profile, crontab, systemd units, init.d, rc.local
4. **Suspicious Executables** — Unexpected binaries, shell scripts with obfuscation
5. **Web Shells** — PHP/Python/Perl web shells, eval() with base64, reverse shells
   Patterns: eval(base64_decode, exec(request, shell_exec, system(
6. **Exfiltration Artifacts** — Compressed archives in web dirs, outbound curl/wget in scripts
7. **Lateral Movement** — SSH keys added, new user accounts, modified sudoers

For each artifact:
- File path
- Type of artifact
- Suspicious indicator
- Timestamp (created/modified/accessed)
- Severity""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
    "containment-planner": AgentDefinition(
        description=(
            "Develops incident containment and remediation playbooks. Creates prioritized "
            "action plans for isolating compromised systems, revoking access, and "
            "restoring services safely."
        ),
        prompt="""You are a Containment & Remediation Planner. Based on investigation findings:

**IMMEDIATE CONTAINMENT (0-1 hour):**
1. Access Revocation — Which credentials/tokens/keys must be rotated immediately?
2. Network Isolation — Which services/IPs should be blocked?
3. Process Termination — Any malicious processes to kill?
4. Evidence Preservation — What logs/files must be preserved before changes?

**SHORT-TERM REMEDIATION (1-24 hours):**
1. Patch/Update — Which vulnerabilities need immediate patching?
2. Configuration Fixes — What misconfigurations to correct?
3. Monitoring — What new alerts/rules to add?

**LONG-TERM HARDENING (1-30 days):**
1. Architecture changes to prevent recurrence
2. Additional security controls to implement
3. Security awareness/process improvements

**RECOVERY STEPS:**
1. Service restoration sequence
2. Validation checks before going live
3. Post-incident monitoring period

Output a numbered playbook with clear owner assignments (Security Team / DevOps / Management)
and estimated time for each action.""",
        tools=["Read", "Glob", "Grep"],
    ),
}


async def run_incident_response(target_path: str = "."):
    """Standalone incident response investigation."""
    print("Starting Incident Response Agent...")
    print(f"Target: {target_path}\n")

    async for message in query(
        prompt=f"""Conduct a full incident response investigation on: {target_path}

Use your subagents in this order:
1. log-analyzer — parse all available logs for anomalies and attack patterns
2. forensics-investigator — examine file system artifacts, persistence, web shells
3. containment-planner — build an actionable containment and remediation playbook

Reconstruct the attack timeline if possible and output a complete IR report.""",
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
            print("\n=== INCIDENT RESPONSE COMPLETE ===")
            print(message.result)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    anyio.run(run_incident_response, target)
