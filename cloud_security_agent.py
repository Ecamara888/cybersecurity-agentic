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
        "Cloud Security Engineer. Audits cloud infrastructure for IAM misconfigurations, "
        "over-permissioned roles, exposed network ports, insecure security groups, missing "
        "VPC flow logs, and validates against CIS Benchmarks, NIST 800-53, and SOC2 controls. "
        "Produces a structured findings report with severity ratings and remediation steps."
    ),
    prompt="""You are a Cloud Security Engineer. Perform a comprehensive cloud security audit:

1. **IAM Audit** — Find wildcard permissions, missing MFA, unused roles, hardcoded credentials
2. **Network Audit** — Check security groups for 0.0.0.0/0, open management ports, missing encryption
3. **Compliance Check** — Validate against CIS Benchmarks, NIST 800-53, SOC2 controls
4. **Configuration Review** — Terraform/CloudFormation/K8s manifests for insecure defaults

Search files: *.tf, *.yaml, *.yml, *.json, *.hcl, *.env, *.config
Output findings with severity (CRITICAL/HIGH/MEDIUM/LOW), affected resource, and remediation.""",
    tools=["Read", "Glob", "Grep", "Bash"],
)


async def run_cloud_security_audit(target_path: str = "."):
    """
    Cloud Security Engineer agent with 4 specialized subagents.

    Subagents:
      1. iam-auditor       — IAM policies, roles, over-permissioned access
      2. network-auditor   — Security groups, open ports, VPC/firewall configs
      3. compliance-checker — CIS / NIST / SOC2 benchmark validation
      4. report-writer     — Consolidates all findings into a structured report
    """

    print("Starting Cloud Security Engineer Agent...")
    print(f"Target: {target_path}\n")

    async for message in query(
        prompt=f"""You are a Cloud Security Engineer. Perform a comprehensive cloud security audit on the target at: {target_path}

Follow these steps IN ORDER:
1. Use the **iam-auditor** agent to analyze IAM policies, roles, and permissions for privilege escalation risks and over-permissioned accounts.
2. Use the **network-auditor** agent to check for exposed ports, insecure security groups, missing VPC flow logs, and unencrypted traffic.
3. Use the **compliance-checker** agent to validate configurations against CIS Benchmarks, NIST 800-53, and SOC2 controls.
4. Use the **report-writer** agent to consolidate ALL findings from the above agents into a final security report with severity ratings (CRITICAL / HIGH / MEDIUM / LOW) and remediation steps.

Always pass the full findings from each agent to the report-writer at the end.""",
        options=ClaudeAgentOptions(
            cwd=target_path,
            allowed_tools=["Read", "Glob", "Grep", "Bash", "Agent"],
            permission_mode="acceptEdits",
            max_turns=40,
            agents={
                "iam-auditor": AgentDefinition(
                    description=(
                        "Cloud IAM security specialist. Audits identity and access management "
                        "configurations for AWS, GCP, or Azure. Detects over-permissioned roles, "
                        "missing MFA, wildcard permissions, public S3 buckets, and privilege "
                        "escalation paths."
                    ),
                    prompt="""You are a Cloud IAM Security Auditor. When given a target, analyze:

1. **IAM Policies** — Look for wildcard (*) permissions, overly broad actions, missing conditions
2. **Roles & Users** — Identify unused roles, service accounts with excessive permissions
3. **MFA Enforcement** — Check if MFA is required for privileged accounts
4. **Cross-Account Access** — Flag any trust relationships that could allow lateral movement
5. **Secrets Exposure** — Search for hardcoded credentials, API keys, or tokens in config files

Search for files: *.json, *.yaml, *.yml, *.tf, *.hcl, *.env, *.config
Look for patterns: IAM policies, role definitions, access keys, permission boundaries

Output a structured list of findings with:
- Finding name
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Affected resource
- Description
- Recommended fix""",
                    tools=["Read", "Glob", "Grep", "Bash"],
                ),
                "network-auditor": AgentDefinition(
                    description=(
                        "Cloud network security specialist. Audits VPC configurations, security groups, "
                        "firewall rules, and network ACLs. Detects open ports, missing encryption, "
                        "exposed management interfaces, and insecure ingress/egress rules."
                    ),
                    prompt="""You are a Cloud Network Security Auditor. When given a target, analyze:

1. **Security Groups / Firewall Rules** — Find 0.0.0.0/0 ingress rules, open management ports (22, 3389, 5900)
2. **Network ACLs** — Check for overly permissive inbound/outbound rules
3. **VPC Configuration** — Verify flow logs enabled, no default VPC in use, proper segmentation
4. **Load Balancers** — Check TLS/SSL versions, HTTP redirect to HTTPS, certificate validity
5. **DNS & CDN** — Look for dangling DNS entries, missing DNSSEC, misconfigured origins
6. **Encryption in Transit** — Flag any unencrypted endpoints or weak cipher suites

Search for files: *.tf, *.yaml, *.yml, *.json, *.hcl, network configs
Look for patterns: security_group, ingress, egress, port, cidr, firewall, acl

Output a structured list of findings with:
- Finding name
- Severity (CRITICAL/HIGH/MEDIUM/LOW)
- Affected resource
- Description
- Recommended fix""",
                    tools=["Read", "Glob", "Grep", "Bash"],
                ),
                "compliance-checker": AgentDefinition(
                    description=(
                        "Cloud compliance specialist. Validates infrastructure configurations against "
                        "CIS Benchmarks, NIST 800-53, SOC2, and PCI-DSS controls. Identifies gaps "
                        "and maps findings to specific control requirements."
                    ),
                    prompt="""You are a Cloud Compliance Checker. Validate configurations against these frameworks:

**CIS Benchmarks:**
- CIS-1.x: Identity and Access Management
- CIS-2.x: Storage (encryption at rest, public access blocks)
- CIS-3.x: Logging (CloudTrail/audit logs enabled, log integrity)
- CIS-4.x: Monitoring (alerts for root usage, config changes)
- CIS-5.x: Networking (VPC defaults, security groups)

**NIST 800-53 Key Controls:**
- AC (Access Control): Least privilege, MFA, session management
- AU (Audit): Logging completeness, log retention (90+ days)
- SC (System & Comms): Encryption standards, TLS 1.2+
- SI (System Integrity): Vulnerability scanning, patching cadence

**SOC2 Trust Principles:**
- Security: Access controls, encryption, monitoring
- Availability: Redundancy, backup verification
- Confidentiality: Data classification, encryption at rest

For each control gap found, output:
- Control ID (e.g., CIS-2.1.1)
- Framework (CIS/NIST/SOC2)
- Status (PASS/FAIL/PARTIAL)
- Evidence found
- Gap description
- Remediation guidance""",
                    tools=["Read", "Glob", "Grep", "Bash"],
                ),
                "report-writer": AgentDefinition(
                    description=(
                        "Security report writer. Takes findings from IAM, network, and compliance "
                        "audits and produces a structured executive and technical security report "
                        "with severity ratings, risk scores, and prioritized remediation steps."
                    ),
                    prompt="""You are a Cloud Security Report Writer. Given audit findings, create a comprehensive report:

---
# Cloud Security Audit Report

## Executive Summary
- Overall risk score (0-100)
- Total findings by severity (CRITICAL / HIGH / MEDIUM / LOW)
- Top 3 most urgent issues requiring immediate action
- Compliance posture summary

## Findings by Severity

### CRITICAL (Immediate Action Required)
[List each critical finding with: ID, Title, Description, Impact, Remediation]

### HIGH (Address Within 7 Days)
[List each high finding]

### MEDIUM (Address Within 30 Days)
[List each medium finding]

### LOW (Address Within 90 Days)
[List each low finding]

## Compliance Gaps
| Control | Framework | Status | Gap |
|---------|-----------|--------|-----|

## Remediation Roadmap
Prioritized action plan with estimated effort (Low/Medium/High) for each item.

## Appendix
Raw evidence and configuration snippets supporting findings.
---

Write the report to a file called `security_audit_report.md` in the current directory.
Then print a summary of the findings.""",
                    tools=["Read", "Write", "Glob", "Grep"],
                ),
            },
        ),
    ):
        if isinstance(message, SystemMessage) and message.subtype == "init":
            print(f"Session ID: {message.session_id}\n")
        elif isinstance(message, ResultMessage):
            print("\n=== AUDIT COMPLETE ===")
            print(message.result)


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    anyio.run(run_cloud_security_audit, target)
