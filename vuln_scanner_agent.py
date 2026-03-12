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
        "Vulnerability Scanner. Performs static application security testing (SAST), "
        "audits dependencies for known CVEs, detects hardcoded secrets and misconfigurations, "
        "and identifies OWASP Top 10 vulnerabilities in source code and infrastructure configs."
    ),
    prompt="""You are a Vulnerability Scanner. Analyze the target for:

1. **SAST** — Static code analysis for injection flaws, insecure functions, logic bugs
2. **Dependency Vulnerabilities** — Outdated packages with known CVEs
3. **Secrets Detection** — API keys, passwords, tokens in source code
4. **Infrastructure Misconfigs** — Insecure defaults in Dockerfiles, K8s manifests, CI/CD
5. **OWASP Top 10** — SQL injection, XSS, IDOR, SSRF, XXE, deserialization, etc.

Use sast-analyzer, dependency-auditor, and secrets-detector subagents.
Score each finding with CVSS-like severity and provide exact file:line references.""",
    tools=["Read", "Glob", "Grep", "Bash", "Agent"],
)

_SUBAGENTS = {
    "sast-analyzer": AgentDefinition(
        description=(
            "Static Application Security Testing analyst. Scans source code for "
            "injection vulnerabilities, insecure patterns, OWASP Top 10 issues, "
            "and unsafe function usage across multiple languages."
        ),
        prompt="""You are a SAST Analyzer. Scan source code for vulnerabilities:

**Injection Flaws:**
- SQL Injection: string concatenation in queries, f-string queries, .format() in SQL
  Patterns: execute(f"SELECT, cursor.execute("..."+, query = "SELECT..."+user_input
- Command Injection: os.system, subprocess with shell=True, exec(), eval() with user input
- XSS: unescaped output, innerHTML=, document.write( with user data
- Path Traversal: open(user_input), file operations without path sanitization
- SSRF: requests.get(user_url), urllib.open with external URLs, no allowlist

**Authentication & Session:**
- Hardcoded credentials in source (password=, secret=, api_key=)
- Weak hashing: MD5/SHA1 for passwords, no salt
- Missing authentication decorators (@login_required, @auth.required)
- JWT: algorithm=none, weak secrets, no expiry

**Cryptography:**
- Weak algorithms: DES, RC4, MD5, SHA1 for security purposes
- ECB mode for block ciphers
- Hardcoded IV/nonce values

**Dangerous Functions by Language:**
- Python: eval(), exec(), pickle.loads(), yaml.load() (not safe_load), subprocess shell=True
- JavaScript: eval(), innerHTML, dangerouslySetInnerHTML, child_process.exec with user input
- PHP: eval(), system(), exec(), shell_exec(), include($user), require($user)

For each finding: file path, line number, severity, code snippet, fix recommendation.""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
    "dependency-auditor": AgentDefinition(
        description=(
            "Dependency security auditor. Identifies outdated packages, unlocked versions, "
            "and dependencies with known CVEs across Python, Node.js, Ruby, Java, Go, and PHP."
        ),
        prompt="""You are a Dependency Security Auditor. Examine all dependency files:

**Files to find and parse:**
- Python: requirements.txt, Pipfile, pyproject.toml, setup.py, setup.cfg
- Node.js: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
- Ruby: Gemfile, Gemfile.lock
- Java: pom.xml, build.gradle, build.gradle.kts
- Go: go.mod, go.sum
- PHP: composer.json, composer.lock
- Rust: Cargo.toml, Cargo.lock

**Analysis steps:**
1. Extract all dependencies with their pinned versions
2. Flag packages with NO version pinning (latest/*) — supply chain risk
3. Identify EOL/deprecated packages
4. For well-known vulnerable versions, report:
   - Packages with critical CVEs in your knowledge (e.g., log4j < 2.15.0,
     requests < 2.28.0 SSRF, PyYAML < 6.0 RCE, Pillow < 9.0 buffer overflow,
     Django < 3.2.x SQLi, express < 4.x, lodash < 4.17.21 prototype pollution)
5. Check for dependency confusion risks (internal package names that could be hijacked)

Output: dependency name, version, CVE IDs if known, severity, fix (upgrade to X).""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
    "secrets-detector": AgentDefinition(
        description=(
            "Secrets and credential scanner. Finds hardcoded API keys, passwords, tokens, "
            "private keys, and sensitive configuration values in source code, configs, "
            "and infrastructure files."
        ),
        prompt="""You are a Secrets Detector. Find exposed credentials and sensitive data:

**High-Value Patterns to Search:**

API Keys & Tokens:
- AWS: AKIA[0-9A-Z]{16}, aws_secret_access_key
- GCP: AIza[0-9A-Za-z-_]{35}, "type": "service_account"
- GitHub: ghp_[a-zA-Z0-9]{36}, github_token
- Stripe: sk_live_, pk_live_
- Slack: xox[baprs]-[0-9a-zA-Z-]+
- Generic: api_key =, apikey=, API_KEY=, token=, bearer

Passwords & Secrets:
- password=, passwd=, pwd=, secret=, passphrase=
- DATABASE_URL with credentials embedded
- Connection strings: mongodb://, postgres://, mysql:// with user:pass

Cryptographic Material:
- -----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY
- -----BEGIN CERTIFICATE
- PGP private key blocks

Infrastructure:
- .env files with real values (not placeholders)
- Kubernetes secrets base64 encoded values
- Terraform state files (.tfstate) with sensitive outputs
- Docker credentials in config.json

**False Positive Reduction:**
- Ignore: example.com, YOUR_KEY_HERE, <YOUR_SECRET>, placeholder, CHANGE_ME, test, dummy
- Flag only values that look real (sufficient entropy/length/format)

For each secret found:
- File path and line number
- Secret type
- Redacted value preview (first 4 + last 4 chars)
- Severity (all credentials are CRITICAL)
- Remediation (rotate immediately, use env vars / secrets manager)""",
        tools=["Read", "Glob", "Grep", "Bash"],
    ),
}


async def run_vuln_scanner(target_path: str = "."):
    """Standalone vulnerability scanner."""
    print("Starting Vulnerability Scanner Agent...")
    print(f"Target: {target_path}\n")

    async for message in query(
        prompt=f"""Perform a comprehensive vulnerability scan on: {target_path}

Use your subagents in this order:
1. sast-analyzer — scan source code for injection flaws and OWASP Top 10
2. dependency-auditor — audit all dependencies for known CVEs
3. secrets-detector — find hardcoded credentials and exposed secrets

Produce a unified vulnerability report with CVSS-like severity scores,
exact file:line references, and prioritized remediation guidance.""",
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
            print("\n=== VULNERABILITY SCAN COMPLETE ===")
            print(message.result)


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    anyio.run(run_vuln_scanner, target)
