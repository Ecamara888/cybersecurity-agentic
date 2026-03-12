#!/usr/bin/env python3
"""
Cybersecurity Analyst Agent — Powered by Claude Opus 4.6

A professional SOC analyst + threat intelligence assistant with five core capabilities:
  1. Threat Intelligence & CVE Research  (SecurityResearcher sub-agent)
  2. Security News Monitoring            (web search)
  3. Phishing Email Detection & Triage  (inline analysis)
  4. Report Generation                   (Google Docs)
  5. Email Delivery                      (Gmail with human-in-the-loop)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SETUP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Required — create a .env file in this directory:
    ANTHROPIC_API_KEY=sk-ant-...

Web search (needed for news monitoring):
    TAVILY_API_KEY=tvly-...
    (Get a free key at https://tavily.com)

Gmail + Google Docs (optional):
    1. Go to https://console.cloud.google.com
    2. Create a project → Enable "Gmail API" and "Google Docs API"
    3. Create OAuth 2.0 Desktop credentials → Download as credentials.json
    4. Place credentials.json in this directory
    5. First run will open a browser for OAuth consent

Install dependencies:
    pip install -r requirements.txt

Usage:
    python cybersecurity_agent.py
"""

import html
import json
import logging
import os
import re
import sys
import datetime
import urllib.request
import urllib.error
from typing import Any

# Load .env file if present (works on Windows, macOS, Linux)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed; fall back to environment variables

import anthropic

# ── Optional: Google API ─────────────────────────────────────────────────────
try:
    import base64
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build as google_build

    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

# ── Optional: requests (for Tavily) ─────────────────────────────────────────
try:
    import requests as _requests

    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY", "")
GOOGLE_CREDS_FILE = "credentials.json"
GOOGLE_TOKEN_FILE = "token.json"
GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/drive.file",
]

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("analyst_agent.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Prompt
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SYSTEM_PROMPT = """Cybersecurity Analyst Agent
You are a professional cybersecurity analyst assistant. Your job is to help users stay on top of threats, investigate vulnerabilities, analyze suspicious emails, research security topics, and generate actionable reports. You operate with the mindset of a seasoned SOC analyst and threat intelligence professional.
Core Capabilities
You can perform the following tasks. Always determine which task the user is requesting before taking action.
1. 🔍 Threat Intelligence & CVE Research
When a user asks about a specific CVE, vulnerability, threat actor, malware family, or general cybersecurity topic:
1. Delegate to the SecurityResearcher worker — call call_security_researcher ONCE per topic/CVE being researched. If the user asks about multiple CVEs or topics, call the worker once for each one independently.
2. Receive the structured report back from the worker.
3. Present the findings clearly in the chat.
4. Offer to save the report as a Google Doc and/or send it via email.
2. 📰 Security News Monitoring
When a user asks for the latest cybersecurity news, recent threats, or emerging vulnerabilities:
1. Use tavily_web_search to search for the latest cybersecurity news (last 7 days). Query examples:
   * "latest cybersecurity threats this week"
   * "new CVEs disclosed this week"
   * "critical vulnerabilities 2024"
   * "ransomware attacks latest news"
2. Read relevant URLs with read_url_content for additional detail on top stories.
3. Summarize the top 5–10 most important items in a structured list, grouped by category (e.g., Critical Vulnerabilities, Ransomware, Nation-State Threats, Data Breaches).
4. Offer to generate a full report as a Google Doc and/or send it via email.
3. 📧 Phishing Email Detection & Triage
When a user asks you to analyze an email for phishing, or pastes email headers/content for review:
1. Analyze the provided email content or headers for the following red flags:
   * Sender address spoofing or lookalike domains
   * Suspicious URLs or redirects
   * Urgency language or social engineering tactics
   * Unusual attachments or requests for credentials
   * Mismatched reply-to addresses
   * SPF/DKIM/DMARC failures (if headers provided)
2. If the user wants you to check their Gmail inbox for suspicious emails, use gmail_read_emails with include_body: true to read recent emails and assess them.
3. Provide a clear verdict: Phishing, Suspicious, or Likely Legitimate, with a confidence level and explanation.
4. List specific indicators that triggered the verdict.
5. Recommend immediate actions (e.g., delete, report, block sender, reset credentials).
4. 📄 Report Generation (Google Docs)
When a user requests a written report or after completing a research/analysis task:
1. Use google_docs_create_document to create a new Google Doc with an appropriate title (e.g., "CVE-2024-XXXX Threat Intelligence Report – [Date]").
2. Use google_docs_append_text to populate the document with the full structured report content.
3. Share the Google Doc link with the user in the chat.
Report structure to use:
* Title & Date
* Executive Summary
* Technical Details
* Indicators of Compromise (if applicable)
* Recommended Mitigations / Actions
* References
5. 📬 Email Delivery
When a user asks to send a report or summary via email:
1. Compose a professional, well-formatted email with the findings.
2. Use gmail_send_email to send it to the user's specified email address.
3. If a Google Doc was created, include the document link in the email body.
4. Always request user approval before sending (human-in-the-loop is enabled for this action).
General Behavior Guidelines
* Be factual and precise. Never speculate or fabricate CVE details, IOCs, or threat data. If information is unavailable, say so clearly.
* Prioritize authoritative sources such as NVD, MITRE, CISA, vendor advisories, and reputable threat intel blogs.
* Use plain language for summaries and technical detail in the body. Assume the user may need to share findings with both technical and non-technical stakeholders.
* Be proactive. After completing a task, always offer follow-up actions such as generating a report, emailing results, or researching related topics.
* Stay in scope. Focus exclusively on cybersecurity topics. For unrelated requests, politely redirect the user.
* Never store or log credentials, API keys, or sensitive personal data shared by the user. Treat all security data with appropriate confidentiality."""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Google API Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _get_google_creds() -> "Credentials | None":
    """Return valid Google OAuth credentials, refreshing or re-authenticating as needed."""
    if not GOOGLE_AVAILABLE:
        return None

    creds = None
    if os.path.exists(GOOGLE_TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(GOOGLE_TOKEN_FILE, GOOGLE_SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
        else:
            if not os.path.exists(GOOGLE_CREDS_FILE):
                return None
            flow = InstalledAppFlow.from_client_secrets_file(GOOGLE_CREDS_FILE, GOOGLE_SCOPES)
            creds = flow.run_local_server(port=0)

        with open(GOOGLE_TOKEN_FILE, "w") as f:
            f.write(creds.to_json())

    return creds


def _google_service(service_name: str, version: str):
    """Build an authenticated Google API service client, or None if unavailable."""
    creds = _get_google_creds()
    if creds is None:
        return None
    return google_build(service_name, version, credentials=creds)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Utility
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _strip_html(raw: str) -> str:
    """Strip HTML tags and decode entities, returning clean plain text."""
    # Remove <script> and <style> blocks entirely
    raw = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.DOTALL | re.IGNORECASE)
    # Remove all remaining tags
    raw = re.sub(r"<[^>]+>", " ", raw)
    # Decode HTML entities (&amp; &lt; etc.)
    raw = html.unescape(raw)
    # Collapse whitespace
    return re.sub(r"\s+", " ", raw).strip()


def _parse_researcher_json(text: str, topic: str) -> dict:
    """Try to extract a JSON object from the researcher's response text."""
    text = text.strip()
    # Strip markdown code fences
    for fence in ("```json", "```"):
        if fence in text:
            parts = text.split(fence)
            if len(parts) >= 3:
                text = parts[1].split("```")[0].strip()
                break
    # Find the outermost JSON object
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    # Fallback: return the raw text wrapped in a dict
    return {"topic": topic, "summary": text[:600], "full_report": text}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool: Web Search (Tavily)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def tavily_web_search(query: str, max_results: int = 5) -> dict:
    """Search the web via Tavily API and return structured results."""
    if not TAVILY_API_KEY:
        return {
            "error": (
                "TAVILY_API_KEY is not set. "
                "Export it with: export TAVILY_API_KEY=tvly-... "
                "Get a free key at https://tavily.com"
            )
        }
    if not REQUESTS_AVAILABLE:
        return {"error": "requests library not installed. Run: pip install requests"}

    try:
        resp = _requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key": TAVILY_API_KEY,
                "query": query,
                "max_results": min(max_results, 10),
                "include_raw_content": False,
                "search_depth": "advanced",
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "query": query,
            "results": [
                {
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "snippet": (r.get("content") or "")[:600],
                    "published_date": r.get("published_date"),
                    "score": r.get("score"),
                }
                for r in data.get("results", [])
            ],
        }
    except _requests.HTTPError as exc:
        return {"error": f"Tavily HTTP error: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Web search failed: {exc}"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool: Read URL Content
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def read_url_content(url: str, max_chars: int = 8000) -> dict:
    """Fetch a URL and return extracted plain text (HTML stripped)."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; SecurityAnalystBot/1.0; "
                    "+https://github.com/Ecamara888/cybersecurity-agentic)"
                ),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content_type = response.headers.get("Content-Type", "")
            raw_bytes = response.read(1_000_000)  # cap at 1 MB

        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=")[-1].strip().split(";")[0]

        try:
            text = raw_bytes.decode(charset, errors="replace")
        except LookupError:
            text = raw_bytes.decode("utf-8", errors="replace")

        if "html" in content_type.lower():
            text = _strip_html(text)

        return {
            "url": url,
            "content": text[:max_chars],
            "total_chars": len(text),
            "truncated": len(text) > max_chars,
        }

    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code} {exc.reason}", "url": url}
    except urllib.error.URLError as exc:
        return {"error": f"URL error: {exc.reason}", "url": url}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Could not read {url}: {exc}"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool: Gmail — Read Emails
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def gmail_read_emails(max_results: int = 10, include_body: bool = False) -> dict:
    """Read recent emails from the Gmail inbox."""
    if not GOOGLE_AVAILABLE:
        return {"error": "Google API libraries not installed. Run: pip install google-api-python-client google-auth-oauthlib"}

    service = _google_service("gmail", "v1")
    if service is None:
        return {"error": f"Google credentials not configured. Place {GOOGLE_CREDS_FILE} in this directory."}

    try:
        result = service.users().messages().list(
            userId="me", maxResults=max_results, labelIds=["INBOX"]
        ).execute()

        messages_list = result.get("messages", [])
        emails = []

        for msg_ref in messages_list[:max_results]:
            fmt = "full" if include_body else "metadata"
            msg = service.users().messages().get(
                userId="me", id=msg_ref["id"], format=fmt
            ).execute()

            headers = {
                h["name"].lower(): h["value"]
                for h in msg.get("payload", {}).get("headers", [])
            }

            email_data: dict[str, Any] = {
                "id": msg["id"],
                "from": headers.get("from", ""),
                "to": headers.get("to", ""),
                "subject": headers.get("subject", "(no subject)"),
                "date": headers.get("date", ""),
                "reply_to": headers.get("reply-to", ""),
            }

            if include_body:
                body = ""
                payload = msg.get("payload", {})
                parts = payload.get("parts", [payload])
                for part in parts:
                    if part.get("mimeType") == "text/plain":
                        data = part.get("body", {}).get("data", "")
                        if data:
                            import base64 as _b64
                            body = _b64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
                            break
                email_data["body_preview"] = body[:1000]

            emails.append(email_data)

        return {"inbox_count": len(emails), "emails": emails}

    except Exception as exc:  # noqa: BLE001
        return {"error": f"Gmail read failed: {exc}"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool: Gmail — Send Email (Human-in-the-Loop)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def gmail_send_email(to: str, subject: str, body: str, doc_link: str | None = None) -> dict:
    """
    Send an email via Gmail — requires explicit human approval before sending.
    Shows a preview and asks the user to confirm (y/n).
    """
    if not GOOGLE_AVAILABLE:
        return {"error": "Google API libraries not installed. Run: pip install google-api-python-client google-auth-oauthlib"}

    service = _google_service("gmail", "v1")
    if service is None:
        return {"error": f"Google credentials not configured. Place {GOOGLE_CREDS_FILE} in this directory."}

    full_body = body
    if doc_link:
        full_body += f"\n\n📄 Full report: {doc_link}"

    # ── Human-in-the-Loop confirmation ───────────────────
    print("\n" + "─" * 55)
    print("  📬  EMAIL APPROVAL REQUIRED")
    print("─" * 55)
    print(f"  To     : {to}")
    print(f"  Subject: {subject}")
    print(f"  Body preview:\n")
    for line in full_body.splitlines()[:10]:
        print(f"    {line}")
    if full_body.count("\n") > 10:
        print("    ...")
    print("─" * 55)

    try:
        confirm = input("  Send this email? (y/n): ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        confirm = "n"

    if confirm != "y":
        return {"status": "cancelled", "message": "Email was not sent (user declined)."}

    try:
        msg = MIMEMultipart()
        msg["to"] = to
        msg["subject"] = subject
        msg.attach(MIMEText(full_body, "plain"))

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        service.users().messages().send(userId="me", body={"raw": raw}).execute()

        return {
            "status": "sent",
            "to": to,
            "subject": subject,
            "message": f"Email successfully sent to {to}.",
        }

    except Exception as exc:  # noqa: BLE001
        return {"error": f"Send failed: {exc}"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool: Google Docs — Create Document
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def google_docs_create_document(title: str) -> dict:
    """Create a new Google Doc and return its ID and URL."""
    if not GOOGLE_AVAILABLE:
        return {"error": "Google API libraries not installed. Run: pip install google-api-python-client google-auth-oauthlib"}

    service = _google_service("docs", "v1")
    if service is None:
        return {"error": f"Google credentials not configured. Place {GOOGLE_CREDS_FILE} in this directory."}

    try:
        doc = service.documents().create(body={"title": title}).execute()
        doc_id = doc["documentId"]
        doc_url = f"https://docs.google.com/document/d/{doc_id}/edit"

        return {
            "document_id": doc_id,
            "title": title,
            "url": doc_url,
            "message": f"Google Doc created: {doc_url}",
        }

    except Exception as exc:  # noqa: BLE001
        return {"error": f"Failed to create Google Doc: {exc}"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool: Google Docs — Append Text
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def google_docs_append_text(document_id: str, content: str) -> dict:
    """Append text content to an existing Google Doc."""
    if not GOOGLE_AVAILABLE:
        return {"error": "Google API libraries not installed. Run: pip install google-api-python-client google-auth-oauthlib"}

    service = _google_service("docs", "v1")
    if service is None:
        return {"error": f"Google credentials not configured. Place {GOOGLE_CREDS_FILE} in this directory."}

    try:
        # Get current end index
        doc = service.documents().get(documentId=document_id).execute()
        end_index = doc["body"]["content"][-1]["endIndex"] - 1

        service.documents().batchUpdate(
            documentId=document_id,
            body={
                "requests": [
                    {
                        "insertText": {
                            "location": {"index": end_index},
                            "text": content,
                        }
                    }
                ]
            },
        ).execute()

        doc_url = f"https://docs.google.com/document/d/{document_id}/edit"
        return {
            "status": "success",
            "document_id": document_id,
            "url": doc_url,
            "chars_appended": len(content),
        }

    except Exception as exc:  # noqa: BLE001
        return {"error": f"Failed to append to Google Doc: {exc}"}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SecurityResearcher Sub-Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_RESEARCHER_SYSTEM = """You are SecurityResearcher, a specialized threat intelligence analyst worker.

Your mission: Research the given CVE, threat actor, malware family, or security topic using authoritative sources and produce a comprehensive structured report.

Research workflow:
1. Search for the topic using web_search — include queries to NVD, MITRE CVE, CISA KEV, and vendor advisories.
2. Use web_fetch to read 2–3 authoritative source pages for technical depth.
3. Synthesize all findings into the JSON report format below.

Return ONLY a JSON object with these fields (no prose before or after):
{
  "topic": "<the exact topic researched>",
  "summary": "<2-3 sentence executive summary suitable for non-technical stakeholders>",
  "severity": "<CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL>",
  "cvss_score": "<e.g. 9.8 (CVSS 3.1)> or null",
  "affected_systems": ["<vendor/product/version>"],
  "technical_details": "<detailed technical explanation of the vulnerability or threat>",
  "indicators_of_compromise": ["<ioc1>", "<ioc2>"],
  "mitigations": ["<actionable mitigation step>"],
  "patch_available": true | false | null,
  "threat_actors": ["<actor name>"],
  "date_published": "<ISO 8601 date> or null",
  "references": ["<authoritative URL>"]
}

Rules:
- Use ONLY authoritative sources: NVD (nvd.nist.gov), MITRE (cve.mitre.org), CISA (cisa.gov), vendor advisories, Mandiant, CrowdStrike, Microsoft MSRC, etc.
- If you cannot find reliable data for a field, use null or [] — never fabricate details.
- Be precise with CVSS scores and severity ratings.
"""


def call_security_researcher(topic: str) -> dict:
    """
    SecurityResearcher sub-agent: performs deep CVE/threat research.

    Uses Anthropic's server-side web search tools (no Tavily key required) to
    query NVD, MITRE, CISA, and vendor advisories, then returns structured JSON.
    """
    print(f"\n  🔬 [SecurityResearcher] Researching: {topic}", flush=True)
    print("     (searching authoritative sources...)", flush=True)

    client = anthropic.Anthropic()
    messages: list[dict] = [
        {"role": "user", "content": f"Research this topic and return a structured JSON report: {topic}"}
    ]

    max_continuations = 6  # Guard against infinite loops
    for attempt in range(max_continuations):
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=8096,
            thinking={"type": "adaptive"},
            system=_RESEARCHER_SYSTEM,
            tools=[
                {"type": "web_search_20260209", "name": "web_search"},
                {"type": "web_fetch_20260209", "name": "web_fetch"},
            ],
            messages=messages,
        )

        if response.stop_reason == "end_turn":
            for block in response.content:
                if block.type == "text":
                    return _parse_researcher_json(block.text, topic)
            return {"topic": topic, "error": "SecurityResearcher returned no text output."}

        if response.stop_reason == "pause_turn":
            # Server-side tool loop hit its iteration limit; re-send to continue
            messages = [
                messages[0],  # original user message
                {"role": "assistant", "content": response.content},
            ]
            continue

        # Unexpected stop reason
        break

    return {
        "topic": topic,
        "error": f"Research for '{topic}' could not be completed within {max_continuations} iterations.",
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Claude Tool Definitions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TOOLS: list[dict] = [
    {
        "name": "tavily_web_search",
        "description": (
            "Search the web for cybersecurity news, threat intelligence, CVE details, "
            "or any security topic. Use for recent news and general research tasks. "
            "Requires TAVILY_API_KEY to be set."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": (
                        "Search query. Examples: 'latest ransomware attacks this week', "
                        "'CVE-2024-21413 Microsoft Outlook', 'CISA KEV new entries 2024'"
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "description": "Number of results to return (1–10, default 5).",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "read_url_content",
        "description": (
            "Fetch and read the text content of a specific URL. Use to get full details "
            "from security advisories, NVD pages, vendor bulletins, or blog posts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The full URL to fetch."},
                "max_chars": {
                    "type": "integer",
                    "description": "Maximum characters to return (default 8000).",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "call_security_researcher",
        "description": (
            "Delegate in-depth research to the SecurityResearcher worker. Use for CVE analysis, "
            "threat actor profiles, malware analysis, or any topic requiring authoritative sources. "
            "Call ONCE per topic. The worker queries NVD, MITRE, CISA, and vendor advisories, "
            "then returns a structured JSON threat intelligence report."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "topic": {
                    "type": "string",
                    "description": (
                        "CVE ID (e.g. 'CVE-2024-21413'), threat actor name (e.g. 'APT29'), "
                        "malware family (e.g. 'LockBit 3.0'), or security topic to research."
                    ),
                }
            },
            "required": ["topic"],
        },
    },
    {
        "name": "gmail_read_emails",
        "description": (
            "Read recent emails from the user's Gmail inbox. Use when the user asks to "
            "check Gmail for phishing or security threats."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "max_results": {
                    "type": "integer",
                    "description": "Number of emails to retrieve (default 10).",
                },
                "include_body": {
                    "type": "boolean",
                    "description": "Include email body preview (default false).",
                },
            },
        },
    },
    {
        "name": "gmail_send_email",
        "description": (
            "Send an email via the user's Gmail account. "
            "IMPORTANT: This action always requires explicit human approval — "
            "the tool will display a preview and prompt the user to confirm before sending."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address."},
                "subject": {"type": "string", "description": "Email subject line."},
                "body": {"type": "string", "description": "Email body (plain text)."},
                "doc_link": {
                    "type": "string",
                    "description": "Optional Google Doc URL to append to the email body.",
                },
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "google_docs_create_document",
        "description": (
            "Create a new Google Doc with the given title. "
            "Returns the document ID and shareable URL. "
            "Call this first, then use google_docs_append_text to add content."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": (
                        "Document title, e.g. 'CVE-2024-21413 Threat Intelligence Report – 2024-01-15'"
                    ),
                }
            },
            "required": ["title"],
        },
    },
    {
        "name": "google_docs_append_text",
        "description": (
            "Append text content to an existing Google Doc (identified by document_id). "
            "Use after google_docs_create_document to populate the report."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "document_id": {
                    "type": "string",
                    "description": "The Google Doc document ID returned by google_docs_create_document.",
                },
                "content": {
                    "type": "string",
                    "description": "Text to append to the document.",
                },
            },
            "required": ["document_id", "content"],
        },
    },
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool Dispatcher
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_TOOL_FUNCTIONS: dict[str, Any] = {
    "tavily_web_search": tavily_web_search,
    "read_url_content": read_url_content,
    "call_security_researcher": call_security_researcher,
    "gmail_read_emails": gmail_read_emails,
    "gmail_send_email": gmail_send_email,
    "google_docs_create_document": google_docs_create_document,
    "google_docs_append_text": google_docs_append_text,
}


def _execute_tool(name: str, tool_input: dict) -> str:
    """Dispatch a tool call and return its result as a JSON string."""
    logger.info("Tool call → %s(%s)", name, json.dumps(tool_input)[:200])
    fn = _TOOL_FUNCTIONS.get(name)
    if fn is None:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        result = fn(**tool_input)
        return json.dumps(result, indent=2, default=str)
    except TypeError as exc:
        return json.dumps({"error": f"Invalid tool arguments for '{name}': {exc}"})
    except Exception as exc:  # noqa: BLE001
        logger.exception("Tool '%s' raised an exception", name)
        return json.dumps({"error": f"Tool '{name}' failed: {exc}"})


def _fmt_input(tool_input: dict) -> str:
    """Compact single-line representation of tool input for display."""
    s = json.dumps(tool_input)
    return s[:100] + "…" if len(s) > 100 else s


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Main Agent Loop (streaming + tool use)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _run_agent_turn(client: anthropic.Anthropic, messages: list[dict]) -> list[dict]:
    """
    Execute one complete agent turn:
      • Streams text tokens to stdout as they arrive.
      • When tool calls appear, executes them and feeds results back.
      • Loops until stop_reason == "end_turn".
    Returns the updated messages list.
    """
    while True:
        print("\nAgent: ", end="", flush=True)

        with client.messages.stream(
            model="claude-opus-4-6",
            max_tokens=8096,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        ) as stream:
            for text in stream.text_stream:
                print(text, end="", flush=True)
            response = stream.get_final_message()

        print()  # newline after streamed text

        if response.stop_reason == "end_turn":
            messages.append({"role": "assistant", "content": response.content})
            break

        if response.stop_reason == "tool_use":
            tool_results = []

            for block in response.content:
                if block.type == "tool_use":
                    print(f"\n  🔧 [{block.name}] {_fmt_input(block.input)}")

                    raw = _execute_tool(block.name, block.input)
                    data = json.loads(raw)
                    is_error = "error" in data

                    if is_error:
                        print(f"  ✗  {data['error']}")
                    else:
                        keys = ", ".join(list(data.keys())[:4])
                        print(f"  ✓  {{{keys}{'…' if len(data) > 4 else ''}}}")

                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": raw,
                            **({"is_error": True} if is_error else {}),
                        }
                    )

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        else:
            # Unexpected stop (pause_turn from server-side tools, etc.)
            messages.append({"role": "assistant", "content": response.content})
            break

    return messages


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Interactive REPL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def _print_banner() -> None:
    w = 65
    print("=" * w)
    print("  CYBERSECURITY ANALYST AGENT  —  Claude Opus 4.6")
    print("=" * w)
    print("  Capabilities:")
    print("  🔍  CVE & Threat Intelligence Research")
    print("  📰  Security News Monitoring")
    print("  📧  Phishing Email Detection & Triage")
    print("  📄  Google Docs Report Generation")
    print("  📬  Gmail Email Delivery")
    print("=" * w)

    warnings: list[str] = []
    if not TAVILY_API_KEY:
        warnings.append("TAVILY_API_KEY not set — web search unavailable")
    if not GOOGLE_AVAILABLE:
        warnings.append(
            "Google libs missing — Gmail/Docs unavailable "
            "(pip install google-api-python-client google-auth-oauthlib)"
        )
    elif not os.path.exists(GOOGLE_CREDS_FILE):
        warnings.append(
            f"'{GOOGLE_CREDS_FILE}' not found — Gmail/Docs unavailable "
            "(download OAuth credentials from Google Cloud Console)"
        )

    if warnings:
        print("\n  ⚠  Setup notes:")
        for w_msg in warnings:
            print(f"     • {w_msg}")

    print(f"\n  Example prompts:")
    print('  • "Research CVE-2024-21413"')
    print('  • "What are the biggest security threats this week?"')
    print('  • "Analyze this email for phishing: [paste content]"')
    print('  • "Check my Gmail for suspicious emails"')
    print('  • "Generate a report on the SolarWinds attack"')
    print(f'\n  Type "exit" to quit.\n')


def main() -> None:
    """Run the interactive Cybersecurity Analyst Agent REPL."""
    _print_banner()

    client = anthropic.Anthropic()
    messages: list[dict] = []

    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\nGoodbye!")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "bye", "q"):
            print("Goodbye!")
            break

        messages.append({"role": "user", "content": user_input})

        try:
            messages = _run_agent_turn(client, messages)
        except anthropic.AuthenticationError:
            print("\nError: Invalid ANTHROPIC_API_KEY.")
            messages.pop()
        except anthropic.RateLimitError:
            print("\nRate limited — please wait a moment.")
            messages.pop()
        except anthropic.APIError as exc:
            print(f"\nAPI error: {exc}")
            messages.pop()
        except Exception as exc:  # noqa: BLE001
            print(f"\nUnexpected error: {exc}")
            messages.pop()


if __name__ == "__main__":
    main()
