# Cybersecurity Analyst Agent

A professional SOC analyst + threat intelligence assistant powered by **Claude Opus 4.6**.
Ask it about CVEs, check today's threat landscape, triage phishing emails, and auto-generate Google Docs reports — all from a single terminal chat.

---

## Features

| Capability | What it does |
|---|---|
| **CVE & Threat Intelligence** | Delegates to a SecurityResearcher sub-agent that queries NVD, MITRE, CISA, and vendor advisories and returns a structured JSON report |
| **Security News Monitoring** | Uses Tavily web search to surface the top stories of the week, grouped by category (ransomware, nation-state threats, data breaches, etc.) |
| **Phishing Email Triage** | Analyzes pasted email headers/content or scans your Gmail inbox for red flags, returning a verdict with confidence level and IOCs |
| **Google Docs Report Generation** | Creates and populates a formatted threat report document and returns the shareable link |
| **Gmail Email Delivery** | Sends reports via Gmail with a human-in-the-loop confirmation step before sending |

---

## Requirements

- Python 3.10+
- An [Anthropic API key](https://console.anthropic.com)

---

## Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/Ecamara888/cybersecurity-agentic.git
cd cybersecurity-agentic
pip install -r requirements.txt
```

### 2. Create a `.env` file

Copy the example and fill in your keys:

```bash
cp .env.example .env
```

Then edit `.env`:

```
ANTHROPIC_API_KEY=sk-ant-...          # Required
TAVILY_API_KEY=tvly-...               # For security news monitoring (free at https://tavily.com)
```

### 3. (Optional) Enable Gmail + Google Docs

1. Go to [Google Cloud Console](https://console.cloud.google.com) and create a project.
2. Enable the **Gmail API** and **Google Docs API**.
3. Create **OAuth 2.0 Desktop** credentials and download as `credentials.json`.
4. Place `credentials.json` in the project directory.
5. On first run the browser will open for OAuth consent — after that a `token.json` is cached.

### 4. Run

```bash
python cybersecurity_agent.py
```

---

## Example Prompts

```
Research CVE-2024-21413
What are the biggest cybersecurity threats this week?
Analyze this email for phishing: [paste headers or body]
Check my Gmail inbox for suspicious emails
Generate a report on the SolarWinds attack and email it to me@example.com
Tell me about the APT29 threat actor
```

---

## Project Structure

```
cybersecurity-agentic/
├── cybersecurity_agent.py   # Main agent + all tool implementations
├── requirements.txt         # Python dependencies
├── .env.example             # Environment variable template
├── credentials.json         # (You create) Google OAuth credentials
└── token.json               # (Auto-generated) Google OAuth token cache
```

---

## How It Works

The main agent runs as an interactive REPL using **streaming** Claude Opus 4.6 responses with tool use.
For deep CVE research it spawns a **SecurityResearcher sub-agent** that uses Claude's built-in `web_search` and `web_fetch` tools to query authoritative sources and returns a structured JSON report — no Tavily key required for this path.

```
You ──► Main Agent (claude-opus-4-6, streaming)
              │
              ├── tavily_web_search      (security news)
              ├── read_url_content       (fetch advisories)
              ├── call_security_researcher ──► Sub-Agent (claude-opus-4-6)
              │                                    └── web_search / web_fetch
              ├── gmail_read_emails
              ├── gmail_send_email       (human approval required)
              ├── google_docs_create_document
              └── google_docs_append_text
```

---

## Security Notes

- `credentials.json` and `token.json` are listed in `.gitignore` — never commit them.
- The `.env` file is also excluded from git.
- Gmail sending always requires explicit user confirmation (`y/n`) before any message is dispatched.
- The agent is instructed never to store or log credentials or sensitive data shared in chat.
