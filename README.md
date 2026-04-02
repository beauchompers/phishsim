# PhishSim Injector

A self-hosted tool for injecting realistic phishing simulation emails into Microsoft 365 mailboxes via the Microsoft Graph API. Built for security awareness training — test your users' ability to identify and report phishing emails.

![PhishSim Injector UI](screenshots/phishsim%20screenshot.png)

## Features

- **5 built-in scenarios** — Credential harvester, BEC, malware attachment, URL phishing, and a legitimate email (false positive test)
- **Non-draft injection** — Emails appear as real received messages, not drafts
- **Single-page UI** — Select scenarios and users side-by-side, inject with one click
- **Inject, clean, reset, status** — Full lifecycle management of simulation emails
- **Extensible templates** — HTML email templates with variable substitution, no code changes needed to add scenarios
- **API key authentication** — Optional shared-secret auth for all API endpoints
- **Persistent settings** — Simulation config survives container restarts

## Quick Start

```bash
git clone <repo-url>
cd phishsim-app
cp .env.example .env
# Edit .env with your Azure credentials
docker compose up -d
```

Open **http://localhost:5001** — the app auto-connects and loads users.

## Prerequisites

- **Microsoft 365 tenant** (developer/lab tenant recommended)
- **Entra ID app registration** with:
  - `Mail.ReadWrite` (Application) — create/search/delete messages
  - `User.Read.All` (Application) — list tenant users
  - Admin consent granted for both
- **Docker** (or Python 3.12+)

## Configuration

Copy `.env.example` to `.env` and set:

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Entra ID tenant ID |
| `AZURE_CLIENT_ID` | Yes | App registration client ID |
| `AZURE_CLIENT_SECRET` | Yes | App registration client secret |
| `API_KEY` | Recommended | Shared secret to protect API endpoints |
| `ATTACKER_DOMAIN` | No | Phishing domain (default: `m1crosoft-alerts.com`) |
| `BEC_DOMAIN` | No | BEC impersonation domain (default: `contoso-corp.com`) |
| `CEO_NAME` | No | CEO name for BEC scenario (default: `Michael Chen, CEO`) |
| `COMPANY_NAME` | No | Target company name (default: `Contoso`) |
| `LANDING_URL` | No | Phishing landing page URL |

All optional settings are also configurable via the UI (gear icon).

## Scenarios

| # | Name | Verdict | Difficulty | Key Indicators |
|---|------|---------|------------|----------------|
| 1 | Credential Harvester | MALICIOUS | OBVIOUS | SPF=fail, typosquat domain, PHPMailer |
| 2 | Business Email Compromise | SUSPICIOUS | SUBTLE | CEO impersonation, wire transfer request |
| 3 | Malware Attachment (Invoice) | MALICIOUS | MODERATE | Overdue invoice, macro-enabled attachment |
| 4 | URL Phishing — Security Alert | MALICIOUS | MODERATE | Fake sign-in alert, subdomain abuse |
| 5 | Legitimate Email (FP Test) | BENIGN | BENIGN | SPF/DKIM/DMARC=pass, internal sender |

### Adding Custom Scenarios

1. Create a new HTML file in `templates/` (e.g., `scenario-6.html`)
2. Add an entry to `templates/scenarios.json`
3. Use `{{variable}}` placeholders for dynamic content
4. Rebuild the container

Available variables: `{{attacker_domain}}`, `{{bec_domain}}`, `{{ceo_name}}`, `{{company_name}}`, `{{landing_url}}`, `{{run_id}}`, `{{now_str}}`, `{{date_short}}`, `{{recipient_email}}`

## Architecture

```
app.py              Flask backend — Graph API client, email injection, API routes
static/index.html   React 18 SPA (CDN-loaded, no build step)
templates/
  scenarios.json    Scenario metadata (name, verdict, headers, etc.)
  scenario-*.html   Email body templates with {{variable}} placeholders
```

## Security

- **Set `API_KEY`** — Without it, all endpoints are unauthenticated
- **Use a lab/dev tenant** — The app has full mailbox access to all users
- **Credentials stay server-side** — Azure secrets are never sent to the browser
- **Run behind a reverse proxy with TLS** if exposing beyond localhost

## Phishing Report Workflow

PhishSim pairs with Outlook's built-in "Report Phishing" button. The full loop:

1. **PhishSim injects** simulation emails into user inboxes
2. **Users identify** the phishing email and click **Report → Report Phishing** in Outlook
3. **The report lands** in a shared mailbox you control (e.g., `phishing@yourdomain.onmicrosoft.com`)
4. **Your SIEM/SOAR** (or manual review) picks up the report and runs triage

To complete this setup, you need a shared mailbox configured as a SecOps mailbox (so Defender doesn't strip malicious content) with Outlook's user reporting pointed at it. See [SETUP.md — Step 4](SETUP.md#step-4-configure-user-reported-phishing-to-a-shared-mailbox) for full instructions.

## Full Setup Guide

See [SETUP.md](SETUP.md) for detailed instructions including Entra ID app registration, shared mailbox configuration for phishing reports, and threat intelligence indicators.

## Disclaimer

This tool is provided for **authorized security testing, education, and research purposes only**. It is intended to be used by security professionals and administrators to conduct phishing awareness training within organizations they are authorized to test.

**You are solely responsible for ensuring you have proper authorization before using this tool.** Unauthorized use of this tool to send phishing emails, access mailboxes without consent, or conduct social engineering attacks against individuals or organizations you do not have explicit permission to test is **illegal** and may violate computer fraud, unauthorized access, and privacy laws in your jurisdiction.

The authors and contributors of this project assume no liability and are not responsible for any misuse or damage caused by this tool.

By using this software, you agree that you will:
- Only use it on tenants and mailboxes you own or have written authorization to test
- Comply with all applicable local, state, national, and international laws
- Not use it for unauthorized access, harassment, or any malicious purpose

## License

MIT
