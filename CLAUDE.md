# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PhishSim Injector is a self-hosted tool that injects realistic phishing simulation emails into Microsoft 365 mailboxes via the Microsoft Graph API. It's used for security awareness training — testing users' ability to identify and report phishing emails.

## Commands

### Run locally (development)
```bash
pip install -r requirements.txt
python app.py
```

### Run with Docker
```bash
docker compose up --build
```

### No test suite or linter is configured.

## Architecture

Flask backend (`app.py`) with a CDN-bundled React frontend (`static/index.html`) — no build step required.

- **`app.py`** — Flask routes, `GraphClient` class (Microsoft Graph API wrapper with token caching), scenario loading, and email injection logic.
- **`static/index.html`** — Self-contained React 18 SPA loaded via CDN (Babel JSX transform in-browser). Single-page split-view UI with scenarios, users, action bar, and collapsible log/status panel.
- **`templates/`** — Scenario definitions (`scenarios.json`) and individual HTML email body templates (`scenario-*.html`). Adding a scenario requires no Python changes.

### Key backend components in app.py

- **`GraphClient`**: Handles OAuth2 client credentials flow, token caching with expiry, and Graph API calls for listing users, injecting emails (with MAPI extended properties to avoid draft flag), searching messages, and soft-deleting.
- **`build_scenarios()`**: Loads scenario metadata from `templates/scenarios.json`, renders HTML templates with `{{variable}}` substitution.
- **API endpoints**: `/api/inject`, `/api/clean`, `/api/reset`, `/api/status`, `/api/users`, `/api/scenarios`, `/api/auth/test`, `/api/config`.

### Non-draft email injection

Messages are created via `POST /users/{id}/mailFolders/inbox/messages` with three `singleValueExtendedProperties` that clear the draft flag:
- `Integer 0x0E07` (PidTagMessageFlags): `1`
- `Integer 0x0E17` (PR_MESSAGE_STATE): `1`
- `String 0x001A` (PR_MESSAGE_CLASS): `IPM.Note`

### Environment variables

Required: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`. Optional: `API_KEY` for endpoint authentication. See `.env.example` for full list.

### Settings persistence

Simulation settings (domains, CEO name, etc.) are persisted to `/app/data/settings.json`. In Docker, this is mounted as a named volume (`phishsim-data`). Priority: saved settings > env vars > defaults.

## Conventions

- The frontend uses no build tooling; React/Babel are loaded from CDN. Edit `static/index.html` directly.
- Email templates live in `templates/` as standalone HTML files with `{{variable}}` placeholders.
- Gunicorn is the production server (2 workers, 120s timeout, configured in Dockerfile).
