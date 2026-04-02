#!/usr/bin/env python3
"""
PhishSim Injector — Backend API
================================
Flask API that authenticates to Microsoft Graph and provides endpoints
for user listing, email injection, cleanup, and mailbox status checking.

Credentials stay server-side. The React frontend talks to this API.
"""

import os
import time
import uuid
import json
import logging
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import requests as http_requests

# ═══════════════════════════════════════════════════════════════
# App Setup
# ═══════════════════════════════════════════════════════════════

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("phishsim")

API_KEY = os.environ.get("API_KEY", "")

@app.before_request
def check_api_key():
    """Protect all /api/ endpoints with a shared API key."""
    if not API_KEY:
        return  # no key configured = open access
    if not request.path.startswith("/api/"):
        return  # static files don't need auth
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

# ═══════════════════════════════════════════════════════════════
# Configuration — from environment variables
# ═══════════════════════════════════════════════════════════════

SETTINGS_FILE = os.environ.get("SETTINGS_FILE", "/app/data/settings.json")

def _load_settings():
    """Load saved settings from disk, or return empty dict."""
    try:
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _save_settings(data):
    """Persist settings to disk."""
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f, indent=2)

_saved = _load_settings()

class Config:
    TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
    CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
    CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

    # Simulation defaults: saved settings > env vars > hardcoded defaults
    ATTACKER_DOMAIN = _saved.get("attacker_domain", os.environ.get("ATTACKER_DOMAIN", "m1crosoft-alerts.com"))
    BEC_DOMAIN = _saved.get("bec_domain", os.environ.get("BEC_DOMAIN", "contoso-corp.com"))
    CEO_NAME = _saved.get("ceo_name", os.environ.get("CEO_NAME", "Michael Chen, CEO"))
    COMPANY_NAME = _saved.get("company_name", os.environ.get("COMPANY_NAME", "Contoso"))
    LANDING_URL = _saved.get("landing_url", os.environ.get("LANDING_URL", "https://m1crosoft-alerts.com/security/verify"))


# ═══════════════════════════════════════════════════════════════
# Graph API Client
# ═══════════════════════════════════════════════════════════════

class GraphClient:
    TOKEN_URL = "https://login.microsoftonline.com/{}/oauth2/v2.0/token"
    BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self):
        self._token = None
        self._expiry = 0

    def _get_token(self):
        if self._token and time.time() < self._expiry - 60:
            return self._token
        resp = http_requests.post(
            self.TOKEN_URL.format(Config.TENANT_ID),
            data={
                "client_id": Config.CLIENT_ID,
                "client_secret": Config.CLIENT_SECRET,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._expiry = time.time() + data.get("expires_in", 3600)
        log.info("Graph API token acquired")
        return self._token

    def _headers(self):
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def test_auth(self):
        """Test authentication and return tenant info."""
        token = self._get_token()
        resp = http_requests.get(
            f"{self.BASE}/organization?$select=displayName,verifiedDomains",
            headers=self._headers(),
            timeout=15,
        )
        if resp.ok:
            orgs = resp.json().get("value", [])
            if orgs:
                return {
                    "ok": True,
                    "org_name": orgs[0].get("displayName", "Unknown"),
                    "domains": [
                        d.get("name") for d in orgs[0].get("verifiedDomains", [])
                    ],
                }
        return {"ok": True, "org_name": "Connected", "domains": []}

    def list_users(self):
        """List all licensed users with mailboxes."""
        users = []
        url = (
            f"{self.BASE}/users"
            f"?$filter=accountEnabled eq true"
            f"&$select=id,displayName,mail,jobTitle,department,userPrincipalName"
            f"&$top=100"
        )
        while url:
            resp = http_requests.get(url, headers=self._headers(), timeout=30)
            if not resp.ok:
                log.error(f"List users failed: {resp.status_code} {resp.text[:200]}")
                break
            data = resp.json()
            users.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return users

    def inject_email(self, target, payload):
        """Create a non-draft message in user's inbox via Graph API."""
        # Add extended properties to mark as non-draft
        payload["singleValueExtendedProperties"] = [
            {"id": "Integer 0x0E07", "value": "1"},   # PidTagMessageFlags: read + sent
            {"id": "Integer 0x0E17", "value": "1"},   # PR_MESSAGE_STATE: not draft
            {"id": "String 0x001A", "value": "IPM.Note"},  # PR_MESSAGE_CLASS: standard email
        ]
        resp = http_requests.post(
            f"{self.BASE}/users/{target}/mailFolders/inbox/messages",
            headers=self._headers(),
            json=payload,
            timeout=30,
        )
        if resp.ok:
            return True, resp.json().get("id", "ok")
        return False, f"{resp.status_code}: {resp.text[:300]}"

    def search_by_subject(self, mailbox, subject):
        """Find messages by exact subject."""
        safe = subject.replace("'", "''")
        resp = http_requests.get(
            f"{self.BASE}/users/{mailbox}/messages"
            f"?$filter=subject eq '{safe}'"
            f"&$select=id,subject,from,receivedDateTime,isRead"
            f"&$top=50",
            headers=self._headers(),
            timeout=30,
        )
        if resp.ok:
            return resp.json().get("value", [])
        return []

    def soft_delete(self, mailbox, message_id):
        """Move message to Deleted Items."""
        resp = http_requests.post(
            f"{self.BASE}/users/{mailbox}/messages/{message_id}/move",
            headers=self._headers(),
            json={"destinationId": "deleteditems"},
            timeout=30,
        )
        return resp.ok


graph = GraphClient()


# ═══════════════════════════════════════════════════════════════
# Scenario Definitions (loaded from templates/)
# ═══════════════════════════════════════════════════════════════

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

def _load_scenario_defs():
    """Load scenario metadata from templates/scenarios.json."""
    with open(os.path.join(TEMPLATES_DIR, "scenarios.json")) as f:
        return json.load(f)

SCENARIO_DEFS = _load_scenario_defs()

def _render(template, variables):
    """Simple {{var}} substitution in a string."""
    result = template
    for key, val in variables.items():
        result = result.replace("{{" + key + "}}", str(val))
    return result

def build_scenarios(cfg, run_id):
    """Build all scenario payloads using provided config and template files."""
    variables = {
        "attacker_domain": cfg.get("attacker_domain", Config.ATTACKER_DOMAIN),
        "bec_domain": cfg.get("bec_domain", Config.BEC_DOMAIN),
        "ceo_name": cfg.get("ceo_name", Config.CEO_NAME),
        "company_name": cfg.get("company_name", Config.COMPANY_NAME),
        "company_name_lower": cfg.get("company_name", Config.COMPANY_NAME).lower(),
        "landing_url": cfg.get("landing_url", Config.LANDING_URL),
        "run_id": run_id,
        "run_id_upper": run_id.upper(),
        "now_str": datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC"),
        "date_short": datetime.now().strftime("%b %d"),
    }

    result = {}
    for sc_def in SCENARIO_DEFS:
        sc = {}
        for key, val in sc_def.items():
            if key == "template":
                continue
            elif key == "headers":
                sc[key] = [{"name": h["name"], "value": _render(h["value"], variables)} for h in val]
            elif isinstance(val, str):
                sc[key] = _render(val, variables)
            else:
                sc[key] = val

        # Load and render the HTML body template
        tmpl_path = os.path.join(TEMPLATES_DIR, sc_def["template"])
        with open(tmpl_path) as f:
            sc["body"] = _render(f.read(), variables)

        result[sc["id"]] = sc
    return result


def build_graph_payload(scenario, target_email):
    """Build the Graph API message creation payload."""
    from_addr = scenario["from_address"]
    if from_addr is None:
        domain = target_email.split("@")[1]
        from_addr = f"sarah.johnson@{domain}"

    headers = list(scenario["headers"])
    if scenario.get("headers_template"):
        domain = target_email.split("@")[1]
        headers.insert(0, {
            "name": "X-Authentication-Results",
            "value": f"mx.{domain}; spf=pass smtp.mailfrom={domain}; dkim=pass header.d={domain}; dmarc=pass",
        })

    body = scenario["body"].replace("{{recipient_email}}", target_email)

    payload = {
        "subject": scenario["subject"],
        "from": {"emailAddress": {"name": scenario["from_name"], "address": from_addr}},
        "sender": {"emailAddress": {"name": scenario["from_name"], "address": from_addr}},
        "internetMessageHeaders": headers,
        "body": {"contentType": "HTML", "content": body},
        "isRead": False,
        "importance": "high" if scenario["verdict"] == "MALICIOUS" else "normal",
    }

    if scenario.get("reply_to"):
        payload["replyTo"] = [{"emailAddress": {"address": scenario["reply_to"]}}]

    return payload


# ═══════════════════════════════════════════════════════════════
# API Routes
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/config", methods=["GET"])
def get_config():
    """Return non-secret configuration for the UI."""
    return jsonify({
        "configured": bool(Config.TENANT_ID and Config.CLIENT_ID and Config.CLIENT_SECRET),
        "attacker_domain": Config.ATTACKER_DOMAIN,
        "bec_domain": Config.BEC_DOMAIN,
        "ceo_name": Config.CEO_NAME,
        "company_name": Config.COMPANY_NAME,
        "landing_url": Config.LANDING_URL,
    })


@app.route("/api/config", methods=["PUT"])
def update_config():
    """Update simulation config (not credentials — those are env vars)."""
    data = request.json or {}
    fields = ["attacker_domain", "bec_domain", "ceo_name", "company_name", "landing_url"]
    attr_map = {
        "attacker_domain": "ATTACKER_DOMAIN",
        "bec_domain": "BEC_DOMAIN",
        "ceo_name": "CEO_NAME",
        "company_name": "COMPANY_NAME",
        "landing_url": "LANDING_URL",
    }
    for field in fields:
        if field in data:
            setattr(Config, attr_map[field], data[field])
    # Persist to disk
    saved = {f: getattr(Config, attr_map[f]) for f in fields}
    _save_settings(saved)
    return jsonify({"ok": True})


@app.route("/api/auth/test", methods=["POST"])
def test_auth():
    """Test Graph API authentication."""
    try:
        result = graph.test_auth()
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 401


@app.route("/api/users", methods=["GET"])
def list_users():
    """List tenant users with mailboxes."""
    try:
        users = graph.list_users()
        return jsonify({"users": users})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scenarios", methods=["GET"])
def list_scenarios():
    """List available phishing scenarios."""
    variables = {
        "attacker_domain": Config.ATTACKER_DOMAIN,
        "bec_domain": Config.BEC_DOMAIN,
        "ceo_name": Config.CEO_NAME,
        "company_name": Config.COMPANY_NAME,
        "date_short": datetime.now().strftime("%b %d"),
    }
    result = []
    for sc in SCENARIO_DEFS:
        result.append({
            "id": sc["id"],
            "name": _render(sc["name"], variables),
            "verdict": sc["verdict"],
            "difficulty": sc["difficulty"],
            "subject": _render(sc["subject"], variables),
            "from_name": _render(sc["from_name"], variables),
            "from_address": _render(sc["from_address"], variables) if sc["from_address"] else "(internal sender)",
        })
    return jsonify({"scenarios": result})


@app.route("/api/inject", methods=["POST"])
def inject_emails():
    """
    Inject simulation emails.
    Body: { "scenario_ids": ["1","2",...], "targets": ["user@domain.com",...] }
    """
    data = request.json or {}
    scenario_ids = data.get("scenario_ids", [])
    targets = data.get("targets", [])
    sim_config = data.get("config", {})

    if not scenario_ids or not targets:
        return jsonify({"error": "scenario_ids and targets are required"}), 400

    run_id = uuid.uuid4().hex[:8]
    cfg = {
        "attacker_domain": sim_config.get("attacker_domain", Config.ATTACKER_DOMAIN),
        "bec_domain": sim_config.get("bec_domain", Config.BEC_DOMAIN),
        "ceo_name": sim_config.get("ceo_name", Config.CEO_NAME),
        "company_name": sim_config.get("company_name", Config.COMPANY_NAME),
        "landing_url": sim_config.get("landing_url", Config.LANDING_URL),
    }

    scenarios = build_scenarios(cfg, run_id)
    results = []

    for sid in scenario_ids:
        sc = scenarios.get(sid)
        if not sc:
            results.append({"scenario": sid, "error": "Unknown scenario"})
            continue

        for target in targets:
            payload = build_graph_payload(sc, target)
            try:
                ok, detail = graph.inject_email(target, payload)
                results.append({
                    "scenario_id": sid,
                    "scenario_name": sc["name"],
                    "target": target,
                    "ok": ok,
                    "detail": detail if not ok else None,
                })
                time.sleep(0.3)  # rate limiting
            except Exception as e:
                results.append({
                    "scenario_id": sid,
                    "scenario_name": sc["name"],
                    "target": target,
                    "ok": False,
                    "detail": str(e),
                })

    ok_count = sum(1 for r in results if r["ok"])
    fail_count = sum(1 for r in results if not r["ok"])

    return jsonify({
        "run_id": run_id,
        "injected": ok_count,
        "failed": fail_count,
        "results": results,
    })


@app.route("/api/clean", methods=["POST"])
def clean_emails():
    """
    Remove simulation emails from mailboxes.
    Body: { "scenario_ids": ["1","2",...], "targets": ["user@domain.com",...] }
    """
    data = request.json or {}
    scenario_ids = data.get("scenario_ids", [])
    targets = data.get("targets", [])

    if not targets:
        return jsonify({"error": "targets required"}), 400

    cfg = {
        "attacker_domain": Config.ATTACKER_DOMAIN,
        "bec_domain": Config.BEC_DOMAIN,
        "ceo_name": Config.CEO_NAME,
        "company_name": Config.COMPANY_NAME,
        "landing_url": Config.LANDING_URL,
    }
    scenarios = build_scenarios(cfg, "clean")

    # If no scenario_ids specified, clean all
    if not scenario_ids:
        scenario_ids = list(scenarios.keys())

    subjects = [scenarios[sid]["subject"] for sid in scenario_ids if sid in scenarios]
    cleaned = 0

    for target in targets:
        for subject in subjects:
            try:
                msgs = graph.search_by_subject(target, subject)
                for msg in msgs:
                    if graph.soft_delete(target, msg["id"]):
                        cleaned += 1
                    time.sleep(0.15)
            except Exception as e:
                log.error(f"Clean error for {target}: {e}")

    return jsonify({"cleaned": cleaned})


@app.route("/api/reset", methods=["POST"])
def reset_lab():
    """Full reset: clean all + re-inject fresh."""
    data = request.json or {}
    scenario_ids = data.get("scenario_ids", ["1", "2", "3", "4", "5"])
    targets = data.get("targets", [])

    if not targets:
        return jsonify({"error": "targets required"}), 400

    # Phase 1: Clean
    cfg = {
        "attacker_domain": Config.ATTACKER_DOMAIN,
        "bec_domain": Config.BEC_DOMAIN,
        "ceo_name": Config.CEO_NAME,
        "company_name": Config.COMPANY_NAME,
        "landing_url": Config.LANDING_URL,
    }
    all_scenarios = build_scenarios(cfg, "clean")
    cleaned = 0
    for target in targets:
        for sid, sc in all_scenarios.items():
            try:
                msgs = graph.search_by_subject(target, sc["subject"])
                for msg in msgs:
                    if graph.soft_delete(target, msg["id"]):
                        cleaned += 1
                    time.sleep(0.1)
            except:
                pass

    # Phase 2: Inject
    run_id = uuid.uuid4().hex[:8]
    scenarios = build_scenarios(cfg, run_id)
    injected = 0
    failed = 0

    for sid in scenario_ids:
        sc = scenarios.get(sid)
        if not sc:
            continue
        for target in targets:
            try:
                payload = build_graph_payload(sc, target)
                ok, _ = graph.inject_email(target, payload)
                if ok:
                    injected += 1
                else:
                    failed += 1
                time.sleep(0.3)
            except:
                failed += 1

    return jsonify({
        "run_id": run_id,
        "cleaned": cleaned,
        "injected": injected,
        "failed": failed,
    })


@app.route("/api/status", methods=["POST"])
def check_status():
    """
    Check which simulation emails exist in target mailboxes.
    Body: { "targets": ["user@domain.com",...] }
    """
    data = request.json or {}
    targets = data.get("targets", [])

    if not targets:
        return jsonify({"error": "targets required"}), 400

    cfg = {
        "attacker_domain": Config.ATTACKER_DOMAIN,
        "bec_domain": Config.BEC_DOMAIN,
        "ceo_name": Config.CEO_NAME,
        "company_name": Config.COMPANY_NAME,
        "landing_url": Config.LANDING_URL,
    }
    scenarios = build_scenarios(cfg, "status")

    result = {}
    for target in targets:
        result[target] = []
        for sid, sc in scenarios.items():
            try:
                msgs = graph.search_by_subject(target, sc["subject"])
                if msgs:
                    result[target].append({
                        "id": sc["id"],
                        "name": sc["name"],
                        "verdict": sc["verdict"],
                        "count": len(msgs),
                        "read": any(m.get("isRead") for m in msgs),
                    })
            except:
                pass

    return jsonify({"status": result})


# ═══════════════════════════════════════════════════════════════
# Run
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    if not Config.TENANT_ID:
        log.warning("AZURE_TENANT_ID not set — configure via environment variables")
    if not Config.CLIENT_ID:
        log.warning("AZURE_CLIENT_ID not set — configure via environment variables")
    if not Config.CLIENT_SECRET:
        log.warning("AZURE_CLIENT_SECRET not set — configure via environment variables")

    log.info(f"PhishSim Injector starting on port {port}")
    app.run(host="127.0.0.1", port=port, debug=debug)
