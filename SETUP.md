# PhishSim Injector — Setup Guide

## Overview

PhishSim Injector is a self-hosted web application for injecting realistic phishing
simulation emails into Microsoft 365 mailboxes via the Graph API. It's designed for
security awareness training — testing users' ability to identify and report phishing emails.

**Architecture:** Python Flask backend (handles Graph API auth + operations) serving a
React frontend (user selection, scenario management, injection control). Runs as a
single Docker container.

---

## Step 1: Register the App in Entra ID

This creates the service identity that PhishSim uses to access your tenant's mailboxes.

### 1a. Create the App Registration

1. Navigate to **https://entra.microsoft.com**
2. Go to **Identity → Applications → App registrations → New registration**
3. Configure:
   - **Name:** `PhishSim-Injector`
   - **Supported account types:** "Accounts in this organizational directory only"
   - **Redirect URI:** Leave blank
4. Click **Register**
5. On the overview page, copy these two values — you'll need them:
   - **Application (client) ID**
   - **Directory (tenant) ID**

### 1b. Add API Permissions

1. In the app registration, go to **API permissions → Add a permission**
2. Select **Microsoft Graph → Application permissions**
3. Search for and add these permissions:

| Permission | Purpose |
|---|---|
| **Mail.ReadWrite** | Create, search, and delete messages in all tenant mailboxes |
| **User.Read.All** | List tenant users so the UI can show a user picker |

4. Click **Grant admin consent for [Your Org]** and confirm
5. Both permissions should show green checkmarks under "Status"

### 1c. Create a Client Secret

1. Go to **Certificates & secrets → Client secrets → New client secret**
2. Set description: `PhishSim` and expiration: 12 or 24 months
3. Click **Add**
4. **Copy the secret Value immediately** — it's only shown once

### 1d. Summary of Values Needed

You should now have three values:

```
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your-secret-value
```

---

## Step 2: Deploy PhishSim Injector

### Option A: Docker (Recommended)

```bash
git clone <repo-url>
cd phishsim-app

# Create your .env file
cp .env.example .env
# Edit .env and fill in your three Azure values + set an API_KEY
nano .env

# Build and run
docker compose up -d

# View logs
docker compose logs -f
```

The app will be available at **http://localhost:5001**

### Option B: Run Directly with Python

```bash
cd phishsim-app
pip install -r requirements.txt

# Set environment variables
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-secret"
export API_KEY="your-api-key"

# Run
python app.py
```

---

## Step 3: Using the UI

### First Connection

1. Open **http://your-host:5001** in a browser
2. If you set an `API_KEY`, click the gear icon and enter it in Settings first
3. The app auto-connects to your tenant and loads users on page load
4. You should see your tenant name and a green "CONNECTED" indicator

### Workflow

The UI is a single-page split view:

1. **Left panel (Scenarios)** — Review the 5 phishing scenarios, toggle which ones to include
2. **Right panel (Users)** — Browse all tenant users, search/filter, select targets
3. **Action bar** — Run operations:
   - **Inject** — Creates simulation emails in selected users' inboxes
   - **Clean** — Removes all simulation emails from selected mailboxes
   - **Reset** — Cleans + re-injects in one operation
   - **Status** — Scans mailboxes to see which simulation emails are present
4. **Bottom panel** — Collapsible log and status results
5. **Gear icon** — Settings modal for domains, CEO name, company name, landing URL

### Quick Reset Workflow

```
1. Select All scenarios, Select All users
2. Click "Reset" in the action bar
3. Verify with "Status"
```

---

## Step 4: Configure User-Reported Phishing to a Shared Mailbox

This is the other half of the simulation: when users click "Report Phishing" in Outlook, where does that report go? By setting up a shared mailbox, you control the destination and can monitor whether users correctly identified and reported the simulation emails.

This is also how you'd integrate with a SIEM/SOAR — your automation monitors the shared mailbox for incoming reported emails and triggers triage workflows.

### 4a. Create the Shared Mailbox

```powershell
# Install the Exchange Online module if you haven't already
# Install-Module ExchangeOnlineManagement

Connect-ExchangeOnline -UserPrincipalName admin@yourdomain.onmicrosoft.com

# Create the shared mailbox
New-Mailbox -Shared -Name "Phishing Triage" -Alias "phishing" `
  -PrimarySmtpAddress phishing@yourdomain.onmicrosoft.com

# Grant yourself access so you can monitor it
Add-MailboxPermission -Identity "phishing@yourdomain.onmicrosoft.com" `
  -User "admin@yourdomain.onmicrosoft.com" -AccessRights FullAccess
```

### 4b. Mark as SecOps Mailbox

This step is important — without it, Microsoft Defender will strip malicious content (links, headers, attachments) from reported emails before they land in the shared mailbox. Marking it as a SecOps mailbox preserves the original email intact for analysis.

1. Go to **security.microsoft.com → Settings → Email & Collaboration → Advanced Delivery**
2. Click the **SecOps Mailbox** tab
3. Add `phishing@yourdomain.onmicrosoft.com`
4. Click **Save**

### 4c. Route User Reports to the Shared Mailbox

Configure Outlook's built-in "Report" button to send reported emails to your shared mailbox instead of (or in addition to) Microsoft:

1. Go to **security.microsoft.com → Settings → Email & Collaboration → User reported settings**
2. Toggle **"Monitor reported messages in Outlook"** to On
3. Select **"Use the built-in Report button in Outlook"**
4. Under **"Reported message destinations"**, select **"My reporting mailbox only"**
5. Enter `phishing@yourdomain.onmicrosoft.com`
6. Click **Save**

### 4d. Verify the Flow

1. Inject a simulation email using PhishSim
2. Open the target user's mailbox in Outlook (web or desktop)
3. Select the simulation email and click **Report → Report Phishing**
4. Check the shared mailbox — the reported email should appear as an attachment (`.eml`) within a report message
5. The original email headers, body, and indicators are preserved for analysis

---

## Step 5: Threat Intelligence Indicators

The simulation emails use these indicators, which can be seeded into your SIEM/SOAR
threat intelligence feeds for automated detection:

| Type | Value | Severity |
|------|-------|----------|
| Domain | m1crosoft-alerts.com | Critical |
| Domain | contoso-corp.com | Medium |
| Domain | netglobal-svcs.com | High |
| URL | https://m1crosoft-alerts.com/security/verify | Critical |
| URL | https://microsoft.com.m1crosoft-alerts.com/security/verify-identity | Critical |
| IP | 185.220.101.34 | High |
| IP | 91.234.99.42 | High |
| IP | 103.75.201.2 | Medium |
| Email | security-alerts@m1crosoft-alerts.com | Critical |
| Email | billing@netglobal-svcs.com | High |

---

## Troubleshooting

**"AUTH FAILED" when connecting**
- Verify AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET in your .env file
- Confirm admin consent was granted for both Mail.ReadWrite and User.Read.All
- Check that permissions are **Application** type (not Delegated)

**"Unauthorized" errors**
- If `API_KEY` is set on the server, enter the same key in Settings (gear icon)
- The key is stored in your browser's localStorage

**"No users found"**
- User.Read.All permission may not have admin consent
- Some tenants require users to have mailboxes provisioned

**Emails don't appear in inbox**
- Graph API message creation is near-instant but Outlook web may take 15-30 seconds to refresh
- Check the user's Deleted Items and Junk folder

**"403 Forbidden" on inject**
- Mail.ReadWrite must be an **Application permission** with admin consent

**Docker container won't start**
- Check `docker compose logs` for errors
- Verify .env file has no trailing spaces or quotes around values

---

## Security Notes

- The client secret provides **full mailbox access to every user in the tenant**
- Only use this with a developer/lab tenant — never production
- The backend keeps credentials server-side (never sent to the browser)
- **Set an `API_KEY`** to protect the API endpoints when exposed on a network
- For additional security, use certificate-based auth instead of a client secret
- Consider running behind a reverse proxy with TLS if exposed beyond localhost
