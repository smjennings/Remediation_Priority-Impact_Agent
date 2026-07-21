# Remediation Priority & Impact Agent

A Claude Code skill (invoked with `/fix-today`) that answers the question **"What should I fix today?"** by pulling live data from [Tenable](https://www.tenable.com/) (Tenable One / Exposure Management and Vulnerability Management) and producing a prioritized remediation briefing.

It ranks fixes using a composite of:

- **Asset Exposure Score (AES)** — Tenable One's exposure measure per asset
- **Real exploited-in-the-wild status** — confirmed from plugin exploit-intelligence (CISA KEV, exploited-by-malware, in-the-news, exploit frameworks), *not* inferred from VPR
- **VPR** and **Asset Criticality Rating (ACR)**
- **MITRE ATT&CK / Attack Path Analysis** — sourced from Tenable's own APA where available, then CVE→tactic mapping
- **Blast radius** — how many assets share the same vulnerability

The output is an interactive dashboard (priority table, ATT&CK heatmap, batched remediation groups, risk-reduction forecast) plus a "Fix FIRST / NEXT / SOON" text summary.

Each finding carries its **actual remediation** — the verbatim Tenable plugin `Solution` (exact KBs, package versions, registry keys) plus any interim mitigation for when a patch window isn't available. On request, the command also generates ready-to-paste **change tickets**, one per host, populated from the gathered data (CVEs, VPR, CISA KEV dates, plugin IDs, fix steps, verification and rollback).

## Requirements

- [Claude Code](https://claude.com/claude-code)
- A **Tenable VM/EM (Tenable One) MCP server** connected in your client, configured with **your own** API keys and region. The skill contains no credentials — set them up in your MCP config before running.
  - The command's tool calls use the `mcp__tenable__*` prefix (the default server name). If you register the server under a different name, substitute that prefix — the skill's Phase 0 explains how. If no Tenable MCP is connected, the skill stops and asks you to set one up rather than proceeding.

## Install

Copy the command into your Claude Code commands directory:

```bash
cp commands/fix-today.md ~/.claude/commands/fix-today.md
```

## Setup: connect the Tenable MCP

The skill ships **no credentials** — it reads everything through a Tenable MCP server that you configure with your own keys. Set this up once before running.

1. **Generate Tenable API keys.** In the Tenable UI: **Settings → My Account → API Keys → Generate**. You'll get an **access key** and a **secret key**. Treat these like passwords.

2. **Add Tenable's hosted MCP server**, named `tenable` (this matches the `mcp__tenable__*` prefix the skill uses by default). It's a **remote HTTP MCP server** — no local install:

   - **Server URL:** `https://cloud.tenable.com/mcp/`
   - **Auth:** the `X-ApiKeys` HTTP header, formatted `accessKey=<YOUR_ACCESS_KEY>;secretKey=<YOUR_SECRET_KEY>`

   **Claude Code (CLI):**

   ```bash
   claude mcp add --transport http tenable https://cloud.tenable.com/mcp/ \
     --header "X-ApiKeys: accessKey=<YOUR_ACCESS_KEY>;secretKey=<YOUR_SECRET_KEY>"
   ```

   **Or edit the Claude Code config directly** (`~/.claude.json` / your project `.mcp.json`):

   ```json
   {
     "mcpServers": {
       "tenable": {
         "type": "http",
         "url": "https://cloud.tenable.com/mcp/",
         "headers": {
           "X-ApiKeys": "accessKey=<YOUR_ACCESS_KEY>;secretKey=<YOUR_SECRET_KEY>"
         }
       }
     }
   }
   ```

   **Claude Desktop** doesn't connect to remote HTTP MCP servers directly — it bridges to them through the [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) npm package running as a local stdio proxy (requires [Node.js](https://nodejs.org)). In `claude_desktop_config.json`:

   ```json
   {
     "mcpServers": {
       "tenable": {
         "command": "npx",
         "args": [
           "-y", "mcp-remote",
           "https://cloud.tenable.com/mcp/",
           "--header", "X-ApiKeys:${TENABLE_API_KEYS}"
         ],
         "env": {
           "TENABLE_API_KEYS": "accessKey=<YOUR_ACCESS_KEY>;secretKey=<YOUR_SECRET_KEY>"
         }
       }
     }
   }
   ```

   > The `${TENABLE_API_KEYS}` indirection is deliberate: `mcp-remote` splits `--header` arguments on whitespace, so passing the value via an env var avoids breakage. Keep keys out of source control — prefer environment variables or your OS secret store over committing them. If you register the server under a name other than `tenable`, substitute that prefix when you read the skill (see Phase 0 in `commands/fix-today.md`).

3. **Restart your client** and confirm the Tenable tools are available (tool names like `mcp__tenable__tenable_one_search_assets`). Then run `/fix-today`.

## Usage

In Claude Code, run:

```
/fix-today
```

It will work through the gather → confirm-exploitation → ATT&CK-mapping → prioritize phases and render the briefing.

## Sample output

[`examples/Fix-Today-Report.html`](examples/Fix-Today-Report.html) is a self-contained HTML report from a real run against a test environment — open it in any browser. It shows the executive summary cards, the priority remediation table with per-finding fixes, the MITRE ATT&CK coverage, the Attack Path Analysis findings, the risk-reduction forecast, the Fix FIRST/NEXT/SOON steps, and the generated change tickets. (Asset names and figures are from a Tenable demo environment.)
