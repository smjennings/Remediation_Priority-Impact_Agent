# Remediation Priority & Impact Agent

A Claude Code skill (invoked with `/fix-today`) that answers the question **"What should I fix today?"** by pulling live data from [Tenable](https://www.tenable.com/) (Tenable One / Exposure Management and Vulnerability Management) and producing a prioritized remediation briefing.

It ranks fixes using a composite of:

- **Asset Exposure Score (AES)** — Tenable One's exposure measure per asset
- **Real exploited-in-the-wild status** — confirmed from plugin exploit-intelligence (CISA KEV, exploited-by-malware, in-the-news, exploit frameworks), *not* inferred from VPR
- **External corroboration** — by default, checks CISA's ransomware-use flag (updated silently, no changelog), named threat-intel reporting, and vendor lifecycle pages for the top findings, using web search/fetch
- **VPR** and **Asset Criticality Rating (ACR)**
- **MITRE ATT&CK / Attack Path Analysis** — sourced from Tenable's own APA where available, then CVE→tactic mapping
- **Blast radius** — how many assets share the same vulnerability

The output is an interactive dashboard (priority table, ATT&CK heatmap, batched remediation groups, risk-reduction forecast) plus a "Fix FIRST / NEXT / SOON" text summary. The dashboard and tickets are template-driven: the model writes data, and bundled Python scripts score, sort and render it, so every run looks the same apart from the data.

Each finding carries its **actual remediation** — the verbatim Tenable plugin `Solution` (exact KBs, package versions, registry keys) plus any interim mitigation for when a patch window isn't available. Every run also writes ready-to-paste **change tickets**, one per Fix FIRST host, populated from the gathered data (CVEs, VPR, CISA KEV dates, plugin IDs, fix steps, verification and rollback, with domain-controller-safe rollback steps).

After each run, the skill asks what to do next: create Jira issues from the tickets (or help connect Jira), draft a Slack alert, book maintenance windows, tag the hosts in Tenable, compare with the previous run, schedule daily runs, or produce a Word handoff. It only offers actions your session has tools for, and it never sends or creates anything until you confirm the exact plan. Slack messages are drafts only.

## Requirements

- [Claude Code](https://claude.com/claude-code)
- A **Tenable VM/EM (Tenable One) MCP server** connected in your client, configured with **your own** API keys and region. The skill contains no credentials — set them up in your MCP config before running.
  - The command's tool calls use the `mcp__tenable__*` prefix (the default server name). If you register the server under a different name, substitute that prefix — the skill's Phase 0 explains how. If no Tenable MCP is connected, the skill stops and asks you to set one up rather than proceeding.
- **Python 3** (standard library only) to run the bundled render, ticket and compare scripts.
- **Web search/fetch tools** (`WebSearch`/`WebFetch`) available in your client for the external-corroboration step (Phase 3.5). These ship with Claude Code by default. If they're unavailable, the skill still runs the full Tenable-only briefing and says explicitly that external corroboration was skipped.

## Install

Copy the skill folder into your Claude Code skills directory:

```bash
cp -R skills/fix-today ~/.claude/skills/
```

Upgrading from the earlier single-file command? Remove it so only one `/fix-today` is registered:

```bash
rm ~/.claude/commands/fix-today.md
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

   > The `${TENABLE_API_KEYS}` indirection is deliberate: `mcp-remote` splits `--header` arguments on whitespace, so passing the value via an env var avoids breakage. Keep keys out of source control — prefer environment variables or your OS secret store over committing them. If you register the server under a name other than `tenable`, substitute that prefix when you read the skill (see Phase 0 in `skills/fix-today/SKILL.md`).

3. **Restart your client** and confirm the Tenable tools are available (tool names like `mcp__tenable__tenable_one_search_assets`). Then run `/fix-today`.

## Usage

In Claude Code, run:

```
/fix-today
```

It will work through the gather → confirm-exploitation → corroborate externally → ATT&CK-mapping → prioritize phases, render the briefing, write the change tickets, and then ask what you'd like to do next.

### Run history

Each run saves its data to `~/.local/share/fix-today/history/<date>/`, which powers "Compare with last run" (new, fixed and still-open items, with how long each has been open). The history holds your hostnames and IPs, so it lives outside the skill folder; keep it out of any repo you share the skill through.

### What's in the skill folder

| File | Role |
|---|---|
| `SKILL.md` | The instructions Claude follows |
| `schema.json`, `render.py`, `template.html` | Briefing data shape, scoring and dashboard |
| `tickets_schema.json`, `tickets.py` | Change-ticket data shape and generator |
| `compare.py` | Compares a run with the previous one |
| `examples/` | Worked examples of both data files (demo environment, addresses replaced with documentation IPs) |

## Sample output

[`examples/Fix-Today-Report.html`](examples/Fix-Today-Report.html) is a self-contained HTML report from a real run against a test environment — open it in any browser. It shows the executive summary cards, the priority remediation table with per-finding fixes, the MITRE ATT&CK coverage, the Attack Path Analysis findings, the risk-reduction forecast, the Fix FIRST/NEXT/SOON steps, and the generated change tickets. (Asset names and figures are from a Tenable demo environment.)
