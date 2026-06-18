# Remediation Priority & Impact Agent

A Claude Code slash command (`/fix-today`) that answers the question **"What should I fix today?"** by pulling live data from [Tenable](https://www.tenable.com/) (Tenable One / Exposure Management and Vulnerability Management) and producing a prioritized remediation briefing.

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
- The **Tenable MCP server** connected (the command calls `mcp__tenable__*` tools)

## Install

Copy the command into your Claude Code commands directory:

```bash
cp commands/fix-today.md ~/.claude/commands/fix-today.md
```

## Usage

In Claude Code, run:

```
/fix-today
```

It will work through the gather → confirm-exploitation → ATT&CK-mapping → prioritize phases and render the briefing.
