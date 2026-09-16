---
name: "Remediation Priority & Impact Agent"
author: "smjennings"
github_url: "https://github.com/smjennings/Remediation_Priority-Impact_Agent"
description: "Prioritizes daily vulnerability fixes using Tenable exposure data, CISA KEV exploitation, MITRE ATT&CK and attack paths"
license: "MIT"
tier: "unreviewed"
tags: ["vulnerability-management", "exposure-management", "remediation-prioritization", "cisa-kev", "mitre-attack", "attack-path-analysis", "threat-intelligence"]
integrations: ["Tenable"]
date_added: 2026-06-18
compatible_platforms: ["Claude Code"]
invocation: "/fix-today"
---

A Claude Code skill that answers "What should I fix today?" by pulling live data from Tenable (Tenable One / Exposure Management and Vulnerability Management) and producing a prioritized remediation briefing.

## What it does

- **Ranks your most exposed assets** by Tenable's Asset Exposure Score (AES)
- **Confirms real exploited-in-the-wild status** from plugin exploit-intelligence (CISA KEV, exploited-by-malware, in-the-news, exploit frameworks) — not inferred from VPR
- **Corroborates externally, by default, for the findings that matter most** — web-searches CISA's silently-updated ransomware-use flag, named threat-intel reporting (Unit42, Huntress, GreyNoise, vendor PSIRT) for confirmed real-world exploitation, and vendor lifecycle pages for EOL/ESU status, scoped to Tier 1/2 findings so it stays fast
- **Layers MITRE ATT&CK and Attack Path Analysis**, sourced from Tenable's own APA where available, then CVE→tactic mapping
- **Scores each remediation** with a composite of AES, confirmed-exploit tier, VPR, asset criticality, attack-path position and blast radius
- **Surfaces the actual fix** — verbatim Tenable remediation (exact KBs, package versions, registry keys) plus interim mitigations
- **Renders an interactive dashboard** (priority table, ATT&CK heatmap, batched remediation groups, risk-reduction forecast) and a "Fix FIRST / NEXT / SOON" plan
- **Generates ready-to-paste change tickets** per host on request

## How it works

Invoked with `/fix-today`, the skill works through gather → confirm-exploitation → corroborate externally → ATT&CK/attack-path mapping → prioritize phases, calling the Tenable MCP tools plus web search/fetch for the external-corroboration step. It treats VPR as a ranking input only, confirming actual exploitation at the plugin level, then checks whether Tenable's picture is corroborated (or contradicted) by outside sources before it queries Tenable's Attack Path Analysis to flag the assets that sit on real attack paths (including identity/privilege pivots that patching won't fix). The output leads with what attackers are actually using, on the assets that matter most.
