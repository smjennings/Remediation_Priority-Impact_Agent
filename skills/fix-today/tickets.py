#!/usr/bin/env python3
"""Deterministic change-ticket generator for /fix-today.

Usage:  python3 tickets.py <tickets.json> <out.md>

Validates the data against tickets_schema.json (exit 2 listing every problem),
orders tickets, and writes one plain-text ticket per host inside ```text blocks.
Prints the ticket order and the tickets to show inline (per group, the host
with the most findings).
Same input -> byte-identical output.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from render import _check  # noqa: E402  shared schema validator

RULE = "=" * 78
MAX_LINE = 100  # data lines; long enough for a full registry key or file path on one line
CONT = " " * 15

ROLLBACK = {
    "dc": [
        "- Take a system-state backup before the change (wbadmin start systemstatebackup).",
        "- Do NOT revert a domain controller from a VM snapshot: that causes USN rollback",
        "  and AD replication corruption. Restore from the system-state backup if needed.",
        "- To back out the update itself: DISM /Online /Get-Packages to find the LCU package,",
        "  then DISM /Online /Remove-Package /PackageName:<name>. Combined SSU+LCU packages",
        "  cannot be removed with wusa /uninstall.",
    ],
    "server": [
        "- Take a VM snapshot or full backup before the change; delete the snapshot after",
        "  the rescan confirms the fix.",
        "- To back out the update itself: DISM /Online /Get-Packages to find the LCU package,",
        "  then DISM /Online /Remove-Package /PackageName:<name>. Combined SSU+LCU packages",
        "  cannot be removed with wusa /uninstall.",
    ],
}


def validate(data):
    schema = json.loads((HERE / "tickets_schema.json").read_text())
    errs = []
    _check(data, schema, "$", errs)
    if not errs:
        gids = {g["id"] for g in data["groups"]}
        names = set()
        for i, h in enumerate(data["hosts"]):
            p = f"$.hosts[{i}] ({h['name']})"
            if h["name"] in names:
                errs.append(f"{p}: duplicate host name")
            names.add(h["name"])
            if h["group"] not in gids:
                errs.append(f"{p}: group '{h['group']}' not in groups")
            for pid in h["plugins"]:
                if pid not in data["plugins"]:
                    errs.append(f"{p}: plugin {pid} not defined in plugins")
            if isinstance(h["rollback"], str) and h["rollback"] not in ROLLBACK:
                errs.append(f"{p}: rollback must be one of {sorted(ROLLBACK)} or a list of lines")
            if h.get("is_dc") and h["rollback"] != "dc":
                errs.append(f"{p}: domain controller must use rollback 'dc' (never VM-snapshot revert)")
            if (h["aes"] is None) != (h["acr"] is None):
                errs.append(f"{p}: aes and acr must both be set or both be null")
            for field in ("summary", "change", "interim", "risk", "notes", "rollback"):
                lines = h.get(field, [])
                for j, line in enumerate(lines if isinstance(lines, list) else []):
                    if len(line) > MAX_LINE:
                        errs.append(f"{p}.{field}[{j}]: line is {len(line)} chars (max {MAX_LINE}) — wrap it")
        used = {pid for h in data["hosts"] for pid in h["plugins"]}
        for pid in data["plugins"]:
            if pid not in used:
                errs.append(f"$.plugins.{pid}: defined but no host references it")
    if errs:
        sys.stderr.write("fix-today tickets data failed validation (fix the data, not the script):\n")
        sys.stderr.write("".join(f"  - {e}\n" for e in errs))
        raise SystemExit(2)


def indent(lines):
    return "\n".join("  " + l if l else "" for l in lines)


def join_en(items):
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def ticket(h, data):
    plugins = data["plugins"]
    role = h["role"] + (" (role inferred from hostname)" if h["role_inferred"] else "")
    aes = "AES/ACR unavailable" if h["aes"] is None else f"AES {h['aes']} | ACR {h['acr']}"
    out = [
        RULE,
        f"{'TITLE:':<15}SECURITY CRITICAL: {h['title']}",
        f"{'PRIORITY:':<15}{h['priority']}",
        f"{'ASSET:':<15}{h['name']} ({h['ip']}) | {h['os']}",
        f"{CONT}{role} | {aes}",
        f"{CONT}Attack path: {data['attack_path_status']}",
        f"{'REQUESTED BY:':<15}{data['requested_by']}",
        f"{'DATE RAISED:':<15}{data['run_date']}",
    ]

    notes = h.get("notes", [])
    summary = list(h["summary"]) + [("Note: " if i == 0 else "      ") + n for i, n in enumerate(notes)]
    vulns = []
    for pid in h["plugins"]:
        p = plugins[pid]
        vulns.append(f"- Plugin {pid:<7} {p['title']}")
        vulns.append(f"    CVEs: {p['cves'][0]}")
        vulns += [f"          {c}" for c in p["cves"][1:]]
        vulns.append(f"    VPR: {p['vpr']:.1f}   CVSS v3: {p['cvss3']:.1f}")
        vulns.append(f"    CISA KEV: {p['kev']}")
    n = len(h["plugins"])
    verify = [f"Rescan in Tenable and confirm plugin{'s' if n > 1 else ''} {join_en(h['plugins'])} "
              f"no longer fire{'' if n > 1 else 's'} on {h['name']}."]
    rollback = ROLLBACK[h["rollback"]] if isinstance(h["rollback"], str) else h["rollback"]

    for label, lines in (("SUMMARY", summary), ("VULNERABILITIES", vulns),
                         ("CHANGE / REMEDIATION", h["change"]), ("INTERIM MITIGATION", h["interim"]),
                         ("VERIFICATION", verify), ("ROLLBACK", rollback), ("RISK IF NOT DONE", h["risk"])):
        out += ["", f"{label}:", indent(lines)]
    out.append(RULE)
    return "\n".join(out)


def main(src, dst):
    data = json.loads(Path(src).read_text())
    validate(data)

    groups = sorted(data["groups"], key=lambda g: (g["rank"], g["id"]))
    grank = {g["id"]: (g["rank"], g["id"]) for g in groups}
    hosts = sorted(data["hosts"], key=lambda h: (grank[h["group"]], not h.get("is_dc", False),
                                                 -(h["aes"] if h["aes"] is not None else -1), h["name"]))

    counts = [(g, sum(1 for h in hosts if h["group"] == g["id"])) for g in groups]
    header = [
        f"# Change tickets: Fix FIRST hosts, {data['run_date']}",
        "",
        f"Generated from the /fix-today briefing of {data['run_date']}. One ticket per host, one maintenance window each.",
        f"{len(hosts)} tickets: " + ", ".join(f"{c} {g['label']}" for g, c in counts if c) + ".",
        "",
    ]
    if data.get("not_covered"):
        header += ["**Not covered:** " + data["not_covered"][0]] + data["not_covered"][1:] + [""]
    header += [
        'Text marked "Own note" is advice added beyond Tenable\'s solution text. "Role inferred from',
        'hostname" means Tenable did not record the role.',
        "",
        "",
    ]
    body = "\n\n".join(f"```text\n{ticket(h, data)}\n```" for h in hosts)
    Path(dst).write_text("\n".join(header) + body + "\n")

    print("order\tgroup\thost")
    for i, h in enumerate(hosts, 1):
        print(f"{i}\t{h['group']}\t{h['name']}")
    # Inline samples: per group (rank order), the host with the most plugins; ties -> ticket order
    inline = []
    for g in groups:
        members = [h for h in hosts if h["group"] == g["id"]]
        if members:
            inline.append(max(members, key=lambda h: len(h["plugins"]))["name"])
    print("inline:\t" + ", ".join(inline))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: tickets.py <tickets.json> <out.md>")
    main(sys.argv[1], sys.argv[2])
