#!/usr/bin/env python3
"""Deterministic scorer + renderer for /fix-today.

Usage:  python3 render.py <data.json> <out.html>

Validates briefing data against schema.json (exit 2 with every problem
listed if it fails), computes the Phase 5 priority score for
every row, sorts, colour-codes, and fills template.html. Prints the final
ranking to stdout so the text summary can follow the same order.
Same input -> byte-identical output.
"""
import html
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

TIER_FACTOR = {1: 1.0, 2: 0.7, 3: 0.4, 0: 0.1}
TIER_BADGE = {
    1: ("🔴 Tier 1", "t1"),
    2: ("🟠 Tier 2", "t2"),
    3: ("🟡 Tier 3", "t3"),
    0: ("⚪ Unconfirmed", "t0"),
}
AP_FACTOR = {"critical": 1.0, "high": 0.7}  # anything else -> 0.3
# ATT&CK enterprise tactics in kill-chain order (tie-break order for the chart)
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]
# Sequential red ramp, dark -> light; highest distinct count gets the darkest stop
TACTIC_RAMP = ["#A32D2D", "#E24B4A", "#F09595", "#F7C1C1"]


# --- Data validation -------------------------------------------------------
# Minimal draft-07 subset (no third-party deps). Covers every keyword schema.json
# uses; an unknown keyword is a hard error so the schema can't outgrow this check.
_KNOWN = {"$schema", "title", "description", "type", "required", "properties",
          "additionalProperties", "items", "enum", "minItems", "maxItems", "uniqueItems"}
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _check(value, schema, path, errs):
    unknown = set(schema) - _KNOWN
    if unknown:
        raise SystemExit(f"schema.json uses unsupported keyword(s) {sorted(unknown)} at {path} — extend render.py's validator")
    types = schema.get("type")
    if types is not None:
        types = types if isinstance(types, list) else [types]
        if not any(_TYPES[t](value) for t in types):
            errs.append(f"{path}: expected {' or '.join(types)}, got {type(value).__name__} {value!r:.60}")
            return
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: {value!r} not one of {schema['enum']}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in value:
                errs.append(f"{path}: missing required field '{k}'")
        extra = schema.get("additionalProperties")
        if extra is False:
            for k in value:
                if k not in props:
                    errs.append(f"{path}: unexpected field '{k}' (typo? allowed: {', '.join(props)})")
        elif isinstance(extra, dict):
            for k in value:
                if k not in props:
                    _check(value[k], extra, f"{path}.{k}", errs)
        for k, sub in props.items():
            if k in value:
                _check(value[k], sub, f"{path}.{k}", errs)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errs.append(f"{path}: needs at least {schema['minItems']} item(s), has {len(value)}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errs.append(f"{path}: allows at most {schema['maxItems']} item(s), has {len(value)}")
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errs.append(f"{path}: items must be unique")
        if "items" in schema:
            for i, v in enumerate(value):
                _check(v, schema["items"], f"{path}[{i}]", errs)


def validate(data):
    schema = json.loads((HERE / "schema.json").read_text())
    errs = []
    _check(data, schema, "$", errs)
    if not errs:
        # Cross-field rules the schema can't express
        n_ext = len(data.get("external", []))
        if data["summary"]["externally_corroborated"] != n_ext:
            errs.append(f"$.summary.externally_corroborated is {data['summary']['externally_corroborated']} but external has {n_ext} entr{'y' if n_ext == 1 else 'ies'}")
        if not data["apa_available"]:
            bad = [r["assets"] for r in data["rows"] if r["attack_path"] in ("critical", "high")]
            if bad:
                errs.append(f"apa_available is false but rows claim an attack path: {bad}")
        for i, r in enumerate(data["rows"]):
            if r["affected_hosts"] > data["total_hosts_checked"]:
                errs.append(f"$.rows[{i}].affected_hosts ({r['affected_hosts']}) exceeds total_hosts_checked ({data['total_hosts_checked']})")
            if r.get("aes") is not None and not 0 <= r["aes"] <= 1000:
                errs.append(f"$.rows[{i}].aes {r['aes']} outside 0–1000")
            if not 0 <= r["vpr"] <= 10:
                errs.append(f"$.rows[{i}].vpr {r['vpr']} outside 0–10")
            if r.get("acr") is not None and not 0 <= r["acr"] <= 10:
                errs.append(f"$.rows[{i}].acr {r['acr']} outside 0–10")
    if errs:
        sys.stderr.write("fix-today data failed validation (fix the data, not the template):\n")
        sys.stderr.write("".join(f"  - {e}\n" for e in errs))
        raise SystemExit(2)


def esc(v):
    return html.escape("" if v is None else str(v))


def score(row, total_hosts):
    if row.get("aes") is None:
        return None
    blast = min(row.get("affected_hosts", 1) / max(total_hosts, 1), 1.0)
    return (
        row["aes"] / 1000 * 0.25
        + TIER_FACTOR[row["tier"]] * 0.25
        + row["vpr"] / 10 * 0.15
        + (row.get("acr") or 0) / 10 * 0.10
        + AP_FACTOR.get(row.get("attack_path"), 0.3) * 0.15
        + blast * 0.10
    )


def row_class(p):
    if p is None:
        return "y"
    if p >= 0.8:
        return "r"
    if p >= 0.6:
        return "o"
    if p >= 0.4:
        return "y"
    return ""


def main(src, dst):
    data = json.loads(Path(src).read_text())
    validate(data)
    total = data["total_hosts_checked"]

    rows = data["rows"]
    for r in rows:
        r["_p"] = score(r, total)
    # Scored rows first (desc), unscored last; ties broken by tier then VPR then name.
    rows.sort(key=lambda r: (r["_p"] is None, -(r["_p"] or 0), -r["tier"], -r["vpr"], r["assets"]))

    s = data["summary"]
    cards = [
        ("Assets in inventory", f'{s["inventory_assets"]:,}', s.get("inventory_note", "")),
        ("Critical plugins with exploits", f'{s["critical_exploitable_plugins"]:,}', "Workbenches, exploitable=true"),
        ("KEV-confirmed plugins here", str(s["kev_confirmed_plugins"]), "Tier 1 (CISA KEV)"),
        ("Externally corroborated", str(s["externally_corroborated"]), "Confirmed outside Tenable"),
    ]
    cards_html = "\n".join(
        f'<div class="m"><div class="l">{esc(a)}</div><div class="v">{esc(b)}</div><div class="s">{esc(c)}</div></div>'
        for a, b, c in cards
    )

    tr = []
    for r in rows:
        label, tcls = TIER_BADGE[r["tier"]]
        tag = f'<span class="tag">{esc(r["ext_tag"])}</span>' if r.get("ext_tag") else ""
        p = "—" if r["_p"] is None else f'{r["_p"]:.2f}'
        aes = "n/a" if r.get("aes") is None else r["aes"]
        tr.append(
            f'<tr class="{row_class(r["_p"])}"><td>{p}</td><td>{esc(r["assets"])}</td><td>{esc(aes)}</td>'
            f'<td>{esc(r["vulnerability"])}</td><td><span class="b {tcls}">{label}</span>{tag}</td>'
            f'<td>{r["vpr"]:.1f}</td><td class="mono">{esc(r["cves"])}</td><td>{esc(r["tactic"])}</td>'
            f'<td class="mono">{esc(r["fix"])}</td><td>{esc(r["impact"])}</td></tr>'
        )

    notes = list(data.get("notes", []))
    if not data.get("apa_available", False):
        notes.insert(0, "Attack-path factor fixed at 0.3 for every row: APA data unavailable this run.")
    notes.append(f"Blast radius uses {total} hosts examined.")
    table_note = " ".join(notes)

    ext = data.get("external", [])
    if ext:
        ext_html = '<h3>External corroboration</h3>\n<ul class="ext">' + "".join(
            f'<li><b>{esc(e["subject"])}</b>: {esc(e["text"])}</li>' for e in ext
        ) + "</ul>"
    else:
        ext_html = ""

    counts = {}
    for r in rows:
        for tac in dict.fromkeys(r["tactics"]):
            if tac not in TACTICS:
                sys.exit(f"unknown tactic {tac!r} in row {r['assets']!r}")
            counts[tac] = counts.get(tac, 0) + 1
    tac_sorted = sorted(counts, key=lambda k: (-counts[k], TACTICS.index(k)))
    tac_labels = [k[0] + k[1:].lower() for k in tac_sorted]  # "Initial access" style
    tac_values = [counts[k] for k in tac_sorted]
    distinct = sorted(set(tac_values), reverse=True)
    tac_colors = [TACTIC_RAMP[min(distinct.index(v), len(TACTIC_RAMP) - 1)] for v in tac_values]

    batches = "\n".join(
        f'<div class="bc"><div class="t">{esc(b["title"])}</div><div class="d">{esc(b["detail"])}</div></div>'
        for b in data["batches"]
    )

    closed = [r.get("kev_closed", 0) for r in rows]
    cum, run = [], 0
    for c in closed:
        run += c
        cum.append(run)
    kev_total = run or 1

    tpl = (HERE / "template.html").read_text()
    out = (
        tpl.replace("{{RUN_DATE}}", esc(data["run_date"]))
        .replace("{{ROW_COUNT}}", str(len(rows)))
        .replace("{{CARDS}}", cards_html)
        .replace("{{ROWS}}", "\n".join(tr))
        .replace("{{TABLE_NOTE}}", esc(table_note))
        .replace("{{EXTERNAL}}", ext_html)
        .replace("{{TAC_LABELS}}", json.dumps(tac_labels))
        .replace("{{TAC_VALUES}}", json.dumps(tac_values))
        .replace("{{TAC_COLORS}}", json.dumps(tac_colors))
        .replace("{{TAC_HEIGHT}}", str(len(tac_labels) * 44 + 50))
        .replace("{{BATCHES}}", batches)
        .replace("{{CUM}}", json.dumps(cum))
        .replace("{{KEV_TOTAL}}", str(kev_total))
    )
    Path(dst).write_text(out)

    print("rank\tscore\tbucket\tassets\tvulnerability")
    for i, r in enumerate(rows, 1):
        bucket = "FIRST" if i <= 3 else "NEXT" if i <= 8 else "SOON"
        p = "-" if r["_p"] is None else f'{r["_p"]:.2f}'
        print(f'{i}\t{p}\t{bucket}\t{r["assets"]}\t{r["vulnerability"]}')


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: render.py <data.json> <out.html>")
    main(sys.argv[1], sys.argv[2])
