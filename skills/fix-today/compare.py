#!/usr/bin/env python3
"""Compare two /fix-today runs.

Usage:  python3 compare.py <history-dir> <run-date>

<history-dir> holds one folder per run (YYYY-MM-DD/) containing
fixtoday-<date>.json and, optionally, fixtoday-tickets-<date>.json.
Compares <run-date> against the most recent earlier run and prints a
Markdown section. Exit 3 (and prints nothing) when there is no earlier run.

Rows are matched on their plugin_ids; rows without plugin_ids fall back
to the `fix` text. Ticket hosts are matched on (host, plugin) pairs.
Same input -> same output.
"""
import json
import sys
from datetime import date
from pathlib import Path


def load(d, name):
    p = d / name
    return json.loads(p.read_text()) if p.exists() else None


def row_key(r):
    ids = r.get("plugin_ids")
    return ("plugins", tuple(sorted(ids))) if ids else ("fix", r["fix"])


def by_key(rows):
    """Index rows by key; rows sharing a key (same plugins, different host groups) are merged."""
    out = {}
    for r in rows:
        k = row_key(r)
        if k in out:
            m = dict(out[k])
            m["assets"] = f"{m['assets']}; {r['assets']}"
            m["affected_hosts"] += r["affected_hosts"]
            out[k] = m
        else:
            out[k] = r
    return out


def label(r):
    return f"{r['vulnerability']} ({r['fix']}) on {r['assets']}"


def pairs(tickets):
    if not tickets:
        return set()
    return {(h["name"], p) for h in tickets["hosts"] for p in h["plugins"]}


def first_seen(history, key, upto):
    """Earliest run date in history (<= upto) that contains this row key."""
    for d in sorted(x for x in history.iterdir() if x.is_dir() and x.name <= upto):
        data = load(d, f"fixtoday-{d.name}.json")
        if data and any(row_key(r) == key for r in data["rows"]):
            return d.name
    return upto


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    history, run = Path(sys.argv[1]).expanduser(), sys.argv[2]
    cur_dir = history / run
    cur = load(cur_dir, f"fixtoday-{run}.json")
    if cur is None:
        raise SystemExit(f"no fixtoday-{run}.json in {cur_dir}")
    earlier = sorted(x.name for x in history.iterdir() if x.is_dir() and x.name < run)
    if not earlier:
        sys.exit(3)
    prev_run = earlier[-1]
    prev = load(history / prev_run, f"fixtoday-{prev_run}.json")

    cur_rows = by_key(cur["rows"])
    prev_rows = by_key(prev["rows"])
    new = [cur_rows[k] for k in cur_rows if k not in prev_rows]
    gone = [prev_rows[k] for k in prev_rows if k not in cur_rows]
    still = [(k, cur_rows[k], prev_rows[k]) for k in cur_rows if k in prev_rows]

    cur_pairs = pairs(load(cur_dir, f"fixtoday-tickets-{run}.json"))
    prev_pairs = pairs(load(history / prev_run, f"fixtoday-tickets-{prev_run}.json"))

    out = [f"## Since last run ({prev_run})", ""]
    out.append(f"{len(new)} new, {len(gone)} no longer in the list, {len(still)} still open.")
    out.append("")
    if new:
        out.append("**New:**")
        out += [f"- {label(r)}" for r in new]
        out.append("")
    if gone:
        out.append("**No longer in the list (fixed, or dropped out of scope; confirm with a rescan):**")
        out += [f"- {label(r)}" for r in gone]
        out.append("")
    if still:
        out.append("**Still open:**")
        today = date.fromisoformat(run)
        for k, r, p in still:
            since = first_seen(history, k, run)
            days = (today - date.fromisoformat(since)).days
            delta = r["affected_hosts"] - p["affected_hosts"]
            hosts = f"{r['affected_hosts']} hosts ({delta:+d})" if delta else f"{r['affected_hosts']} hosts (no change)"
            out.append(f"- {label(r)}: {hosts}, open since {since} ({days} days)")
        out.append("")
    if prev_pairs:
        closed = sorted(prev_pairs - cur_pairs)
        out.append(f"**Ticketed host/plugin pairs from {prev_run}:** {len(closed)} of {len(prev_pairs)} "
                   "no longer ticketed this run.")
        out.append("")
    print("\n".join(out).rstrip())


if __name__ == "__main__":
    main()
