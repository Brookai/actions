#!/usr/bin/env python3
"""
Render the scanners' own report files into a GitHub Actions job summary.

The PASS/WARN/FAIL table tells you a scanner found something. It does not tell
you what, and "go read 600 lines of step log" was the original complaint that
put the summary here in the first place. This itemises the findings so the run
page answers "what is wrong" on its own.

Deliberately prints rule + severity + file:line and NOTHING ELSE. No code
snippets, no matched text: gitleaks and semgrep both carry the matching line in
their SARIF, and a job summary is a durable, widely-readable artifact. Locations
are enough to act on; values never belong here.

Reads $REPORTS. Writes the markdown to $REPORTS/summary.md and prints the total
finding count to stdout, so the caller can surface it as an action output.
(A step cannot read another step's $GITHUB_STEP_SUMMARY - Actions gives each
step its own file - so the count has to travel as an output, not a summary.)
"""
import json, os, re, sys, collections

REPORTS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("REPORTS", "")
MAX_ROWS = 25          # per scanner, before rolling up
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "ERROR": 1, "MEDIUM": 2, "WARNING": 2, "LOW": 3, "NOTE": 3, "INFO": 4, "UNKNOWN": 5}


def rel(p):
    if not p:
        return "?"
    p = str(p)
    for pre in ("/src/", "file:///src/", "src/"):
        if p.startswith(pre):
            p = p[len(pre):]
    return p.lstrip("/")


def read_json(name):
    path = os.path.join(REPORTS, name)
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def short_rule(rid):
    """semgrep ids are long and end in a duplicated leaf: a.b.c.name.name -> name"""
    if not rid:
        return "?"
    if "." in rid and len(rid) > 40:
        parts = rid.split(".")
        if len(parts) >= 2 and parts[-1] == parts[-2]:
            return parts[-1]
        return parts[-1]
    return rid


def from_sarif(name, sev_from_props=None):
    """-> list of (severity, rule, location, title)"""
    d = read_json(name)
    if not d:
        return []
    out = []
    for run in d.get("runs", []):
        # rule metadata, because tools disagree about where severity lives:
        # checkov puts level on the result, semgrep only on the rule's
        # defaultConfiguration, and some emit a CVSS-ish security-severity.
        rules = {}
        for r in (run.get("tool", {}).get("driver", {}).get("rules") or []):
            rules[r.get("id")] = r
        for res in run.get("results", []):
            # A result the tool itself suppressed is not a finding. SARIF marks
            # these with a suppressions[] entry - kind "inSource" for an
            # in-code annotation (# nosemgrep, checkov:skip=...). The tool has
            # already honoured them: its exit code and its own tally exclude
            # them, so counting them here contradicts the status row directly.
            # Observed on care-nexus run 33128486556, where checkov reported
            # "Failed checks: 0, Skipped checks: 2" - it passed - while this
            # summary rendered "checkov - 2 findings".
            #
            # Someone who writes a justified suppression should see the backlog
            # go down. Otherwise the number never moves and the summary stops
            # being worth reading, which defeats the point of having it.
            if res.get("suppressions"):
                continue
            rid = res.get("ruleId") or "?"
            rule = rules.get(rid) or {}
            rprops = rule.get("properties") or {}
            props = res.get("properties") or {}
            sev = ((props.get("severity") or "").upper()
                   or (res.get("level") or "").upper()
                   or ((rule.get("defaultConfiguration") or {}).get("level") or "").upper()
                   or "UNKNOWN")
            cvss = rprops.get("security-severity")
            if cvss is not None:
                try:
                    n = float(cvss)
                    sev = "CRITICAL" if n >= 9 else "HIGH" if n >= 7 else "MEDIUM" if n >= 4 else "LOW"
                except (TypeError, ValueError):
                    pass
            rid = short_rule(rid)
            loc = "?"
            locs = res.get("locations") or []
            if locs:
                pl = (locs[0].get("physicalLocation") or {})
                uri = ((pl.get("artifactLocation") or {}).get("uri"))
                line = ((pl.get("region") or {}).get("startLine"))
                loc = f"{rel(uri)}:{line}" if line else rel(uri)
            title = ((res.get("message") or {}).get("text") or "").strip().split("\n")[0]
            out.append((sev, rid, loc, title[:110]))
    return out


def from_trivy(name):
    d = read_json(name)
    if not d:
        return []
    out = []
    for r in (d.get("Results") or []):
        target = rel(r.get("Target"))
        for m in (r.get("Misconfigurations") or []):
            line = ((m.get("CauseMetadata") or {}).get("StartLine"))
            loc = f"{target}:{line}" if line else target
            out.append(((m.get("Severity") or "UNKNOWN").upper(), m.get("ID") or "?", loc,
                        (m.get("Title") or "")[:110]))
        for v in (r.get("Vulnerabilities") or []):
            pkg = f"{v.get('PkgName')} {v.get('InstalledVersion')}"
            fix = v.get("FixedVersion")
            title = (v.get("Title") or "")[:80]
            if fix:
                title = f"{title} (fixed in {fix})"
            out.append(((v.get("Severity") or "UNKNOWN").upper(), v.get("VulnerabilityID") or "?",
                        f"{target} → {pkg}", title[:110]))
        for s in (r.get("Secrets") or []):
            out.append(((s.get("Severity") or "UNKNOWN").upper(), s.get("RuleID") or "?",
                        f"{target}:{s.get('StartLine')}", (s.get("Title") or "")[:110]))
    return out


def from_hadolint(name):
    path = os.path.join(REPORTS, name)
    out = []
    try:
        with open(path, errors="replace") as fh:
            for line in fh:
                m = re.match(r'^(?:/src/)?(\S+?):(\d+)\s+(DL\d+|SC\d+)\s+(\w+):\s*(.*)$', line.strip())
                if m:
                    out.append((m.group(4).upper(), m.group(3), f"{rel(m.group(1))}:{m.group(2)}",
                                m.group(5)[:110]))
    except Exception:
        pass
    return out


def table(findings):
    """Itemise, or roll up by rule when there are too many to read."""
    findings = sorted(findings, key=lambda f: (SEV_ORDER.get(f[0], 9), f[1], f[2]))
    lines = []
    if len(findings) <= MAX_ROWS:
        lines.append("| severity | rule | location | what |")
        lines.append("|---|---|---|---|")
        for sev, rule, loc, title in findings:
            lines.append(f"| {sev} | `{rule}` | `{loc}` | {title} |")
    else:
        by = collections.OrderedDict()
        for sev, rule, loc, title in findings:
            k = (sev, rule, title)
            by.setdefault(k, []).append(loc)
        lines.append(f"Rolled up by rule — {len(findings)} findings across {len(by)} rules.")
        lines.append("")
        lines.append("| severity | rule | count | example location | what |")
        lines.append("|---|---|---|---|---|")
        for (sev, rule, title), locs in list(by.items())[:MAX_ROWS]:
            lines.append(f"| {sev} | `{rule}` | {len(locs)} | `{locs[0]}` | {title} |")
        if len(by) > MAX_ROWS:
            lines.append(f"| … | _{len(by) - MAX_ROWS} more rules_ | | | see the `scan-reports` artifact |")
    return lines


SOURCES = [
    ("checkov",           lambda: from_sarif("checkov.sarif")),
    ("trivy-config",      lambda: from_trivy("trivy-config.json")),
    ("trivy-sca",         lambda: from_trivy("trivy-sca.json")),
    ("trivy-image",       lambda: from_trivy("trivy-image.json")),
    ("gitleaks",          lambda: from_sarif("gitleaks.sarif")),
    ("semgrep",           lambda: from_sarif("semgrep.sarif")),
    ("hadolint",          lambda: from_hadolint("hadolint.txt")),
]

out = []
total = 0
for name, fn in SOURCES:
    try:
        f = fn()
    except Exception as e:                       # never let the summary break the scan
        out.append(f"> could not summarise `{name}`: {type(e).__name__}")
        continue
    if not f:
        continue
    total += len(f)
    sev_counts = collections.Counter(s for s, _, _, _ in f)
    head = " · ".join(f"{n} {s}" for s, n in sorted(sev_counts.items(), key=lambda x: SEV_ORDER.get(x[0], 9)))
    out.append(f"<details><summary><b>{name}</b> — {len(f)} findings ({head})</summary>")
    out.append("")
    out.extend(table(f))
    out.append("")
    out.append("</details>")
    out.append("")

md = []
if total:
    md.append("")
    md.append(f"<h4>Findings — {total} total</h4>")
    md.append("")
    md.append("Rule and location only, by design; no matched values are printed here. "
              "Full reports are in the `scan-reports` artifact on this run.")
    md.append("")
    md.append("\n".join(out))

if REPORTS:
    try:
        with open(os.path.join(REPORTS, "summary.md"), "w") as fh:
            fh.write("\n".join(md))
    except Exception:
        pass

print(total)
