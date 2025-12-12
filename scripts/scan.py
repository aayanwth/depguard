"""DepGuard scanner: check a project's dependencies for known vulnerabilities.

Usage:
    python scripts/scan.py path/to/project              # scans requirements*.txt, package-lock.json, package.json
    python scripts/scan.py requirements.txt --fail-on critical
    python scripts/scan.py . --json report.json

Exit code is 1 when a finding at or above --fail-on is present (CI friendly),
0 when clean, 2 on usage errors.
"""
import argparse
import json
import os
import sys

from depguard_common import (
    SEVERITY_ORDER,
    discover_manifests,
    fetch_vulns,
    fixed_versions,
    osv_query_batch,
    parse_manifest,
    severity_from_vuln,
)


def collect_dependencies(targets):
    deps, seen = [], set()
    for target in targets:
        if not os.path.exists(target):
            raise FileNotFoundError(f"Path not found: {target}")
        manifests = discover_manifests(target)
        if not manifests:
            print(f"warning: no supported manifest found in {target}", file=sys.stderr)
        for manifest in manifests:
            for dep in parse_manifest(manifest):
                key = (dep["ecosystem"], dep["name"], dep["version"])
                if key not in seen:
                    seen.add(key)
                    deps.append(dep)
    return deps


def scan(deps):
    """Return (findings, unpinned). Pinned deps are matched against their exact
    version; unpinned ones can't be judged and are reported separately."""
    pinned = [d for d in deps if d["version"]]
    unpinned = [d for d in deps if not d["version"]]

    queries = [
        {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]}
        for d in pinned
    ]
    stubs = osv_query_batch(queries) if queries else []
    full = fetch_vulns([v["id"] for per_dep in stubs for v in per_dep])

    findings = []
    for dep, dep_stubs in zip(pinned, stubs):
        for stub in dep_stubs:
            vuln = full[stub["id"]]
            label, score = severity_from_vuln(vuln)
            cves = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
            findings.append({
                "package": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "id": vuln["id"],
                "cves": cves,
                "severity": label,
                "cvss_score": score,
                "fixed_in": fixed_versions(vuln, dep["name"], dep["ecosystem"]),
                "summary": vuln.get("summary") or (vuln.get("details", "").split("\n")[0][:120]),
                "approximate": bool(dep.get("approximate")),
                "source": dep["source"],
            })
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["package"], f["id"]))
    return findings, unpinned


def print_report(deps, findings, unpinned):
    print(f"Scanned {len(deps) - len(unpinned)} pinned dependencies "
          f"({len(unpinned)} unpinned and skipped).\n")
    if not findings:
        print("No known vulnerabilities found.")
    for f in findings:
        ids = f["id"] + (f" ({', '.join(f['cves'])})" if f["cves"] else "")
        fix = f"upgrade to {' or '.join(f['fixed_in'])}" if f["fixed_in"] else "no fix listed"
        approx = "  [version approximated from package.json range]" if f["approximate"] else ""
        print(f"[{f['severity']:<8}] {f['package']}=={f['version']} ({f['ecosystem']})  {ids}")
        print(f"           {f['summary']}")
        print(f"           fix: {fix}{approx}")
    if unpinned:
        print("\nUnpinned dependencies (pin an exact version to get a verdict):")
        for d in unpinned:
            print(f"  - {d['name']} ({d['ecosystem']}) in {d['source']}")
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    summary = ", ".join(f"{n} {s.lower()}" for s, n in sorted(
        counts.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]]) if n)
    print(f"\nSummary: {len(findings)} findings" + (f" ({summary})" if summary else ""))


