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


