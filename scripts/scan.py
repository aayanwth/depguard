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


