"""Shared helpers for the DepGuard scanner and ingestion scripts."""
import json
import math
import os
import re
from concurrent.futures import ThreadPoolExecutor

import requests
import yaml
from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, ".env"))

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_BATCH_SIZE = 500

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ---------------------------------------------------------------------------
# Environment / destination
# ---------------------------------------------------------------------------
def configure_snowflake_env():
    """Map our SNOWFLAKE_* vars to the names dlt expects."""
    if os.getenv("DESTINATION_NAME") != "snowflake":
        return
    mapping = {
        "DATABASE": "SNOWFLAKE_DATABASE",
        "HOST": "SNOWFLAKE_ACCOUNT",
        "USERNAME": "SNOWFLAKE_USER",
        "PASSWORD": "SNOWFLAKE_PASSWORD",
        "WAREHOUSE": "SNOWFLAKE_WAREHOUSE",
        "ROLE": "SNOWFLAKE_ROLE",
    }
    for dlt_key, env_key in mapping.items():
        os.environ[f"DESTINATION__SNOWFLAKE__CREDENTIALS__{dlt_key}"] = os.getenv(env_key, "")


def get_destination():
    """Return the dlt destination. DuckDB runs write to <project>/duckdb.duckdb,
    the same file dbt and Soda read, so local mode works end to end."""
    import dlt

    if os.getenv("DESTINATION_NAME", "duckdb") == "snowflake":
        return "snowflake"
    return dlt.destinations.duckdb(os.path.join(ROOT, "duckdb.duckdb"))


# ---------------------------------------------------------------------------
# Watchlist (what the pipeline tracks)
# ---------------------------------------------------------------------------
def normalize_name(name, ecosystem):
    name = name.strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def load_watchlist(path=None):
    """Return (packages, repos). `packages` is a de-duplicated list of
    {"name", "ecosystem"} including every dependency found in the manifests
    listed in the watchlist. `repos` maps explicit repo entries to packages."""
    path = path or os.path.join(ROOT, "config", "watchlist.yml")
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    packages, repos, seen = [], [], set()

    def add(name, ecosystem):
        key = (normalize_name(name, ecosystem), ecosystem)
        if key not in seen:
            seen.add(key)
            packages.append({"name": key[0], "ecosystem": ecosystem})

    for entry in cfg.get("packages") or []:
        add(entry["name"], entry["ecosystem"])
        if entry.get("repo"):
            owner, repo_name = entry["repo"].split("/", 1)
            repos.append({
                "owner": owner,
                "name": repo_name,
                "package_name": normalize_name(entry["name"], entry["ecosystem"]),
                "ecosystem": entry["ecosystem"],
            })

    for manifest in cfg.get("manifests") or []:
        manifest_path = manifest if os.path.isabs(manifest) else os.path.join(ROOT, manifest)
        for dep in parse_manifest(manifest_path):
            add(dep["name"], dep["ecosystem"])

    return packages, repos


# ---------------------------------------------------------------------------
# Manifest parsing
# ---------------------------------------------------------------------------
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_VERSION_RE = re.compile(r"^\d+(\.\d+)*([.-]?(a|b|rc|alpha|beta|post|dev)?\d*)*$")


def parse_requirements(path):
    """Parse a pip requirements file. Only `==` pins give an exact version;
    anything else is returned with version=None (unpinned)."""
    deps = []
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.split(" #")[0].strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            line = line.split(";")[0].strip()  # drop environment markers
            m = _REQ_RE.match(line)
            if not m:
                continue
            name, _, spec = m.groups()
            version = None
            pin = re.match(r"^===?\s*([^\s,]+)$", spec.strip())
            if pin and "*" not in pin.group(1):
                version = pin.group(1)
            deps.append({
                "name": normalize_name(name, "PyPI"),
                "ecosystem": "PyPI",
                "version": version,
                "source": path,
            })
    return deps


def parse_package_lock(path):
    """Parse package-lock.json (v1, v2 and v3). Includes transitive deps."""
    with open(path, encoding="utf-8") as f:
        lock = json.load(f)
    deps = {}
    if "packages" in lock:  # lockfile v2/v3
        for key, info in lock["packages"].items():
            if not key or "node_modules/" not in key:
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[1]
            if info.get("version") and not info.get("link"):
                deps[(name, info["version"])] = info.get("dev", False)
    else:  # lockfile v1

        def walk(tree):
            for name, info in (tree or {}).items():
                if info.get("version"):
                    deps[(name, info["version"])] = info.get("dev", False)
                walk(info.get("dependencies"))

        walk(lock.get("dependencies"))
    return [
        {"name": n, "ecosystem": "npm", "version": v, "source": path}
        for (n, v) in sorted(deps)
    ]


def parse_package_json(path):
    """Fallback when there is no lockfile. Ranges like ^1.2.3 are approximated
    by their base version, so results are flagged as approximate."""
    with open(path, encoding="utf-8") as f:
        pkg = json.load(f)
    deps = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (pkg.get(section) or {}).items():
            base = re.sub(r"^[\^~=v<>\s]+", "", str(spec)).split(" ")[0]
            version = base if re.match(r"^\d+\.\d+\.\d+", base) else None
            deps.append({
                "name": name,
                "ecosystem": "npm",
                "version": version,
                "approximate": True,
                "source": path,
            })
    return deps


def parse_manifest(path):
    base = os.path.basename(path).lower()
    if base == "package-lock.json":
        return parse_package_lock(path)
    if base == "package.json":
        return parse_package_json(path)
    if base.endswith(".txt"):
        return parse_requirements(path)
    raise ValueError(f"Unsupported manifest: {path}")


def discover_manifests(target):
    """Return manifest files for a file or directory. In a directory,
    package-lock.json wins over package.json from the same folder."""
    if os.path.isfile(target):
        return [target]
    found = []
    skip = {"node_modules", ".git", "venv", ".venv", "__pycache__", "dbt_packages"}
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in sorted(filenames):
            low = fn.lower()
            if re.match(r"^requirements.*\.txt$", low) or low == "package-lock.json":
                found.append(os.path.join(dirpath, fn))
            elif low == "package.json" and "package-lock.json" not in [f.lower() for f in filenames]:
                found.append(os.path.join(dirpath, fn))
    return found


