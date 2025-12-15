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


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
def _roundup(x):
    return math.ceil(round(x * 10, 5)) / 10


def cvss3_score(vector):
    """CVSS v3.x base score from a vector string, or None if unparseable."""
    try:
        parts = dict(p.split(":") for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        pr = ({"N": 0.85, "L": 0.68, "H": 0.5} if scope_changed
              else {"N": 0.85, "L": 0.62, "H": 0.27})[parts["PR"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[parts["C"]]) * (1 - cia[parts["I"]]) * (1 - cia[parts["A"]])
    except (KeyError, ValueError, AttributeError):
        return None
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = impact + exploitability
    return _roundup(min((1.08 if scope_changed else 1.0) * total, 10))


def label_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNKNOWN"


def severity_from_vuln(vuln):
    """Return (label, cvss_score_or_None) for a full OSV vulnerability record."""
    score = None
    for sev in vuln.get("severity") or []:
        if sev.get("type") == "CVSS_V3":
            score = cvss3_score(sev.get("score", ""))
            if score is not None:
                break

    label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    label = {"MODERATE": "MEDIUM"}.get(label, label)
    if label in SEVERITY_ORDER and label != "UNKNOWN":
        return label, score
    return label_from_score(score), score


def repo_from_vuln(vuln):
    """GitHub 'owner/name' from the vulnerability's git ranges, if present."""
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            m = re.match(r"^https?://github\.com/([^/]+/[^/.]+)", rng.get("repo") or "")
            if m:
                return m.group(1)
    return ""


def fixed_versions(vuln, name, ecosystem):
    """Versions in which the vuln is fixed, for the given package."""
    fixes = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem:
            continue
        if normalize_name(pkg.get("name", ""), ecosystem) != normalize_name(name, ecosystem):
            continue
        for rng in aff.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed and not re.fullmatch(r"[0-9a-f]{40}", fixed) and fixed not in fixes:  # skip git SHAs
                    fixes.append(fixed)
    return fixes


# ---------------------------------------------------------------------------
# OSV API
# ---------------------------------------------------------------------------
def _session():
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        max_retries=requests.adapters.Retry(total=4, backoff_factor=1.0,
                                            status_forcelist=(429, 500, 502, 503, 504))
    )
    s.mount("https://", adapter)
    return s


