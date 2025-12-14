import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

from depguard_common import (  # noqa: E402
    cvss3_score,
    discover_manifests,
    fixed_versions,
    label_from_score,
    parse_package_json,
    parse_package_lock,
    parse_requirements,
    repo_from_vuln,
    severity_from_vuln,
)


def test_cvss3_known_scores():
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert cvss3_score("garbage") is None


def test_label_boundaries():
    assert [label_from_score(s) for s in (None, 0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10)] == [
        "UNKNOWN", "UNKNOWN", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL",
    ]


def test_severity_prefers_database_label_then_cvss():
    assert severity_from_vuln({"database_specific": {"severity": "MODERATE"}}) == ("MEDIUM", None)
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert severity_from_vuln({"severity": [{"type": "CVSS_V3", "score": vec}]}) == ("CRITICAL", 9.8)
    assert severity_from_vuln({}) == ("UNKNOWN", None)


def test_requirements_parsing(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text(
        "# comment\n"
        "Django==3.2.0\n"
        "requests>=2.0  # loose\n"
        "Flask_Cors[extra]==4.0.0 ; python_version > '3'\n"
        "-r other.txt\n"
        "numpy==1.*\n"
    )
    deps = {d["name"]: d["version"] for d in parse_requirements(str(f))}
    assert deps == {"django": "3.2.0", "requests": None, "flask-cors": "4.0.0", "numpy": None}


def test_package_lock_v3_and_json(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/a/node_modules/@scope/b": {"version": "1.0.0", "dev": True},
    }}))
    assert [(d["name"], d["version"]) for d in parse_package_lock(str(lock))] == [
        ("@scope/b", "1.0.0"), ("lodash", "4.17.20"),
    ]

    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"x": "^1.2.3", "y": "latest"}}))
    deps = {d["name"]: d["version"] for d in parse_package_json(str(pkg))}
    assert deps == {"x": "1.2.3", "y": None}


def test_discover_prefers_lockfile(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "requirements-dev.txt").write_text("")
    names = sorted(os.path.basename(p) for p in discover_manifests(str(tmp_path)))
    assert names == ["package-lock.json", "requirements-dev.txt"]


def test_fixed_versions_and_repo():
    vuln = {"affected": [
        {"package": {"name": "Django", "ecosystem": "PyPI"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.2.1"}]},
                    {"type": "GIT", "repo": "https://github.com/django/django.git", "events": []}]},
        {"package": {"name": "other", "ecosystem": "PyPI"},
         "ranges": [{"events": [{"fixed": "9.9"}]}]},
    ]}
    assert fixed_versions(vuln, "django", "PyPI") == ["3.2.1"]
    assert repo_from_vuln(vuln) == "django/django"
