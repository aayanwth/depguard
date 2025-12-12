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


