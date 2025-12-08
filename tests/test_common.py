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


