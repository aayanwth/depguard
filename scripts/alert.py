"""Alert on high-risk vulnerabilities in the gold layer.

Prints incidents whose Dependency Risk Index is at or above ALERT_MIN_DRI
(default 8.0) and, if SLACK_WEBHOOK_URL is set, posts the same summary to Slack.
Exit code is 0 either way; alerting must not fail the pipeline.
"""
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from depguard_common import ROOT  # noqa: E402

QUERY = """
SELECT p.package_name, p.ecosystem, f.cve_id, f.severity_label, f.dependency_risk_index
FROM gold.fact_vulnerability_incident f
JOIN gold.dim_package p ON f.package_sk = p.package_sk
WHERE f.dependency_risk_index >= {threshold}
ORDER BY f.dependency_risk_index DESC, p.package_name
LIMIT {limit}
"""


