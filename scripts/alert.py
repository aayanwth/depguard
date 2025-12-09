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


def fetch_rows(threshold, limit):
    sql = QUERY.format(threshold=float(threshold), limit=int(limit))
    if os.getenv("DESTINATION_NAME", "duckdb") == "snowflake":
        import snowflake.connector

        conn = snowflake.connector.connect(
            account=os.environ["SNOWFLAKE_ACCOUNT"],
            user=os.environ["SNOWFLAKE_USER"],
            password=os.environ["SNOWFLAKE_PASSWORD"],
            warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
            database=os.getenv("SNOWFLAKE_DATABASE"),
            role=os.getenv("SNOWFLAKE_ROLE"),
        )
    else:
        import duckdb

        conn = duckdb.connect(os.path.join(ROOT, "duckdb.duckdb"), read_only=True)
    try:
        cur = conn.cursor()
        cur.execute(sql)
        return cur.fetchall()
    finally:
        conn.close()


def build_message(rows, threshold):
    if not rows:
        return None
    lines = [f"DepGuard: {len(rows)} vulnerabilities with DRI >= {threshold}"]
    for package, ecosystem, vuln_id, severity, dri in rows:
        lines.append(f"  [{dri:>5.2f}] {package} ({ecosystem})  {vuln_id}  {severity}")
    return "\n".join(lines)


def main():
    threshold = float(os.getenv("ALERT_MIN_DRI", "8.0"))
    try:
        rows = fetch_rows(threshold, limit=25)
    except Exception as exc:  # alerting is best-effort
        print(f"ALERT CHECK FAILED: could not read gold layer: {exc}")
        return 0

    message = build_message(rows, threshold)
    if not message:
        print(f"No vulnerabilities at or above DRI {threshold}.")
        return 0

    print(message)
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if webhook:
        try:
            requests.post(webhook, json={"text": f"```{message}```"}, timeout=15).raise_for_status()
            print("Posted alert to Slack.")
        except requests.RequestException as exc:
            print(f"Slack post failed: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
