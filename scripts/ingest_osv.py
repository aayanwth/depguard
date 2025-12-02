import os
import sys
from datetime import datetime, timezone

import dlt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from depguard_common import (  # noqa: E402
    configure_snowflake_env,
    fetch_vulns,
    get_destination,
    load_watchlist,
    osv_query_batch,
    repo_from_vuln,
    severity_from_vuln,
)

configure_snowflake_env()


@dlt.resource(table_name="bronze_osv_vulnerabilities", write_disposition="append")
def osv_vulnerabilities_resource(packages):
    """All known OSV vulnerabilities (full records) for the tracked packages."""
    queries = [{"package": {"name": p["name"], "ecosystem": p["ecosystem"]}} for p in packages]
    stubs_per_pkg = osv_query_batch(queries)
    full = fetch_vulns([s["id"] for stubs in stubs_per_pkg for s in stubs])
    loaded_at = datetime.now(timezone.utc).isoformat()

    for pkg, stubs in zip(packages, stubs_per_pkg):
        for stub in stubs:
            vuln = dict(full[stub["id"]])
            label, score = severity_from_vuln(vuln)
            # Keep the raw record; add stable, derived columns alongside it.
            vuln["summary"] = vuln.get("summary") or ""
            vuln["published"] = vuln.get("published") or vuln.get("modified")
            vuln["_severity_label"] = label
            vuln["_cvss_score"] = score if score is not None else 0.0  # 0.0 = unknown
            vuln["_repo_url"] = repo_from_vuln(vuln)
            vuln["_loaded_at_utc"] = loaded_at
            vuln["_queried_package_name"] = pkg["name"]
            vuln["_queried_package_ecosystem"] = pkg["ecosystem"]
            yield vuln


@dlt.source(schema_contract="evolve", max_table_nesting=2)
def osv_source(packages):
    return osv_vulnerabilities_resource(packages)


if __name__ == "__main__":
    destination = get_destination()
    packages, _ = load_watchlist()

    pipeline = dlt.pipeline(
        pipeline_name="osv_ingestion",
        destination=destination,
        dataset_name="bronze",
    )
    print(f"Running OSV pipeline for {len(packages)} packages to: {os.getenv('DESTINATION_NAME', 'duckdb')}")
    print(pipeline.run(osv_source(packages)))
