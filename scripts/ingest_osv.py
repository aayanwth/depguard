import dlt
from dlt.sources.helpers import requests
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

load_dotenv()

# Map custom Snowflake vars to dlt expected format
if os.getenv("DESTINATION_NAME") == "snowflake":
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__DATABASE"] = os.getenv("SNOWFLAKE_DATABASE", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__HOST"] = os.getenv('SNOWFLAKE_ACCOUNT', '')
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__USERNAME"] = os.getenv("SNOWFLAKE_USER", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__PASSWORD"] = os.getenv("SNOWFLAKE_PASSWORD", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__WAREHOUSE"] = os.getenv("SNOWFLAKE_WAREHOUSE", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__ROLE"] = os.getenv("SNOWFLAKE_ROLE", "")

@dlt.resource(table_name="bronze_osv_vulnerabilities", write_disposition="append")
def osv_vulnerabilities_resource(packages):
    """
    Fetch batch vulnerabilities from OSV API for a list of packages.
    """
    url = "https://api.osv.dev/v1/querybatch"
    
    queries = []
    for pkg in packages:
        queries.append({"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}})
    
    response = requests.post(url, json={"queries": queries})
    response.raise_for_status()
    
    data = response.json()
    results = data.get("results", [])
    
    for i, result in enumerate(results):
        pkg_queried = packages[i]
        
        vulns = result.get("vulns", [])
        for vuln in vulns:
            # Append metadata
            vuln["_loaded_at_utc"] = datetime.now(timezone.utc).isoformat()
            vuln["_queried_package_name"] = pkg_queried["name"]
            vuln["_queried_package_ecosystem"] = pkg_queried["ecosystem"]
            yield vuln

@dlt.source(schema_contract="evolve", max_table_nesting=2)
def osv_source(packages):
    return osv_vulnerabilities_resource(packages)

if __name__ == "__main__":
    destination_name = os.getenv("DESTINATION_NAME", "duckdb")
    
    pipeline = dlt.pipeline(
        pipeline_name="osv_ingestion",
        destination=destination_name,
        dataset_name="bronze"
    )
    
    # Test packages with known/potential historical vulnerabilities for testing
    packages_to_check = [
        {"name": "requests", "ecosystem": "PyPI"},
        {"name": "django", "ecosystem": "PyPI"},
        {"name": "lodash", "ecosystem": "npm"}
    ]
    
    print(f"Running OSV pipeline to destination: {destination_name}")
    load_info = pipeline.run(osv_source(packages_to_check))
    print(load_info)
