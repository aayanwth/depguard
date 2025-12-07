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


