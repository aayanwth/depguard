"""Native (no Docker) orchestrator. Mirrors dags/depguard_orchestrator_dag.py.

Stops at the first failing step: a failed ingest or data-quality check must not
flow into the transformations. Set DESTINATION_NAME=duckdb in .env to run fully
locally, or snowflake for the warehouse.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_cmd(command, cwd=None):
    print("========================================")
    print(f"Running: {command}")
    print("========================================")
    result = subprocess.run(command, shell=True, cwd=cwd)
    if result.returncode != 0:
        print(f"\n[ERROR] Command failed with exit code {result.returncode}. Aborting pipeline.")
        sys.exit(result.returncode)
    print("\n[SUCCESS] Task completed.\n")


def main():
    os.chdir(ROOT)
    from dotenv import load_dotenv

    load_dotenv()
    snowflake = os.getenv("DESTINATION_NAME", "duckdb") == "snowflake"
    dbt_target = "snowflake_prod" if snowflake else "duckdb_dev"
    soda_prefix = "depguard_snowflake" if snowflake else "depguard_duckdb"
    print(f"Starting DepGuard Orchestrator (local Python mode, target: {dbt_target})...")

    py = f'"{sys.executable}"'
    soda_exe = os.path.join(os.path.dirname(sys.executable), "soda.exe")
    soda = f'"{soda_exe}"' if os.path.exists(soda_exe) else "soda"
    dbt = f"{py} -m dbt.cli.main"
    dbt_dir = os.path.join(ROOT, "dbt_depguard")

    print("\n--- Task 1: Ingestion ---")
    run_cmd(f"{py} scripts/ingest_osv.py")
    run_cmd(f"{py} scripts/ingest_github.py")

    print("\n--- Task 2: Bronze data quality (Soda) ---")
    run_cmd(f"{soda} scan -d {soda_prefix} -c soda/configuration.yml soda/checks_bronze.yml")

    print("\n--- Task 3: dbt transformations and tests ---")
    run_cmd(f"{dbt} run -t {dbt_target}", cwd=dbt_dir)
    run_cmd(f"{dbt} test -t {dbt_target}", cwd=dbt_dir)

    print("\n--- Task 4: Silver data quality (Soda) ---")
    run_cmd(f"{soda} scan -d {soda_prefix}_silver -c soda/configuration.yml soda/checks_silver.yml")

    print("\n--- Task 5: Alerting ---")
    run_cmd(f"{py} scripts/alert.py")

    print("\nDepGuard Pipeline Execution Completed!")


if __name__ == "__main__":
    main()
