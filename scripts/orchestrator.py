import subprocess
import sys
import os

def run_cmd(command, cwd=None):
    print(f"========================================")
    print(f"Running: {command}")
    print(f"========================================")
    result = subprocess.run(command, shell=True, cwd=cwd)
    if result.returncode != 0:
        print(f"\n[ERROR] Command failed with exit code {result.returncode}")
        print("Continuing to next task...")
        # We continue to allow dbt to run even if soda fails
    else:
        print("\n[SUCCESS] Task completed.\n")

def main():
    print("Starting DepGuard Orchestrator (Local Python Mode)...")
    
    # Task 1: Ingestion
    print("\n--- Task 1: Ingestion ---")
    run_cmd(f'"{sys.executable}" scripts/ingest_osv.py')
    run_cmd(f'"{sys.executable}" scripts/ingest_github.py')
    
    # Task 2: Soda Core Checks
    print("\n--- Task 2: Soda Data Quality Checks ---")
    # Try to find soda in the same directory as python
    soda_exe = os.path.join(os.path.dirname(sys.executable), "Scripts", "soda.exe")
    if not os.path.exists(soda_exe):
        soda_exe = "soda" # fallback to PATH
    
    run_cmd(f'"{soda_exe}" scan -d depguard_snowflake -c soda/configuration.yml soda/checks_bronze.yml')
    
    # Task 3: dbt Transform and Test
    print("\n--- Task 3: dbt Transformations ---")
    dbt_dir = os.path.join(os.getcwd(), "dbt_depguard")
    dbt_cmd = f'"{sys.executable}" -m dbt.cli.main'
    
    run_cmd(f"{dbt_cmd} run -t snowflake_prod", cwd=dbt_dir)
    run_cmd(f"{dbt_cmd} test -t snowflake_prod", cwd=dbt_dir)
    
    # Task 4: Alerting
    print("\n--- Task 4: Alerting ---")
    print("ALERT: Dependency Risk check completed.")
    
    print("\nDepGuard Pipeline Execution Completed!")

if __name__ == "__main__":
    main()
