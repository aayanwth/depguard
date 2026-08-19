from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator
from datetime import datetime, timedelta

def alert_high_severity(**kwargs):
    # Mock alert log/Slack webhook if high severity vulnerability ingested
    print("ALERT: High severity vulnerability detected in recent ingestion.")
    return "Alert check completed"

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

with DAG(
    'depguard_orchestrator_dag',
    default_args=default_args,
    description='DepGuard Lakehouse Pipeline',
    schedule_interval='0 2 * * *',
    start_date=datetime(2023, 1, 1),
    catchup=False,
    tags=['depguard'],
) as dag:

    # Task 1: Ingestion
    ingest_osv = BashOperator(
        task_id='ingest_osv',
        bash_command='cd /opt/airflow && python scripts/ingest_osv.py',
    )
    
    ingest_github = BashOperator(
        task_id='ingest_github',
        bash_command='cd /opt/airflow && python scripts/ingest_github.py',
    )

    # Task 2: Soda Core Ingress Checks
    soda_checks = BashOperator(
        task_id='soda_bronze_checks',
        bash_command='cd /opt/airflow && set -a && source .env && set +a && soda scan -d depguard_snowflake -c soda/configuration.yml soda/checks_bronze.yml',
    )

    # Task 3: dbt Transform and Test
    dbt_run = BashOperator(
        task_id='dbt_run_silver_gold',
        bash_command='cd /opt/airflow/dbt_depguard && dbt run -t snowflake_prod',
    )
    
    dbt_test = BashOperator(
        task_id='dbt_test_models',
        bash_command='cd /opt/airflow/dbt_depguard && dbt test -t snowflake_prod',
    )

    # Task 4: Alerting
    alert_task = PythonOperator(
        task_id='alert_high_severity',
        python_callable=alert_high_severity,
    )

    [ingest_osv, ingest_github] >> soda_checks >> dbt_run >> dbt_test >> alert_task
