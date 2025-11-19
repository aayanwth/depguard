from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

default_args = {
    'owner': 'airflow',
    'depends_on_past': False,
    'email_on_failure': False,
    'email_on_retry': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

ENV = 'cd /opt/airflow && set -a && source .env && set +a'

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
        bash_command=f'{ENV} && python scripts/ingest_osv.py',
    )

    ingest_github = BashOperator(
        task_id='ingest_github',
        bash_command=f'{ENV} && python scripts/ingest_github.py',
    )

    # Task 2: Soda Core bronze checks
    soda_bronze = BashOperator(
        task_id='soda_bronze_checks',
        bash_command=f'{ENV} && soda scan -d depguard_snowflake -c soda/configuration.yml soda/checks_bronze.yml',
    )

    # Task 3: dbt transform and test
    dbt_run = BashOperator(
        task_id='dbt_run_silver_gold',
        bash_command=f'{ENV} && cd dbt_depguard && dbt run -t snowflake_prod',
    )

    dbt_test = BashOperator(
        task_id='dbt_test_models',
        bash_command=f'{ENV} && cd dbt_depguard && dbt test -t snowflake_prod',
    )

    # Task 4: Soda Core silver checks
    soda_silver = BashOperator(
        task_id='soda_silver_checks',
        bash_command=f'{ENV} && soda scan -d depguard_snowflake_silver -c soda/configuration.yml soda/checks_silver.yml',
    )

    # Task 5: Alert on high-risk vulnerabilities (Slack if SLACK_WEBHOOK_URL is set)
    alert_task = BashOperator(
        task_id='alert_high_risk',
        bash_command=f'{ENV} && python scripts/alert.py',
    )

    [ingest_osv, ingest_github] >> soda_bronze >> dbt_run >> dbt_test >> soda_silver >> alert_task
