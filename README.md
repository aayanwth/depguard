# 🛡️ DepGuard — Open-Source Dependency Risk Intelligence Platform

**DepGuard** is a production-grade, end-to-end Data Lakehouse pipeline that monitors **open-source software supply chain risks**. It ingests live vulnerability data from the [OSV](https://osv.dev/) database and repository health metrics from the [GitHub API](https://docs.github.com/en/rest), transforms them through a medallion architecture (Bronze → Silver → Gold), and surfaces a **Dependency Risk Index (DRI)** via a Power BI dashboard.

It also ships a **dependency scanner** (`scripts/scan.py`) that checks *your own* project's `requirements.txt` / `package-lock.json` / `package.json` against OSV and tells you which of your exact dependency versions are vulnerable and what to upgrade to.

---

## 🔍 Scan Your Own Project

```bash
python scripts/scan.py path/to/your/project          # finds requirements*.txt, package-lock.json, package.json
python scripts/scan.py requirements.txt --fail-on critical
python scripts/scan.py . --json report.json
```

- Pinned versions (`pkg==1.2.3`, lockfile entries) are matched against OSV for that exact version, with severity (CVSS or GitHub's rating) and the version(s) that fix each issue.
- Unpinned entries (`pkg>=1.0`) can't be judged and are listed separately. `package.json` ranges are approximated by their base version; prefer `package-lock.json`, which also covers transitive dependencies.
- Exit code is `1` if a finding at or above `--fail-on` (default `high`) exists, so it can gate CI.
- Severity is `UNKNOWN` when OSV publishes no rating (common for `PYSEC-` entries).

To also track your project in the pipeline and dashboard, add its manifest to `manifests:` in `config/watchlist.yml`.

---

## 🧮 Dependency Risk Index (DRI)

`DRI = min(10, severity_score × (1 + 0.5 × repo_health_risk))`

- `severity_score` is the CVSS score when known, otherwise mapped from the label (CRITICAL 9.5, HIGH 8, MEDIUM 5.5, LOW 2, UNKNOWN 5).
- `repo_health_risk` is 0–1: +0.5 if the GitHub repo is archived, +0.2/+0.4 if there's been no push for 180/365 days, +0.1 for more than 500 open issues. Packages without a tracked repo get 0.

So the same flaw ranks higher in a neglected project than in an actively maintained one.

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────┐
│   OSV API    │     │  GitHub API  │
└──────┬───────┘     └──────┬───────┘
       │  Python/dlt         │  Python/dlt
       ▼                     ▼
┌─────────────────────────────────────┐
│         BRONZE (Raw Ingestion)      │  ◄── Soda Core DQ Checks
│         Snowflake / DuckDB          │
└──────────────────┬──────────────────┘
                   │  dbt
                   ▼
┌─────────────────────────────────────┐
│        SILVER (Cleaned & Typed)     │
│  silver_cve_incidents               │
│  silver_packages                    │
│  silver_repositories                │
└──────────────────┬──────────────────┘
                   │  dbt
                   ▼
┌─────────────────────────────────────┐
│      GOLD (Dimensional Models)      │
│  fact_vulnerability_incident        │
│  dim_package    dim_repository      │
└──────────────────┬──────────────────┘
                   │
                   ▼
         ┌─────────────────┐
         │  Power BI / BI  │
         └─────────────────┘
```

**Orchestration:** Apache Airflow (Docker) or native Python orchestrator (Windows)

![Apache Airflow Pipeline](images/airflow_dag.png)

---

## 🧰 Technology Stack

| Layer              | Tool                          |
|--------------------|-------------------------------|
| **Ingestion**      | `dlt` (Data Load Tool)        |
| **Data Warehouse** | Snowflake (+ DuckDB for local)|
| **Transformation** | dbt (Data Build Tool)         |
| **Data Quality**   | Soda Core                     |
| **Orchestration**  | Apache Airflow (Docker)       |
| **Infrastructure** | Terraform                     |
| **Visualization**  | Microsoft Power BI            |

---

## 📂 Project Structure

```
depguard/
├── dags/                              # Airflow DAG definitions
│   └── depguard_orchestrator_dag.py   # Main pipeline DAG
├── scripts/                           # Python ingestion & orchestration
│   ├── scan.py                        # Dependency scanner CLI for your own projects
│   ├── depguard_common.py             # Shared OSV client, severity logic, manifest parsers
│   ├── ingest_osv.py                  # OSV vulnerability ingestion (dlt)
│   ├── ingest_github.py               # GitHub repo metrics ingestion (dlt)
│   ├── alert.py                       # High-DRI alerts (console + optional Slack)
│   ├── orchestrator.py                # Native orchestrator (no Docker), stops on first failure
│   └── snowflake_init.sql             # Snowflake warehouse/role setup DDL
├── config/watchlist.yml               # Packages/repos/manifests the pipeline tracks
├── tests/                             # pytest unit tests for the scanner helpers
├── dbt_depguard/                      # dbt project
│   ├── models/
│   │   ├── bronze/sources.yml         # Source definitions
│   │   ├── silver/                    # Cleaned staging models
│   │   └── gold/                      # Dimensional models (star schema)
│   ├── macros/                        # Custom dbt macros
│   ├── dbt_project.yml
│   └── profiles.yml                   # Connection profiles (uses env vars)
├── soda/                              # Soda Core data quality checks
│   ├── configuration.yml              # Soda connection config
│   ├── checks_bronze.yml              # Bronze layer quality checks
│   └── checks_silver.yml              # Silver layer quality checks
├── terraform/                         # IaC for Snowflake resources (alternative to snowflake_init.sql)
│   ├── main.tf
│   └── legacy_aws_s3.tf.txt           # Old, unused AWS S3 example kept for reference
├── .env.example                       # Template for environment variables
├── Dockerfile                         # Airflow custom image
├── docker-compose.yml                 # Full Airflow stack (Postgres, Webserver, Scheduler)
├── DepGuard_Cyber_Theme.json          # Custom Power BI dark theme
└── requirements.txt                   # Python dependencies
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- Docker Desktop (for Airflow) **or** native Python (for Windows orchestrator)
- A Snowflake account
- A GitHub Personal Access Token

### 1. Clone & Configure

```bash
git clone https://github.com/<your-username>/depguard.git
cd depguard
cp .env.example .env
# Edit .env with your Snowflake and GitHub credentials
```

### 2. Initialize Snowflake

Run the DDL script in your Snowflake worksheet to create the database, warehouse, schemas, and role:

```sql
-- Execute contents of scripts/snowflake_init.sql in Snowflake
```

### 3a. Run with Apache Airflow (Recommended)

```bash
docker compose up -d --build
```

Open [http://localhost:8080](http://localhost:8080) and log in with `admin` / `admin`.  
Unpause the `depguard_orchestrator_dag` and trigger it manually.

### 3b. Run Natively on Windows (No Docker)

```powershell
pip install -r requirements.txt
python scripts/orchestrator.py
```

Set `DESTINATION_NAME=duckdb` in `.env` to run entirely locally (everything lands in `duckdb.duckdb`); the orchestrator then uses the DuckDB dbt target and Soda sources. Choose what to track in `config/watchlist.yml`. The pipeline stops at the first failing step, so a bad `GITHUB_TOKEN` or a failed quality check never reaches the transformations.

Run the unit tests with `pip install pytest && pytest tests`.

---

## 📊 Data Catalog

### Gold Layer (Star Schema)

| Model | Type | Description |
|-------|------|-------------|
| `fact_vulnerability_incident` | Fact | Each row is a vulnerability linked to a package with severity score, repo health risk and the Dependency Risk Index (DRI). |
| `dim_package` | Dimension | Unique packages tracked across ecosystems (PyPI, npm). |
| `dim_repository` | Dimension | GitHub repository health metrics (stars, forks, open issues, last push, archived) and the derived `health_risk`. |

### Silver Layer (Cleaned)

| Model | Description |
|-------|-------------|
| `silver_cve_incidents` | Latest copy of each (vulnerability, package) pair from OSV, with severity and CVSS score. |
| `silver_packages` | Deduplicated package list with ecosystem classification. |
| `silver_repositories` | Latest GitHub snapshot per repository. |

---

## 📈 Power BI Dashboard

The project includes a custom cybersecurity-themed Power BI configuration (`DepGuard_Cyber_Theme.json`) with a dark UI and neon accent colors.

**Key Visuals:**
- KPI Cards (Total Vulnerabilities, Avg Severity Score)
- Decomposition Tree (drill down by Ecosystem → Severity → Package)
- Ribbon Chart (vulnerability timeline by ecosystem)
- Dynamic severity-colored data table
- Interactive slicers (Ecosystem, Severity)
- GitHub repository health scatter plot

![DepGuard Power BI Dashboard](images/powerbi_dashboard.png)

---

## 🔒 Security Notes

- **Never commit `.env`** — it is excluded via `.gitignore`.
- The `profiles.yml` uses `env_var()` to read credentials from environment variables at runtime.
- The `.env.example` file contains only placeholder values and is safe to commit.

---

## 📝 License

This project is for educational and portfolio demonstration purposes.
