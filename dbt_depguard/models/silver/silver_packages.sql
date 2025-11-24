{{ config(materialized='view') }}

-- Every tracked package: those with known vulnerabilities plus those that only
-- appear via a GitHub repo (so a clean package still shows up).
WITH from_osv AS (
    SELECT
        _queried_package_name AS package_name,
        UPPER(_queried_package_ecosystem) AS ecosystem,
        _loaded_at_utc
    FROM {{ source('bronze', 'bronze_osv_vulnerabilities') }}
),
from_github AS (
    SELECT
        package_name,
        UPPER(package_ecosystem) AS ecosystem,
        _loaded_at_utc
    FROM {{ source('bronze', 'bronze_github_repos') }}
),
combined AS (
    SELECT * FROM from_osv
    UNION ALL
    SELECT * FROM from_github
)
SELECT
    package_name,
    ecosystem,
    MAX(_loaded_at_utc) AS last_seen_at
FROM combined
GROUP BY package_name, ecosystem
