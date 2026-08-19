{{ config(materialized='view') }}

WITH raw_osv AS (
    SELECT 
        _queried_package_name AS package_name,
        _queried_package_ecosystem AS ecosystem,
        _loaded_at_utc
    FROM {{ source('bronze', 'bronze_osv_vulnerabilities') }}
),
deduped AS (
    SELECT 
        package_name,
        ecosystem,
        MAX(_loaded_at_utc) AS last_seen_at
    FROM raw_osv
    GROUP BY 1, 2
)
SELECT 
    package_name,
    UPPER(ecosystem) AS ecosystem,
    last_seen_at
FROM deduped
