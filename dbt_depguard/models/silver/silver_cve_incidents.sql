{{ config(materialized='view') }}

WITH raw_osv AS (
    SELECT *
    FROM {{ source('bronze', 'bronze_osv_vulnerabilities') }}
)
SELECT 
    id AS cve_id,
    _queried_package_name AS package_name,
    _queried_package_ecosystem AS ecosystem,
    modified,
    -- Default severity score for logic (published/summary not available in source)
    'MEDIUM' as severity_label,
    _loaded_at_utc
FROM raw_osv
