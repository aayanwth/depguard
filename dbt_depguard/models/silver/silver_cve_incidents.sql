{{ config(materialized='view') }}

-- Bronze is append-only (one copy per run), so keep the latest copy of each
-- (vulnerability, package) pair.
WITH raw_osv AS (
    SELECT
        id,
        _queried_package_name AS package_name,
        UPPER(_queried_package_ecosystem) AS ecosystem,
        summary,
        published,
        modified,
        _severity_label,
        _cvss_score,
        _loaded_at_utc,
        ROW_NUMBER() OVER (
            PARTITION BY id, _queried_package_name, UPPER(_queried_package_ecosystem)
            ORDER BY _loaded_at_utc DESC
        ) AS rn
    FROM {{ source('bronze', 'bronze_osv_vulnerabilities') }}
)
SELECT
    md5(id || '|' || package_name || '|' || ecosystem) AS incident_sk,
    id AS cve_id,
    package_name,
    ecosystem,
    summary,
    published,
    modified,
    COALESCE(_severity_label, 'UNKNOWN') AS severity_label,
    CASE WHEN _cvss_score > 0 THEN _cvss_score END AS cvss_score,
    _loaded_at_utc
FROM raw_osv
WHERE rn = 1
