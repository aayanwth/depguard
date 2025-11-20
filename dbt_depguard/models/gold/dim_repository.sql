{{ config(materialized='table') }}

-- health_risk is 0 (healthy) to 1 (neglected). It rises when the repo is
-- archived, has had no pushes for a long time, or has a very large issue backlog.
WITH repos AS (
    SELECT
        *,
        datediff('day', pushed_at, current_timestamp) AS days_since_push
    FROM {{ ref('silver_repositories') }}
)
SELECT
    md5(owner || '/' || repo_name) AS repo_sk,
    md5(package_name || '|' || ecosystem) AS package_sk,
    repo_name,
    owner,
    package_name,
    ecosystem,
    stargazers,
    forks,
    open_issues,
    total_commits,
    is_archived,
    pushed_at,
    days_since_push,
    LEAST(
        1.0,
        CASE WHEN is_archived THEN 0.5 ELSE 0.0 END
        + CASE WHEN days_since_push > 365 THEN 0.4
               WHEN days_since_push > 180 THEN 0.2
               ELSE 0.0 END
        + CASE WHEN open_issues > 500 THEN 0.1 ELSE 0.0 END
    ) AS health_risk,
    _loaded_at_utc
FROM repos
