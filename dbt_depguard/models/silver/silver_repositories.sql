{{ config(materialized='view') }}

-- Latest snapshot per repository (bronze keeps every run).
WITH raw_github AS (
    SELECT
        *,
        ROW_NUMBER() OVER (
            PARTITION BY owner, repo_name
            ORDER BY _loaded_at_utc DESC
        ) AS rn
    FROM {{ source('bronze', 'bronze_github_repos') }}
)
SELECT
    repo_name,
    owner,
    package_name,
    UPPER(package_ecosystem) AS ecosystem,
    COALESCE(stargazers, 0) AS stargazers,
    COALESCE(forks, 0) AS forks,
    COALESCE(open_issues, 0) AS open_issues,
    COALESCE(total_commits, 0) AS total_commits,
    COALESCE(is_archived, FALSE) AS is_archived,
    CAST(pushed_at AS TIMESTAMP) AS pushed_at,
    _loaded_at_utc
FROM raw_github
WHERE rn = 1
