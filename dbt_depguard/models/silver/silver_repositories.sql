{{ config(materialized='view') }}

WITH raw_github AS (
    SELECT *
    FROM {{ source('bronze', 'bronze_github_repos') }}
)
SELECT 
    repo_name,
    owner,
    COALESCE(stargazers, 0) AS stargazers,
    COALESCE(forks, 0) AS forks,
    COALESCE(open_issues, 0) AS open_issues,
    COALESCE(total_commits, 0) AS total_commits,
    -- collaborators not available due to GitHub API token scope
    1 AS collaborators,
    FALSE AS is_single_maintainer,
    _loaded_at_utc
FROM raw_github
