{{ config(materialized='table') }}

SELECT 
    md5(repo_name || owner) AS repo_sk,
    repo_name,
    owner,
    stargazers,
    forks,
    open_issues,
    total_commits,
    collaborators,
    is_single_maintainer,
    _loaded_at_utc
FROM {{ ref('silver_repositories') }}
