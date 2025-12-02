import os
import sys
from datetime import datetime, timezone

import dlt
from dlt.sources.helpers import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from depguard_common import configure_snowflake_env, get_destination, load_watchlist  # noqa: E402

configure_snowflake_env()

QUERY = """
query($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
        name
        owner { login }
        stargazerCount
        forkCount
        isArchived
        pushedAt
        issues(states: OPEN) { totalCount }
        defaultBranchRef {
            target {
                ... on Commit { history { totalCount } }
            }
        }
    }
}
"""


@dlt.resource(table_name="bronze_github_repos", write_disposition="append")
def github_repos_resource(repos):
    """GitHub health metrics for each repo, tagged with the package it belongs to."""
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN is not set in the environment.")

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    loaded_at = datetime.now(timezone.utc).isoformat()

    for repo in repos:
        label = f"{repo['owner']}/{repo['name']}"
        response = requests.post(
            "https://api.github.com/graphql",
            json={"query": QUERY, "variables": {"owner": repo["owner"], "name": repo["name"]}},
            headers=headers,
        )
        if response.status_code != 200:
            raise RuntimeError(f"GitHub request failed for {label}: {response.status_code} {response.text}")

        payload = response.json()
        data = (payload.get("data") or {}).get("repository")
        if payload.get("errors") or not data:
            raise RuntimeError(f"GitHub query failed for {label}: {payload.get('errors')}")

        branch = data.get("defaultBranchRef") or {}
        commits = ((branch.get("target") or {}).get("history") or {}).get("totalCount", 0)

        yield {
            "repo_name": data["name"],
            "owner": data["owner"]["login"],
            "package_name": repo["package_name"],
            "package_ecosystem": repo["ecosystem"],
            "stargazers": data["stargazerCount"],
            "forks": data["forkCount"],
            "open_issues": data["issues"]["totalCount"],
            "total_commits": commits,
            "is_archived": data["isArchived"],
            "pushed_at": data["pushedAt"],
            "_loaded_at_utc": loaded_at,
        }


@dlt.source(schema_contract="evolve")
def github_source(repos):
    return github_repos_resource(repos)


if __name__ == "__main__":
    destination = get_destination()
    _, repos = load_watchlist()
    if not repos:
        sys.exit("No repos in config/watchlist.yml (add `repo: owner/name` to a package).")

    pipeline = dlt.pipeline(
        pipeline_name="github_ingestion",
        destination=destination,
        dataset_name="bronze",
    )
    print(f"Running GitHub pipeline for {len(repos)} repos to: {os.getenv('DESTINATION_NAME', 'duckdb')}")
    print(pipeline.run(github_source(repos)))
