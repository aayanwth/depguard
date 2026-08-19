import dlt
from dlt.sources.helpers import requests
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

load_dotenv()

# Map custom Snowflake vars to dlt expected format
if os.getenv("DESTINATION_NAME") == "snowflake":
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__DATABASE"] = os.getenv("SNOWFLAKE_DATABASE", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__HOST"] = os.getenv('SNOWFLAKE_ACCOUNT', '')
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__USERNAME"] = os.getenv("SNOWFLAKE_USER", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__PASSWORD"] = os.getenv("SNOWFLAKE_PASSWORD", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__WAREHOUSE"] = os.getenv("SNOWFLAKE_WAREHOUSE", "")
    os.environ["DESTINATION__SNOWFLAKE__CREDENTIALS__ROLE"] = os.getenv("SNOWFLAKE_ROLE", "")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

@dlt.resource(table_name="bronze_github_repos", write_disposition="append")
def github_repos_resource(repos):
    """
    Query GitHub GraphQL API for repository metrics.
    """
    if not GITHUB_TOKEN:
        raise ValueError("GITHUB_TOKEN is not set in the environment.")
    
    url = "https://api.github.com/graphql"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Content-Type": "application/json"
    }
    
    for repo in repos:
        owner = repo["owner"]
        name = repo["name"]
        
        query = """
        query($owner: String!, $name: String!) {
            repository(owner: $owner, name: $name) {
                name
                owner { login }
                stargazerCount
                forkCount
                issues(states: OPEN) {
                    totalCount
                }
                defaultBranchRef {
                    target {
                        ... on Commit {
                            history {
                                totalCount
                            }
                        }
                    }
                }
                collaborators {
                    totalCount
                }
            }
        }
        """
        
        variables = {"owner": owner, "name": name}
        
        response = requests.post(url, json={"query": query, "variables": variables}, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if "errors" in data:
                print(f"Error querying {owner}/{name}: {data['errors']}")
                # If the token lacks permission to read collaborators, it will return an error here
                # Let's extract what we can if partial data is returned
                repo_data = data.get("data", {}).get("repository")
                if not repo_data:
                    continue
            else:
                repo_data = data["data"]["repository"]
            
            if not repo_data:
                continue
            
            issues_count = repo_data.get("issues", {}).get("totalCount", 0)
            commits_count = 0
            if repo_data.get("defaultBranchRef") and repo_data["defaultBranchRef"].get("target"):
                commits_count = repo_data["defaultBranchRef"]["target"]["history"]["totalCount"]
            
            collab_data = repo_data.get("collaborators")
            collab_count = collab_data.get("totalCount", 1) if collab_data else None
            
            record = {
                "repo_name": repo_data["name"],
                "owner": repo_data["owner"]["login"],
                "stargazers": repo_data["stargazerCount"],
                "forks": repo_data["forkCount"],
                "open_issues": issues_count,
                "total_commits": commits_count,
                "collaborators": collab_count,
                "is_single_maintainer": (collab_count == 1) if collab_count is not None else None,
                "_loaded_at_utc": datetime.now(timezone.utc).isoformat()
            }
            yield record
        else:
            print(f"Failed to fetch data for {owner}/{name}. Status: {response.status_code}")
            print(response.text)

@dlt.source(schema_contract="evolve")
def github_source(repos):
    return github_repos_resource(repos)

if __name__ == "__main__":
    destination_name = os.getenv("DESTINATION_NAME", "duckdb")
    
    pipeline = dlt.pipeline(
        pipeline_name="github_ingestion",
        destination=destination_name,
        dataset_name="bronze"
    )
    
    test_repos = [
        {"owner": "psf", "name": "requests"},
        {"owner": "django", "name": "django"}
    ]
    
    print(f"Running GitHub pipeline to destination: {destination_name}")
    load_info = pipeline.run(github_source(test_repos))
    print(load_info)
