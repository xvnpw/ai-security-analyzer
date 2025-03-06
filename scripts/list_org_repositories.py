import requests
import datetime
import argparse
import time
import os
import json

excludes_description_lower = [
    "tutorial",
    "example",
    "demo",
    "test",
    "tests",
    "testing",
    "sample",
    "samples",
    "examples",
    "docs",
    "documentation",
    "mirror",
]

whitelisted_repos = [
    "aws/aws-sdk-js",
    "aws/sagemaker-xgboost-container",
    "angular/dgeni",
    "angular/dgeni-packages",
    "dotnet/MQTTnet",
    "dotnet/WatsonWebserver",
]

excluded_languages = ["HTML", "Jupyter Notebook", "Markdown", "YAML", "JSON", "XML", "CSS", "CartoCSS", "Vim Script"]


def get_org_repos(
    token,
    org_names,
    per_page=100,
    rate_limit_wait=60,
):
    """
    Fetches repositories from GitHub organizations, filtered by activity in the last year and not archived.

    Args:
        token: Your GitHub Personal Access Token.
        org_names: List of organization names to fetch repositories from.
        per_page: The number of results to fetch per page (max 100).
        rate_limit_wait: Seconds to wait if rate limit is exceeded.

    Returns:
        A list of dictionaries, or an empty list on error.
    """
    all_repos = []
    now = datetime.datetime.now(datetime.timezone.utc)
    one_year_ago = now - datetime.timedelta(days=365 * 1)
    one_year_ago_str = one_year_ago.strftime("%Y-%m-%dT%H:%M:%SZ")

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }

    for org_name in org_names:
        page = 1

        while True:
            url = f"https://api.github.com/orgs/{org_name}/repos?per_page={per_page}&page={page}"
            # print(f"DEBUG: URL = {url}") # uncomment for debug

            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()

                repos = response.json()
                if not repos:
                    break

                # Filter repositories
                for repo in repos:
                    # Skip if archived
                    if repo.get("archived"):
                        continue
                    description = repo.get("description")
                    if description is not None:
                        description = description.lower()
                    else:
                        description = ""
                    repo_full_name = repo.get("full_name")
                    if (
                        any(word in description for word in excludes_description_lower)
                        and repo_full_name not in whitelisted_repos
                    ):
                        print(f"Skipping {repo_full_name} because of description")
                        continue

                    name = repo.get("name").lower()
                    if (
                        any(word in name for word in excludes_description_lower)
                        and repo_full_name not in whitelisted_repos
                    ):
                        print(f"Skipping {repo_full_name} because of name")
                        continue

                    # Check if updated in the last year
                    updated_at = datetime.datetime.strptime(repo["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
                        tzinfo=datetime.timezone.utc
                    )

                    stars = repo.get("stargazers_count", 0)
                    if stars < 100:
                        print(f"Skipping {repo_full_name} because of stars: {stars}")
                        continue

                    if updated_at > one_year_ago:
                        # Get Language Stats
                        languages = {}
                        if repo.get("languages_url"):
                            try:
                                lang_response = requests.get(repo["languages_url"], headers=headers)
                                lang_response.raise_for_status()
                                languages = lang_response.json()
                            except requests.exceptions.RequestException as lang_e:
                                print(f"Error fetching languages for {repo['name']}: {lang_e}")
                                # Don't halt; skip languages

                        main_lang = next(iter(languages)) if languages else None
                        if not main_lang:
                            print(f"Skipping {repo['full_name']} because of no main language")
                            continue

                        if main_lang:
                            main_lang_size = languages[main_lang]
                            if main_lang_size > 500_000:
                                print(f"Skipping {repo['full_name']} because of main language size: {main_lang_size}")
                                continue
                        if main_lang in excluded_languages:
                            print(f"Skipping {repo['full_name']} because of main language: {main_lang}")
                            continue

                        repo_info = {
                            "name": repo["name"],
                            "full_name": repo["full_name"],
                            "url": repo["html_url"],
                            "stars": repo["stargazers_count"],
                            "updated_at": repo["updated_at"],
                            "description": repo.get("description", ""),
                            "size_kb": repo["size"],
                            "languages": languages,
                        }
                        all_repos.append(repo_info)

                if "next" not in response.links:
                    break
                page += 1  # Increment page *after* processing the current page

            except requests.exceptions.RequestException as e:
                if response.status_code == 403:
                    if "Retry-After" in response.headers:
                        retry_after = int(response.headers["Retry-After"])
                        print(f"Rate limit. Waiting {retry_after}s (Retry-After header)...")
                        time.sleep(retry_after)
                    else:
                        print(f"Rate limit. Waiting {rate_limit_wait}s (default)...")
                        time.sleep(rate_limit_wait)
                    continue
                print(f"An error occurred: {e}")
                if "response" in locals() and response:
                    print(f"Status: {response.status_code}, Content: {response.text}")
                continue  # Continue to next organization instead of returning empty list
            except Exception as e:
                print(f"Unexpected error: {e}")
                continue  # Continue to next organization

    return all_repos


def read_org_names(file_path):
    """
    Read organization names from a file.

    Args:
        file_path: Path to the file containing organization names, one per line.

    Returns:
        List of organization names.
    """
    with open(file_path, "r") as f:
        # Strip whitespace and filter out empty lines
        return [line.strip() for line in f if line.strip()]


def main():
    parser = argparse.ArgumentParser(description="Fetch repositories from GitHub organizations.")
    parser.add_argument("-i", "--input", required=True, help="Input file containing organization names")
    parser.add_argument("-o", "--output", help="Output JSON file (default: repos.json)")
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN environment variable not set.")
        return

    try:
        org_names = read_org_names(args.input)
        if not org_names:
            print("Error: No organization names found in input file.")
            return
    except Exception as e:
        print(f"Error reading organization names: {e}")
        return

    repos = get_org_repos(
        token,
        org_names=org_names,
    )

    if repos:
        output_filename = args.output or "repos.json"
        try:
            with open(output_filename, "w", encoding="utf-8") as f:
                json.dump(repos, f, indent=4)
            print(f"Wrote data for {len(repos)} repositories to {output_filename}")
        except Exception as e:
            print(f"Error writing to {output_filename}: {e}.  Printing to console...")
            print(json.dumps(repos, indent=4))
    else:
        print("No matching repositories found.")


if __name__ == "__main__":
    main()
