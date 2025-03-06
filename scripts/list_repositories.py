import os
import json
import requests
import time
import argparse
import re
import datetime

# GitHub API configuration
GITHUB_API_URL = "https://api.github.com"
# Get GitHub token from environment variables for authentication
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

# Configure request headers
headers = {"Accept": "application/vnd.github.v3+json"}

# Add token to headers if available
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    print("Warning: GITHUB_TOKEN not found. Rate limits will be severely restricted.")

# Languages to exclude
excluded_languages = ["HTML", "Jupyter Notebook", "Markdown", "YAML", "JSON", "XML", "CSS", "CartoCSS"]


def fetch_repositories(org_name):
    """Fetch all repositories from a GitHub organization."""
    repos = []
    page = 1

    while True:
        try:
            response = requests.get(
                f"{GITHUB_API_URL}/orgs/{org_name}/repos", headers=headers, params={"per_page": 100, "page": page}
            )
            response.raise_for_status()

            page_repos = response.json()
            if not page_repos:
                break

            repos.extend(page_repos)
            page += 1

            # Check for rate limiting
            if "X-RateLimit-Remaining" in response.headers and int(response.headers["X-RateLimit-Remaining"]) < 5:
                reset_time = int(response.headers["X-RateLimit-Reset"])
                sleep_time = reset_time - time.time() + 1
                if sleep_time > 0:
                    print(f"Rate limit nearly reached. Sleeping for {sleep_time:.0f} seconds.")
                    time.sleep(sleep_time)

        except requests.exceptions.RequestException as e:
            print(f"Error fetching repositories for {org_name}: {e}")
            break

    return repos


def fetch_specific_repository(org_name, repo_name):
    """Fetch a specific repository."""
    try:
        response = requests.get(f"{GITHUB_API_URL}/repos/{org_name}/{repo_name}", headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching repository {org_name}/{repo_name}: {e}")
        return None


def process_repository(repo):
    """Process a single repository and format it according to requirements."""

    now = datetime.datetime.now(datetime.timezone.utc)
    one_year_ago = now - datetime.timedelta(days=365 * 1)
    updated_at = datetime.datetime.strptime(repo["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )

    if updated_at < one_year_ago:
        print(f"Skipping {repo['full_name']} because of updated at: {updated_at}")
        return None

    stars = repo.get("stargazers_count", 0)
    if stars < 100:
        print(f"Skipping {repo['full_name']} because of stars: {stars}")
        return None

    # Fetch languages for the repository
    languages = {}
    if "languages_url" in repo:
        try:
            lang_response = requests.get(repo["languages_url"], headers=headers)
            lang_response.raise_for_status()
            languages = lang_response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching languages for {repo['name']}: {e}")

    # Apply filtering logic
    if not languages:
        print(f"Skipping {repo['full_name']} because of no languages")
        return None

    main_lang = next(iter(languages)) if languages else None
    if not main_lang:
        print(f"Skipping {repo['full_name']} because of no main language")
        return None

    main_lang_size = languages[main_lang]
    if main_lang_size > 500000:
        print(f"Skipping {repo['full_name']} because of main language size: {main_lang_size}")
        return None

    if main_lang in excluded_languages:
        print(f"Skipping {repo['full_name']} because of main language: {main_lang}")
        return None

    # Format the repository data
    return {
        "name": repo["name"],
        "full_name": repo["full_name"],
        "url": repo["html_url"],
        "stars": repo["stargazers_count"],
        "updated_at": repo["updated_at"],
        "description": repo["description"],
        "size_kb": repo["size"],
        "languages": languages,
    }


def parse_github_urls(file_path):
    """Parse GitHub URLs from the input file."""
    repos = []
    pattern = r"https://github\.com/([^/]+)/([^/\s]+)"

    try:
        with open(file_path, "r") as f:
            for line in f:
                match = re.search(pattern, line.strip())
                if match:
                    org_name = match.group(1)
                    repo_name = match.group(2)
                    repos.append((org_name, repo_name))
    except Exception as e:
        print(f"Error reading input file: {e}")
        return []

    return repos


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Fetch GitHub repositories information")
    parser.add_argument("input_file", help="Path to file containing GitHub repository URLs")
    parser.add_argument("--output", default="repos_output.json", help="Output JSON file name")
    args = parser.parse_args()

    # Parse GitHub URLs from the input file
    print(f"Parsing GitHub URLs from {args.input_file}...")
    repos_to_fetch = parse_github_urls(args.input_file)

    if not repos_to_fetch:
        print("No valid GitHub URLs found in the input file.")
        return

    print(f"Found {len(repos_to_fetch)} repositories to fetch.")

    # Process each repository
    processed_repos = []
    for org_name, repo_name in repos_to_fetch:
        print(f"Fetching {org_name}/{repo_name}...")
        repo = fetch_specific_repository(org_name, repo_name)
        if repo:
            processed_repo = process_repository(repo)
            if processed_repo:
                processed_repos.append(processed_repo)

        # Add a small delay to avoid hitting rate limits
        time.sleep(0.5)

    # Sort repositories by stars (descending)
    processed_repos.sort(key=lambda x: x["stars"], reverse=True)

    # Write the results to a JSON file
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(processed_repos, f, indent=4)

    print(f"Successfully processed {len(processed_repos)} repositories.")
    print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
