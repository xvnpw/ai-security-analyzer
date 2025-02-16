import requests
import datetime
import argparse
import time
import os
import json


def get_python_repos(
    token,
    per_page=100,
    rate_limit_wait=60,
    max_repos=1000,
    min_stars=2460,
    max_stars=2490,
    repo_name_filter=None,
    excludes_description=None,
    required_in_name=None,
    max_python_size=1000000,  # Added max_python_size
):
    """
    Fetches a list of popular Python repositories from GitHub, including size and language stats.

    Args:
        token: Your GitHub Personal Access Token.
        per_page:  The number of results to fetch per page (max 100).
        rate_limit_wait: Seconds to wait if rate limit is exceeded.
        max_repos: Maximum number of repositories to fetch.
        min_stars: Minimum number of stars.
        max_stars: Maximum number of stars.
        repo_name_filter: A list of repository names to filter by (full names, e.g., 'user/repo').
                         If None, no name filtering is applied.
        excludes_description: A list of words.  If a repo's description contains *any* of these
                             words, the repo will be excluded.  Case-insensitive.
        required_in_name: A string that must be present in the repository name (case-insensitive).
                           If None, no name requirement is enforced.
        max_python_size: The maximum size (in bytes) allowed for the Python portion of the repository.

    Returns:
        A list of dictionaries, or an empty list on error.
    """
    all_repos = []
    page = 1
    now = datetime.datetime.now(datetime.timezone.utc)
    one_year_ago = now - datetime.timedelta(days=365)
    one_year_ago_str = one_year_ago.strftime("%Y-%m-%dT%H:%M:%SZ")

    if excludes_description is None:
        excludes_description = []  # Make sure it's a list
    excludes_description_lower = [word.lower() for word in excludes_description]

    while True:
        if len(all_repos) >= max_repos:
            break

        stars_query = f"stars:{min_stars}..{max_stars}"

        # Build the base query
        query = f"language:python+{stars_query}+pushed:>{one_year_ago_str}"

        # Add the 'in:name' part if required_in_name is provided
        if required_in_name:
            query += f"+{required_in_name.lower()}+in:name"  # Add to the query string.

        url = (
            f"https://api.github.com/search/repositories?q={query}"  # Use the constructed query
            f"&sort=stars&order=desc&per_page={per_page}&page={page}"
        )
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        }
        # print(f"DEBUG: URL = {url}") # uncomment for debug

        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            data = response.json()
            items = data.get("items", [])
            if not items:
                break

            filtered_items = []  # Create a list to store filtered items
            for item in items:
                if not item.get("archived"):
                    full_name = item["full_name"]
                    description = item.get("description")
                    if description is not None:
                        description = description.lower()
                    else:
                        description = ""

                    # Apply name filter and description filter
                    if (repo_name_filter is None or full_name in repo_name_filter) and not any(
                        word in description for word in excludes_description_lower
                    ):
                        filtered_items.append(item)  # Append to filtered items

            # Process only the filtered items
            for item in filtered_items:  # Iterate through filtered items
                # Get Language Stats
                languages = {}
                if item.get("languages_url"):
                    try:
                        lang_response = requests.get(item["languages_url"], headers=headers)
                        lang_response.raise_for_status()
                        languages = lang_response.json()
                    except requests.exceptions.RequestException as lang_e:
                        print(f"Error fetching languages for {item['name']}: {lang_e}")
                        # Don't halt; skip languages

                # Check if Python size is within the limit
                if "Python" in languages and languages["Python"] <= max_python_size:
                    repo_info = {
                        "name": item["name"],
                        "full_name": item["full_name"],
                        "url": item["html_url"],
                        "stars": item["stargazers_count"],
                        "updated_at": item["updated_at"],
                        "description": item.get("description", ""),
                        "size_kb": item["size"],
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
            return []
        except Exception as e:
            print(f"Unexpected error: {e}")
            return []

    return all_repos[:max_repos]


def main():
    parser = argparse.ArgumentParser(description="Fetch popular Python repositories from GitHub.")
    parser.add_argument("-o", "--output", help="Output JSON file (default: repos.json)")
    parser.add_argument("-m", "--max", type=int, default=1000, help="Max repos (default: 1000)")
    parser.add_argument("--min-stars", type=int, default=1000, help="Minimum stars (default: 2500)")
    parser.add_argument("--max-stars", type=int, default=30000, help="Maximum stars (default: 2600)")
    parser.add_argument(
        "--max-python-size", type=int, default=1000000, help="Maximum Python size in bytes (default: 1000000)"
    )  # Added argument
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN environment variable not set.")
        return

    # repo_name_filter = [...]  # (Optional)
    repo_name_filter = None
    excludes_description = ["diffusion", "transformer", "pytest"]
    required_in_name = "django"

    repos = get_python_repos(
        token,
        max_repos=args.max,
        min_stars=args.min_stars,
        max_stars=args.max_stars,
        repo_name_filter=repo_name_filter,
        excludes_description=excludes_description,
        required_in_name=required_in_name,
        max_python_size=args.max_python_size,  # Pass the argument
    )

    if repos:
        output_filename = args.output or "repos.json"
        try:
            with open(output_filename, "w", encoding="utf-8") as f:
                json.dump(repos, f, indent=4)
            print(f"Wrote data to {output_filename}")
        except Exception as e:
            print(f"Error writing to {output_filename}: {e}.  Printing to console...")
            print(json.dumps(repos, indent=4))
    else:
        print("No matching repositories found.")


if __name__ == "__main__":
    main()
