#!/usr/bin/env python3
import sys


def filter_github_organizations(urls):
    """
    Filter a list of GitHub URLs to extract only organization names.

    Args:
        urls (list): List of GitHub URLs

    Returns:
        list: List of GitHub organization names
    """
    organizations = set()

    for url in urls:
        # Remove any trailing whitespace and split by '/'
        parts = url.strip().split("/")

        # Skip invalid URLs
        if len(parts) < 4:
            continue

        # Check if it's a GitHub URL
        if "github.com" not in parts[2]:
            continue

        # Extract organization name (index 3 after splitting)
        if len(parts) >= 5:
            organizations.add(url)

    return sorted(list(organizations))


def main():
    # Check if input file was provided
    if len(sys.argv) != 2:
        print("Usage: python script.py input_file.txt")
        sys.exit(1)

    input_file = sys.argv[1]

    try:
        # Read URLs from the input file
        with open(input_file, "r") as file:
            urls = [line.strip() for line in file if line.strip()]

        # Get organizations
        organizations = filter_github_organizations(urls)

        # Print organizations
        for org in organizations:
            print(org)

    except FileNotFoundError:
        print(f"Error: The file '{input_file}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
