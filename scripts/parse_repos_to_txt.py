#!/usr/bin/env python3

import json
import argparse


def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="Generate a summary of repositories from a JSON file.")
    parser.add_argument("input_file", help="Path to the JSON file containing repository data")
    parser.add_argument(
        "-o",
        "--output_file",
        default="repos_summary.txt",
        help="Path to the output text file (default: repos_summary.txt)",
    )

    # Parse arguments
    args = parser.parse_args()

    # Define language mapping dictionary for special cases
    language_mapping = {
        "C#": "csharp",
        "C++": "cpp",
        # Add more mappings here in the future
    }

    # Read the JSON file
    with open(args.input_file, "r") as f:
        repos = json.load(f)

    # Process each repository and format the output
    output_lines = []
    for repo in repos:
        full_name = repo["full_name"]
        # Get the first language (first key) from the languages dictionary
        if "languages" in repo and repo["languages"]:
            first_language = next(iter(repo["languages"]))
            # Apply language mapping if necessary
            first_language = language_mapping.get(first_language, first_language)
            output_lines.append(f"{first_language} {full_name}".lower())
        else:
            # Handle cases where languages might be missing or empty
            output_lines.append(f"unknown {full_name}".lower())

    # Write the output to a text file
    with open(args.output_file, "w") as f:
        f.write("\n".join(output_lines))
        f.write("\n")

    print(f"Output written to {args.output_file}")


if __name__ == "__main__":
    main()
