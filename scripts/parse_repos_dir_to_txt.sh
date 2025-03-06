# Check if directory argument is provided
if [ -z "$1" ]; then
    echo "Error: Please provide a directory path"
    echo "Usage: $0 <directory_path>"
    exit 1
fi

DIR_PATH=$1

# Check if directory exists
if [ ! -d "$DIR_PATH" ]; then
    echo "Error: Directory '$DIR_PATH' does not exist"
    exit 1
fi

# Check if directory contains JSON files
if [ -z "$(ls -A "$DIR_PATH"/*.json 2>/dev/null)" ]; then
    echo "Warning: No JSON files found in '$DIR_PATH'"
    exit 0
fi

for file in "$DIR_PATH"/*.json; do
    # Use the filename only when calling the Python script
    # The current version would create an incorrect path like /path/to/dir//path/to/dir/file.json
    python scripts/parse_repos_to_txt.py "$file" -o "./$(basename "$file" .json).txt"
done
