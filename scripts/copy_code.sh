#!/bin/bash

# Define the output file
OUTPUT_FILE="output.txt"

# Clear the output file if it exists
> "$OUTPUT_FILE"

# Find all .py files excluding __init__.py and loop through them
find ./ai_security_analyzer -type f -name "*.py" ! -name "__init__.py" | while read -r file; do
  # Get the filename without the path
  FILENAME=$(basename "$file")

  # Add the file header to the output file
  echo "#####" >> "$OUTPUT_FILE"
  echo "# $file" >> "$OUTPUT_FILE"
  echo "#####" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"

  # Append the content of the file to the output file
  cat "$file" >> "$OUTPUT_FILE"

  # Add a newline for separation
  echo "" >> "$OUTPUT_FILE"

done

echo "All Python files have been copied to $OUTPUT_FILE."
