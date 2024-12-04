# Define paths
TARGET_FILE="./node_modules/mermaid/dist/chunks/mermaid.core/chunk-6DBFFHIP.mjs"
SOURCE_FILE="./node_src/chunk-6DBFFHIP.mjs"

# Check if the target file exists
if [ -f "$TARGET_FILE" ]; then
  echo "Found $TARGET_FILE. Overriding with $SOURCE_FILE."
  cp "$SOURCE_FILE" "$TARGET_FILE"
  echo "Override successful."
else
  echo "File $TARGET_FILE not found in ./node_modules."
fi
