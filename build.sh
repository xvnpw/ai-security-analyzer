#!/bin/sh

npm install
poetry install --no-interaction --no-ansi
scripts/fix_mermaid_dompurify.sh
