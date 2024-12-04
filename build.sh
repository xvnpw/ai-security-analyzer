#!/bin/sh

npm install
poetry config virtualenvs.create false
poetry install --no-root --no-interaction --no-ansi
scripts/fix_mermaid_dompurify.sh
