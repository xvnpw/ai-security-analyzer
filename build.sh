#!/bin/sh

npm install && \
poetry install && \
scripts/fix_mermaid_dompurify.sh
