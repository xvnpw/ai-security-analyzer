#!/bin/sh -l

# setting up correct python path to find ai_security_analyzer module
export PYTHONPATH="/app:$PYTHONPATH"

# copying fabric configuration to temporary $HOME set by github workflow
if [ -n "$GITHUB_WORKSPACE" ]; then
    echo "Detected GitHub runner"
fi

exec /usr/local/bin/python /app/ai_security_analyzer/app.py "$@"
