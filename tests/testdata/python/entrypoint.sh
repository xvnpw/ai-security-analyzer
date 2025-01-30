#!/bin/sh -l

# setting up correct python path to find fabric_agent_action module
export PYTHONPATH="/app:$PYTHONPATH"

# copying fabric configuration to temporary $HOME set by github workflow
if [ -n "$GITHUB_WORKSPACE" ]; then
    echo "Detected GitHub runner"
fi

# Initialize empty ARGS with proper quoting
ARGS=""

# Set initial arguments based on input/output files
if [ -n "$INPUT_INPUT_FILE" ] && [ -n "$INPUT_OUTPUT_FILE" ]; then
    ARGS="-i '$INPUT_INPUT_FILE' -o '$INPUT_OUTPUT_FILE'"
else
    ARGS="-h"
fi

if [ -n "$INPUT_AGENT_TYPE" ]; then
    ARGS="$ARGS --agent-type '$INPUT_AGENT_TYPE'"
fi

if [ -n "$INPUT_AGENT_PROVIDER" ]; then
    ARGS="$ARGS --agent-provider '$INPUT_AGENT_PROVIDER'"
fi

if [ -n "$INPUT_AGENT_MODEL" ]; then
    ARGS="$ARGS --agent-model '$INPUT_AGENT_MODEL'"
fi

if [ -n "$INPUT_AGENT_TEMPERATURE" ]; then
    ARGS="$ARGS --agent-temperature '$INPUT_AGENT_TEMPERATURE'"
fi

if [ "$INPUT_AGENT_PREAMBLE_ENABLED" = 'true' ]; then
    ARGS="$ARGS --agent-preamble-enabled"
fi

if [ -n "$INPUT_AGENT_PREAMBLE" ]; then
    ARGS="$ARGS --agent-preamble '$INPUT_AGENT_PREAMBLE'"
fi

if [ -n "$INPUT_FABRIC_PROVIDER" ]; then
    ARGS="$ARGS --fabric-provider '$INPUT_FABRIC_PROVIDER'"
fi

if [ -n "$INPUT_FABRIC_MODEL" ]; then
    ARGS="$ARGS --fabric-model '$INPUT_FABRIC_MODEL'"
fi

if [ -n "$INPUT_FABRIC_TEMPERATURE" ]; then
    ARGS="$ARGS --fabric-temperature '$INPUT_FABRIC_TEMPERATURE'"
fi

if [ -n "$INPUT_FABRIC_PATTERNS_INCLUDED" ]; then
    ARGS="$ARGS --fabric-patterns-included '$INPUT_FABRIC_PATTERNS_INCLUDED'"
fi

if [ -n "$INPUT_FABRIC_PATTERNS_EXCLUDED" ]; then
    ARGS="$ARGS --fabric-patterns-excluded '$INPUT_FABRIC_PATTERNS_EXCLUDED'"
fi

if [ -n "$INPUT_FABRIC_MAX_NUM_TURNS" ]; then
    ARGS="$ARGS --fabric-max-num-turns '$INPUT_FABRIC_MAX_NUM_TURNS'"
fi

if [ "$INPUT_VERBOSE" = 'true' ]; then
    ARGS="$ARGS --verbose"
fi

if [ "$INPUT_DEBUG" = 'true' ]; then
    ARGS="$ARGS --debug"
fi

echo "[start] app.py..."

echo "[debug] $ARGS"

# Use eval to properly handle the quoted arguments
eval "/usr/local/bin/python /app/fabric_agent_action/app.py $ARGS"
