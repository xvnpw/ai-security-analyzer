#!/usr/bin/env bats

setup() {
  # Build the Docker image before running tests
  docker build -t test-fabric-agent-action .
}

@test "Check if environment variables are passed correctly to app.py" {
  run docker run --rm \
    -e INPUT_INPUT_FILE="entrypoint.sh" \
    -e INPUT_OUTPUT_FILE="test_output.txt" \
    -e INPUT_AGENT_TYPE=router \
    -e INPUT_AGENT_PROVIDER=openrouter \
    -e INPUT_AGENT_MODEL=test_model \
    -e INPUT_AGENT_TEMPERATURE=0.7 \
    -e INPUT_AGENT_PREAMBLE_ENABLED=true \
    -e INPUT_AGENT_PREAMBLE="Sample Preamble" \
    -e INPUT_FABRIC_PROVIDER=anthropic \
    -e INPUT_FABRIC_MODEL=fabric_model_test \
    -e INPUT_FABRIC_TEMPERATURE=0.8 \
    -e INPUT_FABRIC_PATTERNS_INCLUDED="pattern1,pattern2" \
    -e INPUT_FABRIC_PATTERNS_EXCLUDED="pattern3,pattern4" \
    -e INPUT_VERBOSE=true \
    -e INPUT_DEBUG=true \
    test-fabric-agent-action

  # Check if the container exited successfully
  [ "$status" -ne 0 ]

  # Check for expected output
  [[ "$output" =~ "-i 'entrypoint.sh' -o 'test_output.txt'" ]]
  [[ "$output" =~ "--agent-type 'router'" ]]
  [[ "$output" =~ "--agent-provider 'openrouter'" ]]
  [[ "$output" =~ "--agent-model 'test_model'" ]]
  [[ "$output" =~ "--agent-temperature '0.7'" ]]
  [[ "$output" =~ "--agent-preamble-enabled" ]]
  [[ "$output" =~ "--agent-preamble 'Sample Preamble'" ]]
  [[ "$output" =~ "--fabric-provider 'anthropic'" ]]
  [[ "$output" =~ "--fabric-model 'fabric_model_test'" ]]
  [[ "$output" =~ "--fabric-temperature '0.8'" ]]
  [[ "$output" =~ "--fabric-patterns-included 'pattern1,pattern2'" ]]
  [[ "$output" =~ "--fabric-patterns-excluded 'pattern3,pattern4'" ]]
  [[ "$output" =~ "--verbose" ]]
  [[ "$output" =~ "--debug" ]]
}

@test "Check behavior when some optional environment variables are missing" {
  run docker run --rm \
    -e INPUT_INPUT_FILE="entrypoint.sh" \
    -e INPUT_OUTPUT_FILE="test_output.txt" \
    -e INPUT_AGENT_TYPE=react \
    test-fabric-agent-action

  # Check if the container exited successfully
  [ "$status" -ne 0 ]

  # Check for expected output without the optional variables
  [[ "$output" =~ "-i 'entrypoint.sh' -o 'test_output.txt'" ]]
  [[ "$output" =~ "--agent-type 'react'" ]]
  [[ ! "$output" =~ "--agent-provider" ]]
  [[ ! "$output" =~ "--agent-model" ]]
  [[ ! "$output" =~ "--agent-temperature" ]]
  [[ ! "$output" =~ "--agent-preamble-enabled" ]]
  [[ ! "$output" =~ "--agent-preamble" ]]
  [[ ! "$output" =~ "--fabric-provider" ]]
  [[ ! "$output" =~ "--fabric-model" ]]
  [[ ! "$output" =~ "--fabric-temperature" ]]
  [[ ! "$output" =~ "--fabric-patterns-included" ]]
  [[ ! "$output" =~ "--fabric-patterns-excluded" ]]
  [[ ! "$output" =~ "--verbose" ]]
  [[ ! "$output" =~ "--debug" ]]
}

@test "Check behavior when no environment variables are set" {
  run docker run --rm test-fabric-agent-action

  # Check if the container exited successfully
  [ "$status" -eq 0 ]

  # Check if the help message is displayed since no env variables are provided
  [[ "$output" =~ "-h" ]]
}
