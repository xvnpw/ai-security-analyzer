#!/bin/bash

AGENT_PROMPT_TYPES="sec-design threat-modeling attack-surface attack-tree mitigations vulnerabilities"

OUTPUT_DIR="examples-2025-08"

declare -A models
declare -A deep_analysis_models
models["gpt-5"]="openai"
# models["o3-pro"]="openai"
# models["o1"]="openai"
# models["o4-mini"]="openai"
# models["gpt-4.5-preview"]="openai"
# models["gpt-4.1"]="openai"
models["gemini-2.5-flash"]="google"
models["gemini-2.5-pro"]="google"
# models["gemini-2.5-pro-preview-05-06"]="google"
# models["gemini-2.5-flash-preview-04-17"]="google"
# models["gemini-2.5-pro-exp-03-25"]="google"
# models["claude-3-7-sonnet-latest"]="anthropic"
models["anthropic/claude-opus-4.1"]="openrouter"

# deep_analysis_models["gemini-2.0-pro-exp"]="google"
# deep_analysis_models["gemini-2.0-flash-thinking-exp"]="google"

declare -A temperatures
temperatures["gpt-5"]="1"
temperatures["o3-pro"]="1"
temperatures["gemini-2.5-flash"]="0.7"
temperatures["gemini-2.5-pro"]="0.7"
temperatures["anthropic/claude-opus-4.1"]="1"

mkdir -p $OUTPUT_DIR

for agent_prompt_type in $AGENT_PROMPT_TYPES; do
    # Iterate over the keys of the models array
    for agent_model in "${!models[@]}"; do
        agent_provider="${models[$agent_model]}"
        safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

        echo "Generating example for $agent_prompt_type with $agent_model"

        ARGS="dir -t ../screenshot-to-code/ -v -o $OUTPUT_DIR/dir-${agent_prompt_type}-screenshot-to-code-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

        CMD="python ai_security_analyzer/app.py $ARGS"
        echo "Running: $CMD"

        python ai_security_analyzer/app.py $ARGS
    done
done

for agent_prompt_type in $AGENT_PROMPT_TYPES; do
    if [ "$agent_prompt_type" == "vulnerabilities" ]; then
        continue
    fi
    # Iterate over the keys of the models array
    for agent_model in "${!models[@]}"; do
        agent_provider="${models[$agent_model]}"
        safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

        echo "Generating example for $agent_prompt_type with $agent_model"

        ARGS="file -t tests/EXAMPLE_ARCHITECTURE.md -v -o $OUTPUT_DIR/file-${agent_prompt_type}-ai-nutrition-pro-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

        CMD="python ai_security_analyzer/app.py $ARGS"
        echo "Running: $CMD"

        python ai_security_analyzer/app.py $ARGS

    done
done

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     if [ "$agent_prompt_type" == "vulnerabilities" ]; then
#         continue
#     fi
#     # Iterate over the keys of the models array
#     for agent_model in "${!models[@]}"; do
#         agent_provider="${models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         ARGS="github -t https://github.com/abi/screenshot-to-code -v -o $OUTPUT_DIR/github-${agent_prompt_type}-screenshot-to-code-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         sleep 10
#     done
# done

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     if [ "$agent_prompt_type" == "vulnerabilities" ]; then
#         continue
#     fi
#     # Iterate over the keys of the models array
#     for agent_model in "${!models[@]}"; do
#         agent_provider="${models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         ARGS="github -t https://github.com/pallets/flask -v -o $OUTPUT_DIR/github-${agent_prompt_type}-flask-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         sleep 10
#     done
# done

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     if [ "$agent_prompt_type" == "vulnerabilities" ]; then
#         continue
#     fi
#     for agent_model in "${!deep_analysis_models[@]}"; do
#         agent_provider="${deep_analysis_models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         mkdir -p $OUTPUT_DIR/deep-analysis/${safe_agent_model}

#         ARGS="github -t https://github.com/pallets/flask -v -o $OUTPUT_DIR/deep-analysis/${safe_agent_model}/github-da-${agent_prompt_type}-flask-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --deep-analysis"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         sleep 5
#     done
# done

# for agent_model in "${!models[@]}"; do
#     agent_prompt_type="vulnerabilities-workflow-1"
#     agent_provider="${models[$agent_model]}"
#     secondary_agent_provider="openai"
#     secondary_agent_model="o3-mini"
#     secondary_agent_temperature="1"
#     safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#     echo "Generating example for $agent_prompt_type with $agent_model"

#     ARGS="dir -t ../screenshot-to-code/ -v -o $OUTPUT_DIR/dir-vulnerabilitiesworkflow1-screenshot-to-code-${safe_agent_model}-i2.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --vulnerabilities-iterations 2"

#     CMD="python ai_security_analyzer/app.py $ARGS"
#     echo "Running: $CMD"

#     python ai_security_analyzer/app.py $ARGS

#     sleep 10
# done

# for agent_model in "${!models[@]}"; do
#     agent_prompt_type="vulnerabilities-workflow-1"
#     agent_provider="${models[$agent_model]}"
#     secondary_agent_provider="openai"
#     secondary_agent_model="o3-mini"
#     secondary_agent_temperature="1"
#     safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#     echo "Generating example for $agent_prompt_type with $agent_model"

#     ARGS="dir -t ../screenshot-to-code/ -v -o $OUTPUT_DIR/dir-vulnerabilitiesworkflow1-screenshot-to-code-${safe_agent_model}-i8.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --vulnerabilities-iterations 8"

#     CMD="python ai_security_analyzer/app.py $ARGS"
#     echo "Running: $CMD"

#     python ai_security_analyzer/app.py $ARGS

#     sleep 10
# done

########################
# form3tech-oss
########################

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     # Iterate over the keys of the models array
#     for agent_model in "${!models[@]}"; do
#         agent_provider="${models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         ARGS="dir -t ../terraform-provider-chronicle/ -v -o $OUTPUT_DIR/form3tech-oss/dir-${agent_prompt_type}-terraform-provider-chronicle-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider -p go --include **/*.tf,**/*.tmpl,**/GNUmakefile"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         sleep 10
#     done
# done
