#!/bin/bash

AGENT_PROMPT_TYPES="threat-modeling mitigations"

declare -A models
declare -A deep_analysis_models
# models["o3"]="openai"
# models["o1-mini"]="openai"
# models["o1"]="openai"
# models["o4-mini"]="openai"
# models["gpt-4.5-preview"]="openai"
# models["gpt-4.1"]="openai"
# models["gemini-2.0-flash-thinking-exp"]="google"
# models["gemini-2.0-pro-exp"]="google"
# models["gemini-2.5-pro-preview-05-06"]="google"
# models["gemini-2.5-flash-preview-04-17"]="google"
# models["gemini-2.5-pro-exp-03-25"]="google"
models["claude-3-7-sonnet-latest"]="anthropic"

# deep_analysis_models["gemini-2.0-pro-exp"]="google"
# deep_analysis_models["gemini-2.0-flash-thinking-exp"]="google"

declare -A temperatures
temperatures["o3"]="1"
temperatures["o1-mini"]="1"
temperatures["o1"]="1"
temperatures["o4-mini"]="1"
temperatures["gpt-4.5-preview"]="1"
temperatures["gpt-4.1"]="1"
temperatures["gemini-2.0-flash-thinking-exp"]="0.7"
temperatures["gemini-2.0-pro-exp"]="0.7"
temperatures["gemini-2.5-flash-preview-04-17"]="0.7"
temperatures["gemini-2.5-pro-exp-03-25"]="0.7"
temperatures["gemini-2.5-pro-preview-05-06"]="0.7"
temperatures["claude-3-7-sonnet-latest"]="1"

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     # Iterate over the keys of the models array
#     for agent_model in "${!models[@]}"; do
#         agent_provider="${models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         ARGS="dir -t ../screenshot-to-code/ -v -o examples/dir-${agent_prompt_type}-screenshot-to-code-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         sleep 10
#     done
# done

for agent_prompt_type in $AGENT_PROMPT_TYPES; do
    if [ "$agent_prompt_type" == "vulnerabilities" ]; then
        continue
    fi
    # Iterate over the keys of the models array
    for agent_model in "${!models[@]}"; do
        agent_provider="${models[$agent_model]}"
        safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

        echo "Generating example for $agent_prompt_type with $agent_model"

        ARGS="file -t tests/EXAMPLE_ARCHITECTURE.md -v -o examples/file-${agent_prompt_type}-ai-nutrition-pro-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

        CMD="python ai_security_analyzer/app.py $ARGS"
        echo "Running: $CMD"

        python ai_security_analyzer/app.py $ARGS

        sleep 10
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

#         ARGS="github -t https://github.com/abi/screenshot-to-code -v -o examples/github-${agent_prompt_type}-screenshot-to-code-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

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

#         ARGS="github -t https://github.com/pallets/flask -v -o examples/github-${agent_prompt_type}-flask-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

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

#         mkdir -p examples/deep-analysis/${safe_agent_model}

#         ARGS="github -t https://github.com/pallets/flask -v -o examples/deep-analysis/${safe_agent_model}/github-da-${agent_prompt_type}-flask-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --deep-analysis"

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

#     ARGS="dir -t ../screenshot-to-code/ -v -o examples/dir-vulnerabilitiesworkflow1-screenshot-to-code-${safe_agent_model}-i2.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --vulnerabilities-iterations 2"

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

#     ARGS="dir -t ../screenshot-to-code/ -v -o examples/dir-vulnerabilitiesworkflow1-screenshot-to-code-${safe_agent_model}-i8.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --vulnerabilities-iterations 8"

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

#         ARGS="dir -t ../terraform-provider-chronicle/ -v -o examples/form3tech-oss/dir-${agent_prompt_type}-terraform-provider-chronicle-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider -p go --include **/*.tf,**/*.tmpl,**/GNUmakefile"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         sleep 10
#     done
# done
