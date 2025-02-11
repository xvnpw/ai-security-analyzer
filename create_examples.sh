#!/bin/bash

AGENT_PROMPT_TYPES="attack-surface"

declare -A models
declare -A deep_analysis_models
# models["o1"]="openai"
# models["o3-mini"]="openai"
# models["gemini-2.0-flash-thinking-exp"]="google"
models["deepseek/deepseek-r1"]="openrouter"
# models["gemini-2.0-pro-exp"]="google"

# deep_analysis_models["gemini-2.0-pro-exp"]="google"
# deep_analysis_models["gemini-2.0-flash-thinking-exp"]="google"

declare -A temperatures
temperatures["o1"]="1"
temperatures["o3-mini"]="1"
temperatures["gemini-2.0-flash-thinking-exp"]="0.7"
temperatures["deepseek/deepseek-r1"]="0.7"
temperatures["gemini-2.0-pro-exp"]="0.7"

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

#         sleep 60
#     done
# done

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     # Iterate over the keys of the models array
#     for agent_model in "${!models[@]}"; do
#         agent_provider="${models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         ARGS="file -t tests/EXAMPLE_ARCHITECTURE.md -v -o examples/file-${agent_prompt_type}-ai-nutrition-pro-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         sleep 60
#     done
# done

for agent_prompt_type in $AGENT_PROMPT_TYPES; do
    # Iterate over the keys of the models array
    for agent_model in "${!models[@]}"; do
        agent_provider="${models[$agent_model]}"
        safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

        echo "Generating example for $agent_prompt_type with $agent_model"

        ARGS="github -t https://github.com/abi/screenshot-to-code -v -o examples/github-${agent_prompt_type}-screenshot-to-code-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

        CMD="python ai_security_analyzer/app.py $ARGS"
        echo "Running: $CMD"

        python ai_security_analyzer/app.py $ARGS

        sleep 60
    done
done

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     for agent_model in "${!deep_analysis_models[@]}"; do
#         agent_provider="${deep_analysis_models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         mkdir -p examples/deep-analysis/${safe_agent_model}

#         ARGS="github -t https://github.com/pallets/flask -v -o examples/deep-analysis/${safe_agent_model}/github-da-${agent_prompt_type}-flask-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --deep-analysis"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         if [ $agent_prompt_type == "sec-design" ]; then
#             printf "| [flask](https://github.com/pallets/flask)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](github-da-${agent_prompt_type}-flask-${safe_agent_model}.md), [deep-analysis](github-da-${agent_prompt_type}-flask-${safe_agent_model}-deep-analysis.md) |\n" "$CMD" >> examples/README.md
#         else
#             printf "| [flask](https://github.com/pallets/flask)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](github-da-${agent_prompt_type}-flask-${safe_agent_model}.md) |\n" "$CMD" >> examples/README.md
#         fi

#         sleep 5
#     done
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

#         sleep 60
#     done
# done
