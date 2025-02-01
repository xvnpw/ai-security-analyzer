#!/bin/bash

AGENT_PROMPT_TYPES="attack-tree"

declare -A models
# models["o1"]="openai"
# models["o3-mini"]="openai"
# models["gemini-2.0-flash-thinking-exp"]="google"
models["deepseek/deepseek-r1"]="openrouter"

declare -A temperatures
temperatures["o1"]="1"
temperatures["o3-mini"]="1"
temperatures["gemini-2.0-flash-thinking-exp"]="0"
temperatures["deepseek/deepseek-r1"]="0.3"

# printf "# Examples\n\n" > examples/README.md
printf "## dir mode\n\n" >> examples/README.md

printf "| Project Name | Project Type | Model | Documentation |\n" >> examples/README.md
printf "| --- | --- | --- | --- |\n" >> examples/README.md

for agent_prompt_type in $AGENT_PROMPT_TYPES; do
    # Iterate over the keys of the models array
    for agent_model in "${!models[@]}"; do
        agent_provider="${models[$agent_model]}"
        safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

        echo "Generating example for $agent_prompt_type with $agent_model"

        ARGS="dir -t ../screenshot-to-code/ -v -o examples/dir-${agent_prompt_type}-screenshot-to-code-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

        CMD="python ai_security_analyzer/app.py $ARGS"
        echo "Running: $CMD"

        python ai_security_analyzer/app.py $ARGS

        printf "| [screenshot-to-code](https://github.com/abi/screenshot-to-code)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](dir-${agent_prompt_type}-screenshot-to-code-${safe_agent_model}.md) |\n" "$CMD" >> examples/README.md
    done
done

# printf "\n## file mode\n\n" >> examples/README.md

# printf "| Project Name | Project Type | Model | Documentation |\n" >> examples/README.md
# printf "| --- | --- | --- | --- |\n" >> examples/README.md

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

#         printf "| [AI Nutrition-Pro](../tests/EXAMPLE_ARCHITECTURE.md)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](file-${agent_prompt_type}-ai-nutrition-pro-${safe_agent_model}.md) |\n" "$CMD" >> examples/README.md
#     done
# done

# printf "\n## github mode\n\n" >> examples/README.md

# printf "| Project Name | Project Type | Model | Documentation |\n" >> examples/README.md
# printf "| --- | --- | --- | --- |\n" >> examples/README.md

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     # Iterate over the keys of the models array
#     for agent_model in "${!models[@]}"; do
#         agent_provider="${models[$agent_model]}"
#         safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#         echo "Generating example for $agent_prompt_type with $agent_model"

#         ARGS="github -t https://github.com/pallets/flask -v -o examples/github-${agent_prompt_type}-flask-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider"

#         CMD="python ai_security_analyzer/app.py $ARGS"
#         echo "Running: $CMD"

#         python ai_security_analyzer/app.py $ARGS

#         printf "| [flask](https://github.com/pallets/flask)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](github-${agent_prompt_type}-flask-${safe_agent_model}.md) |\n" "$CMD" >> examples/README.md
#     done
# done

# printf "\n## github mode - deep analysis\n\n" >> examples/README.md

# printf "| Project Name | Project Type | Model | Documentation |\n" >> examples/README.md
# printf "| --- | --- | --- | --- |\n" >> examples/README.md

# for agent_prompt_type in $AGENT_PROMPT_TYPES; do
#     agent_model="gemini-2.0-flash-thinking-exp"
#     agent_provider="google"
#     safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')

#     echo "Generating example for $agent_prompt_type with $agent_model"

#     ARGS="github -t https://github.com/pallets/flask -v -o examples/github-da-${agent_prompt_type}-flask-${safe_agent_model}.md --agent-model $agent_model --agent-temperature ${temperatures[$agent_model]} --agent-prompt-type $agent_prompt_type --agent-provider $agent_provider --deep-analysis"

#     CMD="python ai_security_analyzer/app.py $ARGS"
#     echo "Running: $CMD"

#     python ai_security_analyzer/app.py $ARGS

#     if [ $agent_prompt_type == "sec-design" ]; then
#         printf "| [flask](https://github.com/pallets/flask)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](github-da-${agent_prompt_type}-flask-${safe_agent_model}.md), [deep-analysis](github-da-${agent_prompt_type}-flask-${safe_agent_model}-deep-analysis.md) |\n" "$CMD" >> examples/README.md
#     else
#         printf "| [flask](https://github.com/pallets/flask)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](github-da-${agent_prompt_type}-flask-${safe_agent_model}.md) |\n" "$CMD" >> examples/README.md
#     fi

#     sleep 5
# done

########################
# form3tech-oss
########################

# printf "# form3tech-oss Examples\n\n" > examples/form3tech-oss/README.md
# printf "## dir mode\n\n" >> examples/form3tech-oss/README.md

# printf "| Project Name | Project Type | Model | Documentation |\n" >> examples/form3tech-oss/README.md
# printf "| --- | --- | --- | --- |\n" >> examples/form3tech-oss/README.md

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

#         printf "| [terraform-provider-chronicle](https://github.com/form3tech-oss/terraform-provider-chronicle)<br/><details><summary>commands...</summary>\`\`\` %s\`\`\`</details> | python | $agent_model | [${agent_prompt_type}](dir-${agent_prompt_type}-terraform-provider-chronicle-${safe_agent_model}.md) |\n" "$CMD" >> examples/form3tech-oss/README.md
#     done
# done
