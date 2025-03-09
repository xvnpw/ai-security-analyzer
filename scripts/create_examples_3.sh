#!/bin/bash

declare -A models
models["o3-mini"]="openai"
models["gemini-2.0-flash-thinking-exp"]="google"
models["anthropic/claude-3.7-sonnet:thinking"]="openrouter"
# models["openai/gpt-4.5-preview"]="openrouter"
models["qwen/qwq-32b"]="openrouter"

declare -A temperatures
temperatures["o3-mini"]="1"
temperatures["gemini-2.0-flash-thinking-exp"]="0.7 1"
temperatures["anthropic/claude-3.7-sonnet:thinking"]="1"
temperatures["openai/gpt-4.5-preview"]="1"
temperatures["qwen/qwq-32b"]="0.7"

declare -A dirs
dirs["vscode-laravel-extra-intellisense"]="typescript"
dirs["vscode_deno"]="typescript"
dirs["screenshot-to-code"]="python"
dirs["django-unicorn"]="python"

declare -A github_repo_urls
github_repo_urls["vscode-laravel-extra-intellisense"]="https://github.com/amir9480/vscode-laravel-extra-intellisense"
github_repo_urls["vscode_deno"]="https://github.com/denoland/vscode_deno"
github_repo_urls["screenshot-to-code"]="https://github.com/abi/screenshot-to-code"
github_repo_urls["django-unicorn"]="https://github.com/adamghill/django-unicorn"

declare -A threat_actors
threat_actors["vscode-laravel-extra-intellisense"]="vscode_extension_malicious_repo"
threat_actors["vscode_deno"]="vscode_extension_malicious_repo"
threat_actors["screenshot-to-code"]="external_web"
threat_actors["django-unicorn"]="external_web"

declare -A included_classes_of_vulnerabilities
included_classes_of_vulnerabilities["vscode-laravel-extra-intellisense"]="RCE, Command Injection, Code Injection"
included_classes_of_vulnerabilities["vscode_deno"]="RCE, Command Injection, Code Injection"
included_classes_of_vulnerabilities["screenshot-to-code"]=""
included_classes_of_vulnerabilities["django-unicorn"]=""

declare -A context_windows
context_windows["gemini-2.0-flash-thinking-exp"]="71000" # for bigger projects: 150000 500000
context_windows["anthropic/claude-3.7-sonnet:thinking"]="100000"
context_windows["o3-mini"]="100000"
context_windows["openai/gpt-4.5-preview"]="100000"
context_windows["qwen/qwq-32b"]="90000"

declare -A chunk_sizes
chunk_sizes["gemini-2.0-flash-thinking-exp"]="60000" # for bigger projects: 140000 450000
chunk_sizes["anthropic/claude-3.7-sonnet:thinking"]="90000"
chunk_sizes["o3-mini"]="90000"
chunk_sizes["openai/gpt-4.5-preview"]="90000"
chunk_sizes["qwen/qwq-32b"]="80000"

declare -A iterations
iterations["gemini-2.0-flash-thinking-exp"]="2 4 8"
iterations["anthropic/claude-3.7-sonnet:thinking"]="4"
iterations["o3-mini"]="4"
iterations["openai/gpt-4.5-preview"]="2"
iterations["qwen/qwq-32b"]="2 4"

# Split prompt types into an array
prompt_types=("vulnerabilities-workflow-1" "vulnerabilities-workflow-2")

for dir_name in "${!dirs[@]}"; do
    for agent_model in "${!models[@]}"; do
        agent_provider="${models[$agent_model]}"
        project_type="${dirs[$dir_name]}"
        safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')
        
        # Read the temperatures as an array
        read -ra temp_array <<< "${temperatures[$agent_model]}"
        
        # Read the context windows and chunk sizes as arrays
        read -ra ctx_array <<< "${context_windows[$agent_model]}"
        read -ra chunk_array <<< "${chunk_sizes[$agent_model]}"
        
        # Read the iterations as an array
        read -ra iter_array <<< "${iterations[$agent_model]}"

        # Loop through each context window and corresponding chunk size
        for i in "${!ctx_array[@]}"; do
            ctx="${ctx_array[$i]}"
            chunk="${chunk_array[$i]}"
                    
            # Use the values directly, not as arrays
            github_repo_url="${github_repo_urls[$dir_name]}"
            threat_actor="${threat_actors[$dir_name]}"
            included_classes="${included_classes_of_vulnerabilities[$dir_name]}"
                    
            # Loop through each iteration count
            for iter in "${iter_array[@]}"; do
                # Loop through each temperature
                for temp in "${temp_array[@]}"; do
                    # Loop through each prompt type
                    for prompt_type in "${prompt_types[@]}"; do
                        echo "Generating example for $dir_name with model $agent_model, prompt $prompt_type, temp $temp, context $ctx, chunk $chunk, iterations $iter"
                        
                        output_file="examples-3/${safe_agent_model}/${dir_name}-${safe_agent_model}-${prompt_type}-temp${temp}-iter${iter}-ctx${ctx}.md"
                        
                        mkdir -p "examples-3/${safe_agent_model}"

                        # Use an array for arguments to avoid shell parsing/quoting issues
                        ARGS=(
                            "dir"
                            "-t" "../${dir_name}/"
                            "-v"
                            "-o" "$output_file"
                            "--agent-model" "$agent_model"
                            "--agent-temperature" "$temp"
                            "--agent-prompt-type" "$prompt_type"
                            "--agent-provider" "$agent_provider"
                            "--vulnerabilities-iterations" "$iter"
                            "--exclude" "**/.github/**"
                            "--vulnerabilities-threat-actor" "$threat_actor"
                            "--included-classes-of-vulnerabilities" "$included_classes"
                            "-p" "$project_type"
                            "--files-context-window" "$ctx"
                            "--files-chunk-size" "$chunk"
                            "--vulnerabilities-github-repo-url" "$github_repo_url"
                            "--recursion-limit" "100"
                        )
                        
                        echo "Running: python ai_security_analyzer/app.py ${ARGS[@]}"
                        
                        python ai_security_analyzer/app.py "${ARGS[@]}"
                        
                        sleep 10
                    done
                done
            done
        done
    done
done