#!/bin/bash

declare -A models
# models["o1"]="openai"
models["o3-mini"]="openai"
models["gemini-2.0-flash-thinking-exp"]="google"
models["anthropic/claude-3.7-sonnet:thinking"]="openrouter"

# deep_analysis_models["gemini-2.0-pro-exp"]="google"
# deep_analysis_models["gemini-2.0-flash-thinking-exp"]="google"

declare -A temperatures
# temperatures["o1"]="1"
temperatures["o3-mini"]="1"
temperatures["gemini-2.0-flash-thinking-exp"]="0.7 1"
temperatures["anthropic/claude-3.7-sonnet:thinking"]="1"

dirs=("vscode-laravel-extra-intellisense" "vscode_deno" "vscode-csharp")

declare -A context_windows
context_windows["gemini-2.0-flash-thinking-exp"]="71000 150000 250000 500000"
context_windows["anthropic/claude-3.7-sonnet:thinking"]="100000"
context_windows["o3-mini"]="100000"

declare -A chunk_sizes
chunk_sizes["gemini-2.0-flash-thinking-exp"]="60000 140000 240000 490000"
chunk_sizes["anthropic/claude-3.7-sonnet:thinking"]="90000"
chunk_sizes["o3-mini"]="90000"

declare -A iterations
iterations["gemini-2.0-flash-thinking-exp"]="2 4 6 8"
iterations["anthropic/claude-3.7-sonnet:thinking"]="2 4"
iterations["o3-mini"]="2 4"

agent_prompt_type="vulnerabilities-workflow-1"

for dir in "${dirs[@]}"; do
    for agent_model in "${!models[@]}"; do
        agent_provider="${models[$agent_model]}"
        safe_agent_model=$(echo $agent_model | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]_.-')
        
        # Read the temperatures as an array
        read -ra temp_array <<< "${temperatures[$agent_model]}"
        
        # Read the context windows and chunk sizes as arrays
        read -ra ctx_array <<< "${context_windows[$agent_model]}"
        read -ra chunk_array <<< "${chunk_sizes[$agent_model]}"
        
        # Read the iterations as an array
        read -ra iter_array <<< "${iterations[$agent_model]}"
        
        # Loop through each temperature
        for temp in "${temp_array[@]}"; do
            # Loop through context windows and corresponding chunk sizes
            for i in "${!ctx_array[@]}"; do
                ctx="${ctx_array[$i]}"
                chunk="${chunk_array[$i]}"
                
                # Loop through each iteration count
                for iter in "${iter_array[@]}"; do
                    echo "Generating example for $dir with model $agent_model, temp $temp, context $ctx, chunk $chunk, iterations $iter"
                    
                    output_file="examples-2/${dir}-${safe_agent_model}-t${temp}-i${iter}-c${ctx}.md"
                    
                    # Use an array for arguments to avoid shell parsing/quoting issues
                    ARGS=(
                        "dir"
                        "-t" "../${dir}/"
                        "-v"
                        "-o" "$output_file"
                        "--agent-model" "$agent_model"
                        "--agent-temperature" "$temp"
                        "--agent-prompt-type" "$agent_prompt_type"
                        "--agent-provider" "$agent_provider"
                        "--vulnerabilities-iterations" "$iter"
                        "--exclude" "**/.github/**"
                        "--vulnerabilities-threat-actor" "vscode_extension_malicious_repo"
                        "--included-classes-of-vulnerabilities" "RCE, Command Injection, Code Injection"
                        "-p" "javascript"
                        "--files-context-window" "$ctx"
                        "--files-chunk-size" "$chunk"
                    )
                    
                    echo "Running: python ai_security_analyzer/app.py ${ARGS[@]}"
                    
                    python ai_security_analyzer/app.py "${ARGS[@]}"
                    
                    sleep 10
                done
            done
        done
    done
done