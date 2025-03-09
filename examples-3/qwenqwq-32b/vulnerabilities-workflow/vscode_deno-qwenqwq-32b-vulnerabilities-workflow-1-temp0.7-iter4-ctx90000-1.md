# Vulnerability List

## 1. Command Injection via Task Definitions in Deno Configuration Files

### Vulnerability Name: Deno Task Configuration Command Injection
### Description:
The extension supports executing Deno tasks defined in configuration files like `deno.json`. When a malicious repository defines tasks with crafted command-line arguments, these arguments are directly passed to the Deno CLI without proper sanitization or validation. This allows an attacker to inject arbitrary commands that are executed with the permissions of the user running VSCode.

#### Trigger Steps:
1. An attacker creates a malicious repository containing a `deno.json` file with a task definition containing malicious command arguments (e.g., `{"tasks": {"malicious_task": {"command": "run", "args": ["--allow-run", "sh -c 'rm -rf /'"]}}`).
2. The victim opens the repository in VSCode and runs the malicious task via the tasks sidebar or command palette.
3. The extension executes the task using the unsanitized arguments, leading to arbitrary command execution.

### Impact:
An attacker can execute arbitrary commands on the victim's machine, leading to remote code execution (RCE). This includes deleting files, stealing data, or deploying malware.

### Vulnerability Rank: Critical
### Currently Implemented Mitigations:
- None. The extension directly uses user-provided arguments without validation.
### Missing Mitigations:
- Input validation and sanitization of task arguments to prevent shell metacharacters.
- Restricting allowed command-line flags for Deno tasks.
### Preconditions:
- The victim must open a malicious workspace containing a `deno.json` file defining vulnerable tasks.
### Source Code Analysis:
- **File:** `client/src/tasks.ts`
  - The `buildDenoTask` function constructs task commands using `args` from task definitions without sanitization:
    ```typescript
    const args = [definition.command].concat(definition.args ?? []);
    ```
  - **Vulnerable Line:** The `args` array is directly passed to the process execution, allowing arbitrary command injection.

### Security Test Case:
1. Create a malicious `deno.json` file with a task like:
```json
{
  "tasks": {
    "attack": {
      "command": "run",
      "args": ["--allow-run", "echo 'Command Injection Test' > /tmp/injection_success"]
    }
  }
}
```
2. Open this repository in VSCode and run the task via the Tasks sidebar.
3. Check if `/tmp/injection_success` is created, confirming command execution.
