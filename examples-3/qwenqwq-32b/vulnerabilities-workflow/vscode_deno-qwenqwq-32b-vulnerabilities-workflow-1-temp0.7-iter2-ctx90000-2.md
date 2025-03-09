# Vulnerability List

## 1. Insecure Deno Path Configuration Leading to RCE (Critical)

### Description
The extension allows users to specify the Deno executable path via the `deno.path` setting. When starting the Deno Language Server, the extension constructs the command using this path without validating its integrity. An attacker could set `deno.path` to a malicious executable (e.g., a script or binary that performs arbitrary actions), which would be executed when the language server starts, leading to Remote Code Execution (RCE).

### Step-by-Step Trigger:
1. **Malicious Configuration**: Set `deno.path` to a malicious path (e.g., `"/tmp/evil_deno"`).
2. **Restart Extension**: The extension restarts the Language Server, which executes `/tmp/evil_deno` instead of the legitimate Deno binary.
3. **Exploit**: The malicious executable runs with the privileges of the victim's VSCode process, executing arbitrary code.

### Impact
Attackers can execute arbitrary code with the permissions of the VSCode instance. This includes accessing project files, network resources, or system-level commands.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
None. The code uses `deno.path` directly without validation.

### Missing Mitigations
- Validate that `deno.path` points to a trusted Deno executable (e.g., using checksum verification or path constraints).
- Sanitize and validate the path to prevent arbitrary command execution.

### Preconditions
- User has write access to VSCode settings to set `deno.path`.
- The attacker can control the content of the path specified in `deno.path`.

### Source Code Analysis
- **File**: `client/src/commands.ts`
  - **Function**: `startLanguageServer` uses `getDenoCommandPath` to resolve the Deno path.
  - **Vulnerable Code**:
    ```typescript
    const command = await getDenoCommandPath();
    if (command == null) {
      // ...
    }
    const serverOptions: ServerOptions = {
      run: {
        command,
        args: ["lsp"],
        options: { env },
      },
    };
    ```
  - The `command` is directly used as the executable path without validation.

- **File**: `client/src/util.ts`
  - **Function**: `getWorkspaceConfigDenoExePath` retrieves `deno.path` from configuration:
    ```typescript
    function getWorkspaceConfigDenoExePath() {
      const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
      return exePath;
    }
    ```

### Security Test Case
1. **Setup**: Create a malicious script (e.g., `evil_deno.sh`) that executes `echo "Exploited!" > /tmp/exploit.txt`.
2. **Configuration**:
   - Set `deno.path` in VSCode settings to the malicious script's path.
3. **Trigger**: Restart the VSCode Deno extension to start the Language Server.
4. **Verification**: Check for `exploit.txt` creation, indicating RCE.

---

## 2. Command Injection via Task Definitions (High)

### Description
The extension executes tasks configured in `deno.json` or `tasks.json` using the Deno CLI. Task arguments and environment variables are passed directly to the shell. An attacker can craft malicious task definitions with arguments containing shell metacharacters (e.g., `;`, `&&`, `|`), leading to command injection and arbitrary code execution.

### Step-by-Step Trigger:
1. **Malicious Task Configuration**: Add a task in `tasks.json` with injected commands:
   ```json
   {
     "type": "deno",
     "command": "run",
     "args": ["script.ts", "; rm -rf /"]
   }
   ```
2. **Execution**: Run the task via the VSCode task runner.
3. **Exploit**: The shell interprets the injected command, executing the malicious payload.

### Impact
Attackers can execute arbitrary commands in the context of the VSCode task runner, leading to data destruction or unauthorized access.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. Task arguments are passed to the CLI without sanitization.

### Missing Mitigations
- Sanitize task arguments to escape shell metacharacters.
- Validate task definitions to prevent command injection.

### Preconditions
- Attacker can control task definitions (e.g., via a malicious repository's `deno.json` or `tasks.json`).

### Source Code Analysis
- **File**: `client/src/tasks.ts`
  - **Function**: `buildDenoTask` constructs command arguments directly from task definitions:
    ```typescript
    const args = [definition.command].concat(definition.args ?? []);
    const task = buildDenoTask(..., [command, ...args], ...);
    ```
  - **Function**: `buildDenoConfigTask` uses user-provided arguments:
    ```typescript
    const args = [];
    if (sourceUri) { ... }
    args.push("-c", configPath);
    args.push(name);
    ```

### Security Test Case
1. **Setup**: Create a malicious `tasks.json` with:
   ```json
   {
     "version": "2.0.0",
     "tasks": [
       {
         "type": "deno",
         "command": "run",
         "args": ["script.ts", "; echo 'ATTACK' > /tmp/exploit.txt"]
       }
     ]
   }
   ```
2. **Trigger**: Run the task via the VSCode task runner.
3. **Verification**: Check `/tmp/exploit.txt` for the injected command's output.
```

### Explanation:
- Both vulnerabilities are **RCE/Command Injection** with **Critical/High rank**, valid, and unmitigated. They meet the inclusion criteria.
- Exclusion criteria (developer insecure code, DoS, documentation-only fixes) do not apply here.
- The vulnerabilities are straightforwardly applicable to attacker-controlled repositories and settings.
