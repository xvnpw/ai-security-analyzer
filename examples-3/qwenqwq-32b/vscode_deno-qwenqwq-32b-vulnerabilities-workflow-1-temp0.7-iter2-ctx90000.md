# Combined Vulnerability Report

## 1. Task Definition Argument Injection
**Vulnerability Name:** Task Definition Argument Injection
**Description:**
The extension executes Deno tasks defined in `deno.json` files without validating or sanitizing user-provided arguments. An attacker can create a malicious `deno.json` file specifying tasks with crafted arguments that execute arbitrary commands.

**Step to Trigger:**
1. Create a malicious `deno.json` file in a project directory with a task like:
```json
{
  "tasks": {
    "malicious-task": {
      "command": "run",
      "args": ["--allow-run", "/path/to/malicious.sh"]
    }
  }
}
```
2. The user opens the project in VSCode and runs the task via the Tasks sidebar or command palette.

**Impact:**
The task executes malicious code with permissions granted by Deno CLI, leading to **Remote Code Execution (RCE)** in the context of the user's system.

**Vulnerability Rank:** Critical
**Currently Implemented Mitigations:** None. The extension reads task arguments as-is.
**Missing Mitigations:** Input validation/sanitization of task arguments.
**Preconditions:** Attacker must control the project's `deno.json` file (e.g., via a malicious repository).

**Source Code Analysis:**
- `tasks_sidebar.ts` parses task definitions without validation.
- `tasks.ts` builds tasks using user-provided `args` directly:
  ```typescript
  const args = [definition.command].concat(definition.args ?? []);
  ```

**Security Test Case:**
1. Create a malicious repository with `deno.json` containing a harmful task.
2. Open the repository in VSCode and run the task.
3. Observe arbitrary code execution (e.g., a script that creates a file or runs `whoami`).

---

## 2. Test Argument Injection
**Vulnerability Name:** Test Argument Injection
**Description:**
The extension uses user-configured `deno.codeLens.testArgs` to pass arguments to Deno test commands without validation. Attackers can set these arguments to include malicious flags or code paths.

**Step to Trigger:**
1. Configure `settings.json` with malicious test arguments:
```json
"deno.codeLens.testArgs": ["--allow-run", "/path/to/attack.ts"]
```
2. Run a test via the Test Explorer or code lens, which executes the test with the injected arguments.

**Impact:**
Arbitrary commands execute under Deno's permissions, enabling **RCE**.

**Vulnerability Rank:** High
**Currently Implemented Mitigations:** None. The arguments are used directly.
**Missing Mitigations:** Validation of test arguments.
**Preconditions:** User must explicitly misconfigure settings or use a compromised workspace (e.g., via a malicious `settings.json` in a project's `.vscode/` folder).

**Source Code Analysis:**
- `commands.ts` appends `testArgs` directly to command-line arguments:
  ```typescript
  const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
  ```

**Security Test Case:**
1. Set malicious test arguments in VSCode settings.
2. Run a test and observe execution of harmful code (e.g., via a script that outputs system information).

---

## 3. Executable Path Spoofing
**Vulnerability Name:** Executable Path Spoofing
**Description:**
The extension uses the `deno.path` configuration to locate the Deno executable. If this points to a malicious binary (e.g., placed in a workspace folder), the extension executes it when starting the language server, leading to **RCE**.

**Step to Trigger:**
1. Create a malicious `deno` executable in a project directory.
2. Configure `deno.path` to point to the malicious binary:
```json
"deno.path": "./malicious_deno"
```
3. Restart VSCode or trigger the language server (e.g., via `Deno: Enable`).

**Impact:**
The malicious binary runs with privileges of the user, enabling full system compromise.

**Vulnerability Rank:** Critical
**Currently Implemented Mitigations:** Only checks existence, not authenticity.
**Missing Mitigations:** Path validation (e.g., checking against known good binaries).
**Preconditions:** Attacker must control the workspace's `deno.path` configuration.

**Source Code Analysis:**
- **File 1:** `client/src/commands.ts`
  ```typescript
  const command = await getDenoCommandPath();
  // ...
  const serverOptions: ServerOptions = {
    run: {
      command,
      args: ["lsp"],
      options: { env },
    },
  };
  ```
- **File 2:** `client/src/util.ts`
  ```typescript
  function getWorkspaceConfigDenoExePath() {
    const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
    return exePath;
  }
  ```

**Security Test Case:**
1. Place a malicious Deno executable in a project folder.
2. Set `deno.path` to the malicious path.
3. Observe the malicious executable executing during language server startup (e.g., via network exfiltration or file creation).

---

## 4. Command Injection via Task Definitions (VS Code Tasks)
**Vulnerability Name:** Command Injection via Task Definitions
**Description:**
The extension executes VS Code tasks configured in `tasks.json` using the Deno CLI. Task arguments and environment variables are passed directly to the shell, allowing attackers to inject malicious commands via shell metacharacters (e.g., `;`, `&&`, `|`).

**Step to Trigger:**
1. **Malicious Task Configuration**: Add a task in `tasks.json` with injected commands:
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
2. **Execution**: Run the task via the VSCode task runner.

**Impact:**
Attackers can execute arbitrary commands in the context of the VSCode task runner, leading to data destruction or unauthorized access.

**Vulnerability Rank:** High
**Currently Implemented Mitigations:** None. Task arguments are passed to the CLI without sanitization.
**Missing Mitigations:** Sanitize task arguments to escape shell metacharacters.
**Preconditions:** Attacker can control task definitions (e.g., via a malicious repository's `tasks.json`).

**Source Code Analysis:**
- **File:** `client/src/tasks.ts`
  - **Function:** `buildDenoTask` constructs command arguments directly from task definitions:
    ```typescript
    const args = [definition.command].concat(definition.args ?? []);
    const task = buildDenoTask(..., [command, ...args], ...);
    ```

**Security Test Case:**
1. **Setup**: Create a malicious `tasks.json` with the above payload.
2. **Trigger**: Run the task via the VSCode task runner.
3. **Verification**: Check `/tmp/exploit.txt` for the injected command's output.
