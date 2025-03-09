# Vulnerability Report

The following vulnerabilities were identified across both lists, combined into a single report:

---

### 1. **Vulnerability Name:** Command Injection via Deno Task Definitions
**Description:**
An attacker can create a malicious Deno task configuration in the project's `deno.json` or `tasks.json` file, specifying a task with malicious command-line arguments. The extension executes these commands without proper sanitization, leading to command injection. Specifically, an attacker can define a task with shell metacharacters (e.g., `; rm -rf /`), which execute unintended commands.

**Impact:**
Attackers can execute arbitrary commands on the user's machine with the privileges of the VSCode process, leading to full system compromise, data theft, or disruption.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:** None.

**Missing Mitigations:**
User-provided task commands and arguments must be sanitized to block shell metacharacters. Input validation should restrict commands to safe parameters.

**Preconditions:**
- The victim must have the extension installed and enabled.
- The attacker must control the project's configuration files (`deno.json` or `tasks.json`).

**Source Code Analysis:**
1. In `tasks.ts`, `buildDenoTask` constructs commands using user-provided `definition.command` and `args`:
   ```typescript
   const args = [definition.command].concat(definition.args ?? []);
   return buildDenoTask(workspaceFolder, process, definition, command, args, ...);
   ```
   Here, `definition.command` and `args` come from user-controlled JSON configurations.
2. `util.ts` parses task definitions without sanitization:
   ```typescript
   const taskValue = taskProperty.children?.[1];
   command = taskValue.value; // Directly uses user-provided string
   ```
3. The command is executed via `ProcessExecution`:
   ```typescript
   new vscode.ProcessExecution(process, ["task", ...args]);
   ```
   This passes unsanitized arguments directly to the shell, enabling injection.

**Security Test Case:**
1. Create a malicious `deno.json`:
   ```json
   {
     "tasks": {
       "malicious": "run --allow-run '; echo EXPLOIT > /tmp/exploit.txt'"
     }
   }
   ```
2. Open the project in VSCode with the extension enabled.
3. Run the "malicious" task via the task interface.
4. Verify `/tmp/exploit.txt` exists, confirming command execution.

---

### 2. **Vulnerability Name:** Arbitrary Command Execution via `deno.path` Configuration
**Description:**
The `deno.path` configuration allows specifying the Deno executable path. An attacker can set this to a malicious binary, leading the extension to execute arbitrary code. The extension resolves the path without verifying its integrity, allowing execution of a user-specified executable.

**Impact:**
Attackers can execute arbitrary code by pointing `deno.path` to a malicious binary, leading to full system compromise.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:** None.

**Missing Mitigations:**
The Deno executable path must be validated (e.g., checksum verification) or restricted to trusted locations.

**Preconditions:**
- The victim must configure `deno.path` to a malicious binary location.
- The attacker must have write access to the configured path (if it's within the workspace).

**Source Code Analysis:**
1. In `util.ts`, `getDenoCommandPath` resolves paths without validation:
   ```typescript
   if (!path.isAbsolute(command)) {
     for (const workspace of workspaceFolders) {
       const commandPath = path.resolve(workspace.uri.fsPath, command);
       if (await fileExists(commandPath)) {
         return commandPath; // Returns attacker-controlled path
       }
     }
   }
   ```
   This allows execution of any executable within a workspace folder.

**Security Test Case:**
1. Create a malicious `deno` executable with a payload (e.g., writes to `/tmp/exploit`).
2. Place it in a workspace directory (e.g., `./malicious/deno`).
3. Set `deno.path` in VSCode settings to `"./malicious/deno"`.
4. Trigger a Deno command via the extension (e.g., debugging).
5. Verify the malicious payload executes (e.g., `/tmp/exploit` exists).

---

### 3. **Vulnerability Name:** Default Test Arguments Enable Arbitrary Code Execution (RCE)
**Description:**
The extension sets a default configuration for test runs (`deno.codeLens.testArgs`) to `["--allow-all"]`. This flag grants full permissions to any test executed via the test code lens. An attacker can exploit this by providing a malicious test file (e.g., a Deno script that executes shell commands) within a manipulated project. When the user runs the test via the code lens, the malicious script executes with unrestricted privileges, leading to RCE.

**Step-by-Step Trigger:**
1. **Malicious Repository Setup:**
   - Create a malicious Deno test file (e.g., `test.ts`) that contains code to execute arbitrary commands, such as:
     ```typescript
     Deno.run({ cmd: ["sh", "-c", "echo 'Malicious Output' > /tmp/exploit.txt"] });
     ```
   - Ensure the test file is part of a project that uses a `deno.json` or `deno.jsonc` to enable Deno.
2. **User Execution:**
   - The victim opens the malicious project in VSCode with the Deno extension installed.
   - The victim right-clicks the test code and selects "Run Test" (using the test code lens).
3. **Exploitation:**
   - The extension runs the test with `deno test --allow-all`, which executes the malicious code, granting full access to the system.

**Impact:**
- An attacker can execute arbitrary commands on the user’s system, such as file deletion, data exfiltration, or cryptocurrency mining.
- Severity: **Critical** (CVE-2023-XXXXX).

**Vulnerability Rank:** Critical

**Current Mitigations:**
- The default `deno.codeLens.testArgs` is explicitly set to `["--allow-all"]` in the [VS Code configuration documentation](https://github.com/denoland/vscode_deno/blob/main/README.md#configuration).

**Missing Mitigations:**
- The extension should not enable dangerous defaults like `--allow-all`. The default test arguments should restrict permissions or require explicit user approval.

**Preconditions:**
- The victim must have the Deno extension installed.
- The malicious test file must be part of a project that triggers Deno’s test runner via the code lens.

**Source Code Analysis:**
- **File:** `../vscode_deno/README.md`:
  ```markdown
  - "deno.codeLens.testArgs": Provides additional arguments that should be set when executing the Deno CLI test command. **Defaults to `["--allow-all"]`**.
  ```
- **File:** `../vscode_deno/client/src/commands.ts`:
  The `test` command logic constructs test arguments using `config.get<string[]>("codeLens.testArgs")`, which includes the default `--allow-all` flag.

**Security Test Case:**
1. **Setup:**
   - Create a malicious project with `deno.json` and `test.ts` (as described above).
   - Ensure the Deno extension is installed in VSCode.
2. **Trigger:**
   - Open the project in VSCode and run the test via the test code lens.
3. **Verify:**
   - Check if the malicious command executes (e.g., `/tmp/exploit.txt` is created).
