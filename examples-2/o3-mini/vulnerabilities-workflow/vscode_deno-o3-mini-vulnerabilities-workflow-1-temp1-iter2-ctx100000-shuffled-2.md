# Vulnerability List

Below is the list of high-severity vulnerabilities that allow remote code execution (RCE) via manipulated workspace configuration and content. These vulnerabilities have a rank of at least high, are valid, and have not been fully mitigated. They fall under the classes of RCE, command injection, and code injection.

---

## Vulnerability 1: Malicious Workspace Configuration – Deno Executable Path Injection

**Description:**
A malicious repository can include a workspace settings file (for example, in `.vscode/settings.json`) that sets the `"deno.path"` configuration to an attacker–controlled executable (for instance, a relative path that resolves to a malicious binary included in the repository). When the extension starts the Deno language server, it calls the utility functions to read the value of `"deno.path"` without any additional validation or sanitization. If the workspace is trusted (or the victim accepts the repository as safe), the extension will resolve and use the attacker–supplied binary for all subsequent Deno operations.

**Impact:**
Arbitrary code execution on the victim’s machine with the same privileges as VSCode. This may lead to further system compromise, data exfiltration, or privilege escalation.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The extension relies on VSCode’s workspace configuration API and—by default—the built–in workspace trust mechanism.
- Relative paths are resolved against the workspace folder; however, no further checks are performed.

**Missing Mitigations:**
- No explicit sanitization or whitelisting of the executable path is performed.
- There is no additional prompt or validation to confirm that a non–standard executable is being used.

**Preconditions:**
- The attacker supplies a repository containing a `.vscode/settings.json` with an attacker–controlled `"deno.path"` value.
- The corresponding malicious executable is present at the specified relative or absolute location.
- The user opens and trusts the workspace.

**Source Code Analysis:**
- In **`util.ts`**, the function `getWorkspaceConfigDenoExePath()` simply reads the `deno.path` setting from the workspace without sanitization.
- In **`getDenoCommandPath()`**, if the path is relative, the extension resolves it against each workspace folder and checks for its existence using a file–system stat call.
- In **`commands.ts`** (inside the `startLanguageServer` function), the returned command is used directly to construct the child process execution via `vscode.ProcessExecution`.

**Security Test Case:**
1. In a test repository, include a `.vscode/settings.json` file with an entry such as:
   ```json
   {
     "deno.path": "./malicious_script"
   }
   ```
2. Place a crafted executable (e.g., a script or binary named `malicious_script` that performs a visible malicious action such as writing to disk or launching a reverse shell) in the repository root.
3. Open the repository in VSCode and trust the workspace.
4. Trigger the command that starts or restarts the Deno language server (for example, by running “Deno: Enable”).
5. Observe that the malicious executable is invoked, thereby confirming that arbitrary code can be executed.

---

## Vulnerability 2: Malicious Workspace Configuration – Environment Variable Injection via _envFile_

**Description:**
The extension allows the workspace to specify an environment file via the `"deno.envFile"` configuration setting. When present, the extension reads the file using `fs.readFileSync` and parses its content with `dotenv.parse`, merging the resulting key–value pairs into the environment for all spawned child processes (such as the language server or tasks). An attacker can supply a malicious environment file that sets dangerous variables (for example, dynamic linker preload settings such as `LD_PRELOAD` on Linux or `DYLD_INSERT_LIBRARIES` on macOS) to alter the behavior of the executed process.

**Impact:**
Manipulation of the process environment can lead to arbitrary code execution (for example, by forcing the dynamic linker to load a malicious library), which in turn may allow full system compromise or privilege escalation.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The extension simply merges the environment variables from the file into the process environment via standard parsing with `dotenv.parse`.
- It relies on the VSCode workspace trust model so that untrusted workspaces are not opened by default.

**Missing Mitigations:**
- There is no whitelist or validation of environment variable keys/values that are loaded from the file.
- No warning is issued to the user if high–risk environment variables (e.g. `LD_PRELOAD`) are being set.

**Preconditions:**
- The attacker provides a repository that defines a `"deno.envFile"` setting in its `.vscode/settings.json` file that points to an attacker–controlled file (for example, `"malicious.env"`).
- The malicious environment file includes variables that can influence process behavior in a dangerous way.
- The user opens and trusts the workspace.

**Source Code Analysis:**
- In **`upgrade.ts`** (inside `denoUpgradePromptAndExecute`) and in **`commands.ts`** (inside the `startLanguageServer` function), the extension retrieves the `"envFile"` setting from configuration.
- If set and if a workspace folder exists, it constructs the full path, reads the file synchronously using `readFileSync`, and then parses it using `dotenv.parse`.
- The parsed variables are merged into the `env` object without any filtering before being passed to the child process execution.

**Security Test Case:**
1. Create a test repository with a `.vscode/settings.json` file that includes:
   ```json
   {
     "deno.envFile": "malicious.env"
   }
   ```
2. In the repository, create a file named `malicious.env` that sets a dangerous variable, for example:
   ```
   LD_PRELOAD=/path/to/attacker_library.so
   ```
3. Open the repository in VSCode and mark it as trusted.
4. Execute an extension command that spawns a Deno process (for example, “Deno: Upgrade” or starting the language server).
5. Verify via process monitoring or logs that the spawned process inherits the malicious variable, thus demonstrating the injection potential.

---

## Vulnerability 3: Malicious Task Definitions Injection via tasks.json Manipulation

**Description:**
The extension processes task definitions by reading and parsing the workspace’s `tasks.json` file using a JSON–with–comments parser (`jsonc-parser`). A malicious repository can include a crafted `tasks.json` file that defines tasks with attacker–controlled command names and arguments. When a user views or executes a task from the extension’s tasks sidebar, the extension builds the task using the provided values and executes it with `vscode.ProcessExecution`. Although tasks execute via an arguments array (which avoids classic shell–based injection), the very fact that the command to be executed is attacker–controlled opens up a vector for arbitrary command execution if the user inadvertently triggers it.

**Impact:**
When a user runs the malicious task (for example, via the command palette or tasks sidebar), an attacker–provided command is executed. This can result in full remote code execution, allowing arbitrary actions (such as file deletion, reverse shell, etc.) to be carried out under the user’s privileges.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- Task execution uses VSCode’s ProcessExecution with a pre–constructed argument array so that there is no direct shell interpolation.
- Tasks are only spawned after an explicit user action through the tasks sidebar or command.

**Missing Mitigations:**
- No validation or sanitization is performed on the task definitions read from `tasks.json`.
- The extension does not warn the user or require additional confirmation when tasks are defined by the workspace.

**Preconditions:**
- The attacker supplies a repository that includes a malicious `tasks.json` file containing task definitions with dangerous commands and arguments.
- The user opens this repository and then manually triggers the execution of one of the tasks (for example, from the tasks sidebar).

**Source Code Analysis:**
- In **`util.ts`**, the function `readTaskDefinitions` parses the workspace file (typically `tasks.json`) using `jsoncParser.parseTree` and iterates over the task properties without sanitizing the values.
- In **`tasks_sidebar.ts`**, the tasks are used to build VSCode tasks through functions such as `buildDenoConfigTask` and `buildDenoTask`.
- These tasks are then executed via `vscode.tasks.executeTask` once the user selects one.

**Security Test Case:**
1. In a controlled test repository, create a malicious `tasks.json` file that contains a task definition with a dangerous command (for example, `"command": "malicious_command"` with crafted arguments that perform destructive actions).
2. Open the repository in VSCode with the Deno extension installed.
3. Navigate to the tasks sidebar and select the malicious task.
4. Execute the task and monitor system behavior or logs to confirm that the malicious command is run.
5. Document the effect (e.g. creation of an unexpected file, deletion of a test file, etc.) to demonstrate arbitrary command execution.
