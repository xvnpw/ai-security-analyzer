## Vulnerability List

- **Vulnerability Name:** Arbitrary Command Execution via Malicious Workspace Configuration

  - **Description:**
    An attacker who can inject or modify the workspace configuration (such as by committing a malicious “.vscode/settings.json” file to a repository) can set the “deno.path” option to point to a malicious executable. When a victim opens the workspace in Visual Studio Code with the Deno extension enabled, the extension reads this configuration value and uses it as the path to the Deno CLI. Because the extension does not validate or sanitize the “deno.path” setting, the malicious executable will be spawned with arguments (e.g., “lsp” during language server startup or task execution), thereby allowing an attacker to run arbitrary code on the victim’s machine.

    _Step-by-step exploitation:_
    1. The attacker creates or modifies a “.vscode/settings.json” file in a repository with contents such as:
       ```json
       {
         "deno.path": "/absolute/path/to/malicious_executable"
       }
       ```
    2. The victim clones the repository and opens it in Visual Studio Code.
    3. During startup (for instance, when executing the “Deno: Enable” command or when the extension starts the language server), the extension calls its helper functions (e.g. `getDenoCommandPath()` in “client/src/util.ts”) to obtain the executable path.
    4. Because the configuration value is used unsanitized, the malicious path is returned and used as the command to run.
    5. The extension invokes the command (for example, by using it in the creation of the language server process or in building a task via `buildDenoTask()`), thereby executing the malicious executable with attacker‑controlled parameters.

  - **Impact:**
    - **Arbitrary Command Execution:** The victim’s system executes the attacker-controlled executable with the same privileges as the VSCode process, potentially leading to full system compromise.
    - **Enterprise Risks:** In environments with elevated privileges or sensitive data access, this vulnerability could lead to further lateral movement and data exfiltration.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The code verifies whether a configured path exists by using functions like `fileExists()` (in “client/src/util.ts”), but this check only confirms the file’s existence and does not validate whether it is a genuine Deno executable.

  - **Missing Mitigations:**
    - **Input Validation / Whitelisting:** There is no verification that the “deno.path” points to a trusted installation of Deno. A whitelist of permitted directories or a signature check on the executable is missing.
    - **User Confirmation:** The extension does not prompt or warn the user if a nondefault or suspicious “deno.path” value is detected.
    - **Sandboxing:** The spawned process is not sandboxed or executed with restricted privileges.

  - **Preconditions:**
    - The attacker must be able to supply or modify the workspace configuration (for example, by committing a malicious “.vscode/settings.json” file to a repository).
    - The victim must open the workspace (or otherwise load the manipulated configuration) in Visual Studio Code with the Deno extension enabled.
    - The malicious executable (or a shim that executes attacker‑controlled code) must be present at the specified path or be deployable within the environment.

  - **Source Code Analysis:**
    - **client/src/util.ts:**
      - The function `getDenoCommandPath()` calls `getWorkspaceConfigDenoExePath()`, which retrieves the configuration value for “deno.path” directly from the workspace settings:
        ```ts
        function getWorkspaceConfigDenoExePath() {
          const exePath = workspace.getConfiguration(EXTENSION_NS).get<string>("path");
          if (typeof exePath === "string" && exePath.trim().length === 0) {
            return undefined;
          } else {
            return exePath;
          }
        }
        ```
      - If a relative path is provided, the code resolves it against the workspace folder using `path.resolve(...)`.
      - The only validation performed is a check that the file exists (via `fileExists()`), without verifying whether it is indeed a trusted Deno executable.
    - **client/src/extension.ts:**
      - In `startLanguageServer()`, the value obtained from `getDenoCommandPath()` is used as the `command` in the `serverOptions` for the LanguageClient:
        ```ts
        const command = await getDenoCommandPath();
        // ...
        const serverOptions: ServerOptions = {
            run: { command, args: ["lsp"], options: { env } },
            debug: { command, args: ["lsp"], options: { env } },
        };
        ```
      - The same unsanitized command is also used when constructing task executions in **client/src/tasks.ts**.
    - This lack of proper validation in the configuration retrieval process makes it an ideal attack vector for arbitrary command execution.

  - **Security Test Case:**
    1. **Setup:**
       - Create a dummy repository that includes a “.vscode/settings.json” file with the following content:
         ```json
         {
           "deno.path": "/absolute/path/to/malicious_simulator.sh"
         }
         ```
       - Develop a script named `malicious_simulator.sh` (or the corresponding executable on Windows) that logs its invocation—e.g., by writing a message to a log file or displaying a dialog—and ensure it has executable permissions.
    2. **Execution:**
       - Open the repository in Visual Studio Code with the Deno extension installed.
       - Trigger the language server startup (e.g., by running the “Deno: Enable” command) or execute any Deno CLI task as defined in “client/src/tasks.ts”.
    3. **Verification:**
       - Confirm that the malicious script is executed by checking for the expected log output or another predefined indicator.
       - Verify that the Deno extension is using the path specified in “.vscode/settings.json”, thereby validating that an attacker-controlled configuration can force the execution of an arbitrary program.
    4. **Environment:**
       - Conduct this test in a controlled environment (such as a virtual machine or container) to safely simulate an arbitrary code execution scenario.
