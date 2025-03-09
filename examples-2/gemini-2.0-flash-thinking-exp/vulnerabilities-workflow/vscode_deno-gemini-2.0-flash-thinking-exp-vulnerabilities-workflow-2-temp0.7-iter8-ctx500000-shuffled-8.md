### Vulnerability List

- Vulnerability Name: **Unsafe handling of `deno.path` configuration leading to arbitrary command execution**
- Description:
    1. The extension allows users to configure the path to the Deno executable via the `deno.path` setting.
    2. This path is used to execute Deno CLI commands for various features like language server, testing, and tasks.
    3. If a malicious user can control the `deno.path` setting, they can point it to a malicious executable instead of the legitimate Deno CLI.
    4. When the extension attempts to execute Deno commands, it will inadvertently execute the malicious executable, leading to arbitrary code execution within the user's VS Code environment.
    5. An attacker can achieve control over the `deno.path` setting by crafting a malicious workspace configuration file (`.vscode/settings.json`) within a Deno project.
    6. When a user opens this malicious Deno project in VS Code with the extension enabled, the extension reads and applies the workspace settings, including the attacker-controlled `deno.path`.
    7. Subsequent actions within VS Code that trigger Deno CLI execution (e.g., starting the language server, running tests, executing tasks) will execute the malicious command.
- Impact: Arbitrary code execution within the user's VS Code environment. This could allow an attacker to:
    - Steal sensitive information (credentials, source code, etc.).
    - Modify or delete files.
    - Install malware or further malicious extensions.
    - Pivot to other systems accessible from the user's environment.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The extension directly uses the configured `deno.path` without validation or sanitization.
- Missing Mitigations:
    - Input validation and sanitization for the `deno.path` setting.
    - Checking if the provided path points to a valid Deno executable.
    - Potentially restricting `deno.path` configuration to user settings only, preventing workspace-level configuration.
    - Displaying a warning message when `deno.path` is changed or when the extension detects a potentially unusual path.
- Preconditions:
    1. The user must have the "Deno for Visual Studio Code" extension installed and enabled.
    2. The user must open a malicious Deno project that contains a crafted `.vscode/settings.json` file.
- Source Code Analysis:
    1. **`client\src\util.ts:getDenoCommandPath()`**: This function retrieves the `deno.path` setting from the workspace configuration:
       ```typescript
       function getWorkspaceConfigDenoExePath() {
           const exePath = workspace.getConfiguration(EXTENSION_NS)
               .get<string>("path");
           // it is possible for the path to be blank. In that case, return undefined
           if (typeof exePath === "string" && exePath.trim().length === 0) {
               return undefined;
           } else {
               return exePath;
           }
       }
       ```
       It directly retrieves the string value of `deno.path` without any validation.
    2. **`client\src\util.ts:getDenoCommandName()`**: This function calls `getDenoCommandPath()` and defaults to "deno" if no path is configured:
       ```typescript
       export async function getDenoCommandName() {
           return await getDenoCommandPath() ?? "deno";
       }
       ```
    3. **`client\src\debug_config_provider.ts:getDenoCommandName()`**:  The `getDenoCommandName` utility function is used to determine the `runtimeExecutable` for debugging configurations:
       ```typescript
       runtimeExecutable: await getDenoCommandName(),
       ```
    4. **`client\src\tasks.ts:buildDenoTask()` and `client\src\tasks_sidebar.ts`**: Task execution also relies on `getDenoCommandName()` to determine the Deno executable path.
    5. **`client\src\commands.ts:startLanguageServer()`**: The language server startup uses `getDenoCommandPath()`:
       ```typescript
       const command = await getDenoCommandPath();
       if (command == null) { ... }
       const serverOptions: ServerOptions = {
           run: {
               command,
               args: ["lsp"],
               options: { env },
           },
           debug: {
               command,
               args: ["lsp"],
               options: { env },
           },
       };
       ```
    **Visualization:**

    ```
    User opens malicious project --> VS Code loads workspace settings (.vscode/settings.json) -->
    .vscode/settings.json sets "deno.path" to malicious executable -->
    Extension uses getDenoCommandPath() to retrieve "deno.path" -->
    Extension executes commands (LSP, tasks, debug) using the malicious path -->
    Arbitrary code execution
    ```

- Security Test Case:
    1. **Setup:**
        - Create a new directory named `malicious-deno-project`.
        - Inside `malicious-deno-project`, create a subdirectory named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json` with the following content:
          ```json
          {
              "deno.enable": true,
              "deno.path": "./malicious.sh"
          }
          ```
        - In the `malicious-deno-project` directory, create a file named `malicious.sh` (or `malicious.bat` for Windows) with the following content:
          ```bash
          #!/bin/bash
          echo "Malicious script executed!" > malicious_output.txt
          ```
          (For Windows `malicious.bat`):
          ```batch
          @echo off
          echo Malicious script executed! > malicious_output.txt
          ```
        - Make `malicious.sh` executable (e.g., `chmod +x malicious.sh`).
        - Create a simple Deno file, e.g., `main.ts` in `malicious-deno-project`.
        ```typescript
        console.log("Hello Deno!");
        ```
    2. **Execution:**
        - Open VS Code and open the `malicious-deno-project` folder.
        - Ensure the "Deno for Visual Studio Code" extension is enabled for this workspace (it should be enabled due to `"deno.enable": true` in `settings.json`).
        - Trigger any Deno command that would use `deno.path`. For example, open the command palette (Ctrl+Shift+P) and execute "Deno: Language Server Status".
    3. **Verification:**
        - Check if a file named `malicious_output.txt` has been created in the `malicious-deno-project` directory.
        - If the file exists and contains "Malicious script executed!", the vulnerability is confirmed. This indicates that `malicious.sh` was executed instead of the actual Deno CLI.

This test case demonstrates that by controlling the `deno.path` setting via workspace configuration, an attacker can achieve arbitrary command execution when the extension attempts to use the Deno CLI.
