### Vulnerability List:

* Vulnerability Name: Arbitrary code execution via `deno.path` setting
* Description:
    1. An attacker crafts a malicious VSCode workspace.
    2. The malicious workspace includes workspace settings (`.vscode/settings.json`) that modify the `deno.path` setting.
    3. The `deno.path` setting is changed to point to a malicious executable under the attacker's control instead of the legitimate Deno CLI executable.
    4. A user is tricked into opening this malicious workspace in VSCode.
    5. The VSCode Deno extension is activated for this workspace because `deno.enable` is set to true or a `deno.json` file is detected.
    6. The user triggers any feature of the Deno extension that requires executing the Deno CLI. This could be:
        - Formatting a file (using Deno as the formatter).
        - Linting a file.
        - Caching dependencies.
        - Running tests (via code lens or test explorer).
        - Debugging code.
        - Starting the Deno Language Server.
    7. When the extension attempts to execute the Deno CLI, it uses the path specified in the `deno.path` setting, which now points to the malicious executable.
    8. The malicious executable is executed with the privileges of the user running VSCode, leading to arbitrary code execution on the user's machine.
* Impact: Critical
    - Arbitrary code execution on the user's machine.
    - Full compromise of the user's system is possible.
    - Potential data theft, malware installation, and other malicious activities.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None
    - The extension currently does not implement any specific mitigations to prevent this vulnerability. It directly uses the path provided in the `deno.path` setting to execute the Deno CLI without any validation or sanitization.
* Missing Mitigations:
    - Input validation and sanitization for the `deno.path` setting.
        - The extension should validate that the provided path is a valid executable and potentially check if it resembles a legitimate Deno CLI path.
    - Path restriction or whitelisting.
        - Restrict `deno.path` setting to only allow paths within the workspace or a predefined safe list of directories.
        - Alternatively, whitelist only the standard installation locations for Deno CLI based on the operating system.
    - Warning message on `deno.path` modification.
        - Display a prominent warning message to the user when the `deno.path` setting is modified, especially if it points to a location outside of standard Deno installations or the workspace.
    - Executable signature verification.
        - Implement signature verification for the Deno CLI executable before execution to ensure it is a legitimate Deno binary.
    - Sandboxed execution environment.
        - Explore running the Deno CLI in a sandboxed environment to limit the potential damage from a malicious executable, although this might be complex to implement.
* Preconditions:
    - User opens a malicious workspace in VSCode.
    - The malicious workspace must contain a `.vscode/settings.json` file that sets the `deno.path` setting to a malicious executable.
    - Deno extension must be enabled for the workspace, either through the `deno.enable` setting or by the presence of a `deno.json` file.
    - The user must trigger a feature of the Deno extension that executes the Deno CLI.
* Source Code Analysis:
    - File: `client/src/util.ts`
        ```typescript
        export async function getDenoCommandPath() {
          const command = getWorkspaceConfigDenoExePath();
          const workspaceFolders = workspace.workspaceFolders;
          if (!command || !workspaceFolders) {
            return command ?? await getDefaultDenoCommand();
          } else if (!path.isAbsolute(command)) {
            // if sent a relative path, iterate over workspace folders to try and resolve.
            for (const workspace of workspaceFolders) {
              const commandPath = path.resolve(workspace.uri.fsPath, command);
              if (await fileExists(commandPath)) {
                return commandPath;
              }
            }
            return undefined;
          } else {
            return command;
          }
        }

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
        - The function `getDenoCommandPath` retrieves the Deno executable path.
        - It first calls `getWorkspaceConfigDenoExePath` to get the path from the workspace configuration (`deno.path` setting).
        - `getWorkspaceConfigDenoExePath` directly reads the `deno.path` setting using `workspace.getConfiguration(EXTENSION_NS).get<string>("path")` without any validation.
        - If `deno.path` is set, `getDenoCommandPath` prioritizes this path.
        - If `deno.path` is a relative path, it attempts to resolve it relative to the workspace folders, but if it's absolute, it directly returns it without any checks for maliciousness.
    - File: `client/src/debug_config_provider.ts`, `client/src/commands.ts`, `client/src/tasks.ts`
        - These files use `getDenoCommandName()` (which calls `getDenoCommandPath()`) to obtain the Deno executable path and use it to spawn child processes for debugging, language server, and tasks, respectively.
        - Example from `client/src/debug_config_provider.ts`:
        ```typescript
        runtimeExecutable: await getDenoCommandName(),
        runtimeArgs: [
          "run",
          ...this.#getAdditionalRuntimeArgs(),
          this.#getInspectArg(),
          "--allow-all",
        ],
        ```
        - The `runtimeExecutable` is set directly to the potentially attacker-controlled path from `getDenoCommandName()`.
    - Visualization:

    ```
    User opens malicious workspace --> .vscode/settings.json (deno.path = malicious_executable)
                                          |
                                          V
    VSCode Deno Extension Activated --> Reads deno.path setting (client/src/util.ts)
                                          |
                                          V
    Extension executes Deno CLI --> Uses malicious_executable (client/src/debug_config_provider.ts, client/src/commands.ts, client/src/tasks.ts)
                                          |
                                          V
    Malicious Code Execution ---------> User's Machine Compromised
    ```

* Security Test Case:
    1. **Setup Malicious Executable:**
        - Create a new directory, e.g., `malicious-deno`.
        - Inside `malicious-deno`, create a file named `deno.bat` (on Windows) or `deno.sh` (on Linux/macOS).
        - **`deno.bat` (Windows Example):**
            ```batch
            @echo off
            echo Malicious Deno Executed! >> %TEMP%\malicious_deno_execution.txt
            echo Original args: %* >> %TEMP%\malicious_deno_execution.txt
            exit 1
            ```
        - **`deno.sh` (Linux/macOS Example):**
            ```bash
            #!/bin/bash
            echo "Malicious Deno Executed!" >> /tmp/malicious_deno_execution.txt
            echo "Original args: $*" >> /tmp/malicious_deno_execution.txt
            exit 1
            ```
        - Make `deno.sh` executable: `chmod +x malicious-deno/deno.sh`
    2. **Create Malicious Workspace:**
        - Create a new directory, e.g., `test-workspace`.
        - Inside `test-workspace`, create a `.vscode` directory.
        - Inside `.vscode`, create a `settings.json` file with the following content, adjusting the path to `malicious-deno` based on your system:
            - **Windows `settings.json` Example:**
                ```json
                {
                    "deno.enable": true,
                    "deno.path": "<ABSOLUTE_PATH_TO>/malicious-deno/deno.bat"
                }
                ```
            - **Linux/macOS `settings.json` Example:**
                ```json
                {
                    "deno.enable": true,
                    "deno.path": "<ABSOLUTE_PATH_TO>/malicious-deno/deno.sh"
                }
                ```
            - Replace `<ABSOLUTE_PATH_TO>` with the absolute path to the `malicious-deno` directory you created.
        - Inside `test-workspace`, create a TypeScript file, e.g., `test.ts`:
            ```typescript
            console.log("Hello, Deno!");
            ```
    3. **Open Workspace and Trigger Vulnerability:**
        - Open the `test-workspace` in VSCode.
        - Ensure the Deno extension is active (check status bar).
        - Try to format the `test.ts` file: Right-click in the editor -> "Format Document With..." -> Select "Deno Formatter".
        - Alternatively, try to run the "Deno: Cache" command from the command palette.
    4. **Verify Malicious Execution:**
        - Check for the file `malicious_deno_execution.txt` in your `%TEMP%` directory (Windows) or `/tmp` directory (Linux/macOS).
        - The file should contain the text "Malicious Deno Executed!" and the arguments passed to the malicious executable, indicating that your malicious `deno.bat` or `deno.sh` was indeed executed instead of the real Deno CLI.
        - The formatting or caching operation will likely fail because the malicious script exits with code 1, further confirming the execution path.

This test case demonstrates successful arbitrary code execution by manipulating the `deno.path` setting.
