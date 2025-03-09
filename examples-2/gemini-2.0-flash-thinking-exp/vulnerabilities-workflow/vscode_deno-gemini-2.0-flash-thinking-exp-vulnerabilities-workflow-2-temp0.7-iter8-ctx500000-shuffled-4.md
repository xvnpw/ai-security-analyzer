- Vulnerability Name: Arbitrary Code Execution via `deno.path` Workspace Setting
- Description:
  - Step 1: An attacker crafts a malicious VS Code workspace.
  - Step 2: Inside this workspace, the attacker creates a `.vscode` folder and a `settings.json` file within it.
  - Step 3: In the `settings.json` file, the attacker sets the `deno.path` setting to point to a malicious executable under their control. For example:
    ```json
    {
      "deno.path": "/path/to/malicious/executable"
    }
    ```
    or on Windows:
    ```json
    {
      "deno.path": "C:\\path\\to\\malicious\\executable.exe"
    }
    ```
    or a relative path within the workspace:
    ```json
    {
      "deno.path": "./malicious-deno"
    }
    ```
  - Step 4: The attacker distributes this malicious workspace (e.g., via email, GitHub repository, or other means) and lures a developer into opening it with VS Code and the "Deno for VS Code" extension enabled.
  - Step 5: When the developer opens the workspace, VS Code reads the `settings.json` and applies the configuration, including the malicious `deno.path`.
  - Step 6: When the "Deno for VS Code" extension initializes or performs any operation that requires invoking the Deno CLI (like type checking, linting, formatting, testing, or running tasks), it uses the `deno.path` from the workspace settings.
  - Step 7: Instead of executing the legitimate Deno CLI, the extension unknowingly executes the malicious executable specified in `deno.path`.
  - Step 8: The malicious executable runs with the privileges of the VS Code process, effectively achieving arbitrary code execution on the developer's machine.

- Impact:
  - Arbitrary code execution on the developer's machine.
  - Full compromise of the developer's environment, potentially leading to data theft, malware installation, or further attacks on internal networks.
  - Loss of trust in the VS Code extension and the Deno ecosystem.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - None. The extension directly uses the path provided in the `deno.path` setting without any validation or sanitization.

- Missing Mitigations:
  - Input validation and sanitization for the `deno.path` setting.
    - The extension should validate that the provided path points to a legitimate Deno executable. This could include checking the file extension, verifying a digital signature, or performing other security checks.
    - Consider restricting `deno.path` to be only an absolute path or only allow paths within the user's home directory to limit the scope of potential attacks.
  - Display a warning message to the user when a workspace setting overrides the `deno.path` and points to a location outside of the expected installation paths.
  - Implement a mechanism to verify the integrity of the Deno executable before execution.
  - Consider using a safer mechanism to locate the Deno executable, such as relying solely on the environment path and not allowing workspace-level overrides for security-sensitive settings like executable paths.
  - Documentation should explicitly warn users about the risks of modifying the `deno.path` setting and advise against using workspaces from untrusted sources.

- Preconditions:
  - The attacker needs to be able to create or modify a VS Code workspace's `settings.json` file.
  - The developer must open the malicious workspace in VS Code with the "Deno for VS Code" extension enabled.
  - The developer must trigger an action within VS Code that causes the extension to execute the Deno CLI.

- Source Code Analysis:
  - File: `client\src\util.ts`
    - Function `getDenoCommandPath()`: This function is responsible for resolving the path to the Deno executable.
    - It first retrieves the path from the workspace configuration using `getWorkspaceConfigDenoExePath()`.
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
      - As seen in the code, `workspace.getConfiguration(EXTENSION_NS).get<string>("path")` directly reads the `deno.path` setting from VS Code configuration without any validation.
    - If `deno.path` is configured, it checks if it is absolute. If not, it tries to resolve it relative to workspace folders. If an absolute path or a resolvable relative path is found (or if `deno.path` is not set), it returns this path.
    - If `deno.path` is not configured or not resolvable within workspace folders, it falls back to `getDefaultDenoCommand()`.
    - Function `getDenoCommandName()`: This function calls `getDenoCommandPath()` and if it returns `undefined`, it defaults to `"deno"`.
    - **Vulnerability Point:** The code prioritizes the `deno.path` setting from workspace configuration and directly uses it to execute the Deno command without any security checks.

  - File: `client\src\tasks.ts`, `client\src\debug_config_provider.ts`, `client\src\commands.ts`
    - These files use `getDenoCommandName()` to obtain the Deno command path and then use it to spawn processes for tasks, debugging, and other Deno CLI operations.
    - For example, in `client\src\tasks.ts`, function `buildDenoTask()`:
      ```typescript
      export function buildDenoTask(
        target: vscode.WorkspaceFolder,
        process: string, // <= Deno command path from getDenoCommandName()
        definition: DenoTaskDefinition,
        name: string,
        args: string[],
        problemMatchers: string[],
      ): vscode.Task {
        const exec = new vscode.ProcessExecution(
          process, // <= Used directly for process execution
          args,
          definition,
        );
        // ...
      }
      ```
    - **Vulnerability Point:** The resolved `denoCommandName` (which can be a malicious path from `deno.path` setting) is passed directly to `vscode.ProcessExecution` to execute the command.

- Security Test Case:
  - Step 1: Create a new directory named `malicious-workspace`.
  - Step 2: Inside `malicious-workspace`, create a file named `malicious-deno.sh` (or `malicious-deno.bat` on Windows) with the following content:
    ```sh
    #!/bin/bash
    echo "Malicious script executed!"
    echo "Workspace path: $PWD"
    touch /tmp/pwned # Or equivalent action like exfiltrating data
    exit 0
    ```
    (For Windows `malicious-deno.bat`):
    ```bat
    @echo off
    echo Malicious script executed!
    echo Workspace path: %CD%
    type nul > C:\temp\pwned # Or equivalent action
    exit 0
    ```
    - Make sure to make `malicious-deno.sh` executable: `chmod +x malicious-deno.sh`.
  - Step 3: Inside `malicious-workspace`, create a folder named `.vscode`.
  - Step 4: Inside `.vscode`, create a file named `settings.json` with the following content:
    ```json
    {
      "deno.path": "./malicious-deno.sh"
    }
    ```
    (Or on Windows, if you created `malicious-deno.bat` in `malicious-workspace`):
    ```json
    {
      "deno.path": ".\\malicious-deno.bat"
    }
    ```
  - Step 5: Open VS Code and open the `malicious-workspace` folder.
  - Step 6: Ensure the "Deno for VS Code" extension is enabled. You might need to enable Deno for the workspace if it's not enabled by default.
  - Step 7: Open any JavaScript or TypeScript file in the workspace. This should trigger the Deno extension to start and attempt to use the Deno CLI. Alternatively, you can manually trigger a Deno command like "Deno: Language Server Status" from the command palette.
  - Step 8: Observe the output. You should see "Malicious script executed!" in the terminal output of VS Code, and the file `/tmp/pwned` (or `C:\temp\pwned` on Windows) should be created, indicating that the malicious script has been executed instead of the real Deno CLI.
