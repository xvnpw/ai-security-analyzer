## Vulnerability List

- Vulnerability Name: Malicious Deno Executable Path Injection

- Description:
    1. An attacker crafts a malicious workspace.
    2. The malicious workspace includes a `.vscode/settings.json` file.
    3. Inside `settings.json`, the attacker sets the `deno.path` setting to point to a malicious executable. This executable can be located anywhere accessible to the user, including within the workspace itself, masquerading as a legitimate `deno` executable.
    4. The victim opens this malicious workspace in Visual Studio Code with the Deno extension installed and enabled.
    5. When the Deno extension initializes or attempts to use the Deno CLI (e.g., for type checking, linting, formatting, testing, or tasks), it reads the `deno.path` setting from the workspace configuration.
    6. Instead of using the legitimate Deno CLI, the extension executes the malicious executable specified in `deno.path`.
    7. The malicious executable runs with the privileges of the user who opened the workspace, leading to arbitrary code execution.

- Impact:
    - Arbitrary code execution on the victim's machine.
    - Potential for data theft, malware installation, or complete system compromise depending on the actions performed by the malicious executable.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The extension reads and uses the `deno.path` setting without any validation or sanitization.

- Missing Mitigations:
    - **Executable Path Validation:** The extension should validate the `deno.path` setting to ensure it points to a legitimate Deno executable. This could involve:
        - Checking if the path is an absolute path or resolving relative paths securely.
        - Verifying the file extension is appropriate for an executable on the operating system.
        - Using operating system APIs to check if the file is actually executable.
    - **Executable Verification:**  Ideally, the extension should verify the integrity and authenticity of the Deno executable at the given path. This could involve:
        - Checking a digital signature or hash of the executable against a known good value.
        - Ensuring the executable is located in a trusted directory.
    - **User Warning:** If the `deno.path` setting is modified in the workspace settings, display a prominent warning to the user, especially if the path is unusual or points to a location within the workspace itself.
    - **Restricting `deno.path` Scope:** Consider limiting the scope of the `deno.path` setting to user or global settings only, preventing workspace-level overrides. However, this might reduce the flexibility of the extension for users with different Deno CLI locations across projects.

- Preconditions:
    - The victim has the "Deno for Visual Studio Code" extension installed and enabled.
    - The victim opens a workspace controlled by an attacker containing a malicious `.vscode/settings.json` file with a compromised `deno.path` setting.
    - The attacker needs to create a malicious executable and place it in a location where they can specify the path in the `deno.path` setting (can be within the workspace itself).

- Source Code Analysis:
    1. **`client\src\util.ts:getDenoCommandPath()`**: This function is responsible for resolving the Deno command path.
    ```typescript
    export async function getDenoCommandPath() {
      const command = getWorkspaceConfigDenoExePath(); // Get path from workspace config
      const workspaceFolders = workspace.workspaceFolders;
      if (!command || !workspaceFolders) {
        return command ?? await getDefaultDenoCommand(); // Fallback to default path
      } else if (!path.isAbsolute(command)) {
        // if sent a relative path, iterate over workspace folders to try and resolve.
        for (const workspace of workspaceFolders) {
          const commandPath = path.resolve(workspace.uri.fsPath, command);
          if (await fileExists(commandPath)) {
            return commandPath; // Returns resolved path if file exists
          }
        }
        return undefined;
      } else {
        return command; // Returns path from config directly
      }
    }
    ```
    - `getDenoCommandPath` first retrieves the path from workspace configuration using `getWorkspaceConfigDenoExePath()`.
    - If a `deno.path` is configured in the workspace and it's an absolute path, it's returned directly without any validation beyond `fileExists`.
    - If the path is relative, it attempts to resolve it within workspace folders, and if a file exists, returns the resolved path.
    - If no path is configured in workspace or not found relatively, it falls back to `getDefaultDenoCommand()` which searches in environment path and default install locations.
    - **Vulnerability Point:** The workspace configuration (`deno.path`) is prioritized and if it's an absolute or resolvable relative path that exists, it's directly used as the Deno command path. There is no check to verify if this path actually points to a legitimate `deno` executable or if it's safe to execute.

    2. **`client\src\util.ts:getWorkspaceConfigDenoExePath()`**: This function retrieves the `deno.path` setting.
    ```typescript
    function getWorkspaceConfigDenoExePath() {
      const exePath = workspace.getConfiguration(EXTENSION_NS)
        .get<string>("path"); // Retrieves "deno.path" setting
      // it is possible for the path to be blank. In that case, return undefined
      if (typeof exePath === "string" && exePath.trim().length === 0) {
        return undefined;
      } else {
        return exePath; // Returns the path as string
      }
    }
    ```
    - This function simply retrieves the string value of the `deno.path` configuration setting without any validation.

    3. **`client\src\tasks.ts:buildDenoTask()` and `client\src\commands.ts`**: These functions use `getDenoCommandName()` (which internally calls `getDenoCommandPath()`) to get the Deno executable path and use it to spawn processes.
    ```typescript
    // client\src\tasks.ts
    export function buildDenoTask(
      target: vscode.WorkspaceFolder,
      process: string, // Path from getDenoCommandName()
      definition: DenoTaskDefinition,
      name: string,
      args: string[],
      problemMatchers: string[],
    ): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process, // Executable path used directly
        args,
        definition,
      );
      // ...
    }
    ```
    ```typescript
    // client\src\commands.ts - Example usage in test command
    export function test( /* ... */ ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const args = ["test", /* ... */, filePath];
        const definition: tasks.DenoTaskDefinition = { /* ... */ };

        assert(workspaceFolder);
        const denoCommand = await getDenoCommandName(); // Resolves Deno command path
        const task = tasks.buildDenoTask(
          workspaceFolder,
          denoCommand, // Malicious path can end up here
          definition,
          `test "${name}"`,
          args,
          ["$deno-test"],
        );
        // ...
        await vscode.tasks.executeTask(task); // Executes the task with malicious path
        // ...
      };
    }
    ```
    - `buildDenoTask` and other functions that execute Deno CLI commands use the path returned by `getDenoCommandName()` directly in `ProcessExecution`, leading to the execution of whatever executable path is resolved, including a potentially malicious one from workspace settings.

- Security Test Case:
    1. **Setup Malicious Executable:**
        - Create a new directory named `malicious-deno-workspace`.
        - Inside `malicious-deno-workspace`, create a file named `malicious-deno.sh` (or `malicious-deno.bat` for Windows) with the following content:
            ```bash
            #!/bin/bash
            # Malicious script to simulate Deno and demonstrate code execution
            echo "[VULNERABILITY-DEMO] Malicious Deno Executable Executed!"
            echo "[VULNERABILITY-DEMO] You are VULNERABLE!"
            # Optionally, perform malicious actions here, e.g., create a file
            touch /tmp/pwned.txt
            ```
            (For Windows `malicious-deno.bat`):
            ```bat
            @echo off
            echo [VULNERABILITY-DEMO] Malicious Deno Executable Executed!
            echo [VULNERABILITY-DEMO] You are VULNERABLE!
            REM Optionally, perform malicious actions here, e.g., create a file
            type nul > C:\pwned.txt
            ```
        - Make `malicious-deno.sh` executable: `chmod +x malicious-deno.sh`
        - Place this script in the root of `malicious-deno-workspace`.

    2. **Create Workspace Settings:**
        - Inside `malicious-deno-workspace`, create a directory named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json` with the following content:
            ```json
            {
                "deno.enable": true,
                "deno.path": "./malicious-deno.sh" // or ".\\malicious-deno.bat" for Windows
            }
            ```

    3. **Create a Dummy Deno File:**
        - In `malicious-deno-workspace`, create a file named `test.ts` (or any `.ts` or `.js` file) with any content.

    4. **Open Workspace in VSCode:**
        - Open the `malicious-deno-workspace` folder in Visual Studio Code with the "Deno for Visual Studio Code" extension installed and enabled.

    5. **Trigger Extension Usage:**
        - Open the `test.ts` file. This should trigger the Deno extension to activate and attempt to use the Deno CLI for language features.
        - Alternatively, you can try to use any Deno extension feature like "Deno: Cache", "Deno: Lint", "Deno: Test", or configure a Deno task.

    6. **Verify Vulnerability:**
        - Observe the output. You should see the messages "[VULNERABILITY-DEMO] Malicious Deno Executable Executed!" and "[VULNERABILITY-DEMO] You are VULNERABLE!" in the VSCode Output panel (usually under "Deno Language Server" output).
        - Check if the `/tmp/pwned.txt` file (or `C:\pwned.txt` on Windows) was created, confirming arbitrary code execution.

This test case demonstrates that by setting a malicious path in the workspace settings, an attacker can achieve arbitrary code execution when a victim opens the workspace, confirming the vulnerability.
