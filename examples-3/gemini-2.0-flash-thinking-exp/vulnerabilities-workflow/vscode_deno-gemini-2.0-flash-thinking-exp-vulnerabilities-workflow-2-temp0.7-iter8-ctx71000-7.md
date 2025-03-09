### Vulnerability List

- Vulnerability Name: Arbitrary Code Execution via Malicious Deno Path Configuration

- Description:
    1. The Visual Studio Code Deno extension allows users to configure the path to the Deno executable using the `deno.path` setting.
    2. An attacker can socially engineer a victim into changing this setting to point to a malicious executable instead of the legitimate Deno CLI.
    3. Once the `deno.path` is set to the malicious executable, any subsequent operation within VS Code that invokes a Deno command through the extension will execute the malicious code.
    4. This includes actions like caching dependencies, running tests, formatting code, and using language server features that rely on the Deno CLI.
    5. The attacker does not need to exploit any code within the extension itself but leverages a configuration setting and social engineering.

- Impact:
    - Critical. Successful exploitation leads to arbitrary code execution on the user's machine with the privileges of the user running VS Code.
    - An attacker can gain complete control over the user's system, steal sensitive data, install malware, or perform other malicious actions.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The extension relies on the user to provide a valid and safe path to the Deno executable. There are no checks within the extension to validate the provided path or the executable itself.

- Missing Mitigations:
    - Input validation for the `deno.path` setting. The extension should check if the provided path is a valid executable and potentially warn users if the path seems suspicious (e.g., points to a temporary directory or a location outside of standard program directories).
    - Display a warning message when the `deno.path` setting is changed, especially if it's being set to a non-standard location.
    - Documentation improvements to explicitly warn users about the security risks of setting `deno.path` to untrusted executables and to advise them to only point it to the official Deno CLI.

- Preconditions:
    - The user must have the VS Code Deno extension installed and enabled.
    - An attacker must successfully socially engineer the user into changing the `deno.path` configuration setting within VS Code to point to a malicious executable.
    - The user must then perform an action within VS Code that triggers the extension to execute a Deno command (e.g., open a Deno project, trigger code formatting, run a test, cache dependencies).

- Source Code Analysis:

    1. **`client\src\util.ts:getDenoCommandPath()`**: This function is responsible for resolving the path to the Deno executable.
    ```typescript
    // File: ..\vscode_deno\client\src\util.ts
    export async function getDenoCommandPath() {
      const command = getWorkspaceConfigDenoExePath(); // Get path from configuration
      const workspaceFolders = workspace.workspaceFolders;
      if (!command || !workspaceFolders) {
        return command ?? await getDefaultDenoCommand(); // Fallback to default path resolution
      } else if (!path.isAbsolute(command)) {
        // Relative path handling (potential issue if malicious relative path)
        for (const workspace of workspaceFolders) {
          const commandPath = path.resolve(workspace.uri.fsPath, command);
          if (await fileExists(commandPath)) {
            return commandPath;
          }
        }
        return undefined;
      } else {
        return command; // Return the configured path directly
      }
    }

    function getWorkspaceConfigDenoExePath() {
      const exePath = workspace.getConfiguration(EXTENSION_NS)
        .get<string>("path"); // Reads "deno.path" setting
      if (typeof exePath === "string" && exePath.trim().length === 0) {
        return undefined;
      } else {
        return exePath; // Returns the configured path
      }
    }
    ```
    - The `getDenoCommandPath` function first tries to get the Deno executable path from the workspace configuration using `getWorkspaceConfigDenoExePath()`.
    - `getWorkspaceConfigDenoExePath()` directly reads the `deno.path` setting from VS Code configuration (`workspace.getConfiguration(EXTENSION_NS).get<string>("path")`).
    - If `deno.path` is set, `getDenoCommandPath()` returns it without any validation.
    - If `deno.path` is not set or is empty, it falls back to `getDefaultDenoCommand()` which attempts to resolve the Deno executable from the environment path and default install locations. However, if `deno.path` is set, this fallback is bypassed, and the configured path is used directly.

    2. **`client\src\commands.ts:startLanguageServer()` and other commands**: This function and other command handlers use `getDenoCommandPath()` to get the Deno executable and execute commands.
    ```typescript
    // File: ..\vscode_deno\client\src\commands.ts
    export function startLanguageServer(
      context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async () => {
        // ...
        const command = await getDenoCommandPath(); // Resolves deno path
        if (command == null) {
          // ... error handling ...
          return;
        }

        const serverOptions: ServerOptions = {
          run: {
            command, // Malicious command from deno.path is used here
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // Malicious command from deno.path is used here
            args: ["lsp"],
            options: { env },
          },
        };
        // ... rest of the language server startup ...
      };
    }

    export function cacheActiveDocument( /* ... */ ): Callback {
      return () => {
        // ...
        return vscode.commands.executeCommand("deno.cache", [uri], uri);
      };
    }

    export function test( /* ... */ ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];

        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test", // Command name, not path
          args,
          env,
        };

        assert(workspaceFolder);
        const denoCommand = await getDenoCommandName(); // Resolves deno path
        const task = tasks.buildDenoTask( // Build task with resolved command path
          workspaceFolder,
          denoCommand, // Malicious command from deno.path is used here
          definition,
          `test "${name}"`,
          args,
          ["$deno-test"],
        );
        // ... execute task ...
      };
    }
    ```
    - In `startLanguageServer()`, the `command` variable, obtained from `getDenoCommandPath()`, is directly used as the `command` in `serverOptions.run` and `serverOptions.debug`. This means the extension will execute whatever is at the path specified in `deno.path` as the Deno language server.
    - Similarly, in `test()` and other command handlers that use tasks (like `cacheActiveDocument` which indirectly uses `deno.cache` task), `getDenoCommandName()` (which internally calls `getDenoCommandPath()`) is used to get the executable path for task execution.
    - The extension code does not perform any validation on the `command` path obtained from `getDenoCommandPath()` before executing it.

- Security Test Case:

    1. **Prepare a malicious executable:** Create a simple executable file (e.g., a `.bat` file on Windows, a `.sh` script on Linux/macOS) that will demonstrate code execution. For example, on Windows, create `malicious_deno.bat` with the following content:
        ```bat
        @echo off
        echo Vulnerability Exploited! > exploited.txt
        echo %PATH% > path.txt
        pause
        ```
        On Linux/macOS, create `malicious_deno.sh`:
        ```sh
        #!/bin/bash
        echo "Vulnerability Exploited!" > exploited.txt
        echo $PATH > path.txt
        chmod +x exploited.txt path.txt
        ```
    2. **Place the malicious executable:** Save this file to a known location on your system, for example, `C:\temp\malicious_deno.bat` on Windows or `/tmp/malicious_deno.sh` on Linux/macOS.
    3. **Social Engineering (Simulated):** Imagine an attacker has tricked you into changing the `deno.path` setting.
    4. **Change `deno.path` in VS Code:** Open VS Code settings (Ctrl+,). Search for "deno.path". Change the `Deno › Path` setting to the path of your malicious executable.
        - Windows: `C:\temp\malicious_deno.bat`
        - Linux/macOS: `/tmp/malicious_deno.sh`
    5. **Trigger Deno Extension Command:** Open any JavaScript or TypeScript file in VS Code. Execute any Deno extension command that invokes the Deno CLI. For example, use the command palette (Ctrl+Shift+P) and run "Deno: Cache".
    6. **Verify Exploitation:** After running the command, check if the `exploited.txt` file has been created in the directory where you placed the malicious script (e.g., `C:\temp` or `/tmp`). If the file exists and contains "Vulnerability Exploited!", it confirms that the malicious executable was executed by the VS Code Deno extension. Also, check `path.txt` to see the PATH environment variable used by the extension.

This test case demonstrates that by changing the `deno.path` configuration, an attacker can achieve arbitrary code execution when the VS Code Deno extension invokes Deno commands.
