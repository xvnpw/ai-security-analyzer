- Vulnerability Name: Local Code Execution via Malicious `deno.path` Configuration

- Description:
    1. An attacker can trick a user into setting a malicious executable path in the `deno.path` configuration within VS Code settings.
    2. The VS Code Deno extension retrieves the `deno.path` configuration value.
    3. When the extension needs to execute the Deno CLI for various features (like language server, formatting, linting, testing, debugging, or upgrading), it directly uses the path from the `deno.path` configuration as the executable command.
    4. If the `deno.path` points to a malicious executable, the extension will unknowingly execute it instead of the legitimate Deno CLI.
    5. This results in arbitrary local code execution on the user's machine with the privileges of the VS Code process.

- Impact:
    - An attacker can achieve local code execution on the user's machine.
    - Depending on the malicious executable, the attacker could potentially:
        - Steal sensitive data.
        - Install malware.
        - Modify or delete files.
        - Take control of the user's system.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The extension directly uses the configured `deno.path` without any validation or sanitization.

- Missing Mitigations:
    - **Path Validation:** The extension should validate the `deno.path` configuration to ensure it points to a legitimate Deno CLI executable. This could include:
        - Checking if the path is absolute.
        - Verifying the executable name (e.g., "deno" or "deno.exe").
        - Potentially checking the file signature or hash against known Deno CLI executables (though this might be complex to maintain).
        - Displaying a warning message if the path is unusual or points to a location outside of typical installation directories.
    - **User Warning:** When the user changes the `deno.path` setting, the extension could display a warning message emphasizing the security risks of setting untrusted executable paths and advising users to only set paths to the official Deno CLI.

- Preconditions:
    - The user must have the VS Code Deno extension installed.
    - The attacker must convince the user to manually change the `deno.path` setting in VS Code to point to a malicious executable. This could be achieved through social engineering, phishing, or other deceptive tactics.
    - The user must trigger a feature of the extension that executes the Deno CLI (e.g., opening a Deno project, running a test, formatting a file, etc.).

- Source Code Analysis:
    1. **File: `client/src/util.ts` - `getDenoCommandPath` function:**
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
        ```
        This function retrieves the `deno.path` from the configuration (`getWorkspaceConfigDenoExePath`). It attempts to resolve relative paths against workspace folders but does not perform any validation on the path itself. If an absolute path is provided in the configuration, it's directly returned.

    2. **File: `client/src/commands.ts` - `startLanguageServer` function:**
        ```typescript
        export function startLanguageServer(
          context: vscode.ExtensionContext,
          extensionContext: DenoExtensionContext,
        ): Callback {
          return async () => {
            // ...
            const command = await getDenoCommandPath();
            if (command == null) {
              // ... error handling ...
              return;
            }

            const serverOptions: ServerOptions = {
              run: {
                command, // <--- Malicious path from deno.path is used directly here
                args: ["lsp"],
                options: { env },
              },
              debug: {
                command, // <--- Malicious path from deno.path is used directly here
                // ...
                args: ["lsp"],
                options: { env },
              },
            };
            const client = new LanguageClient(
              // ...
              serverOptions,
              // ...
            );
            // ... client start ...
          };
        }
        ```
        The `startLanguageServer` function calls `getDenoCommandPath` to get the Deno command. The returned `command` is then directly used in the `serverOptions` for both `run` and `debug` configurations of the Language Client. There is no validation or sanitization of the `command` variable before it's used to spawn the process.

    3. **Other command executions:** Similar pattern is observed in other features like testing, debugging, and upgrade where `getDenoCommandName` (which internally uses `getDenoCommandPath`) is used to get the executable path, and this path is directly used to execute the Deno CLI without any validation.

    **Visualization:**

    ```
    User Configures deno.path (Malicious Path) --> VS Code Settings --> Extension Reads deno.path --> getDenoCommandPath() returns Malicious Path --> startLanguageServer/test/debug/upgrade functions use Malicious Path as Command --> child_process.spawn() executes Malicious Path --> Local Code Execution
    ```

- Security Test Case:
    1. **Prepare Malicious Executable:**
        - Create a new directory, e.g., `malicious_deno`.
        - Inside this directory, create a file named `deno` (or `deno.exe` on Windows).
        - Make this file executable.
        - Add the following script to `deno` (or `deno.exe`):
            ```bash
            #!/bin/bash
            # For Linux/macOS
            touch /tmp/pwned_deno_extension
            echo "[vscode-deno] Malicious Deno Executed!"
            exit 1 # Exit with an error to prevent further Deno execution
            ```
            ```batch
            @echo off
            REM For Windows (deno.exe)
            echo [vscode-deno] Malicious Deno Executed! >> %TEMP%\pwned_deno_extension.txt
            exit /b 1
            ```
        - Ensure the script creates a file named `pwned_deno_extension` in `/tmp` (Linux/macOS) or `%TEMP%` (Windows) and prints a message to the console.
    2. **Configure VS Code Settings:**
        - Open VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
        - Search for "deno.path".
        - Set the `Deno › Path` setting to the absolute path of the `malicious_deno` directory you created (e.g., `/path/to/malicious_deno/deno` or `C:\path\to\malicious_deno\deno.exe`).
    3. **Trigger Extension Feature:**
        - Open any JavaScript or TypeScript file in VS Code.
        - Enable Deno for the workspace if not already enabled (using "Deno: Enable" command).
        - Observe the output console for the "[vscode-deno] Malicious Deno Executed!" message.
        - Check if the file `/tmp/pwned_deno_extension` (or `%TEMP%\pwned_deno_extension.txt` on Windows) has been created.
    4. **Verify Vulnerability:**
        - If the message "[vscode-deno] Malicious Deno Executed!" is printed in the output console and the `pwned_deno_extension` file is created, it confirms that the malicious executable was executed by the VS Code Deno extension, demonstrating the Local Code Execution vulnerability.

This vulnerability allows for critical impact and requires immediate mitigation by implementing path validation and user warnings for the `deno.path` configuration.
