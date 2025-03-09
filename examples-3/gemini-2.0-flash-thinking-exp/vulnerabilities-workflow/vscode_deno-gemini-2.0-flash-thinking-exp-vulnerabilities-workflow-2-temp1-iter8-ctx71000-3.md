### Vulnerability List

- Vulnerability Name: Malicious Deno Path Execution
- Description:
    1. An attacker socially engineers a user into changing the `deno.path` setting in VS Code.
    2. The user, believing they are improving or customizing their Deno extension experience, unknowingly sets `deno.path` to point to a malicious executable on their system.
    3. The VS Code Deno extension, upon activation or when triggered by a Deno command (like type checking, formatting, testing, etc.), uses the configured `deno.path` to locate and execute the Deno CLI.
    4. Instead of executing the legitimate Deno CLI, the extension inadvertently executes the malicious executable specified in `deno.path`.
    5. The malicious executable, now running with the user's privileges, can perform arbitrary actions on the user's system, such as data theft, malware installation, or further system compromise.
- Impact:
    - Critical system compromise.
    - Arbitrary code execution with user privileges.
    - Potential data theft, malware installation, and further system exploitation.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - None. The extension directly uses the path provided in the `deno.path` setting without any validation or security checks.
    - The README.md provides a warning message about the `deno.path` setting, advising users to install Deno CLI and explicitly set the path if needed. However, this is documentation and not a code-level mitigation.
      ```markdown
      > ⚠️ **Important:** You need to have a version of Deno CLI installed (v1.13.0 or
      > later). The extension requires the executable and by default will use the
      > environment path. You can explicitly set the path to the executable in Visual
      > Studio Code Settings for `deno.path`.
      ```
- Missing mitigations:
    - **Path Validation:** The extension should validate the `deno.path` setting to ensure it points to a legitimate Deno executable. This could involve checking if the path is a valid file path and if the file is executable.
    - **Executable Validation:** Implement checks to verify the integrity and authenticity of the Deno executable. This could include:
        - **Signature Verification:** If possible, verify the digital signature of the Deno executable to ensure it's signed by Deno Land Inc.
        - **Known Path Check:**  If the user explicitly sets the `deno.path`, warn the user if the path is unusual or outside of typical installation directories. For example, if the path is within a user's temporary directory.
        - **Heuristics:** Implement basic heuristics to detect potentially malicious executables, although this is less reliable and could lead to false positives.
    - **User Warning:** If the `deno.path` is manually configured, display a prominent warning to the user, emphasizing the security risks of pointing to untrusted executables and advising them to only set this path if they are absolutely sure about the executable's origin and integrity.
- Preconditions:
    - The user must have the VS Code Deno extension installed.
    - An attacker must successfully socially engineer the user into manually configuring the `deno.path` setting in VS Code to point to a malicious executable.
    - The user must trigger any functionality of the Deno extension that necessitates the execution of the Deno CLI.
- Source code analysis:
    - `client/src/util.ts`:
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
        - The `getDenoCommandPath` function retrieves the `deno.path` from the workspace configuration using `getWorkspaceConfigDenoExePath`.
        - It attempts to resolve relative paths against workspace folders.
        - If no `deno.path` is set or resolution fails, it falls back to `getDefaultDenoCommand` to search for "deno" in the environment path and default install locations.
        - **Vulnerability:** There is no validation of the `exePath` obtained from `workspace.getConfiguration(EXTENSION_NS).get<string>("path")`. If a user sets this to a malicious executable path, the function will directly return it.

    - `client/src/commands.ts`:
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
                command, // Vulnerability: `command` (malicious path) is used directly here
                args: ["lsp"],
                options: { env },
              },
              debug: {
                command, // Vulnerability: `command` (malicious path) is used directly here
                args: ["lsp"],
                options: { env },
              },
            };
            const client = new LanguageClient(
              LANGUAGE_CLIENT_ID,
              LANGUAGE_CLIENT_NAME,
              serverOptions,
              {
                outputChannel: extensionContext.outputChannel,
                middleware: { /* ... */ },
                ...extensionContext.clientOptions,
              },
            );
            // ...
          };
        }
        ```
        - The `startLanguageServer` function calls `getDenoCommandPath()` to obtain the `command`.
        - **Vulnerability:** The `command` variable, which can be a path to a malicious executable if configured by the user, is directly used in `serverOptions.run.command` and `serverOptions.debug.command` without any checks. This leads to the execution of the malicious executable when the language server starts or restarts.

- Security test case:
    1. **Setup Malicious Executable:**
        - Create a new directory, for example, `C:\malicious_deno` (Windows) or `/tmp/malicious_deno` (Linux/macOS).
        - Inside this directory, create a file named `deno` (or `deno.exe` on Windows).
        - Make this file executable (e.g., `chmod +x deno` on Linux/macOS).
        - Write malicious code into this file. For example, on Linux/macOS using bash:
          ```bash
          #!/bin/bash
          echo "Malicious Deno Executable executed!" >> /tmp/malicious_execution.log
          # Add any other malicious commands here
          exit 1 # Exit with an error code to prevent further execution of extension
          ```
          On Windows, create a `deno.bat` file:
          ```bat
          @echo off
          echo Malicious Deno Executable executed! >> %TEMP%\malicious_execution.log
          exit 1
          ```
    2. **Configure VS Code Deno Extension:**
        - Open VS Code settings (File -> Preferences -> Settings or Code -> Settings -> Settings).
        - Search for `deno.path`.
        - Click "Edit in settings.json".
        - Add or modify the `deno.path` setting to point to the malicious executable created in step 1. For example:
          ```json
          "deno.path": "C:\\malicious_deno\\deno.exe" // Windows
          // or
          "deno.path": "/tmp/malicious_deno/deno"     // Linux/macOS
          ```
    3. **Enable Deno Extension (if not already enabled):**
        - Open the command palette (Ctrl+Shift+P or Cmd+Shift+P).
        - Type and select "Deno: Enable".
    4. **Trigger Extension Functionality:**
        - Open any JavaScript or TypeScript file in the workspace where Deno is enabled.
        - The extension will attempt to start the Deno language server, which will execute the malicious `deno` executable.
    5. **Verify Malicious Execution:**
        - Check for the log file created by the malicious executable. For example, check `/tmp/malicious_execution.log` (Linux/macOS) or `%TEMP%\malicious_execution.log` (Windows). The presence of the "Malicious Deno Executable executed!" line in the log file confirms the vulnerability.
        - Observe that the Deno extension might not function correctly because the malicious executable is not a valid Deno CLI and likely exits with an error, as intended in the test script.

This test case demonstrates that by manipulating the `deno.path` setting, an attacker can execute arbitrary code on the user's system via the VS Code Deno extension.
