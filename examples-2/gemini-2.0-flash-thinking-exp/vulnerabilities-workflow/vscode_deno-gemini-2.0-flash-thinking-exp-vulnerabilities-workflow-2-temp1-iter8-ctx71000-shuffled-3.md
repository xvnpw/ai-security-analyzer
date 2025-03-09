### Vulnerability List

* Vulnerability Name: Command Injection via `deno.path` setting
* Description:
    1. The VS Code Deno extension allows users to specify the path to the Deno executable through the `deno.path` setting.
    2. This path is used by the extension to execute the Deno CLI for various features like language server, debugging, and tasks.
    3. The extension directly uses the user-provided `deno.path` without sufficient sanitization.
    4. An attacker can configure the `deno.path` setting to point to a malicious executable instead of the legitimate Deno CLI.
    5. When the extension attempts to execute Deno CLI, it will execute the malicious executable specified in `deno.path`.
    6. This allows the attacker to achieve arbitrary command execution on the user's machine with the privileges of the VS Code process.
* Impact:
    - An attacker can execute arbitrary commands on the user's machine.
    - This can lead to data theft, malware installation, or complete system compromise.
    - The impact is significant as it allows for full control over the user's development environment.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - None: The code directly uses the `deno.path` setting to execute commands without any sanitization or validation.
* Missing Mitigations:
    - Input sanitization: The extension should sanitize the `deno.path` setting to prevent command injection. This could involve:
        - Validating that the path points to a known Deno executable or verifying its integrity.
        - Restricting the characters allowed in the path to prevent injection of malicious commands.
        - Using secure APIs to execute the Deno CLI that prevent command injection, regardless of the path.
    - User awareness: Documentation should explicitly warn users about the security risks of modifying the `deno.path` setting and advise them to only set it to trusted Deno executable locations.
* Preconditions:
    - The user must have the VS Code Deno extension installed.
    - The attacker must be able to modify the user's VS Code settings, which can be achieved through:
        - Social engineering to trick the user into manually changing the `deno.path` setting.
        - Workspace configuration: If the user opens a workspace provided by the attacker that includes malicious workspace settings (e.g., in `.vscode/settings.json`).
* Source Code Analysis:
    1. **`client\src\util.ts:getDenoCommandPath()`**: This function retrieves the `deno.path` from the workspace configuration using `getWorkspaceConfigDenoExePath()`.
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
        - The function `getWorkspaceConfigDenoExePath()` simply retrieves the `deno.path` setting value without any sanitization.
        - The function checks if the path is absolute or relative but does not validate the content or safety of the path itself.
    2. **`client\src\extension.ts:startLanguageServer()`**: This function starts the Deno Language Server and uses the path obtained from `getDenoCommandPath()`.
        ```typescript
        export function startLanguageServer(
          context: vscode.ExtensionContext,
          extensionContext: DenoExtensionContext,
        ): Callback {
          return async () => {
            // ...
            const command = await getDenoCommandPath();
            if (command == null) {
              // ...
              return;
            }

            const serverOptions: ServerOptions = {
              run: {
                command, // User-controlled path is directly used here
                args: ["lsp"],
                options: { env },
              },
              debug: {
                command, // User-controlled path is directly used here
                // args: ["lsp", "-L", "debug"],
                args: ["lsp"],
                options: { env },
              },
            };
            const client = new LanguageClient(
              LANGUAGE_CLIENT_ID,
              LANGUAGE_CLIENT_NAME,
              serverOptions,
              {
                // ...
              },
            );
            // ...
            await client.start();
            // ...
          };
        }
        ```
        - The `command` variable, which is derived from the user-configurable `deno.path`, is directly passed to the `ServerOptions` without any validation or sanitization.
        - This `command` is then used by `vscode-languageclient` to spawn a process, leading to command injection if a malicious path is provided.
    3. **`client\src\debug_config_provider.ts:DenoDebugConfigurationProvider.provideDebugConfigurations()` and `client\src\tasks.ts:buildDenoTask()`**: These functions also use `getDenoCommandName()` which internally uses the potentially malicious `deno.path` to execute Deno commands for debugging and tasks.

* Security Test Case:
    1. **Setup:**
        - Install the VS Code Deno extension.
        - Create a new workspace in VS Code.
        - Create a file named `malicious.bat` (on Windows) or `malicious.sh` (on Linux/macOS) in a directory of your choice. This script will execute a harmless command for demonstration purposes, such as opening the calculator app on Windows or displaying a notification on Linux/macOS.

        **`malicious.bat` (Windows):**
        ```batch
        @echo off
        start calc.exe
        echo Malicious script executed!
        ```

        **`malicious.sh` (Linux/macOS):**
        ```bash
        #!/bin/bash
        notify-send "VS Code Deno Extension Vulnerability" "Malicious script executed!"
        ```
        (Note: For `notify-send` to work on macOS, you may need to install it using `brew install terminal-notifier` and use `terminal-notifier` instead of `notify-send`)
        - Make the script executable (`chmod +x malicious.sh` on Linux/macOS).
    2. **Configuration:**
        - In VS Code, open the settings (`Ctrl+,`).
        - Search for `deno.path`.
        - Set the `deno.path` setting to the absolute path of the `malicious.bat` or `malicious.sh` script created in step 1. For example: `C:\path\to\malicious.bat` or `/path/to/malicious.sh`.
        - Ensure that Deno is enabled for the workspace (`deno.enable: true`). You may need to run the "Deno: Enable" command.
    3. **Trigger Vulnerability:**
        - Open any JavaScript or TypeScript file in the workspace. This will trigger the Deno Language Server to start, which will use the `deno.path` setting.
        - Alternatively, attempt to run a Deno task or debug a Deno program, which also uses the `deno.path` setting.
    4. **Verification:**
        - Observe that the malicious script executes. For `malicious.bat`, the calculator application should open. For `malicious.sh`, a notification should appear.
        - This demonstrates that the VS Code Deno extension executed the malicious script specified in `deno.path`, confirming the command injection vulnerability.

This vulnerability allows an attacker to execute arbitrary code on a user's machine simply by tricking them into opening a workspace with a malicious `deno.path` setting or by socially engineering them to change their user settings. This is a critical security flaw that needs to be addressed immediately.
