## Vulnerability List

- Vulnerability Name: Arbitrary Code Execution via `deno.path` Setting

- Description:
    1. An attacker uses social engineering to trick a victim into installing the "Deno for Visual Studio Code" extension.
    2. The attacker persuades the victim to modify the `deno.path` setting within VS Code.
    3. Instead of specifying the correct path to the legitimate Deno CLI executable, the victim is misled into setting `deno.path` to point to a malicious executable controlled by the attacker.
    4. When the VS Code Deno extension attempts to invoke the Deno CLI for various features such as type checking, linting, formatting, testing, or upgrading Deno, it uses the path specified in `deno.path`.
    5. Consequently, the extension executes the attacker's malicious executable instead of the genuine Deno CLI.
    6. The malicious executable runs with the same privileges as the VS Code user, leading to arbitrary code execution on the victim's system.

- Impact:
    Successful exploitation of this vulnerability allows the attacker to achieve arbitrary code execution on the victim's machine. This can have severe consequences, including:
    - Data theft and exfiltration of sensitive information.
    - Installation of malware, ransomware, or other malicious software.
    - Complete compromise of the victim's system, allowing the attacker to control the machine remotely.
    - Unauthorized access to and modification of files and system settings.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None in the code to prevent this specific social engineering attack.
    - The extension's README.md provides a note under "Usage" and "Configuration" sections mentioning the `deno.path` setting and the requirement to have Deno CLI installed. However, this serves as documentation, not an active mitigation against malicious path configuration.

- Missing Mitigations:
    - **Input Validation for `deno.path`:** Implement validation checks for the `deno.path` setting. This could include:
        - Verifying if the path points to an executable file.
        - Checking if the executable is indeed the Deno CLI by verifying its version or signature. (This is complex and might interfere with legitimate use cases, like using custom Deno builds).
        - Restricting the `deno.path` setting to known safe locations or prompting for confirmation if the path is outside standard directories.
    - **Warning on `deno.path` Modification:** Display a prominent warning message whenever a user modifies the `deno.path` setting. This warning should clearly articulate the security risks associated with pointing `deno.path` to untrusted or unknown executables and advise users to only set it to the path of a legitimate and trusted Deno CLI.
    - **Enhanced Documentation:** Improve the documentation to more prominently highlight the security implications of the `deno.path` setting. Add a dedicated security considerations section in the README.md that details this vulnerability and provides clear guidance to users on how to avoid it, emphasizing the importance of only using trusted Deno CLI executables.

- Preconditions:
    1. The victim has Visual Studio Code installed.
    2. The "Deno for Visual Studio Code" extension is installed and enabled in VS Code.
    3. The attacker successfully social engineers the victim into altering the `deno.path` setting in VS Code to point to a malicious executable.

- Source Code Analysis:
    - **`client\src\util.ts`:**
        - `getDenoCommandPath()` function: This function is responsible for determining the path to the Deno executable. It first checks the `deno.path` configuration setting (`getWorkspaceConfigDenoExePath()`). If a path is specified there, it is used directly without any validation. If `deno.path` is not set or is a relative path, it attempts to resolve "deno" from the system's PATH and default installation directories (`getDefaultDenoCommand()`).
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
        - `getDenoCommandName()` function: This function simply calls `getDenoCommandPath()` and defaults to "deno" if no path is found.
        ```typescript
        export async function getDenoCommandName() {
          return await getDenoCommandPath() ?? "deno";
        }
        ```
    - **`client\src\commands.ts`, `client\src\tasks.ts`, `client\src\debug_config_provider.ts`:**
        - These files import and utilize `getDenoCommandName()` to obtain the Deno executable path. This path is then used to spawn child processes for executing Deno CLI commands related to various extension features like language server, testing, tasks, and debugging. For example, in `client\src\commands.ts`, the `startLanguageServer` function uses `getDenoCommandPath()` to define the server options:
        ```typescript
        const serverOptions: ServerOptions = {
          run: {
            command, // from getDenoCommandPath()
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // from getDenoCommandPath()
            // disabled for now, as this gets super chatty during development
            // args: ["lsp", "-L", "debug"],
            args: ["lsp"],
            options: { env },
          },
        };
        ```
        - Similarly, `client\src\tasks.ts` and `client\src\debug_config_provider.ts` use `getDenoCommandName()` in `buildDenoTask`, `buildDenoConfigTask` and `provideDebugConfigurations` respectively to execute Deno commands.
        - **Visualization:**
        ```mermaid
        graph LR
            subgraph VS Code Deno Extension
                client_commands(client\src\commands.ts) --> util_getDenoCommandName(client\src\util.ts: getDenoCommandName)
                client_tasks(client\src\tasks.ts) --> util_getDenoCommandName
                client_debug_config(client\src\debug_config_provider.ts) --> util_getDenoCommandName
                util_getDenoCommandName --> util_getDenoCommandPath(client\src\util.ts: getDenoCommandPath)
                util_getDenoCommandPath --> vscode_configuration(VS Code Configuration: deno.path)
                vscode_configuration -- configured path --> malicious_executable(Malicious Executable)
                vscode_configuration -- not configured or default --> deno_cli(Legitimate Deno CLI)
                client_commands --> malicious_executable
                client_commands --> deno_cli
                client_tasks --> malicious_executable
                client_tasks --> deno_cli
                client_debug_config --> malicious_executable
                client_debug_config --> deno_cli
            end
            user(VS Code User) --> vscode_configuration
            attacker(Attacker) --> user(Social Engineering)
        ```

- Security Test Case:
    1. **Setup Malicious Executable:**
        - Create a file named `malicious_deno` (or `malicious_deno.exe` on Windows) with the following content:
            - For Linux/macOS (`malicious_deno`):
              ```bash
              #!/bin/bash
              echo "[MALICIOUS DENO EXECUTABLE]: Executed!"
              echo "Malicious action can be performed here..."
              exit 1
              ```
              Make it executable: `chmod +x malicious_deno`
            - For Windows (`malicious_deno.exe`):
              ```batch
              @echo off
              echo [MALICIOUS DENO EXECUTABLE]: Executed!
              echo Malicious action can be performed here...
              exit /b 1
              ```
        - Place this executable in a directory, for example, `/tmp/malicious_bin` (or `C:\malicious_bin` on Windows).

    2. **Social Engineering (Simulated):**
        - Assume the attacker has convinced the victim to set `deno.path` to the malicious executable.

    3. **Configure `deno.path` in VS Code:**
        - Open VS Code.
        - Go to Settings (Ctrl+, or Code > Settings > Settings).
        - Search for "deno path".
        - Edit the "Deno › Path" setting and enter the path to the malicious executable. For example:
            - Linux/macOS: `/tmp/malicious_bin/malicious_deno`
            - Windows: `C:\malicious_bin\malicious_deno.exe`

    4. **Trigger Deno Extension Feature:**
        - Open any JavaScript or TypeScript file in VS Code.
        - Enable Deno for the workspace if not already enabled (using "Deno: Enable" command).
        - Attempt to format the document (Right-click in the editor > Format Document > Deno).

    5. **Observe Malicious Execution:**
        - Observe the output. You should see the message "[MALICIOUS DENO EXECUTABLE]: Executed!" in the output panel or terminal, indicating that the malicious executable was run instead of the legitimate Deno CLI.
        - The formatting will likely fail, as the malicious executable is not a valid Deno CLI.

This security test case confirms that the vulnerability is valid and exploitable through social engineering and manipulation of the `deno.path` setting.
