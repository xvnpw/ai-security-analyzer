### Vulnerability List

* Vulnerability Name: Malicious Workspace Arbitrary Code Execution via `deno.path`

* Description:
    1. An attacker creates a malicious workspace folder.
    2. Inside the workspace folder, the attacker creates a `.vscode` directory.
    3. Within the `.vscode` directory, the attacker creates a `settings.json` file.
    4. In the `settings.json` file, the attacker sets the `deno.path` setting to point to a malicious executable located within the workspace or accessible to the victim's machine. For example:
        ```json
        {
            "deno.path": "./.vscode/malicious_deno.sh"
        }
        ```
    5. The attacker convinces a victim to download and open this malicious workspace in Visual Studio Code with the Deno extension installed.
    6. When the workspace is opened, the Deno extension reads the `deno.path` setting from the `settings.json` file.
    7. Subsequently, when the extension attempts to execute a Deno command (e.g., for language server, linting, formatting, testing, or tasks), it uses the attacker-specified malicious path instead of the legitimate Deno CLI.
    8. The malicious executable is then executed with the privileges of the victim user, leading to arbitrary code execution.

* Impact:
    * Critical. Successful exploitation allows the attacker to execute arbitrary code on the victim's machine with the victim's privileges. This can lead to complete compromise of the victim's local system, including data theft, malware installation, and further propagation of attacks.

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    * None in the code. The README.md mentions the `deno.path` setting and that it can be used to explicitly set the path, but it does not warn against setting it to untrusted locations or provide any input validation.

* Missing Mitigations:
    * **Input Validation and Sanitization:** The extension should validate and sanitize the `deno.path` setting to ensure it points to a legitimate Deno executable and not to arbitrary or potentially malicious files, especially within the workspace.
    * **Warning to User:** When the extension detects that `deno.path` is configured within workspace settings, it should display a prominent warning to the user, indicating the security risk of allowing workspace settings to override the Deno executable path. The warning should advise users to only open workspaces from trusted sources.
    * **Path Resolution Restrictions:** The extension could restrict `deno.path` to only allow absolute paths or paths within specific trusted directories, preventing relative paths within the workspace that could be easily manipulated by an attacker.
    * **User Confirmation:** Before using a `deno.path` defined in workspace settings for the first time (or when it changes), the extension could prompt the user for explicit confirmation, emphasizing the security implications.

* Preconditions:
    * The victim must have the VSCode Deno extension installed.
    * The attacker must be able to convince the victim to open a malicious workspace folder in VSCode.
    * The victim must not be aware of the security risks associated with opening workspaces from untrusted sources and allowing workspace settings to be applied.

* Source Code Analysis:
    1. **`client\src\util.ts` - `getDenoCommandPath()` function:**
        ```typescript
        export async function getDenoCommandPath() {
          const command = getWorkspaceConfigDenoExePath(); // [1]
          const workspaceFolders = workspace.workspaceFolders;
          if (!command || !workspaceFolders) {
            return command ?? await getDefaultDenoCommand(); // [2]
          } else if (!path.isAbsolute(command)) { // [3]
            // if sent a relative path, iterate over workspace folders to try and resolve.
            for (const workspace of workspaceFolders) {
              const commandPath = path.resolve(workspace.uri.fsPath, command); // [4]
              if (await fileExists(commandPath)) {
                return commandPath; // [5]
              }
            }
            return undefined;
          } else {
            return command; // [6]
          }
        }
        ```
        - `[1]` `getWorkspaceConfigDenoExePath()` retrieves the `deno.path` setting from the workspace configuration.
        - `[2]` If `deno.path` is not configured in workspace settings, it tries to resolve Deno from the default locations (`getDefaultDenoCommand`).
        - `[3]` Checks if the configured `deno.path` is absolute.
        - `[4]` If `deno.path` is relative, it attempts to resolve it relative to each workspace folder's root path. This is where a malicious relative path in workspace settings could point to an executable within the malicious workspace.
        - `[5]` If a file exists at the resolved path, it's returned as the Deno command path.
        - `[6]` If `deno.path` is absolute, it's directly returned without further validation other than file existence.

    2. **`client\src\util.ts` - `getWorkspaceConfigDenoExePath()` function:**
        ```typescript
        function getWorkspaceConfigDenoExePath() {
          const exePath = workspace.getConfiguration(EXTENSION_NS)
            .get<string>("path"); // [1]
          // it is possible for the path to be blank. In that case, return undefined
          if (typeof exePath === "string" && exePath.trim().length === 0) {
            return undefined;
          } else {
            return exePath; // [2]
          }
        }
        ```
        - `[1]` Retrieves the `deno.path` configuration setting using `vscode.workspace.getConfiguration(EXTENSION_NS).get<string>("path")`.
        - `[2]` Returns the configured path directly without any validation or sanitization, except for checking if it's an empty string.

    3. **Usage of `getDenoCommandName()` in `client\src\debug_config_provider.ts`:**
        ```typescript
        async provideDebugConfigurations(): Promise<vscode.DebugConfiguration[]> {
          // ...
          const debugConfig: vscode.DebugConfiguration = {
            // ...
            runtimeExecutable: await getDenoCommandName(), // [1]
            runtimeArgs: [
              "run",
              // ...
            ],
            // ...
          };
          // ...
          return [debugConfig];
        }
        ```
        - `[1]` `getDenoCommandName()` is called to get the Deno executable path, which is then directly used as `runtimeExecutable` in the debug configuration. VSCode will use this `runtimeExecutable` to spawn a process, thus executing the potentially malicious path from workspace settings.

    **Visualization:**

    ```mermaid
    graph LR
        subgraph VSCode Workspace
            subgraph .vscode
                settings.json --> MaliciousSettings[settings.json: {"deno.path": "./.vscode/malicious_deno.sh"}]
                malicious_deno.sh
            end
            victim_code.ts
        end
        subgraph VSCode Deno Extension
            getWorkspaceConfigDenoExePath --> ReadSettings[Read "deno.path" from settings.json]
            ReadSettings --> getDenoCommandPath
            getDenoCommandPath --> PathResolution[Resolve "./.vscode/malicious_deno.sh" relative to workspace]
            PathResolution --> ReturnMaliciousPath["Return: <workspace>/.vscode/malicious_deno.sh"]
            getDenoCommandName --> getDenoCommandPath
            DebugConfigurationProvider --> getDenoCommandName
            DebugConfigurationProvider --> UseMaliciousPath[Use <workspace>/.vscode/malicious_deno.sh as runtimeExecutable]
            UseMaliciousPath --> ExecuteMaliciousCode[Execute <workspace>/.vscode/malicious_deno.sh]
        end
        ExecuteMaliciousCode --> VictimSystemCompromised[Victim System Compromised]
    ```

* Security Test Case:
    1. **Setup:**
        a. Create a new directory named `malicious-workspace`.
        b. Inside `malicious-workspace`, create a subdirectory named `.vscode`.
        c. Inside `.vscode`, create a file named `settings.json` with the following content:
            ```json
            {
                "deno.path": "./.vscode/malicious_deno.sh"
            }
            ```
        d. Inside `.vscode`, create a file named `malicious_deno.sh` (or `malicious_deno.bat` for Windows) with the following content:
            ```bash
            #!/bin/bash
            echo "Malicious script executed!" > malicious_output.txt
            ```
            (For Windows `malicious_deno.bat`):
            ```batch
            @echo off
            echo Malicious script executed! > malicious_output.txt
            ```
        e. Make `malicious_deno.sh` executable (e.g., `chmod +x .vscode/malicious_deno.sh`).
        f. Create a file named `main.ts` in the `malicious-workspace` directory (content doesn't matter, e.g., `console.log("Hello Deno");`).
    2. **Victim Action:**
        a. Open Visual Studio Code.
        b. Open the `malicious-workspace` folder.
        c. Ensure the Deno extension is enabled for the workspace (if not enabled by default, enable it).
        d. Trigger a Deno command that would use `deno.path`. For example, open `main.ts` and attempt to run a test code lens if available, or try to format the document, or run a Deno task. A simpler trigger is to just attempt to debug `main.ts` by creating a debug configuration and starting debugging.
    3. **Verification:**
        a. After triggering a Deno command, check if a file named `malicious_output.txt` has been created in the `malicious-workspace` directory.
        b. If `malicious_output.txt` exists and contains the text "Malicious script executed!", the vulnerability is confirmed. This indicates that the malicious script specified in `deno.path` was executed by the extension.

This test case demonstrates that by setting a malicious path in workspace settings, an attacker can achieve arbitrary code execution when the victim interacts with the Deno extension in the malicious workspace.
