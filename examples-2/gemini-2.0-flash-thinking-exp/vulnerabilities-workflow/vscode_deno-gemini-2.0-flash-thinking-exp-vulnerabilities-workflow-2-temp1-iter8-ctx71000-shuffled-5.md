### Vulnerability List

- Vulnerability Name: Arbitrary Code Execution via Deno Path Override
- Description:
    1. An attacker crafts a malicious repository.
    2. Within this repository, the attacker creates a `.vscode/settings.json` file inside the `.vscode` directory.
    3. The attacker adds a configuration to `.vscode/settings.json` that overrides the `deno.path` setting. This setting is maliciously crafted to point to an executable under the attacker's control, instead of the legitimate Deno CLI executable.
    4. The attacker then tricks a developer into opening this malicious repository in Visual Studio Code, assuming the developer has the "Deno for Visual Studio Code" extension installed.
    5. When the workspace is opened, and the Deno extension initializes or any feature requiring the Deno CLI is triggered (like language server functionalities, formatting, linting, testing, or tasks), the extension reads the `deno.path` setting from the workspace configuration.
    6. Due to the malicious `.vscode/settings.json`, the extension inadvertently executes the attacker's malicious executable instead of the intended Deno CLI.
    7. This results in arbitrary code execution on the developer's machine, running with the same privileges as the Visual Studio Code process.
- Impact:
    Successful exploitation of this vulnerability allows the attacker to achieve arbitrary code execution on the developer's machine. This can have severe consequences, including:
    - Data exfiltration: Sensitive data, source code, credentials, or intellectual property can be stolen from the developer's machine.
    - Malware installation: The attacker can install malware, ransomware, or backdoors, leading to persistent compromise and further malicious activities.
    - System compromise: Complete control over the developer's system can be gained, allowing the attacker to perform any action a legitimate user could.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    There are no mitigations implemented in the provided project files to prevent this vulnerability. The extension directly uses the path specified in the `deno.path` setting without any validation or security checks.
- Missing Mitigations:
    - Input validation: The extension should validate the `deno.path` setting to ensure it points to a legitimate Deno executable. This could include:
        - Checking if the path is absolute.
        - Verifying the executable exists at the specified path.
        - Potentially checking a digital signature or hash of the executable against known good Deno CLI versions.
    - User warning: When the extension detects that `deno.path` is being overridden by workspace settings (especially for the first time or when changed), it should display a prominent warning to the user, informing them of the potential security risk and asking for confirmation.
    - Restrict workspace setting overrides: Consider an option to restrict the `deno.path` setting to be configurable only in user settings, preventing workspace-level overrides that are susceptible to this attack vector.
- Preconditions:
    - The developer must have Visual Studio Code installed.
    - The "Deno for Visual Studio Code" extension must be installed and enabled.
    - The developer must open a workspace that contains a malicious `.vscode/settings.json` file crafted by the attacker.
- Source Code Analysis:
    1. **`client/src/util.ts` - `getWorkspaceConfigDenoExePath()` function:**
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
       This function retrieves the `deno.path` setting directly from the VS Code workspace configuration without any validation.

    2. **`client/src/util.ts` - `getDenoCommandPath()` function:**
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
       This function uses `getWorkspaceConfigDenoExePath()` to get the configured path. It only checks if the path is absolute for relative path resolution within workspace folders but performs no validation on the executable itself for security.

    3. **`client/src/commands.ts` - `startLanguageServer()` function:**
       ```typescript
       const command = await getDenoCommandPath();
       if (command == null) {
         // ... error handling ...
         return;
       }

       const serverOptions: ServerOptions = {
         run: {
           command, // Malicious path can be injected here
           args: ["lsp"],
           options: { env },
         },
         debug: {
           command, // Malicious path can be injected here
           args: ["lsp"],
           options: { env },
         },
       };
       const client = new LanguageClient( ... serverOptions, ... );
       ```
       The `startLanguageServer` function uses the potentially attacker-controlled `command` variable (obtained from `getDenoCommandPath()`) directly as the `command` for `serverOptions.run` and `serverOptions.debug` when starting the language server.

    4. **`client/src/debug_config_provider.ts` - `provideDebugConfigurations()` and `resolveDebugConfiguration()` functions:**
        These functions also utilize `getDenoCommandName()` which eventually calls `getDenoCommandPath()` to determine the `runtimeExecutable` for debugging configurations, thus being vulnerable in the same way.

    **Visualization:**

    ```
    User Opens Malicious Workspace --> .vscode/settings.json (malicious deno.path) --> VS Code Configuration --> Extension reads deno.path (client/src/util.ts) --> Extension executes malicious executable (client/src/commands.ts, client/src/debug_config_provider.ts) --> Arbitrary Code Execution
    ```

- Security Test Case:
    1. **Setup:**
        - Create a directory named `malicious-repo`.
        - Inside `malicious-repo`, create a file named `malicious_deno.sh` (for Linux/macOS) or `malicious_deno.bat` (for Windows).
        - Add the following content to `malicious_deno.sh`:
          ```bash
          #!/bin/bash
          echo "Malicious Deno Executable is executed!"
          touch /tmp/malicious_deno_executed.txt
          ```
        - Make `malicious_deno.sh` executable: `chmod +x malicious_deno.sh`
        - Add the following content to `malicious_deno.bat`:
          ```batch
          @echo off
          echo Malicious Deno Executable is executed!
          type nul > %TEMP%\malicious_deno_executed.txt
          ```
        - Inside `malicious-repo`, create a directory named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json`.
        - Add the following JSON content to `.vscode/settings.json`:
          ```json
          {
              "deno.path": "./malicious_deno.sh"  // For Linux/macOS
              // "deno.path": ".\\malicious_deno.bat" // For Windows
          }
          ```
          **Note:** Choose the correct `deno.path` based on your operating system and ensure the path to the malicious script is correct relative to the `.vscode/settings.json` file.

    2. **Execution:**
        - Open Visual Studio Code.
        - Open the `malicious-repo` directory as a workspace in VS Code (File -> Open Folder... and select `malicious-repo`). Ensure the "Deno for Visual Studio Code" extension is active in this workspace.
        - Open the command palette (Ctrl+Shift+P or Cmd+Shift+P).
        - Execute the command "Deno: Language Server Status". This command triggers the extension to use the Deno CLI.

    3. **Verification:**
        - **Check Output:** Observe the Output panel in VS Code (View -> Output, and select "Deno Language Server" in the dropdown). You should see the message "Malicious Deno Executable is executed!" printed in the output, indicating that the malicious script was run.
        - **Check File System:** Check for the file `/tmp/malicious_deno_executed.txt` (Linux/macOS) or `%TEMP%\malicious_deno_executed.txt` (Windows). The existence of this file confirms that the malicious executable was successfully executed by the extension.

    If both verification steps are successful, it proves that the arbitrary code execution vulnerability via `deno.path` override is valid.
