### Vulnerability 1: Arbitrary code execution via `deno.path` setting

- Description:
    1. An attacker crafts a malicious Visual Studio Code workspace.
    2. This workspace includes a `.vscode/settings.json` file.
    3. The `.vscode/settings.json` file sets the `deno.path` configuration to point to a malicious executable instead of the legitimate Deno CLI.
    4. A victim user opens this malicious workspace in Visual Studio Code with the Deno extension installed.
    5. When the Deno extension initializes or attempts to use Deno CLI for any feature (like type checking, linting, formatting, testing, etc.), it reads the `deno.path` setting from the workspace configuration.
    6. Instead of executing the legitimate Deno CLI, the extension unknowingly executes the malicious executable specified in the `deno.path` setting.
    7. The malicious executable then runs with the privileges of the user running Visual Studio Code, leading to arbitrary code execution.

- Impact:
    - Critical. Successful exploitation allows the attacker to execute arbitrary code on the victim's machine. This can lead to:
        - Full compromise of the user's system.
        - Data theft, including sensitive files and credentials.
        - Installation of malware, backdoors, or ransomware.
        - Unauthorized access to other systems and networks accessible from the victim's machine.

- Vulnerability rank: Critical

- Currently implemented mitigations:
    - None in the provided code explicitly mitigate this vulnerability.
    - The extension relies on the user having a correctly configured and trusted environment and assumes users will not open workspaces from untrusted sources or modify settings to point to malicious executables.
    - VS Code's Workspace Trust feature is a general mitigation, but it's not specific to the Deno extension and can be bypassed by the user.

- Missing mitigations:
    - Input validation and sanitization for the `deno.path` setting. The extension should verify that the provided path points to a valid Deno executable and potentially check its integrity (e.g., using checksums or signatures).
    - Display a clear warning to the user when the `deno.path` setting is changed within a workspace, especially if it's an unusual or suspicious path.
    - Implement a mechanism to verify the integrity of the Deno CLI executable before execution.
    - Leverage VS Code's Workspace Trust API more explicitly to prompt users to trust workspaces before applying workspace settings, especially those that can lead to code execution.
    - Consider restricting the `deno.path` setting to user settings only and disallowing workspace-level configuration, although this would reduce the flexibility of the extension.

- Preconditions:
    - The victim user has the "Deno for Visual Studio Code" extension installed.
    - The victim user opens a malicious workspace in Visual Studio Code.
    - Workspace Trust in VS Code is either not enabled, or the user has explicitly trusted the malicious workspace, or bypassed the trust prompt.

- Source code analysis:
    1. **`client/src/util.ts:getDenoCommandPath()`**: This function is responsible for resolving the path to the Deno executable.
    ```typescript
    export async function getDenoCommandPath() {
      const command = getWorkspaceConfigDenoExePath(); // [1]
      const workspaceFolders = workspace.workspaceFolders;
      if (!command || !workspaceFolders) {
        return command ?? await getDefaultDenoCommand(); // [2]
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
        - `[1] getWorkspaceConfigDenoExePath()`: This function retrieves the `deno.path` setting from the workspace configuration.
        - `[2] getDefaultDenoCommand()`: If `deno.path` is not set, it tries to resolve "deno" from the environment PATH.
    2. **`client/src/util.ts:getWorkspaceConfigDenoExePath()`**: This function directly fetches the `deno.path` setting without any validation.
    ```typescript
    function getWorkspaceConfigDenoExePath() {
      const exePath = workspace.getConfiguration(EXTENSION_NS)
        .get<string>("path"); // [3]
      // it is possible for the path to be blank. In that case, return undefined
      if (typeof exePath === "string" && exePath.trim().length === 0) {
        return undefined;
      } else {
        return exePath;
      }
    }
    ```
        - `[3] workspace.getConfiguration(EXTENSION_NS).get<string>("path")`: This line gets the `deno.path` setting. There is no validation or sanitization of this path.
    3. **Usage of `getDenoCommandName` and `getDenoCommandPath`**: These functions are used throughout the extension to get the Deno executable path whenever the extension needs to execute a Deno CLI command. For example, in `client/src/debug_config_provider.ts`, `client/src/tasks.ts`, and `client/src/commands.ts`. This means that the potentially malicious path from `deno.path` is used in various extension functionalities.

    **Visualization:**

    ```
    User opens malicious workspace --> .vscode/settings.json sets "deno.path" -->
    VS Code loads workspace settings --> Deno extension reads "deno.path" using `getWorkspaceConfigDenoExePath()` -->
    Extension uses `getDenoCommandName()`/`getDenoCommandPath()` to get Deno executable path -->
    Extension executes command using the path from "deno.path" (malicious executable) -->
    Arbitrary code execution
    ```

- Security test case:
    1. **Prepare a malicious executable:**
        - Create a file named `malicious_deno.sh` (or `malicious_deno.bat` on Windows) with the following content:
            ```bash
            #!/bin/bash
            echo "[MALICIOUS DENO] Executed malicious deno!"
            # Optional: You can add more malicious commands here, e.g., create a file, etc.
            exit 1
            ```
            (For `.bat` file, use equivalent Windows commands)
        - Make the script executable: `chmod +x malicious_deno.sh`
    2. **Create a malicious workspace:**
        - Create a new directory, e.g., `malicious-workspace`.
        - Inside `malicious-workspace`, create a `.vscode` directory.
        - Inside `.vscode`, create a `settings.json` file with the following content:
            ```json
            {
                "deno.path": "./malicious_deno.sh"
            }
            ```
            - Place the `malicious_deno.sh` (or `malicious_deno.bat`) file in the `malicious-workspace` directory (at the same level as `.vscode`).
        - Create a dummy Deno/TypeScript file, e.g., `main.ts` in `malicious-workspace` to trigger extension features if needed (content doesn't matter).
    3. **Open the malicious workspace in VS Code:**
        - Open Visual Studio Code.
        - Open the `malicious-workspace` folder.
        - If prompted by Workspace Trust, choose "No, do not trust" to simulate a more secure default scenario, or "Trust Workspace" to directly test the vulnerability bypassing trust. For testing the vulnerability, trusting workspace makes it easier to trigger without extra confirmation prompts.
    4. **Trigger Deno extension functionality:**
        - Open the `main.ts` file (or any file in the workspace).
        - Try to use any Deno extension feature. For example:
            - Run "Deno: Language Server Status" command from the command palette.
            - Try to format or lint the `main.ts` file.
            - Enable Deno for the workspace using "Deno: Enable" command if it's not already enabled.
    5. **Observe the execution of the malicious executable:**
        - Open the Output panel in VS Code (View -> Output) and select "Deno Language Server" in the dropdown.
        - You should see the output `[MALICIOUS DENO] Executed malicious deno!` in the output panel, indicating that the `malicious_deno.sh` script was executed instead of the real Deno CLI.
        - If you added more malicious commands in the script, observe their effects as well.

This test case demonstrates that by manipulating the `deno.path` setting in workspace settings, an attacker can achieve arbitrary code execution when a user opens a malicious workspace with the Deno extension.
