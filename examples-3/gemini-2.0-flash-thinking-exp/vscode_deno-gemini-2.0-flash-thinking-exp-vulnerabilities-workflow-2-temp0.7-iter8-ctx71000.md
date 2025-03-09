## Vulnerability List

- Vulnerability Name: Command Injection via Test Arguments Configuration

- Description:
    1. An attacker crafts a malicious workspace containing a `.vscode/settings.json` file.
    2. Within this `settings.json`, the attacker sets the `deno.codeLens.testArgs` or `deno.testing.args` configuration options to include malicious system commands. For example: `["--allow-all", "; touch /tmp/pwned ;"]`.
    3. A victim opens this malicious workspace in Visual Studio Code with the Deno extension enabled.
    4. The victim attempts to run Deno tests, either by clicking the "Run Test" code lens or using the Test Explorer.
    5. The Deno extension uses the Deno CLI to execute tests, incorporating the attacker-defined arguments directly from the workspace settings without sanitization.
    6. Consequently, the injected commands are executed by the operating system, leading to command injection.

- Impact:
    - High. Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VS Code process. This can lead to full system compromise, data theft, and malware installation.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The extension directly passes the configuration values from `deno.codeLens.testArgs` and `deno.testing.args` to the Deno CLI without any validation or sanitization.

- Missing Mitigations:
    - Input sanitization and validation: Implement checks to sanitize or validate the `deno.codeLens.testArgs` and `deno.testing.args` settings. This should involve stripping or escaping potentially harmful characters or command sequences. Consider whitelisting allowed arguments or using parameterized command execution.
    - User Warning: Display a prominent warning to the user when the extension detects potentially unsafe settings within a workspace, especially those related to command execution. This warning should advise caution and recommend reviewing the settings before running commands.

- Preconditions:
    1. The victim must have Visual Studio Code installed with the Deno extension enabled.
    2. The victim must open a malicious workspace prepared by an attacker.
    3. The Deno extension must be enabled for the opened workspace.
    4. The victim must attempt to run Deno tests within the malicious workspace, either via Code Lens or Test Explorer.

- Source Code Analysis:
    1. File: `client/src/commands.ts`
    2. Function: `test`
    3. Code Snippet:
        ```typescript
        export function test(
          _context: vscode.ExtensionContext,
          extensionContext: DenoExtensionContext,
        ): Callback {
          return async (uriStr: string, name: string, options: TestCommandOptions) => {
            // ...
            const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
            const testArgs: string[] = [
              ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable code: Reading test arguments from configuration
            ];
            // ... other arguments ...
            const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // Command construction, including unsanitized arguments
            // ...
            const definition: tasks.DenoTaskDefinition = {
              type: tasks.TASK_TYPE,
              command: "test",
              args, // Unsanitized arguments passed to task definition
              env,
            };
            // ...
            const task = tasks.buildDenoTask(
              workspaceFolder,
              denoCommand,
              definition,
              `test "${name}"`,
              args, // Unsanitized arguments passed to buildDenoTask
              ["$deno-test"],
            );
            // ...
            const createdTask = await vscode.tasks.executeTask(task); // Task execution, leading to command injection
            // ...
          };
        }
        ```
    4. Visualization:
        ```
        [Workspace Settings (deno.codeLens.testArgs)] --> config.get() --> testArgs --> args --> vscode.tasks.executeTask() --> System Command Execution
        ```
    5. Explanation:
        - The `test` function in `client/src/commands.ts` retrieves the `deno.codeLens.testArgs` configuration from workspace settings without sanitization.
        - These arguments are directly incorporated into the command array (`args`) that is passed to `vscode.tasks.executeTask`.
        - The `vscode.tasks.executeTask` then executes the Deno CLI command, including the attacker-controlled arguments, leading to command injection.

- Security Test Case:
    1. Create a new directory named `malicious-deno-workspace`.
    2. Navigate into `malicious-deno-workspace` and create a `.vscode` subdirectory.
    3. Inside `.vscode`, create a file named `settings.json` with the following JSON content:
        ```json
        {
            "deno.enable": true,
            "deno.codeLens.testArgs": [
                "--allow-all",
                "; touch /tmp/pwned ;"
            ]
        }
        ```
    4. In `malicious-deno-workspace`, create a file named `test.ts` with the following TypeScript content:
        ```typescript
        Deno.test("vulnerability test", () => {
          console.log("Test running");
        });
        ```
    5. Open the `malicious-deno-workspace` folder in Visual Studio Code.
    6. Confirm that the Deno extension is enabled for this workspace.
    7. Open the `test.ts` file in the editor.
    8. Locate and click the "Run Test" code lens situated above the `Deno.test` declaration in the editor.
    9. After the test execution completes, verify the existence of a file named `pwned` in the `/tmp/` directory of your system using the command `ls /tmp/pwned` (or `dir /tmp/pwned` on Windows after adjusting the command in `settings.json`). If the file exists, it confirms successful command injection and remote code execution.

- Vulnerability Name: Arbitrary Code Execution via Malicious Deno Executable Path Configuration

- Description:
    1. An attacker can trick a user into setting the `deno.path` configuration in VS Code to point to a malicious executable instead of the legitimate Deno CLI. This can be achieved through social engineering or by providing a malicious workspace.
    2. The `deno.path` setting, when configured, is used by the Deno extension to determine the Deno CLI executable path.
    3. When the extension needs to execute any Deno command (e.g., for language server operations, testing, formatting, caching), it will use the configured `deno.path`.
    4. If `deno.path` points to a malicious executable, this executable will be run instead of the actual Deno CLI.
    5. This leads to arbitrary code execution on the user's machine with the privileges of the VS Code process, whenever the Deno extension invokes a Deno command.

- Impact:
    - Critical. Arbitrary code execution. Successful exploitation allows the attacker to execute arbitrary code on the user's machine every time the Deno extension interacts with the Deno CLI. This can result in complete system compromise, data theft, and malware installation.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None. The extension directly uses the path provided in the `deno.path` setting without any validation or sanitization. The extension relies on the user to configure this setting correctly.

- Missing Mitigations:
    - Path validation and sanitization for `deno.path` setting. The extension should validate that the `deno.path` points to a legitimate Deno executable. This could include:
        - Verifying that the path points to an executable file.
        - Checking if the executable is in a standard Deno installation directory or the system's PATH.
        - Implementing checks to verify the integrity of the executable, such as digital signature verification or hash comparison.
    - User Warning: Display a clear warning message to the user when the `deno.path` setting is explicitly configured, especially if it is set to a non-standard location. This warning should highlight the security risks and advise caution.
    - File Picker: Consider using a file picker dialog when setting the `deno.path` to guide users towards selecting the correct Deno executable and reduce the chance of manual path manipulation errors.

- Preconditions:
    1. The user must have the VS Code Deno extension installed.
    2. The attacker must be able to convince the user to change the `deno.path` setting to a malicious executable or provide a malicious workspace with this setting pre-configured.
    3. The Deno extension must be enabled and needs to invoke a Deno command for the exploit to trigger.

- Source Code Analysis:
    1. File: `client/src/util.ts`
    2. Function: `getDenoCommandPath`
    3. Code Snippet:
        ```typescript
        export async function getDenoCommandPath() {
          const command = getWorkspaceConfigDenoExePath();
          const workspaceFolders = workspace.workspaceFolders;
          if (!command || !workspaceFolders) {
            return command ?? await getDefaultDenoCommand();
          } else if (!path.isAbsolute(command)) {
            // ... relative path resolution ...
          } else {
            return command; // Directly returns user-provided path without validation
          }
        }

        function getWorkspaceConfigDenoExePath() {
          const exePath = workspace.getConfiguration(EXTENSION_NS)
            .get<string>("path"); // Retrieves "deno.path" setting
          if (typeof exePath === "string" && exePath.trim().length === 0) {
            return undefined;
          } else {
            return exePath; // Returns the configured path
          }
        }
        ```
    4. File: `client/src/commands.ts` (and other files using Deno CLI)
    5. Function: `startLanguageServer` (and others)
    6. Code Snippet (from `startLanguageServer`):
        ```typescript
        const command = await getDenoCommandPath(); // Retrieves deno path
        const serverOptions: ServerOptions = {
          run: {
            command, // User-controlled path used directly as command
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // User-controlled path used directly as command
            args: ["lsp"],
            options: { env },
          },
        };
        const client = new LanguageClient( ... serverOptions, ... ); // Executes the command
        ```
    7. Visualization:
        ```
        [VS Code Settings (deno.path)] --> getWorkspaceConfigDenoExePath() --> getDenoCommandPath() --> command --> LanguageClient/vscode.tasks.executeTask() --> System Command Execution
        ```
    8. Explanation:
        - `getDenoCommandPath` retrieves the `deno.path` setting and returns it directly if it's an absolute path, without any validation.
        - This path is then used as the `command` in `LanguageClient` and `vscode.tasks.executeTask` when the extension needs to execute Deno commands.
        - If `deno.path` is set to a malicious executable, that executable will be run instead of the real Deno CLI, leading to arbitrary code execution.

- Security Test Case:
    1. **Preparation:**
        - Create a malicious executable file (e.g., `malicious-deno.sh` or `malicious-deno.bat`). This script should perform an identifiable action, such as creating a file named `pwned_deno_path.txt` in the user's temporary directory.
        - Example `malicious-deno.sh`:
          ```bash
          #!/bin/bash
          touch /tmp/pwned_deno_path.txt
          ```
    2. **VS Code Configuration:**
        - Open VS Code.
        - Open User Settings (or Workspace Settings).
        - Search for `deno.path`.
        - Set `deno.path` to the path of your malicious executable (e.g., `/tmp/malicious-deno.sh`).
    3. **Trigger Extension Action:**
        - Open a JavaScript or TypeScript file in VS Code.
        - Ensure the Deno extension is enabled.
        - Trigger any Deno extension feature that executes a Deno command. For example: run "Deno: Cache" command from the command palette.
    4. **Verification:**
        - Check if the malicious executable was executed by verifying if the file `/tmp/pwned_deno_path.txt` was created.
        - If the file exists, it confirms that the malicious executable was run when the Deno extension tried to invoke Deno, demonstrating arbitrary code execution via `deno.path`.
