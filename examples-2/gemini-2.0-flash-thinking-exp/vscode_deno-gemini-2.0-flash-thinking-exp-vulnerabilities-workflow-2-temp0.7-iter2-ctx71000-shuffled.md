- Vulnerability Name: Malicious Deno Path Configuration

- Description:
    - An attacker could socially engineer a user into changing the `deno.path` setting in Visual Studio Code.
    - The user is tricked into setting `deno.path` to point to a malicious executable instead of the legitimate Deno CLI.
    - When the VS Code Deno extension attempts to invoke Deno for various operations (like formatting, linting, testing, caching, or language server functionalities), it will execute the malicious executable specified in `deno.path`.

- Impact:
    - Arbitrary code execution on the user's machine.
    - This can lead to a wide range of malicious activities, including:
        - Data theft: The malicious script could access and exfiltrate sensitive information from the user's system.
        - Malware installation: The attacker could use the code execution to download and install malware on the user's machine.
        - System compromise: The attacker could gain persistent access to the user's system, potentially leading to further attacks or control.

- Vulnerability Rank: Critical

- Currently implemented mitigations:
    - The `README.md` file contains a warning message in the "Important" section, advising users to "explicitly set the path to the executable in Visual Studio Code Settings for `deno.path`."
    - This warning serves as documentation to mitigate the risk by informing users about the setting, but it does not actively prevent a user from configuring a malicious path.

- Missing mitigations:
    - Input validation for the `deno.path` setting: The extension should validate the path provided by the user to ensure it is likely to be a legitimate Deno executable. This could include:
        - Checking if the executable exists at the given path.
        - Verifying the file signature of the executable against a known Deno signature (more complex and might require updates for new Deno versions).
        - Checking if the path is within a typical installation directory for Deno (e.g., `/usr/bin/deno`, `C:\Program Files\deno\deno.exe`, `~/.deno/bin/deno`).
    - Warning message on settings change: Display a prominent warning message when a user modifies the `deno.path` setting, especially if the path is unusual or outside of expected locations. This warning should explicitly mention the security risks of pointing to untrusted executables.
    - Path restriction: Provide an option to restrict the `deno.path` setting, allowing only paths within a predefined safe list of directories or requiring explicit user confirmation for paths outside these directories.

- Preconditions:
    - The user has the "Deno for Visual Studio Code" extension installed.
    - An attacker successfully employs social engineering techniques to convince the user to modify the `deno.path` setting in VS Code to point to a malicious executable. This could be achieved through phishing, misleading instructions, or by exploiting user trust.

- Source code analysis:
    - `client\src\util.ts`:
        - Function `getDenoCommandPath()` is responsible for resolving the path to the Deno executable.
        - It first checks the `deno.path` setting from VS Code configuration (`getWorkspaceConfigDenoExePath()`).
        - If `deno.path` is set, the extension directly uses this path, without any validation, to execute Deno commands.
        - If `deno.path` is not set or is a relative path, it attempts to resolve the "deno" command from the environment path.
        - There is no input validation or sanitization performed on the `deno.path` setting before it is used in process execution.
        ```typescript
        export async function getDenoCommandPath() {
          const command = getWorkspaceConfigDenoExePath(); // Retrieves deno.path setting
          const workspaceFolders = workspace.workspaceFolders;
          if (!command || !workspaceFolders) {
            return command ?? await getDefaultDenoCommand();
          } else if (!path.isAbsolute(command)) {
            // ... relative path resolution ...
          } else {
            return command; // Directly returns user-provided path without validation
          }
        }
        ```
    - `client\src\extension.ts`, `client\src\debug_config_provider.ts`, `client\src\tasks.ts`, `client\src\commands.ts`:
        - These files import and use `getDenoCommandName()` (which calls `getDenoCommandPath()`) to obtain the Deno executable path.
        - They then use this path to spawn child processes for various Deno commands (e.g., `deno lsp`, `deno run`, `deno test`, `deno cache`).
        - Because `getDenoCommandPath()` directly returns the user-configured path without validation, these features will execute whatever executable path is provided in `deno.path`.

- Security test case:
    1. Setup:
        - Create a directory named `malicious_deno` in a temporary location.
        - Inside `malicious_deno`, create a file named `malicious-deno.sh` (for Linux/macOS) or `malicious-deno.bat` (for Windows) with the following content:
            - `malicious-deno.sh`:
              ```bash
              #!/bin/bash
              echo "Malicious Deno Executable Executed!" > /tmp/malicious_execution.txt
              # Optionally, execute a legitimate deno command to avoid immediate errors from the extension
              /usr/bin/env deno "$@"
              ```
            - `malicious-deno.bat`:
              ```batch
              @echo off
              echo Malicious Deno Executable Executed! > %TEMP%\malicious_execution.txt
              # Optionally, execute a legitimate deno command to avoid immediate errors from the extension
              deno %*
              ```
            - Make the script executable: `chmod +x malicious-deno.sh` (Linux/macOS).
        - Ensure you have a legitimate Deno CLI installed and know its actual path (e.g., `/usr/bin/deno` on Linux/macOS, or where it's installed on Windows).  Modify the optional "legitimate deno command" part in the malicious script to point to your actual Deno path if you include it. If you don't include it, expect errors from the extension, but the vulnerability is still demonstrable by the file creation.

    2. VS Code Configuration:
        - Open Visual Studio Code.
        - Open settings (File > Preferences > Settings > or Code > Settings on macOS).
        - Search for "deno.path".
        - Set the `Deno › Path` setting to the absolute path of your malicious script (e.g., `/tmp/malicious_deno/malicious-deno.sh` or `C:\Users\YourUser\AppData\Local\Temp\malicious_deno\malicious-deno.bat`).
        - Ensure Deno is enabled for the workspace (`deno.enable` is true, or a `deno.json` file exists in the workspace root).

    3. Trigger Vulnerability:
        - Open any Deno project or a JavaScript/TypeScript file in a Deno-enabled workspace.
        - Execute any Deno extension command that invokes the Deno CLI. Examples:
            - Format the current document (Format Document command).
            - Run tests (if tests are defined and test code lens is enabled).
            - Cache dependencies (Deno: Cache command).
            - Trigger any language server feature that implicitly invokes Deno.

    4. Verification:
        - Check for the execution of the malicious script:
            - Verify that the file `/tmp/malicious_execution.txt` (Linux/macOS) or `%TEMP%\malicious_execution.txt` (Windows) has been created and contains the text "Malicious Deno Executable Executed!".
        - If you included the optional legitimate Deno command in the malicious script, the Deno extension features might appear to function partially, but the malicious action (file creation) confirms arbitrary code execution. If you didn't include it, the extension might show errors because the malicious script might not fully emulate the Deno CLI, but the file creation still confirms the vulnerability.

- Vulnerability Name: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings

- Description:
    1. The VS Code Deno extension allows users to configure arguments passed to the Deno CLI when running tests via the `deno.codeLens.testArgs` and `deno.testing.args` settings.
    2. These settings are directly used to construct the command line executed by the extension without sufficient sanitization.
    3. An attacker can manipulate these settings (workspace or user settings) to inject arbitrary commands into the Deno CLI execution.
    4. When a test code lens is activated or tests are run via the Test Explorer, the extension executes the Deno CLI with the injected commands.

- Impact:
    - **High**: Successful command injection allows the attacker to execute arbitrary code on the machine running VS Code with the privileges of the VS Code process. This can lead to:
        - Data exfiltration: Accessing and stealing sensitive files, environment variables, or credentials.
        - System compromise: Installing malware, creating backdoors, or modifying system configurations.
        - Lateral movement: Using the compromised machine as a stepping stone to attack other systems on the network.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None: The code directly uses the user-provided arguments without any sanitization or validation.

- Missing Mitigations:
    - Input sanitization: The extension should sanitize or validate the `deno.codeLens.testArgs` and `deno.testing.args` settings to prevent command injection. This could involve:
        - Whitelisting allowed characters or argument patterns.
        - Escaping special characters that could be used for command injection.
        - Using a safer API for command execution that prevents shell interpretation of arguments.
    - Security Context: Running the Deno CLI in a restricted security context could limit the impact of command injection, but it would not prevent the vulnerability itself.

- Preconditions:
    1. Attacker needs to be able to modify VS Code workspace or user settings. This can be achieved if:
        - The attacker has write access to the workspace settings (e.g., if the workspace is in a shared repository and the attacker can commit changes).
        - The attacker can convince a user to import malicious settings (e.g., via a crafted workspace or extension settings).

- Source Code Analysis:
    1. **`client/src/commands.ts` - `test` function:**
        ```typescript
        export function test(
          _context: vscode.ExtensionContext,
          extensionContext: DenoExtensionContext,
        ): Callback {
          return async (uriStr: string, name: string, options: TestCommandOptions) => {
            // ...
            const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
            const testArgs: string[] = [
              ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable setting 1: deno.codeLens.testArgs
            ];
            // ...
            const unstable = config.get("unstable") as string[] ?? [];
            for (const unstableFeature of unstable) {
              const flag = `--unstable-${unstableFeature}`;
              if (!testArgs.includes(flag)) {
                testArgs.push(flag);
              }
            }
            if (options?.inspect) {
              testArgs.push(getInspectArg(extensionContext.serverInfo?.version));
            }
            if (!testArgs.includes("--import-map")) {
              const importMap: string | undefined | null = config.get("importMap");
              if (importMap?.trim()) {
                testArgs.push("--import-map", importMap.trim());
              }
            }
            // ...
            const nameRegex = `/^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$/`;
            const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // Arguments array constructed with user input

            const definition: tasks.DenoTaskDefinition = {
              type: tasks.TASK_TYPE,
              command: "test",
              args, // Arguments passed to task definition
              env,
            };

            assert(workspaceFolder);
            const denoCommand = await getDenoCommandName();
            const task = tasks.buildDenoTask(
              workspaceFolder,
              denoCommand,
              definition,
              `test "${name}"`,
              args, // Arguments array passed to buildDenoTask
              ["$deno-test"],
            );
            // ...
            return createdTask;
          };
        }
        ```
    2. **`client/src/tasks.ts` - `buildDenoTask` function:**
        ```typescript
        export function buildDenoTask(
          target: vscode.WorkspaceFolder,
          process: string,
          definition: DenoTaskDefinition,
          name: string,
          args: string[], // Arguments array received from commands.ts
          problemMatchers: string[],
        ): vscode.Task {
          const exec = new vscode.ProcessExecution(
            process,
            args, // Arguments array passed to ProcessExecution
            definition,
          );

          return new vscode.Task(
            definition,
            target,
            name,
            TASK_SOURCE,
            exec,
            problemMatchers,
          );
        }
        ```
    3. **`client/src/tasks_sidebar.ts` - `DenoTaskProvider.provideTasks` function:**
        ```typescript
        class DenoTaskProvider implements TaskProvider {
          // ...
          async provideTasks(): Promise<Task[]> {
            // ...
            try {
              const configTasks = await client.sendRequest(taskReq);
              for (const configTask of configTasks ?? []) {
                // ...
                const task = buildDenoConfigTask(
                  workspaceFolder,
                  process,
                  configTask.name,
                  configTask.command ?? configTask.detail,
                  Uri.parse(configTask.sourceUri),
                );
                tasks.push(task);
              }
            } catch (err) {
              // ...
            }
            return tasks;
          }
          // ...
        }
        ```
    4. **`client/src/extension.ts` - `clientOptions.initializationOptions` function:**
        ```typescript
        export async function activate(
          context: vscode.ExtensionContext,
        ): Promise<void> {
          // ...
          extensionContext.clientOptions = {
            // ...
            initializationOptions: () => {
              const denoConfiguration = vscode.workspace.getConfiguration().get(
                EXTENSION_NS,
              ) as Record<string, unknown>;
              commands.transformDenoConfiguration(extensionContext, denoConfiguration);
              return {
                ...denoConfiguration, // Includes all deno.* settings, including deno.testing.args
                javascript: vscode.workspace.getConfiguration().get("javascript"),
                typescript: vscode.workspace.getConfiguration().get("typescript"),
                enableBuiltinCommands: true,
              } as object;
            },
            // ...
          };
          // ...
        }
        ```
    5. **`docs/testing.md`:**
        ```markdown
        Additional arguments, outside of just the module to test and the test filter,
        are supplied when executing the Deno CLI. These are configured via
        `deno.codeLens.testArgs`. They default to `[ "--allow-all" ]`. In addition, when
        executing the test, the extension will reflect the `deno.unstable` setting in
        the command line, meaning that if it is `true` then the `--unstable` flag will
        be sent as an argument to the test command.
        ```
        ```markdown
        - `deno.testing.args`: Arguments to use when running tests via the Test
          Explorer. Defaults to `[ \"--allow-all\" ]`.
        ```
        This documentation clearly states that `deno.codeLens.testArgs` and `deno.testing.args` are used as command-line arguments for Deno CLI test execution.

    **Visualization:**

    ```
    UserSettings/WorkspaceSettings (deno.codeLens.testArgs, deno.testing.args) --> vscode.workspace.getConfiguration()
        --> client/src/commands.ts (test function)
            --> testArgs array construction (Vulnerable point: No sanitization)
                --> args array construction
                    --> client/src/tasks.ts (buildDenoTask function)
                        --> vscode.ProcessExecution (process, args) --> Command Execution
    ```

    **Conclusion of Source Code Analysis:**

    The code analysis confirms that the `deno.codeLens.testArgs` and `deno.testing.args` settings are read from the VS Code configuration and directly used to construct the command line arguments for `vscode.ProcessExecution`. There is no evidence of input sanitization or validation applied to these settings before command execution. This creates a command injection vulnerability.

- Security Test Case:
    1. Open VS Code with the Deno extension installed.
    2. Open or create a workspace.
    3. Modify the workspace settings (`.vscode/settings.json`) and add the following configuration:
        ```json
        {
            "deno.codeLens.testArgs": [
                "--allow-all",
                "; touch /tmp/pwned ; #"
            ]
        }
        ```
        Alternatively, you can use user settings to set this globally.
    4. Create a simple Deno test file (e.g., `test.ts`) in the workspace:
        ```typescript
        import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

        Deno.test("vulnerable test", () => {
            assertEquals(1, 1);
        });
        ```
    5. Open the `test.ts` file. You should see the "▶ Run Test" code lens above the `Deno.test` declaration.
    6. Click on the "▶ Run Test" code lens.
    7. After the test execution (even if it succeeds or fails), check if the file `/tmp/pwned` exists.
    8. If the file `/tmp/pwned` exists, the command injection is successful.

    **Explanation of the test case:**

    - The `deno.codeLens.testArgs` is set to include `--allow-all` (default) and the malicious payload `; touch /tmp/pwned ; #`.
    - The semicolon `;` acts as a command separator in shell, allowing to execute multiple commands in sequence.
    - `touch /tmp/pwned` is a simple command that creates an empty file named `pwned` in the `/tmp` directory (on Linux/macOS). On Windows, you could use `cmd /c echo pwned > %TEMP%\pwned.txt`.
    - `#` is a comment character in shell, which will comment out any subsequent arguments that might cause errors.
    - When the "Run Test" code lens is clicked, the extension executes the Deno CLI with the modified `deno.codeLens.testArgs`.
    - The injected command `touch /tmp/pwned` will be executed alongside the test command, creating the `/tmp/pwned` file if successful.
    - The presence of `/tmp/pwned` confirms that arbitrary commands were injected and executed.
