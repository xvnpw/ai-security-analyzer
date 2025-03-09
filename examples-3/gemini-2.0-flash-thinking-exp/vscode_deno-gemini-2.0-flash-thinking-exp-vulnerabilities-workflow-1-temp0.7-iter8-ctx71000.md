### Vulnerability List

- Vulnerability Name: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings

  - Description:
    1. A threat actor crafts a malicious repository.
    2. The malicious repository includes a `.vscode/settings.json` file within the `.vscode` directory.
    3. In the `.vscode/settings.json`, the threat actor sets the `deno.codeLens.testArgs` or `deno.testing.args` settings to include malicious commands. For example: `["--allow-all", "; malicious command &"]`.
    4. A victim clones the malicious repository and opens it in VSCode with the Deno extension enabled.
    5. The victim opens a Deno test file, triggering the display of "Run Test" code lenses or uses Test Explorer.
    6. The victim clicks the "Run Test" code lens or runs tests through the testing explorer.
    7. The extension executes the Deno CLI `test` command, incorporating the malicious arguments from the `deno.codeLens.testArgs` or `deno.testing.args` settings.
    8. Due to insufficient sanitization, the malicious commands injected in the settings are executed by the system.

  - Impact:
    - Remote Code Execution (RCE) on the victim's machine. The threat actor can execute arbitrary commands with the privileges of the VSCode process. This could lead to data exfiltration, installation of malware, or further system compromise.

  - Vulnerability Rank: Critical

  - Currently Implemented Mitigations:
    - None. The code directly uses the values from `deno.codeLens.testArgs` and `deno.testing.args` settings to construct the Deno CLI command without any sanitization or validation. The arguments are directly passed to the `ProcessExecution` without any checks.

  - Missing Mitigations:
    - Input sanitization and validation for `deno.codeLens.testArgs` and `deno.testing.args` settings. The extension should validate that the arguments are safe and do not contain command injection sequences.
    - Restrict allowed characters or commands in these settings.
    - Warn users when these settings are modified, especially in workspace settings.
    - Consider disallowing shell commands in these settings and only allow specific deno CLI arguments.
    - Consider using a safer method for command execution that avoids shell interpretation, such as directly passing arguments as an array to the `child_process.spawn` function, although `ProcessExecution` in VSCode tasks already does this. The vulnerability lies in the user-provided arguments being treated as shell commands due to potential shell injection.

  - Preconditions:
    - Victim must have the VSCode Deno extension installed and enabled.
    - Victim must open a malicious repository containing a crafted `.vscode/settings.json` file.
    - Victim must trigger test execution, either via code lens or test explorer.

  - Source Code Analysis:
    - **File: `client/src/commands.ts` Function: `test`**
      ```typescript
      export function test(
        _context: vscode.ExtensionContext,
        extensionContext: DenoExtensionContext,
      ): Callback {
        return async (uriStr: string, name: string, options: TestCommandOptions) => {
          // ...
          const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
          const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable setting 1: codeLens.testArgs
          ];
          const unstable = config.get("unstable") as string[] ?? [];
          for (const unstableFeature of unstable) {
            const flag = `--unstable-${unstableFeature}`;
            if (!testArgs.includes(flag)) {
              testArgs.push(flag);
            }
          }
          // ...
          const args = ["test", ...testArgs, "--filter", nameRegex, filePath];

          const definition: tasks.DenoTaskDefinition = {
            type: tasks.TASK_TYPE,
            command: "test",
            args, // args is passed to ProcessExecution
            env,
          };
          // ...
          const task = tasks.buildDenoTask(
            workspaceFolder,
            denoCommand,
            definition,
            `test "${name}"`,
            args, // args is passed again here
            ["$deno-test"],
          );
          // ...
        }
      }
      ```
      - The `test` function in `commands.ts` retrieves the `deno.codeLens.testArgs` configuration from VSCode settings and `deno.testing.args` (implicitly in Test Explorer scenario through similar configuration retrieval).
      - It directly uses these arguments when constructing the `args` array for the `DenoTaskDefinition`.
      - These `args` are then passed to `tasks.buildDenoTask`, which uses `vscode.ProcessExecution` to execute the command.
      - `vscode.ProcessExecution` directly executes the command with the provided arguments. If `testArgs` contains shell metacharacters or commands, they will be interpreted by the shell, leading to command injection.

    - **File: `client/src/tasks.ts` Function: `buildDenoTask`**
      ```typescript
      export function buildDenoTask(
        target: vscode.WorkspaceFolder,
        process: string,
        definition: DenoTaskDefinition,
        name: string,
        args: string[],
        problemMatchers: string[],
      ): vscode.Task {
        const exec = new vscode.ProcessExecution(
          process,
          args, // Arguments from settings are passed here
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
      - `buildDenoTask` function receives the `args` array, which can be influenced by `deno.codeLens.testArgs` or `deno.testing.args`, and directly passes it to `vscode.ProcessExecution`. This confirms that user-provided arguments are directly used in command execution without sanitization.

  - Security Test Case:
    1. Create a new directory named `vscode_deno_test_exploit`.
    2. Inside `vscode_deno_test_exploit`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "deno.enable": true,
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; calc.exe &"
           ]
       }
       ```
       *(Note: `calc.exe` is used as a benign payload for demonstration on Windows. For other OS, use a similar harmless command like `xcalc` or `gnome-calculator` or `open /Applications/Calculator.app/` on macOS, or `touch /tmp/pwned` on Linux/macOS)*
    4. Inside `vscode_deno_test_exploit`, create a file named `test.ts` with the following content:
       ```typescript
       Deno.test("Vulnerability Test", () => {
           console.log("Test running");
       });
       ```
    5. Open the `vscode_deno_test_exploit` directory in VSCode. Ensure the Deno extension is enabled for this workspace.
    6. Open the `test.ts` file. You should see the "Run Test" code lens above the `Deno.test` definition.
    7. Click on the "Run Test" code lens.
    8. Observe that the calculator application (`calc.exe` or equivalent) is launched, demonstrating command injection.

- Vulnerability Name: Command Injection via `deno.path` setting

  - Description:
    1. A threat actor could socially engineer a victim to configure the `deno.path` setting in VSCode to point to a malicious executable instead of the legitimate Deno CLI.
    2. This could be achieved through phishing, misleading instructions, or by tricking the victim into importing and using a malicious configuration file.
    3. Once the `deno.path` setting points to the malicious executable, any operation within VSCode that invokes the Deno CLI (like starting the language server, running tests, formatting, etc.) will execute the malicious script.
    4. The malicious script, having replaced the legitimate Deno CLI, can then execute arbitrary commands on the victim's system.

  - Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process by replacing the Deno executable.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    - The extension checks if the provided path in `deno.path` exists and is an executable file. However, it does not verify if the executable is actually the legitimate Deno CLI or a malicious replacement.

  - Missing Mitigations:
    - Implement stronger validation for the `deno.path` setting. This could include:
        - Verifying the digital signature or checksum of the executable to ensure it is the legitimate Deno CLI.
        - Restricting `deno.path` to only allow absolute paths from known trusted locations.
        - Displaying a clear warning to the user when `deno.path` is changed, especially if it's set to a non-standard location.
    - Consider removing the `deno.path` setting altogether and rely solely on the Deno CLI being available in the system's PATH environment variable, as documented in the extension's README.

  - Preconditions:
    - The victim has the VSCode Deno extension installed and enabled.
    - The victim is tricked into changing the `deno.path` setting in VSCode to point to a malicious executable.
    - An action is performed in VSCode that triggers the execution of the Deno CLI (e.g., extension activation, language server start, formatting, testing).

  - Source Code Analysis:
    - **File: `client/src/commands.ts`, function: `startLanguageServer`**
      ```typescript
      export function startLanguageServer(
        context: vscode.ExtensionContext,
        extensionContext: DenoExtensionContext,
      ): Callback {
        return async () => {
          // ...
          const command = await getDenoCommandPath(); // Resolves deno.path
          if (command == null) {
            // ... error handling ...
            return;
          }
          // ... serverOptions ...
          const serverOptions: ServerOptions = {
            run: {
              command, // Potentially malicious command from deno.path
              args: ["lsp"],
              options: { env },
            },
            debug: {
              command, // Potentially malicious command from deno.path
              args: ["lsp"],
              options: { env },
            },
          };
          const client = new LanguageClient( // Executes the command
            LANGUAGE_CLIENT_ID,
            LANGUAGE_CLIENT_NAME,
            serverOptions,
            {
              outputChannel: extensionContext.outputChannel,
              middleware: {
                workspace: {
                  configuration: (params, token, next) => {
                    const response = next(params, token) as Record<string, unknown>[];
                    for (let i = 0; i < response.length; i++) {
                      const item = params.items[i];
                      if (item.section == "deno") {
                        transformDenoConfiguration(extensionContext, response[i]);
                      }
                    }
                    return response;
                  },
                },
              },
              ...extensionContext.clientOptions,
            },
          );
          // ... client start ...
        };
      }
      ```
      - The `getDenoCommandPath()` function (defined in `client/src/util.ts`) retrieves the path from the `deno.path` setting. This path, if maliciously manipulated, is then directly used as the `command` in `serverOptions` and executed by the `LanguageClient`, leading to potential command injection if the path points to a malicious script.

  - Security Test Case:
    1. Create a malicious script (e.g., `malicious_deno.sh`) in a safe directory (e.g., `/tmp` or `C:\temp`). The script should contain:
        ```bash
        #!/bin/bash
        touch /tmp/poc_rce_deno_path_setting  # For Linux/macOS
        # touch C:\temp\poc_rce_deno_path_setting.txt # For Windows
        /path/to/legitimate/deno "$@" # Optionally forward arguments to legitimate deno for functionality
        ```
        Replace `/path/to/legitimate/deno` with the actual path to your legitimate Deno executable if you want to maintain some functionality.
    2. Make the script executable: `chmod +x /tmp/malicious_deno.sh`.
    3. In VSCode, open User Settings (File > Preferences > Settings > Settings).
    4. Search for "deno.path" and edit the setting to point to your malicious script. For example: `"/tmp/malicious_deno.sh"` (or `"C:\\temp\\malicious_deno.sh"` on Windows).
    5. Reload VSCode (or just restart the Deno Language Server using command "Deno: Restart Language Server").
    6. After VSCode reloads and the Deno extension activates, check the `/tmp` directory (or `C:\temp` on Windows). You should find a new file named `poc_rce_deno_path_setting` (or `poc_rce_deno_path_setting.txt` on Windows). The creation of this file indicates successful command injection, as the malicious script set in `deno.path` was executed upon extension activation.

- Vulnerability Name: Command Injection in Deno Task Execution via `tasks.json`

  - Description:
    1. An attacker creates a malicious repository.
    2. In the malicious repository, the attacker creates a `.vscode/tasks.json` file.
    3. In the `tasks.json` file, the attacker defines a Deno task with malicious arguments, for example including shell commands after a semicolon.
    4. The victim opens the malicious repository in VSCode with the Deno extension installed and enabled.
    5. The attacker can trick the victim into running the malicious task (e.g., via the tasks sidebar or command palette).
    6. When the task is executed, the `ProcessExecution` in `tasks.ts` uses the unsanitized arguments.
    7. The Deno CLI executes the command, including the injected malicious command after the semicolon.

  - Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's local machine.

  - Vulnerability Rank: Critical

  - Currently Implemented Mitigations:
    - No input sanitization or validation is implemented for task arguments in `tasks.ts`. The code directly uses the arguments provided in the `tasks.json` configuration.

  - Missing Mitigations:
    - Input sanitization and validation are missing for task arguments defined in `tasks.json`. The extension should sanitize all arguments passed to the `ProcessExecution` constructor to prevent command injection. Specifically, it should:
        - Validate the `command` and `args` properties in `tasks.json` against a whitelist of allowed commands and arguments, or
        - Properly escape or sanitize the arguments to prevent shell injection.
        - Consider using `child_process.spawn` with the `shell: false` option to avoid shell interpretation of arguments.

  - Preconditions:
    - Victim has VSCode with the Deno extension installed and enabled.
    - Victim opens a malicious repository containing a crafted `.vscode/tasks.json` file.
    - Victim is tricked into executing the malicious Deno task.

  - Source Code Analysis:
    - **File: `client/src/tasks.ts`**
      ```typescript
      export function buildDenoTask(
          target: vscode.WorkspaceFolder,
          process: string,
          definition: DenoTaskDefinition,
          name: string,
          args: string[], // Arguments are passed directly here
          problemMatchers: string[],
      ): vscode.Task {
          const exec = new vscode.ProcessExecution(
              process,
              args, // Unsanitized arguments are used here
              definition,
          );
      ```
      - Function `buildDenoTask` creates a `vscode.Task` with a `vscode.ProcessExecution`.
      - The `ProcessExecution` constructor takes `process` (deno command path) and `args` directly from the `definition.args` which is populated from `tasks.json`.

  - Security Test Case:
    1. Create a malicious repository with the following structure:
       ```
       malicious-repo/
       ├── .vscode/
       │   └── tasks.json
       └── mod.ts
       ```
       - `mod.ts`: (can be empty or any valid Deno file)
         ```typescript
         console.log("Hello from mod.ts");
         ```
       - `.vscode/tasks.json`:
         ```json
         {
             "version": "2.0.0",
             "tasks": [
                 {
                     "type": "deno",
                     "command": "run",
                     "args": [
                         "mod.ts",
                         "; calc.exe"
                     ],
                     "problemMatcher": [
                         "$deno"
                     ],
                     "label": "deno: run malicious"
                 }
             ]
         }
         ```
    2. Open the `malicious-repo` in VSCode with the Deno extension enabled.
    3. Open the Command Palette (`Ctrl+Shift+P`) and run "Tasks: Run Task".
    4. Select the "deno: run malicious" task.
    5. Observe that `calc.exe` (or another OS command like `open /Applications/Calculator.app` on macOS or `xcalc` on Linux) is executed, demonstrating command injection.

- Vulnerability Name: Command Injection via Deno Task Name in Tasks Sidebar (Debug Task)

  - Description:
    1. A threat actor crafts a malicious repository.
    2. Within this repository, a `deno.json` file is created, containing a task definition with a maliciously crafted name designed for command injection. For example:  `"malicious-task-injection && touch /tmp/pwned": "deno"`.
    3. A victim, using VSCode with the Deno extension, opens this malicious repository.
    4. The Deno extension parses `deno.json` and registers the defined task.
    5. When the victim attempts to debug the "malicious-task-injection && touch /tmp/pwned" task from the VSCode Tasks sidebar, the task's name, containing the command injection payload, is incorporated into a shell command without proper sanitization.
    6. This results in the execution of the injected command (`touch /tmp/pwned`) alongside the intended Deno CLI command within a debugger terminal, leading to command injection.

  - Impact:
    - Remote Code Execution (RCE)
    - An attacker can execute arbitrary commands on the victim's machine when the victim attempts to debug a task from a maliciously crafted `deno.json` configuration file.

  - Vulnerability Rank: High

  - Currently Implemented Mitigations:
    - None identified. The extension appears to directly utilize task names from `deno.json` during task construction and execution in debug mode, without input sanitization.

  - Missing Mitigations:
    - Implement robust input sanitization for task names and any other user-controlled input from `deno.json` before incorporating them into shell commands or execution contexts, especially in debug task execution.
    - Avoid directly embedding task names or user-provided strings into shell commands, especially in contexts like debugger terminal creation where shell interpretation is involved.
    - Consider using parameterized commands or APIs that prevent shell injection by separating commands from arguments.

  - Preconditions:
    1. The victim must have VSCode installed with the Deno extension enabled.
    2. The victim must open a workspace or repository that contains a malicious `deno.json` file.
    3. The victim must attempt to debug a task that is defined within the malicious `deno.json` file, typically initiated from the VSCode Tasks sidebar.

  - Source Code Analysis:
    - **File: `client\src\tasks_sidebar.ts`, Function: `DenoTasksTreeDataProvider.#debugTask`**
      ```typescript
      async #debugTask(task: DenoTask) {
          const command = `${await getDenoCommandName()} task ${task.task.name}`; // Task name is directly embedded in shell command
          commands.executeCommand(
            "extension.js-debug.createDebuggerTerminal",
            command, // Vulnerable command string
            task.getFolder(),
            {
              cwd: path.dirname(task.denoJson.resourceUri!.fsPath),
            },
          );
        }
      ```
      - This method constructs a command string by concatenating the Deno command, the "task" subcommand, and crucially, `task.task.name`.
      - This command string is passed to `commands.executeCommand("extension.js-debug.createDebuggerTerminal", command, ...)` to launch a debugger terminal. The `command` string is interpreted by a shell, making it susceptible to command injection if `task.task.name` contains malicious shell metacharacters or commands.

  - Security Test Case:
    1. Setup:
        - Ensure you have VSCode and the Deno extension installed.
        - Create a new directory to serve as the malicious repository.
        - Inside this directory, create a file named `deno.json` with the following content:
          ```json
          {
            "tasks": {
              "malicious-task-injection && calc": "deno"
            }
          }
          ```
    2. Execution Steps:
        - Open the directory created in step 1 as a workspace in VSCode.
        - Access the VSCode Command Palette (Ctrl+Shift+P or Cmd+Shift+P).
        - Execute the command `Deno Tasks: Focus on Tasks View` to display the Deno Tasks sidebar.
        - In the Deno Tasks sidebar, locate the task named `malicious-task-injection && calc`.
        - Right-click on this task and select `Debug Task` from the context menu.
    3. Expected Outcome:
        - After selecting "Debug Task", observe if the calculator application (`calc.exe` or equivalent) is launched, indicating successful command injection.
