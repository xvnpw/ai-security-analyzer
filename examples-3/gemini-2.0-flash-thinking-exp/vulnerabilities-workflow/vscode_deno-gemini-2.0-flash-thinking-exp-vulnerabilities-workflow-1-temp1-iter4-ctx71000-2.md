### Vulnerability List

- Vulnerability Name: Command Injection via `deno.path` setting

- Description:
    1. A threat actor can craft a malicious VSCode workspace and include a `.vscode/settings.json` file.
    2. This `settings.json` file will configure the `deno.path` setting to point to a malicious executable instead of the legitimate Deno CLI.
    3. When a victim opens this malicious workspace in VSCode with the Deno extension installed, the extension will attempt to start the Deno language server.
    4. The extension uses the path specified in `deno.path` setting to locate the Deno executable.
    5. Due to the malicious `deno.path` setting, the extension will execute the attacker-controlled malicious executable instead of the legitimate Deno CLI.
    6. This allows the attacker to achieve arbitrary command execution on the victim's machine when the extension starts the language server.

- Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the same privileges as VSCode.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations: None. The extension directly uses the path provided in the `deno.path` setting without validation.

- Missing Mitigations:
    - Input validation for `deno.path` setting: The extension should validate that the provided path points to a legitimate Deno executable. This could include checking the file extension, verifying a digital signature, or using a safelist of known safe paths.
    - Display warning to user: If the `deno.path` setting is changed from the default or points to an unusual location, the extension should display a warning to the user, indicating a potential security risk and asking for confirmation.

- Preconditions:
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious workspace provided by the attacker, or the attacker is able to modify the victim's user or workspace settings to change `deno.path`.

- Source Code Analysis:
    1. File: `client\src\util.ts`
    2. Function: `getDenoCommandPath()`
    3. This function retrieves the `deno.path` setting from VSCode workspace configuration using `workspace.getConfiguration(EXTENSION_NS).get<string>("path")`.
    4. It performs minimal checks, such as resolving relative paths against workspace folders, but no validation to ensure the path is safe or points to a legitimate Deno executable.
    5. File: `client\src\commands.ts`
    6. Function: `startLanguageServer()`
    7. This function calls `getDenoCommandPath()` to get the Deno command.
    8. The returned path is directly used in `serverOptions.run.command` and `serverOptions.debug.command` when creating a new `LanguageClient`.
    9.  ```typescript
        const serverOptions: ServerOptions = {
            run: {
              command, // Path from getDenoCommandPath()
              args: ["lsp"],
              options: { env },
            },
            debug: {
              command, // Path from getDenoCommandPath()
              args: ["lsp"],
              options: { env },
            },
          };
        const client = new LanguageClient( ... , serverOptions, ...);
        await client.start();
        ```
    10. Visualization:
        ```
        User Settings/Workspace Settings --> deno.path --> getDenoCommandPath() --> command
        command --> ServerOptions.run.command, ServerOptions.debug.command --> Process Execution (Language Server Start)
        ```
    11. If the `deno.path` setting points to a malicious executable, `LanguageClient.start()` will execute this malicious code.

- Security Test Case:
    1. Create a directory named `malicious_deno` in a temporary location (e.g., `/tmp/malicious_deno` on Linux/macOS, `C:\malicious_deno` on Windows).
    2. Inside `malicious_deno`, create a file named `deno.sh` (or `deno.bat` for Windows) with the following content:
        - `deno.sh` (Linux/macOS):
            ```bash
            #!/bin/bash
            echo "[VULNERABILITY-DEMO] Malicious Deno Executable Executed!"
            echo "[VULNERABILITY-DEMO] $(whoami) triggered RCE via vscode-deno extension" >> /tmp/rce_vscode_deno.txt # or any other observable action
            exit 0
            ```
        - `deno.bat` (Windows):
            ```batch
            @echo off
            echo [VULNERABILITY-DEMO] Malicious Deno Executable Executed!
            echo [VULNERABILITY-DEMO] %USERNAME% triggered RCE via vscode-deno extension >> %TEMP%\rce_vscode_deno.txt # or any other observable action
            exit 0
            ```
    3. Make `deno.sh` executable: `chmod +x /tmp/malicious_deno/deno.sh`.
    4. Create a new VSCode workspace.
    5. Inside the workspace root, create a `.vscode` directory and within it, create a `settings.json` file with the following content:
        ```json
        {
          "deno.path": "/tmp/malicious_deno/deno.sh"  // or "C:\\malicious_deno\\deno.bat" for Windows
        }
        ```
    6. Open any JavaScript or TypeScript file in the workspace to trigger the Deno extension activation and language server startup.
    7. Check for the observable action (e.g., the `/tmp/rce_vscode_deno.txt` file or `%TEMP%\rce_vscode_deno.txt` file). If the file exists and contains the "[VULNERABILITY-DEMO]" messages, the vulnerability is confirmed.
    8. Verify in the VSCode Output panel (Deno Language Server) that the malicious script execution is logged.

- Vulnerability Name: Command Injection in Test Code Lenses via `deno.codeLens.testArgs` and `deno.testing.args` settings

- Description:
    1. A threat actor can create a malicious VSCode workspace and include a `.vscode/settings.json` file.
    2. This `settings.json` file configures `deno.codeLens.testArgs` or `deno.testing.args` settings with command injection payloads.
    3. When a victim opens this malicious workspace and opens a Deno test file, the Deno extension will display "Run Test" code lenses above test definitions.
    4. If the victim clicks on a "Run Test" code lens, the extension will execute a `deno test` command.
    5. The command is constructed using the arguments from `deno.codeLens.testArgs` or `deno.testing.args` settings, which now contain malicious commands due to the attacker's crafted settings.
    6. This allows the attacker to achieve arbitrary command execution on the victim's machine when the victim attempts to run a test using the code lens feature.

- Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine when the victim clicks "Run Test" code lens.

- Vulnerability Rank: High

- Currently Implemented Mitigations: None. The extension directly uses arguments from settings without sanitization when constructing test commands.

- Missing Mitigations:
    - Input validation for `deno.codeLens.testArgs` and `deno.testing.args` settings: The extension should validate these settings to ensure they only contain legitimate Deno CLI arguments and not shell command separators or malicious commands.
    - Display warning to user: If `deno.codeLens.testArgs` or `deno.testing.args` settings contain unusual characters or command separators, the extension should display a warning to the user indicating a potential security risk.

- Preconditions:
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious workspace provided by the attacker, or the attacker is able to modify the victim's workspace settings to inject malicious arguments into `deno.codeLens.testArgs` or `deno.testing.args`.
    - Victim opens a Deno test file and clicks on "Run Test" code lens.

- Source Code Analysis:
    1. File: `client\src\commands.ts`
    2. Function: `test()`
    3. This function retrieves `deno.codeLens.testArgs` setting from workspace configuration: `const testArgs: string[] = [...(config.get<string[]>("codeLens.testArgs") ?? [])];`.
    4. It constructs the `deno test` command arguments by directly using the values from `testArgs`.
    5.  ```typescript
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // args constructed with potentially malicious testArgs
          env,
        };
        assert(workspaceFolder);
        const denoCommand = await getDenoCommandName();
        const task = tasks.buildDenoTask(workspaceFolder, denoCommand, definition, `test "${name}"`, args, ["$deno-test"]);
        task.presentationOptions = { ... };
        task.group = vscode.TaskGroup.Test;
        const createdTask = await vscode.tasks.executeTask(task);
        ```
    6. File: `client\src\tasks.ts`
    7. Function: `buildDenoTask()`
    8. This function creates a `vscode.Task` using `ProcessExecution`, directly using the provided `process` (deno command) and `args` (including potentially malicious `testArgs`).
    9. Visualization:
        ```
        User Workspace Settings --> deno.codeLens.testArgs --> test() --> testArgs
        testArgs --> args (deno test command) --> buildDenoTask() --> Process Execution (deno test command)
        ```
    10. If `deno.codeLens.testArgs` contains command injection, it will be executed when the test task is run via code lens.

- Security Test Case:
    1. Create a new VSCode workspace.
    2. Inside the workspace root, create a `.vscode` directory and within it, create a `settings.json` file with the following content to inject command into `deno.codeLens.testArgs`:
        ```json
        {
          "deno.codeLens.testArgs": ["--allow-read", "; touch /tmp/vscode_deno_rce_codelens_testargs; "]
        }
        ```
    3. Create a Deno test file named `test_example.ts` at the workspace root with simple test:
        ```typescript
        import { assertEquals } from "https://deno.land/std@0.218.0/assert/mod.ts";

        Deno.test("example test", () => {
          assertEquals(1, 1);
        });
        ```
    4. Open `test_example.ts` in VSCode.
    5. Observe the "Run Test" code lens above `Deno.test`. Click on "Run Test".
    6. Check if the file `/tmp/vscode_deno_rce_codelens_testargs` is created. If it is, command injection via `deno.codeLens.testArgs` is confirmed.
    7. Repeat steps 2-6, but this time use `deno.testing.args` in `settings.json` instead of `deno.codeLens.testArgs`:
         ```json
        {
          "deno.testing.args": ["--allow-read", "; touch /tmp/vscode_deno_rce_testing_args; "]
        }
        ```
    8. Check if the file `/tmp/vscode_deno_rce_testing_args` is created. If it is, command injection via `deno.testing.args` is confirmed.


- Vulnerability Name: Command Injection in Tasks defined in `tasks.json`

- Description:
    1. A threat actor can create a malicious VSCode workspace and include a `tasks.json` file.
    2. This `tasks.json` file defines a Deno task with a malicious command or arguments that include command injection payloads.
    3. When a victim opens this malicious workspace and navigates to the "Deno Tasks" sidebar, the malicious tasks will be listed.
    4. If the victim executes the malicious task from the sidebar or via command palette, the extension will execute the defined command.
    5. Because the task definition in `tasks.json` is attacker-controlled and contains malicious commands, this allows for arbitrary command execution on the victim's machine when the victim runs the task.

- Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine if the victim runs a malicious task from the Deno Tasks sidebar or command palette.

- Vulnerability Rank: High

- Currently Implemented Mitigations: None. The extension directly executes commands defined in `tasks.json` without sanitization.

- Missing Mitigations:
    - Input validation for task definitions in `tasks.json`: The extension should validate task definitions, especially the `command` and `args` properties, to prevent command injection. This could involve parsing and sanitizing the commands and arguments to remove or escape shell command separators and other malicious characters.
    - Display warning to user: When tasks from `tasks.json` are loaded, the extension could perform a basic security scan and display a warning to the user if potentially malicious commands or arguments are detected.

- Preconditions:
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious workspace provided by the attacker containing a malicious `tasks.json` file.
    - Victim executes the malicious task from the Deno Tasks sidebar or using the command palette.

- Source Code Analysis:
    1. File: `client\src\tasks.ts`
    2. Function: `buildDenoTask()`
    3. This function directly uses `definition.command` and `definition.args` from the `DenoTaskDefinition` to create a `ProcessExecution`.
    4.  ```typescript
        export function buildDenoTask( ... , definition: DenoTaskDefinition, ...): vscode.Task {
          const exec = new vscode.ProcessExecution(
            process, // deno command path
            args,    // args from DenoTaskDefinition including command and args
            definition,
          );
          return new vscode.Task( ... , exec, ...);
        }
        ```
    5. File: `client\src\tasks_sidebar.ts`
    6. Class: `DenoTasksTreeDataProvider`, Function: `getChildren()` and `#buildTaskTree()` and `DenoTaskProvider.provideTasks()`
    7. These parts are responsible for reading tasks defined in `tasks.json` (via Language Server Protocol from Deno CLI) and displaying them in the Deno Tasks sidebar. When a task is executed from sidebar, `tasks.executeTask(task.task)` is called, which uses the `vscode.Task` object created by `buildDenoTask`, leading to execution of the command.
    8. Visualization:
        ```
        tasks.json --> Deno Language Server --> LSP (deno/taskDefinitions) --> DenoTasksTreeDataProvider --> Display in Sidebar
        User Action (Run Task in Sidebar) --> tasks.executeTask(task.task) --> Process Execution (Command from tasks.json)
        ```
    9. If `tasks.json` contains malicious commands in task definitions, they will be executed when the user runs the task from sidebar or command palette.

- Security Test Case:
    1. Create a new VSCode workspace.
    2. Inside the workspace root, create a `.vscode` directory and within it, create a `tasks.json` file with the following content to inject a command:
        ```json
        {
          "version": "2.0.0",
          "tasks": [
            {
              "type": "deno",
              "command": "run",
              "args": ["-A",  "`; touch /tmp/vscode_deno_rce_tasks_json;`"]
            }
          ]
        }
        ```
    3. Open the Deno Tasks sidebar in VSCode (View -> Open View -> Deno Tasks or via Command Palette "Deno: Focus Tasks View").
    4. Find the task defined in `tasks.json` (it may be named "deno: run" if label is not defined). Click the "Run Task" icon next to it (or right click and select "Run Task").
    5. Check if the file `/tmp/vscode_deno_rce_tasks_json` is created. If it is, command injection via `tasks.json` is confirmed.
