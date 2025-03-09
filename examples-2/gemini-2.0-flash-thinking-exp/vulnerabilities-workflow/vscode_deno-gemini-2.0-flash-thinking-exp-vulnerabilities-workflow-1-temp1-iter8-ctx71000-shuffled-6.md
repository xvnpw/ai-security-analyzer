* Vulnerability 1
    * Vulnerability name: Command Injection via `deno.path` setting
    * Description:
        1. An attacker creates a malicious repository.
        2. In the repository, the attacker includes instructions for the victim to set a workspace-specific `deno.path` setting to a malicious executable. Alternatively, the attacker can try to convince the victim to set a global `deno.path` to malicious executable.
        3. The victim opens the malicious repository in VSCode with the Deno extension installed.
        4. The victim configures the `deno.path` setting as instructed by the attacker, pointing it to the malicious executable within the repository or a globally accessible path.
        5. The Deno extension attempts to start the Deno language server using the path specified in `deno.path` setting.
        6. Instead of the legitimate Deno CLI, the malicious executable is executed.
        7. The malicious executable can perform arbitrary actions on the victim's machine.
    * Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process.
    * Vulnerability rank: Critical
    * Currently implemented mitigations: None. The extension directly utilizes the `deno.path` setting to execute the Deno CLI without any validation or sanitization.
    * Missing mitigations:
        - Input validation for the `deno.path` setting. The extension should validate that the provided path points to a valid executable file and potentially verify it's the actual Deno CLI.
        - Sandboxing or process isolation. Running the language server in a sandboxed environment could limit the impact of command injection.
    * Preconditions:
        - The victim has VSCode with the Deno extension installed.
        - The victim opens a workspace in VSCode.
        - The attacker can convince the victim to set a malicious path in the `deno.path` setting, either globally or workspace-specific. This could be achieved through social engineering within a malicious repository's README or setup instructions.
    * Source code analysis:
        1. `client/src/util.ts`: The function `getDenoCommandPath()` retrieves the value of the `deno.path` setting from VSCode configuration:
           ```typescript
           function getWorkspaceConfigDenoExePath() {
               const exePath = workspace.getConfiguration(EXTENSION_NS)
                   .get<string>("path");
           ```
        2. `client/src/commands.ts`: The function `startLanguageServer()` calls `getDenoCommandPath()` to get the path and uses it to spawn a process for the language server:
           ```typescript
           const command = await getDenoCommandPath();
           if (command == null) { ... }
           const serverOptions: ServerOptions = {
               run: {
                   command, // Using the path directly here
                   args: ["lsp"],
                   options: { env },
               },
               debug: {
                   command, // And here
                   args: ["lsp"],
                   options: { env },
               },
           };
           const client = new LanguageClient( ... serverOptions, ...);
           await client.start();
           ```
        3. No input validation or sanitization is performed on the `command` variable before it is used to spawn the process. This allows for command injection if a malicious path is provided in the `deno.path` setting.

    * Security test case:
        1. Create a malicious executable file (e.g., `malicious_deno.sh` on Linux/macOS, `malicious_deno.bat` on Windows). This script should perform an easily verifiable action, such as creating a file in the temporary directory (`/tmp/rce_test` or `%TEMP%\rce_test`).
        ```bash
        #!/bin/bash
        touch /tmp/rce_test
        ```
        or (PowerShell for Windows):
        ```powershell
        New-Item -ItemType File -Path "$env:TEMP\rce_test"
        ```
        Make sure to make the script executable (`chmod +x malicious_deno.sh`).
        2. Create a new VSCode workspace or open an existing one.
        3. In VSCode settings, set the `deno.path` setting for the workspace to the path of the malicious executable (`/path/to/malicious_deno.sh` or `C:\path\to\malicious_deno.bat`).
        4. Enable Deno for the workspace, if not already enabled (e.g., using "Deno: Enable" command).
        5. Restart VSCode or reload the workspace to ensure the new settings are applied and the language server attempts to start.
        6. Check if the file `/tmp/rce_test` (or `%TEMP%\rce_test` on Windows) was created. If the file exists, it confirms that the malicious executable was run as the Deno language server, demonstrating successful command injection and RCE.

* Vulnerability 2
    * Vulnerability name: Command Injection via Deno Tasks
    * Description:
        1. An attacker creates a malicious repository.
        2. In the repository, the attacker includes a malicious `deno.json` or contributes to `tasks.json` defining a Deno task with a command injection vulnerability. This could be achieved by crafting malicious arguments or commands within the task definition.
        3. The victim opens the malicious repository in VSCode with the Deno extension installed.
        4. The Deno extension detects the task definitions from `deno.json` or `tasks.json` and displays them in the tasks sidebar or makes them available through the "Run Task" command.
        5. The victim, either unknowingly or through social engineering, executes the malicious Deno task from the VSCode UI (e.g., tasks sidebar or command palette).
        6. The extension executes the task using `vscode.tasks.executeTask`, which in turn executes the command defined in the task definition.
        7. If the task definition contains a command injection, the attacker's injected commands are executed on the victim's machine.
    * Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine when the victim runs a maliciously crafted Deno task.
    * Vulnerability rank: High
    * Currently implemented mitigations: None. The extension processes and executes task definitions directly from workspace configuration files without validation or sanitization of command or arguments.
    * Missing mitigations:
        - Input validation and sanitization for Deno task definitions, particularly the `command` and `args` properties.
        - Principle of least privilege. When executing tasks, the extension should consider running them with the minimal necessary privileges.
        - User awareness and warnings. VSCode could provide better warnings to users when executing tasks, especially those defined in workspace files that may have been created by untrusted sources.
    * Preconditions:
        - The victim has VSCode with the Deno extension installed.
        - The victim opens a workspace containing malicious Deno task definitions in `deno.json` or `tasks.json`.
        - The victim executes the malicious task through the VSCode UI.
    * Source code analysis:
        1. `client/src/tasks.ts`: The functions `buildDenoTask` and `buildDenoConfigTask` construct `vscode.Task` objects based on provided definitions:
        ```typescript
        export function buildDenoTask( ... definition: DenoTaskDefinition, ...): vscode.Task {
            const exec = new vscode.ProcessExecution(
                process,
                args, // 'args' are directly from definition
                definition, // 'definition' is used as env
            );
            return new vscode.Task(definition, target, name, TASK_SOURCE, exec, problemMatchers);
        }
        export function buildDenoConfigTask( ... name: string, command: string | undefined, ...): vscode.Task {
            const args = [];
            ...
            args.push(name);
            const task = new vscode.Task(
                {  // Task definition
                    type: TASK_TYPE,
                    name: name,
                    command: "task",
                    args, // 'args' constructed but based on 'name'
                    sourceUri,
                },
                scope,
                name,
                TASK_SOURCE,
                new vscode.ProcessExecution(process, ["task", ...args]), // 'args' again
                ["$deno"],
            );
            task.detail = `$ ${command}`; // 'command' from definition
            return task;
        }
        ```
        2. `client/src/tasks_sidebar.ts`: The `DenoTasksTreeDataProvider` and related classes handle the UI for Deno tasks and allow users to execute tasks. When a task is executed, `tasks.executeTask(task.task)` is called, which uses the task definition created by `buildDenoTask` or `buildDenoConfigTask`.
        3. The task definitions, including `command` and `args`, are taken directly from configuration files (`deno.json`, `tasks.json`) without sanitization, leading to potential command injection if these files are maliciously crafted.

    * Security test case:
        1. Create a malicious repository.
        2. In the root of the repository, create a `deno.json` file with the following content to define a malicious task:
        ```json
        {
          "tasks": {
            "maliciousTask": "run --allow-read --allow-write --allow-net --allow-env --allow-sys --allow-hrtime --allow-plugin --allow-ffi --unstable '; touch /tmp/rce_task_test; #'"
          }
        }
        ```
        or for Windows `deno.jsonc`:
        ```jsonc
        {
          "tasks": {
            "maliciousTask": "run --allow-read --allow-write --allow-net --allow-env --allow-sys --allow-hrtime --allow-plugin --allow-ffi --unstable \"; New-Item -ItemType File -Path \\\"$env:TEMP\\rce_task_test\\\" #\""
          }
        }
        ```
        3. Open the malicious repository in VSCode with the Deno extension.
        4. Open the Deno tasks sidebar (if visible) or use the "Tasks: Run Task" command and select "deno: task maliciousTask".
        5. Execute the `maliciousTask`.
        6. Check if the file `/tmp/rce_task_test` (or `%TEMP%\rce_task_test` on Windows) was created. If the file exists, it indicates successful command injection through Deno tasks and RCE.
