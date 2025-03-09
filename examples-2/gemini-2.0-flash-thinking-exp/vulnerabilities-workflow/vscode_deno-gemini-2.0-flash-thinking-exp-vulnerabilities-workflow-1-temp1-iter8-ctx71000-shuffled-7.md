- Vulnerability Name: Command Injection via Malicious Deno Configuration File in Tasks Sidebar
- Description:
    - A threat actor can create a malicious repository containing a `deno.json` or `deno.jsonc` file with a crafted task definition.
    - When a victim opens this malicious repository in VSCode with the Deno extension enabled, the extension parses the configuration file.
    - The Deno Tasks sidebar displays tasks defined in the configuration file.
    - If a task definition in `deno.json` or `deno.jsonc` contains a malicious command, and the victim attempts to run this task from the sidebar (either intentionally or accidentally), the malicious command will be executed.
    - This vulnerability stems from the extension's lack of sanitization of task definitions read from configuration files, specifically within the Deno Tasks sidebar feature.
- Impact:
    - Remote Code Execution (RCE) on the victim's machine with the privileges of the VSCode process.
    - An attacker could potentially gain full control of the victim's machine, steal sensitive data, or install malware.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The extension parses and executes tasks from configuration files without any sanitization of the command or arguments.
- Missing Mitigations:
    - Input sanitization and validation for task definitions read from `deno.json` and `deno.jsonc` files.
    - Sandboxing or process isolation for task execution.
    - User confirmation prompt before executing tasks from configuration files, especially those originating from untrusted repositories.
- Preconditions:
    - Victim has VSCode with the Deno extension installed and enabled.
    - Victim opens a malicious repository containing a crafted `deno.json` or `deno.jsonc` file in VSCode.
    - Victim navigates to the Deno Tasks sidebar and attempts to run a malicious task.
- Source Code Analysis:
    - File: `client/src/tasks_sidebar.ts`
    - Function: `DenoTasksTreeDataProvider.#runTask(task: DenoTask)`

    ```typescript
    async #runTask(task: DenoTask) {
        tasks.executeTask(task.task); // [!] Task.task is executed without sanitization
    }
    ```
    - The `#runTask` function directly executes the `task.task` object, which is constructed based on the task definition from the configuration file.
    - File: `client/src/tasks.ts`
    - Function: `buildDenoConfigTask`

    ```typescript
    export function buildDenoConfigTask(
        scope: vscode.WorkspaceFolder,
        process: string,
        name: string,
        command: string | undefined, // [!] Command from config file
        sourceUri?: vscode.Uri,
    ): vscode.Task {
        // ...
        const task = new vscode.Task(
            {
                type: TASK_TYPE,
                name: name,
                command: "task",
                args, // [!] Args are constructed based on config file, but "command" is also used directly in detail
                sourceUri,
            },
            scope,
            name,
            TASK_SOURCE,
            new vscode.ProcessExecution(process, ["task", ...args]), // [!] ProcessExecution is created with potentially malicious "process" and "args"
            ["$deno"],
        );
        task.detail = `$ ${command}`; // [!] Detail displays potentially malicious command
        return task;
    }
    ```
    - `buildDenoConfigTask` creates a `vscode.Task` object. Critically, the `command` parameter (taken from `configTask.command ?? configTask.detail` in `client/src/tasks_sidebar.ts` which originates from the configuration file) is used in `task.detail` and indirectly influences task execution via `args`. The `process` argument comes from `getDenoCommandName()` which should be safe, but `args` are built based on potentially malicious config.
    - File: `client/src/lsp_extensions.ts`
    - Type: `TaskRequestResponse`

    ```typescript
    export interface TaskRequestResponse {
      name: string;
      // TODO(nayeemrmn): `detail` is renamed to `command` for Deno > 2.1.1. Remove
      // `detail` eventually.
      command: string | null; // [!] "command" from LSP (config file)
      detail: string;        // [!] "detail" from LSP (config file)
      sourceUri: string;
    }
    ```
    - The `TaskRequestResponse` interface shows that the task `command` and `detail` are received from the Language Server Protocol, ultimately originating from the parsed configuration file (`deno.json` or `deno.jsonc`).
    - Visualization:

    ```
    Malicious Repo (deno.json) --> VSCode Extension (client/src/tasks_sidebar.ts, client/src/tasks.ts) --> vscode.tasks.executeTask() --> OS Command Execution
    ```

- Security Test Case:
    1. Create a malicious repository with the following `deno.json` file:
        ```json
        {
          "tasks": {
            "maliciousTask": "echo 'Vulnerability Triggered!' && calc.exe"
          }
        }
        ```
        (Note: `calc.exe` is used as a harmless RCE example for Windows. For other OS, use appropriate commands like `gnome-calculator` on Linux or `open /Applications/Calculator.app` on macOS. `echo` is added for more visual confirmation in the output.)
    2. Open this malicious repository in VSCode with the Deno extension enabled.
    3. Navigate to the "Deno Tasks" sidebar in VSCode (if it's not visible, you may need to open the Explorer and find "Deno Tasks").
    4. Find the "maliciousTask" in the sidebar.
    5. Click the "wrench" icon next to "maliciousTask" to "Run Task".
    6. Observe that the command `echo 'Vulnerability Triggered!' && calc.exe` is executed. You should see "Vulnerability Triggered!" in the task output panel and `calc.exe` (or the equivalent calculator app for your OS) should launch, demonstrating Remote Code Execution.
