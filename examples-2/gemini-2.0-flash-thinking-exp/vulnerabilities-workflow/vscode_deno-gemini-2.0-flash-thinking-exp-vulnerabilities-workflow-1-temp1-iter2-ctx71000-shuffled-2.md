### Vulnerability List:

- **Vulnerability Name:** Command Injection via Task Definitions

- **Description:**
    The VSCode Deno extension allows users to define tasks in `tasks.json` that execute Deno CLI commands. The extension parses these task definitions and executes the specified Deno command using `vscode.tasks.executeTask`. A malicious repository can include a crafted `tasks.json` file with a command containing shell metacharacters. When a victim opens the malicious repository in VSCode with the Deno extension active and attempts to run a task from the sidebar, the shell metacharacters in the command can be interpreted by the system shell, leading to command injection.

- **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process by crafting a malicious `tasks.json` file within a repository.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
    None. The extension directly uses the command and arguments from `tasks.json` to execute the Deno CLI task without any sanitization or validation of the command or arguments.

- **Missing Mitigations:**
    - Input sanitization of task commands and arguments defined in `tasks.json`.
    - Command execution should avoid using shell interpretation when executing tasks. Use direct execution of the Deno CLI with arguments as an array to prevent shell injection.
    - Implement a secure way to parse and execute tasks, potentially using a safer task definition format or escaping shell-sensitive characters.
    - User should be warned before executing tasks from untrusted repositories.

- **Preconditions:**
    1. Victim has VSCode with the Deno extension installed and enabled.
    2. Victim opens a malicious repository containing a crafted `tasks.json` file.
    3. Victim attempts to run a task from the Deno Tasks sidebar provided by the extension.

- **Source Code Analysis:**

    1. **`client\src\tasks_sidebar.ts`:** The `DenoTasksTreeDataProvider` is responsible for displaying tasks in the sidebar.
    2. **`DenoTasksTreeDataProvider.getChildren`:** This function in `tasks_sidebar.ts` retrieves tasks by calling `this.taskProvider.provideTasks()`.
    3. **`DenoTaskProvider.provideTasks`:** This function, implemented in `client\src\tasks.ts`, is registered as a `TaskProvider`. Initially, it provides a set of predefined tasks.
    4. **`DenoTaskProvider.provideTasks` (Config Tasks):**  The `provideTasks` function also fetches config tasks from the language server via `client.sendRequest(taskReq)` where `taskReq` is `deno/taskDefinitions`. The language server, in turn, reads tasks from `deno.json` or `deno.jsonc` files in the workspace.
    5. **`buildDenoConfigTask` in `client\src\tasks.ts`:** This function constructs a `vscode.Task` object from the task definition. It takes the task `name` and `command` (or `detail`) directly from the config. It then creates a `vscode.ProcessExecution` with `process` (deno command path) and `args` (`["task", ...args]`). Critically, it uses `ProcessExecution` which, by default, may interpret shell commands if the arguments are not carefully handled.
    6. **`DenoTasksTreeDataProvider.#runTask`:** When a user clicks "Run Task" in the sidebar, the `deno.client.runTask` command is executed, which calls `tasks.executeTask(task.task)`.  This executes the `vscode.Task` object, including the potentially malicious command from `tasks.json`.

    ```typescript
    // File: client\src\tasks.ts

    export function buildDenoConfigTask(
      scope: vscode.WorkspaceFolder,
      process: string,
      name: string,
      command: string | undefined, // Command from deno.json task definition
      sourceUri?: vscode.Uri,
    ): vscode.Task {
      const args = [];
      if (
        sourceUri &&
        vscode.Uri.joinPath(sourceUri, "..").toString() != scope.uri.toString()
      ) {
        const configPath = path.relative(scope.uri.fsPath, sourceUri.fsPath);
        args.push("-c", configPath);
      }
      args.push(name); // Task name from deno.json
      const task = new vscode.Task(
        {
          type: TASK_TYPE,
          name: name,
          command: "task",
          args,
          sourceUri,
        },
        scope,
        name,
        TASK_SOURCE,
        new vscode.ProcessExecution(process, ["task", ...args]), // ProcessExecution, potential shell injection
        ["$deno"],
      );
      task.detail = `$ ${command}`; // Displayed command, can be misleading if injected
      return task;
    }
    ```

    **Visualization:**

    ```mermaid
    sequenceDiagram
        participant User
        participant VSCode Deno Extension
        participant Deno Language Server
        participant OS Shell

        User->>VSCode Deno Extension: Open Malicious Repository
        VSCode Deno Extension->>Deno Language Server: Request Task Definitions (deno/taskDefinitions)
        Deno Language Server-->>VSCode Deno Extension: Task Definitions from deno.json (malicious command)
        VSCode Deno Extension->>User: Display Tasks in Sidebar (malicious task present)
        User->>VSCode Deno Extension: Click "Run Task" on malicious task
        VSCode Deno Extension->>VSCode Deno Extension: buildDenoConfigTask (command from deno.json)
        VSCode Deno Extension->>OS Shell: Execute Task (ProcessExecution with malicious command)
        OS Shell-->>Victim Machine: Arbitrary command execution
    ```


- **Security Test Case:**

    1. **Setup:**
        - Create a new directory for the malicious repository.
        - Create a file named `deno.json` inside the directory with the following content, which contains a command injection payload within a task definition:

        ```jsonc
        {
          "tasks": {
            "maliciousTask": "echo 'Vulnerable!' && touch /tmp/pwned"
          }
        }
        ```

        - Create a file named `test.ts` (or any `.ts` file) in the same directory:
        ```typescript
        console.log("Test file");
        ```
        - Initialize a VSCode workspace by opening the malicious repository directory in VSCode.
        - Ensure the Deno extension is enabled for the workspace (if not enabled by default, use "Deno: Enable").
        - Open the Deno Tasks sidebar (if not already visible, use "View" -> "Open View..." -> "Deno Tasks").

    2. **Execution:**
        - In the Deno Tasks sidebar, you should see "maliciousTask" under your workspace folder.
        - Click the "Run Task" icon (wrench icon) next to "maliciousTask".

    3. **Verification:**
        - Observe the output panel in VSCode. It should display "Vulnerable!".
        - Check if the file `/tmp/pwned` has been created on the system. If it exists, the command injection was successful.

This test case demonstrates that by crafting a `deno.json` file with a malicious command, an attacker can achieve command injection when a victim attempts to run the defined task via the VSCode Deno extension's sidebar.
