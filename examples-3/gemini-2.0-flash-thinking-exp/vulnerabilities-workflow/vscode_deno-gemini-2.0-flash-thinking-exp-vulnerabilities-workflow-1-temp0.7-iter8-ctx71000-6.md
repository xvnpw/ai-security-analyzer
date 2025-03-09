### Vulnerability List

- Vulnerability Name: Command Injection in Deno Task Definitions (Debug Task)
- Description:
    1. A threat actor crafts a malicious repository.
    2. Within this repository, a `deno.json` file is created, containing a task definition with a maliciously crafted name designed for command injection. For example:
       ```json
       {
         "tasks": {
           "malicious-task-injection && touch /tmp/pwned": "deno"
         }
       }
       ```
    3. A victim, using VSCode with the Deno extension, opens this malicious repository.
    4. The Deno extension parses `deno.json` and registers the defined task.
    5. When the victim attempts to debug the "malicious-task-injection && touch /tmp/pwned" task, either from the VSCode Tasks sidebar or command palette, the task's name, containing the command injection payload, is incorporated into a shell command without proper sanitization.
    6. This results in the execution of the injected command (`touch /tmp/pwned`) alongside the intended Deno CLI command within a debugger terminal, leading to command injection.
- Impact:
    - Remote Code Execution (RCE)
    - An attacker can execute arbitrary commands on the victim's machine, gaining control over the system when the victim attempts to debug a task from a maliciously crafted `deno.json` configuration file.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - None identified. The extension appears to directly utilize task names from `deno.json` during task construction and execution, without input sanitization.
- Missing mitigations:
    - Implement robust input sanitization for task names and any other user-controlled input from `deno.json` before incorporating them into shell commands or execution contexts.
    - Avoid directly embedding task names or user-provided strings into shell commands, especially in contexts like debugger terminal creation where shell interpretation is involved.
    - Consider using parameterized commands or APIs that prevent shell injection by separating commands from arguments.
- Preconditions:
    1. The victim must have VSCode installed with the Deno extension enabled.
    2. The victim must open a workspace or repository that contains a malicious `deno.json` file.
    3. The victim must attempt to debug a task that is defined within the malicious `deno.json` file, typically initiated from the VSCode Tasks sidebar.
- Source code analysis:
    1. In `client\src\tasks_sidebar.ts`, the `DenoTasksTreeDataProvider` class is responsible for displaying tasks defined in `deno.json` within the VSCode Tasks sidebar.
    2. The `DenoTask` class, within `client\src\tasks_sidebar.ts`, represents an individual task. Its constructor directly uses the `task.name` (derived from `deno.json`) and stores it.
    3. The critical point is in `client\src\tasks_sidebar.ts`, within the `DenoTasksTreeDataProvider` class, specifically the `#debugTask` method. This method constructs a command string by concatenating the Deno command, the "task" subcommand, and crucially, `task.task.name`.
    4. This command string is then passed to `commands.executeCommand("extension.js-debug.createDebuggerTerminal", command, ...)` to launch a debugger terminal. The `command` string is interpreted by a shell, making it susceptible to command injection if `task.task.name` contains malicious shell metacharacters or commands.
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
- Security test case:
    1. Setup:
        - Ensure you have VSCode and the Deno extension installed.
        - Create a new directory to serve as the malicious repository.
        - Inside this directory, create a file named `deno.json` with the following content:
          ```json
          {
            "tasks": {
              "malicious-task-injection && touch /tmp/pwned": "deno"
            }
          }
          ```
    2. Execution Steps:
        - Open the directory created in step 1 as a workspace in VSCode.
        - Access the VSCode Command Palette (Ctrl+Shift+P or Cmd+Shift+P).
        - Execute the command `Deno Tasks: Focus on Tasks View` to display the Deno Tasks sidebar.
        - In the Deno Tasks sidebar, locate the task named `malicious-task-injection && touch /tmp/pwned`.
        - Right-click on this task and select `Debug Task` from the context menu.
    3. Expected Outcome:
        - After selecting "Debug Task", observe if a file named `pwned` is created in the `/tmp/` directory of your system.
        - If the file `/tmp/pwned` is created, it confirms successful command injection, as the `touch /tmp/pwned` command embedded in the task name has been executed.
        - Note: The path `/tmp/` is used for example and may need to be adjusted based on your operating system to a location where file creation can be easily observed.
