### Vulnerability List

- Vulnerability Name: Command Injection in Test Code Lens via Test Name
- Description:
    - Step 1: An attacker crafts a malicious Javascript or Typescript file within a workspace.
    - Step 2: In this file, the attacker defines a Deno test function (`Deno.test()`) where the test name is maliciously crafted to include shell command injection payloads. For example, a test name could be: `"test\"; touch malicious_file_test_code_lens; //"`.
    - Step 3: The attacker shares this malicious workspace with a victim, for example by hosting it on a public repository.
    - Step 4: The victim opens this malicious workspace in Visual Studio Code with the Deno extension enabled.
    - Step 5: The Deno extension detects the test and displays a "Run Test" code lens above the malicious test definition.
    - Step 6: The victim clicks the "▶ Run Test" code lens.
    - Step 7: The extension executes a `deno test` command that includes the maliciously crafted test name in a regular expression filter. Due to insufficient sanitization, the shell command injection payload embedded in the test name is executed. In the example, this would execute `touch malicious_file_test_code_lens` in the victim's system.
- Impact: Arbitrary code execution. An attacker can execute arbitrary shell commands on the victim's machine with the privileges of the VS Code process simply by tricking them into opening a malicious workspace and clicking "Run Test".
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - The code attempts to sanitize the test name using a regular expression (`name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")`) in `client\src\commands.ts` within the `test()` function to escape special characters before incorporating it into the `deno test --filter` command.
    - However, this sanitization is insufficient to prevent command injection as it does not escape shell metacharacters that can be used to break out of the intended command structure.
- Missing Mitigations:
    - Proper sanitization of the test name to prevent command injection. Instead of just escaping regex special characters, the test name should be treated as a literal string and shell escaping should be applied to ensure it's not interpreted as shell commands. Ideally, avoid using shell `test --filter` argument with user provided input directly. Consider alternative methods for filtering tests if needed, or ensure complete sanitization for shell safety.
- Preconditions:
    - The victim must have the VS Code Deno extension installed and enabled.
    - The victim must open a malicious workspace containing a Javascript or Typescript file with a specially crafted Deno test definition.
    - The victim must click the "▶ Run Test" code lens associated with the malicious test.
- Source Code Analysis:
    - In `client\src\commands.ts`, function `test()`:
    ```typescript
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const nameRegex = `/^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$/`; // Insufficient sanitization
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
        // ...
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // args contains unsanitized nameRegex
          env,
        };
        // ...
        assert(workspaceFolder);
        const denoCommand = await getDenoCommandName();
        const task = tasks.buildDenoTask( // Task is created with command and args
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args, // args are passed to the task execution
          ["$deno-test"],
        );
        // ...
        await vscode.tasks.executeTask(task); // Task is executed
        // ...
      };
    }
    ```
    - The `name` parameter, which is derived from the test definition in the user's file, is used to construct `nameRegex`.
    - The `nameRegex` is then included as part of the `args` array for the `deno test` command.
    - `buildDenoTask()` in `client\src\tasks.ts` creates a `vscode.Task` with these arguments.
    - Finally, `vscode.tasks.executeTask(task)` executes the command, including the potentially malicious `nameRegex` as a command-line argument, leading to command injection.

- Security Test Case:
    - Step 1: Create a new directory named `malicious-deno-workspace`.
    - Step 2: Inside `malicious-deno-workspace`, create a file named `malicious_test.ts` with the following content:
        ```typescript
        Deno.test("test\"; touch malicious_file_test_code_lens; //", () => {
          console.log("This is a malicious test.");
        });
        ```
    - Step 3: Open VS Code and open the `malicious-deno-workspace` folder.
    - Step 4: Ensure the Deno extension is enabled for this workspace (you may need to run "Deno: Enable" command).
    - Step 5: In `malicious_test.ts`, locate the "▶ Run Test" code lens above the `Deno.test` definition and click it.
    - Step 6: After the test execution completes, check the `malicious-deno-workspace` directory. If the vulnerability is present, a file named `malicious_file_test_code_lens` will have been created, indicating successful command injection.

- Vulnerability Name: Command Injection in Tasks via tasks.json Configuration
- Description:
    - Step 1: An attacker crafts a malicious workspace with a `.vscode` folder and a `tasks.json` file.
    - Step 2: In `tasks.json`, the attacker defines a Deno task where the `command` or `args` fields are maliciously crafted to include shell command injection payloads. For example:
        ```json
        {
          "version": "2.0.0",
          "tasks": [
            {
              "type": "deno",
              "command": "run",
              "args": [
                "-A",
                "index.ts",
                "; touch malicious_file_tasks_json; //"
              ],
              "label": "Malicious Task"
            }
          ]
        }
        ```
    - Step 3: The attacker shares this malicious workspace with a victim.
    - Step 4: The victim opens this malicious workspace in Visual Studio Code with the Deno extension enabled.
    - Step 5: The Deno extension parses the `tasks.json` file and registers the malicious task.
    - Step 6: The victim executes the "Malicious Task" from the VS Code task menu (e.g., by running "Tasks: Run Task" and selecting "deno: Malicious Task").
    - Step 7: The extension executes the Deno task with the injected shell command. In the example, this would execute `touch malicious_file_tasks_json` in the victim's system.
- Impact: Arbitrary code execution. An attacker can execute arbitrary shell commands on the victim's machine by crafting a malicious `tasks.json` file and tricking the user into running the defined task.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - There are no explicit mitigations in place to sanitize the task `command` or `args` from `tasks.json` against command injection vulnerabilities within the provided code. The extension directly uses the values from the `tasks.json` to construct and execute shell commands.
- Missing Mitigations:
    - Input validation and sanitization for task definitions from `tasks.json`. The extension should validate and sanitize the `command` and `args` fields in `tasks.json` to prevent command injection.  Consider using a safer API for executing commands that avoids shell interpretation or properly escaping all user-provided arguments before passing them to the shell.
- Preconditions:
    - The victim must have the VS Code Deno extension installed and enabled.
    - The victim must open a malicious workspace containing a `.vscode/tasks.json` file with a specially crafted Deno task definition.
    - The victim must execute the malicious task, either from the task menu or by other means.
- Source Code Analysis:
    - In `client\src\tasks.ts`, function `buildDenoTask()`:
    ```typescript
    export function buildDenoTask(
      target: vscode.WorkspaceFolder,
      process: string,
      definition: DenoTaskDefinition,
      name: string,
      args: string[], // args from task definition
      problemMatchers: string[],
    ): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process,
        args, // args are directly passed to ProcessExecution
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
    - The `args` parameter of `buildDenoTask`, which originates from the `tasks.json` definition, is directly passed to `vscode.ProcessExecution`.
    - `vscode.ProcessExecution` then executes these arguments as part of a shell command.
    - If `tasks.json` contains malicious commands in `args`, they will be executed without sanitization.

- Security Test Case:
    - Step 1: Create a new directory named `malicious-deno-workspace-tasks`.
    - Step 2: Inside `malicious-deno-workspace-tasks`, create a folder named `.vscode`.
    - Step 3: Inside `.vscode`, create a file named `tasks.json` with the malicious task definition from the description above:
        ```json
        {
          "version": "2.0.0",
          "tasks": [
            {
              "type": "deno",
              "command": "run",
              "args": [
                "-A",
                "index.ts",
                "; touch malicious_file_tasks_json; //"
              ],
              "label": "Malicious Task"
            }
          ]
        }
        ```
    - Step 4: Inside `malicious-deno-workspace-tasks`, create an empty file named `index.ts`.
    - Step 5: Open VS Code and open the `malicious-deno-workspace-tasks` folder.
    - Step 6: Ensure the Deno extension is enabled for this workspace.
    - Step 7: Run the malicious task by opening the command palette (Ctrl+Shift+P) and typing "Tasks: Run Task". Select "deno: Malicious Task".
    - Step 8: After the task execution completes, check the `malicious-deno-workspace-tasks` directory. If the vulnerability is present, a file named `malicious_file_tasks_json` will have been created, indicating successful command injection.
