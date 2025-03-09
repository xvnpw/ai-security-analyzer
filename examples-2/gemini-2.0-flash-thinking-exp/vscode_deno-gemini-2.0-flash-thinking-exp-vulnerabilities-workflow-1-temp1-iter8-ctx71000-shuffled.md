### Vulnerability List

- **Vulnerability Name:** Command Injection in tasks.json task execution

- **Description:**
    The VSCode Deno extension allows users to define tasks in `tasks.json`. The extension parses this file and executes the defined commands using `vscode.ProcessExecution`. If a malicious repository contains a `tasks.json` file with a crafted command, it can lead to command injection when the user executes this task.
    Step-by-step trigger:
    1. An attacker creates a malicious repository and includes a `tasks.json` file.
    2. Within `tasks.json`, the attacker defines a task where the `command` or `args` are designed to execute arbitrary commands. For example, they could use command chaining or argument injection techniques.
    3. The attacker hosts this malicious repository on a public platform (e.g., GitHub).
    4. A victim, intending to use or review code from the repository, clones or opens the malicious repository in VSCode with the Deno extension installed and enabled.
    5. The VSCode Deno extension automatically detects and registers the tasks defined in `tasks.json`.
    6. The victim, either through the tasks sidebar or by using the "Tasks: Run Task" command, selects and executes the malicious task.
    7. Upon execution, the Deno extension uses `vscode.ProcessExecution` with the attacker-controlled command and arguments.
    8. This results in the execution of arbitrary commands on the victim's machine, with the privileges of the VSCode process.

- **Impact:**
    Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary commands on the victim's machine. This can lead to full system compromise, data theft, installation of malware, or any other malicious action the attacker desires.

- **Vulnerability Rank:** high

- **Currently implemented mitigations:**
    No mitigations are currently implemented in the project to prevent command injection from `tasks.json`. The extension directly uses the `command` and `args` fields from `tasks.json` to construct and execute `vscode.ProcessExecution`.

- **Missing mitigations:**
    - Input Sanitization: Implement robust sanitization of task `command` and `args` fields read from `tasks.json`. This could involve validating commands against a whitelist of allowed commands or encoding/escaping special characters in arguments to prevent injection.
    - User Confirmation: Before executing any task defined in `tasks.json` (especially for newly added or modified tasks in a workspace), prompt the user for explicit confirmation. Display a clear warning about the potential risks of executing tasks from untrusted sources.
    - Task Definition Schema Validation: Implement a strict schema validation for `tasks.json` to limit the allowed structure and values, reducing the attack surface.

- **Preconditions:**
    1. The VSCode Deno extension must be installed and enabled.
    2. The victim must open a workspace or folder in VSCode that contains a malicious repository.
    3. The malicious repository must contain a `tasks.json` file crafted by the attacker with malicious commands.
    4. The victim must manually execute the malicious task, either from the tasks sidebar or using the "Tasks: Run Task" command.

- **Source code analysis:**
    ```typescript
    // File: ..\vscode_deno\client\src\tasks.ts

    export function buildDenoTask(
      target: vscode.WorkspaceFolder,
      process: string,
      definition: DenoTaskDefinition, // <-- Task definition read from tasks.json
      name: string,
      args: string[], // <-- Arguments, potentially from tasks.json
      problemMatchers: string[],
    ): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process, // Deno command path (relatively safe)
        args,    // Arguments from task definition (potentially unsafe)
        definition, // Definition from tasks.json (can contain env vars)
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
    The `buildDenoTask` function in `client\src\tasks.ts` directly uses the `DenoTaskDefinition`, which originates from parsing `tasks.json`, to construct a `vscode.ProcessExecution`. The `args` array, which is part of the `ProcessExecution`, is directly derived from the task definition and is not sanitized. This allows an attacker to inject arbitrary command arguments or options.

- **Security test case:**
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a file named `tasks.json` with the following content:
    ```json
    {
      "version": "2.0.0",
      "tasks": [
        {
          "type": "deno",
          "command": "echo",
          "args": [
            "Vulnerable",
            "&&",
            "touch",
            "pwned.txt"
          ],
          "label": "Malicious Task"
        }
      ]
    }
    ```
    3. Open VSCode and open the `malicious-repo` directory as a workspace. Ensure the Deno extension is enabled for this workspace.
    4. Open the Command Palette (Ctrl+Shift+P or Cmd+Shift+P) and type "Tasks: Run Task". Select this command.
    5. From the task list, select "deno: Malicious Task".
    6. After the task execution completes, check the `malicious-repo` directory. You should find a new file named `pwned.txt` created in the directory.
    7. Additionally, observe the output panel. It should display "Vulnerable" as output from the `echo` command.
    8. This confirms that the command injection is successful because the `touch pwned.txt` command, injected through `tasks.json`, was executed by the extension.

- **Vulnerability Name:** Command Injection in `deno.codeLens.testArgs`

- **Description:**
    1. The VSCode Deno extension allows users to configure additional arguments for the `deno test` command invoked via code lens through the `deno.codeLens.testArgs` setting.
    2. This setting accepts an array of strings that are directly passed as arguments to the `deno test` command.
    3. A malicious user can craft a repository with a `.vscode/settings.json` file that includes malicious code within the `deno.codeLens.testArgs` setting.
    4. When a victim opens this malicious repository in VSCode with the Deno extension installed and clicks the "Run Test" code lens, the extension will execute the `deno test` command with the attacker-controlled arguments.
    5. If these arguments contain shell commands, they will be executed by the system, leading to command injection.

- **Impact:**
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process by crafting malicious arguments in the `deno.codeLens.testArgs` setting.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
    - No input sanitization or validation is performed on the `deno.codeLens.testArgs` configuration values before passing them to the `deno test` command execution.

- **Missing Mitigations:**
    - Input sanitization and validation for the `deno.codeLens.testArgs` setting should be implemented.
    - Consider using a safer way to pass arguments to the `deno test` command, avoiding direct string concatenation that could be vulnerable to injection.
    - Restrict allowed characters or patterns in `deno.codeLens.testArgs`.
    - Implement principle of least privilege, ensure extension runs with minimal necessary permissions.

- **Preconditions:**
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious repository containing a crafted `.vscode/settings.json` file.
    - Victim clicks the "Run Test" code lens in a Deno test file within the malicious repository.
    - Deno extension is enabled in the workspace.

- **Source Code Analysis:**
    1. In `client\src\commands.ts`, the `test` function is responsible for executing the `deno test` command when the "Run Test" code lens is clicked.
    2. The code retrieves the `deno.codeLens.testArgs` configuration using `const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);` and `const testArgs: string[] = [...(config.get<string[]>("codeLens.testArgs") ?? []),];`.
    3. These `testArgs` are then directly spread into the `args` array: `const args = ["test", ...testArgs, "--filter", nameRegex, filePath];`.
    4. The `args` array is used to construct the `ProcessExecution` in `buildDenoTask` function from `client\src\tasks.ts`.
    5. `ProcessExecution` in VSCode directly executes the command with the provided arguments via shell, without any sanitization of the arguments retrieved from user settings.

    ```typescript
    // client\src\commands.ts
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // <-- User-provided args
        ];
        // ...
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // <-- Args are directly used
        // ...
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // <-- Args passed to task definition
          env,
        };
        // ...
        const task = tasks.buildDenoTask( // <-- Task is built with the args
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args,
          ["$deno-test"],
        );
        // ...
        await vscode.tasks.executeTask(task); // <-- Task execution
        // ...
      };
    }

    // client\src\tasks.ts
    export function buildDenoTask(
      target: vscode.WorkspaceFolder,
      process: string,
      definition: DenoTaskDefinition,
      name: string,
      args: string[],
      problemMatchers: string[],
    ): vscode.Task {
      const exec = new vscode.ProcessExecution( // <-- ProcessExecution is created
        process,
        args, // <-- User-provided args are passed directly
        definition,
      );

      return new vscode.Task(
        definition,
        target,
        name,
        TASK_SOURCE,
        exec, // <-- ProcessExecution is used in task
        problemMatchers,
      );
    }
    ```

- **Security Test Case:**
    1. Create a new directory and initialize it as a Git repository.
    2. Create a file named `.vscode/settings.json` inside the directory with the following content:
    ```json
    {
        "deno.enable": true,
        "deno.codeLens.testArgs": [
            "--allow-read",
            "--allow-write",
            "--allow-net",
            "--allow-env",
            "--allow-run",
            "--allow-hrtime",
            "--allow-ffi",
            "--allow-sys",
            "--unstable",
            "; open /Applications/Calculator.app ; #"
        ]
    }
    ```
    (For Windows/Linux, replace `/Applications/Calculator.app` with a command appropriate for those systems, e.g., `calc.exe` or `gnome-calculator`). For safety, using `#` to comment out after the malicious command is good practice to prevent errors if the command syntax isn't fully correct for deno's argument parsing.
    3. Create a file named `test.ts` in the root directory with simple Deno test:
    ```typescript
    Deno.test("vulnerability test", () => {
      console.log("Test executed");
    });
    ```
    4. Open the directory in VSCode with the Deno extension enabled.
    5. In the `test.ts` file, observe the "Run Test" code lens above the `Deno.test` declaration.
    6. Click the "Run Test" code lens.
    7. Observe that the Calculator application (or equivalent command from step 2) is launched, demonstrating command injection.
    8. Verify that the "Test executed" message from `console.log` is also present in the output, showing that the intended test execution and malicious command execution both occurred.

- **Vulnerability Name:** Command Injection via `deno.path` setting

- **Description:**
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
