* Vulnerability Name: Command Injection in `deno.codeLens.testArgs`

* Description:
    1. The VSCode Deno extension allows users to configure additional arguments for the `deno test` command invoked via code lens through the `deno.codeLens.testArgs` setting.
    2. This setting accepts an array of strings that are directly passed as arguments to the `deno test` command.
    3. A malicious user can craft a repository with a `.vscode/settings.json` file that includes malicious code within the `deno.codeLens.testArgs` setting.
    4. When a victim opens this malicious repository in VSCode with the Deno extension installed and clicks the "Run Test" code lens, the extension will execute the `deno test` command with the attacker-controlled arguments.
    5. If these arguments contain shell commands, they will be executed by the system, leading to command injection.

* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process by crafting malicious arguments in the `deno.codeLens.testArgs` setting.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - No input sanitization or validation is performed on the `deno.codeLens.testArgs` configuration values before passing them to the `deno test` command execution.

* Missing Mitigations:
    - Input sanitization and validation for the `deno.codeLens.testArgs` setting should be implemented.
    - Consider using a safer way to pass arguments to the `deno test` command, avoiding direct string concatenation that could be vulnerable to injection.
    - Restrict allowed characters or patterns in `deno.codeLens.testArgs`.
    - Implement principle of least privilege, ensure extension runs with minimal necessary permissions.

* Preconditions:
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious repository containing a crafted `.vscode/settings.json` file.
    - Victim clicks the "Run Test" code lens in a Deno test file within the malicious repository.
    - Deno extension is enabled in the workspace.

* Source Code Analysis:
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

* Security Test Case:
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
