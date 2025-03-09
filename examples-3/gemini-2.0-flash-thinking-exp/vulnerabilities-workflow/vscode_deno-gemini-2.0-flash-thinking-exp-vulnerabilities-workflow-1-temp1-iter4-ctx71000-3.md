### Vulnerability List

- Vulnerability Name: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings
- Description:
    1. A threat actor creates a malicious repository.
    2. Inside the repository, the threat actor crafts a `.vscode/settings.json` file.
    3. In the `.vscode/settings.json`, the threat actor sets malicious commands within the `deno.codeLens.testArgs` or `deno.testing.args` settings. For example, they can inject shell commands like `; touch /tmp/pwned ; #` into the settings.
    4. The victim opens the malicious repository in VSCode with the Deno extension installed and enabled.
    5. The victim attempts to run a test, either by clicking on the "Run Test" code lens in the editor or through the Test Explorer.
    6. When the test is executed, the Deno extension reads the `deno.codeLens.testArgs` or `deno.testing.args` settings from `.vscode/settings.json`.
    7. The extension directly passes these settings as arguments to the `deno test` command without proper sanitization.
    8. Due to the injected malicious commands, the Deno CLI executes these commands in addition to the intended test execution.
    9. This results in arbitrary command execution on the victim's machine, effectively leading to Remote Code Execution (RCE).
- Impact:
    Successful exploitation allows the threat actor to achieve Remote Code Execution (RCE) on the victim's machine. The attacker can execute arbitrary commands with the privileges of the user running VSCode. This could lead to full system compromise, data exfiltration, malware installation, and other malicious activities.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    No mitigations are currently implemented in the project to prevent command injection via `deno.codeLens.testArgs` and `deno.testing.args` settings. The extension directly retrieves and uses the settings values without any sanitization or validation.
- Missing Mitigations:
    The extension lacks input sanitization for the `deno.codeLens.testArgs` and `deno.testing.args` settings. It should sanitize these settings to prevent command injection. Potential mitigations include:
    - Validating that each argument is safe and does not contain command separators or malicious characters.
    - Using parameterized commands or argument escaping when constructing the Deno CLI command.
    - Restricting the allowed characters or patterns within these settings.
- Preconditions:
    1. The victim must have the VSCode Deno extension installed and enabled.
    2. The victim must open a malicious repository containing a crafted `.vscode/settings.json` file.
    3. The victim must attempt to run a Deno test within the malicious repository using CodeLens or Test Explorer.
- Source Code Analysis:
    - File: `client/src/commands.ts`
    - Function: `test`
    ```typescript
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable line: Retrieves testArgs directly from configuration
        ];
        // ...
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // Vulnerable line: Constructs command with unsanitized testArgs
        // ...
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // Vulnerable line: args are passed to ProcessExecution
          env,
        };

        // ...
        const task = tasks.buildDenoTask(
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args, // Vulnerable line: args are passed to buildDenoTask
          ["$deno-test"],
        );
        // ...
        const createdTask = await vscode.tasks.executeTask(task); // Vulnerable line: Task is executed

        // ...
        return createdTask;
      };
    }
    ```
    The code in the `test` function directly retrieves the `deno.codeLens.testArgs` configuration using `config.get<string[]>("codeLens.testArgs")` and incorporates it into the `args` array without any sanitization. These `args` are then used to construct a `ProcessExecution` in `buildDenoTask` function from `client/src/tasks.ts`, which ultimately executes the Deno CLI command. This lack of sanitization allows for command injection. The same vulnerability exists for `deno.testing.args` and tasks defined in `tasks.json`.

- Security Test Case:
    1. Create a new directory named `deno-command-injection-test`.
    2. Inside `deno-command-injection-test`, create a file named `.vscode/settings.json` with the following content:
    ```json
    {
        "deno.codeLens.testArgs": [
            "--allow-read",
            "--allow-write",
            "--allow-net",
            "--allow-env",
            "--allow-run",
            "--allow-hrtime",
            "--allow-ffi",
            "; touch /tmp/pwned ; #"
        ]
    }
    ```
    3. Inside `deno-command-injection-test`, create a file named `test.ts` with the following content:
    ```typescript
    Deno.test("command injection test", () => {
        console.log("Test is running");
    });
    ```
    4. Open the `deno-command-injection-test` directory in VSCode. Ensure the Deno extension is enabled for this workspace.
    5. Open the `test.ts` file. You should see a "▶ Run Test" code lens above the `Deno.test` declaration.
    6. Click on the "▶ Run Test" code lens.
    7. After the test execution (which may succeed or fail), check if a file named `pwned` exists in the `/tmp/` directory.
    8. If the file `/tmp/pwned` exists, it confirms that the command injection was successful, and arbitrary commands from `deno.codeLens.testArgs` were executed.
