### Vulnerability List

#### 1. Command Injection via Test Arguments

- Description:
    1. An attacker crafts a malicious workspace.
    2. Within the workspace's `.vscode/settings.json` file, the attacker configures either `deno.codeLens.testArgs` or `deno.testing.args` settings to include system commands. For example: `["--allow-all", "; touch /tmp/pwned ;"]`.
    3. A victim opens this malicious workspace using Visual Studio Code with the Deno extension enabled.
    4. The victim initiates test execution, either through the "Run Test" code lens or the Test Explorer.
    5. The Deno extension, upon running the tests, utilizes the Deno CLI and incorporates the attacker-defined arguments directly from the workspace settings.
    6. Due to the absence of input sanitization, the injected commands are executed by the operating system.

- Impact:
    Remote Code Execution (RCE). This vulnerability allows an attacker to execute arbitrary commands on the victim's machine. The commands are executed with the same privileges as the VS Code process, potentially allowing for full system compromise depending on the victim's environment and permissions.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    None. The extension directly passes the configuration values to the Deno CLI without any validation or sanitization.

- Missing Mitigations:
    - Input sanitization and validation: Implement checks to sanitize or validate the `deno.codeLens.testArgs` and `deno.testing.args` settings. This should involve stripping out or escaping any characters or command sequences that could be used for command injection.
    - User Warning: Display a prominent warning to the user when the extension detects potentially unsafe settings within a workspace, especially those related to command execution. This warning should advise caution and recommend reviewing the settings before running any commands.

- Preconditions:
    1. The victim must have Visual Studio Code installed with the Deno extension enabled.
    2. The victim must open a malicious workspace prepared by an attacker.
    3. The Deno extension must be enabled for the opened workspace.
    4. The victim must attempt to run Deno tests within the malicious workspace, either via Code Lens or Test Explorer.

- Source Code Analysis:
    File: `client\src\commands.ts`
    Function: `test`

    ```typescript
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable code: Reading test arguments from configuration
        ];
        const unstable = config.get("unstable") as string[] ?? [];
        for (const unstableFeature of unstable) {
          const flag = `--unstable-${unstableFeature}`;
          if (!testArgs.includes(flag)) {
            testArgs.push(flag);
          }
        }
        if (options?.inspect) {
          testArgs.push(getInspectArg(extensionContext.serverInfo?.version));
        }
        if (!testArgs.includes("--import-map")) {
          const importMap: string | undefined | null = config.get("importMap");
          if (importMap?.trim()) {
            testArgs.push("--import-map", importMap.trim());
          }
        }
        // ...
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // Command construction, including unsanitized arguments
        // ...
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // Unsanitized arguments passed to task definition
          env,
        };
        // ...
        const task = tasks.buildDenoTask(
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args, // Unsanitized arguments passed to buildDenoTask
          ["$deno-test"],
        );
        // ...
        const createdTask = await vscode.tasks.executeTask(task); // Task execution, leading to command injection
        // ...
      };
    }
    ```
    The `test` function in `client\src\commands.ts` directly retrieves the `codeLens.testArgs` configuration from workspace settings. These arguments are then incorporated into the command array (`args`) that is passed to `vscode.tasks.executeTask`.  Critically, there's no sanitization or validation of these arguments before they are passed to the `ProcessExecution` which executes the Deno CLI command. This allows an attacker to inject arbitrary shell commands by manipulating these settings.

- Security Test Case:
    1. Create a new directory named `malicious-deno-workspace`.
    2. Navigate into `malicious-deno-workspace` and create a `.vscode` subdirectory.
    3. Inside `.vscode`, create a file named `settings.json` with the following JSON content:
        ```json
        {
            "deno.enable": true,
            "deno.codeLens.testArgs": [
                "--allow-all",
                "; touch /tmp/pwned ;"
            ]
        }
        ```
    4. In `malicious-deno-workspace`, create a file named `test.ts` with the following TypeScript content:
        ```typescript
        Deno.test("vulnerability test", () => {
          console.log("Test running");
        });
        ```
    5. Open the `malicious-deno-workspace` folder in Visual Studio Code.
    6. Confirm that the Deno extension is enabled for this workspace.
    7. Open the `test.ts` file in the editor.
    8. Locate and click the "Run Test" code lens situated above the `Deno.test` declaration in the editor.
    9. After the test execution completes, verify the existence of a file named `pwned` in the `/tmp/` directory of your system. On Unix-like systems, you can use the command `ls /tmp/pwned` in the terminal. If the file exists, it confirms successful command injection and remote code execution. Note: On Windows, the `touch` command will not work, you can use `; New-Item -ItemType file -Path C:\Windows\Temp\pwned.txt ;` instead and check for file `C:\Windows\Temp\pwned.txt`.
