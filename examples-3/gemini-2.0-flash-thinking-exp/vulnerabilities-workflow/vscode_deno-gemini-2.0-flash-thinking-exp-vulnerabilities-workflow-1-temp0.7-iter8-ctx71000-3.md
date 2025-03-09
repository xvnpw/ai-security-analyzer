- Vulnerability Name: Command Injection in `deno.codeLens.testArgs` and `deno.testing.args` settings

  - Description:
    1. A threat actor can create a malicious repository.
    2. The threat actor crafts a `settings.json` file within the `.vscode` directory of the malicious repository.
    3. In the `settings.json`, the threat actor sets the `deno.codeLens.testArgs` or `deno.testing.args` settings to include malicious commands. For example: `["--allow-all", "; malicious command &"]`.
    4. The victim clones the malicious repository and opens it in VSCode with the Deno extension enabled.
    5. The victim opens a test file, triggering the display of "Run Test" code lenses.
    6. The victim clicks the "Run Test" code lens or runs tests through the testing explorer.
    7. The extension executes the Deno CLI `test` command, incorporating the malicious arguments from the `deno.codeLens.testArgs` or `deno.testing.args` settings.
    8. Due to insufficient sanitization, the malicious commands injected in the settings are executed by the system.

  - Impact:
    - Remote Code Execution (RCE) on the victim's machine. The threat actor can execute arbitrary commands with the privileges of the VSCode process. This could lead to data exfiltration, installation of malware, or further system compromise.

  - Vulnerability Rank: critical

  - Currently Implemented Mitigations:
    - None. The code directly uses the values from `deno.codeLens.testArgs` and `deno.testing.args` settings to construct the Deno CLI command without any sanitization or validation.

  - Missing Mitigations:
    - Input sanitization and validation for `deno.codeLens.testArgs` and `deno.testing.args` settings. The extension should validate that the arguments are safe and do not contain command injection sequences.
    -  Consider using a safer method for command execution that avoids shell interpretation, such as directly passing arguments as an array to the `child_process.spawn` function, although `ProcessExecution` in VSCode tasks already does this. The vulnerability lies in the user-provided arguments being treated as shell commands due to potential shell injection.
    - Implement principle of least privilege: While `--allow-all` is the default, consider prompting the user for permissions or restricting the default permissions granted to test execution. However, this will not mitigate the command injection itself.

  - Preconditions:
    - Victim must have the VSCode Deno extension installed and enabled.
    - Victim must open a malicious repository containing a crafted `.vscode/settings.json` file.
    - Victim must trigger test execution, either via code lens or test explorer.

  - Source Code Analysis:
    - **File: `client/src/commands.ts` Function: `test`**
      ```typescript
      export function test(
        _context: vscode.ExtensionContext,
        extensionContext: DenoExtensionContext,
      ): Callback {
        return async (uriStr: string, name: string, options: TestCommandOptions) => {
          // ...
          const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
          const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable setting 1: codeLens.testArgs
          ];
          const unstable = config.get("unstable") as string[] ?? [];
          for (const unstableFeature of unstable) {
            const flag = `--unstable-${unstableFeature}`;
            if (!testArgs.includes(flag)) {
              testArgs.push(flag);
            }
          }
          // ...
          const args = ["test", ...testArgs, "--filter", nameRegex, filePath];

          const definition: tasks.DenoTaskDefinition = {
            type: tasks.TASK_TYPE,
            command: "test",
            args, // args is passed to ProcessExecution
            env,
          };
          // ...
          const task = tasks.buildDenoTask(
            workspaceFolder,
            denoCommand,
            definition,
            `test "${name}"`,
            args, // args is passed again here
            ["$deno-test"],
          );
          // ...
        }
      }
      ```
      - The `test` function in `commands.ts` retrieves the `deno.codeLens.testArgs` configuration from VSCode settings.
      - It directly uses these arguments when constructing the `args` array for the `DenoTaskDefinition`.
      - These `args` are then passed to `tasks.buildDenoTask`, which uses `vscode.ProcessExecution` to execute the command.
      - `vscode.ProcessExecution` directly executes the command with the provided arguments. If `testArgs` contains shell metacharacters or commands, they will be interpreted by the shell, leading to command injection.

    - **File: `client/src/tasks.ts` Function: `buildDenoTask`**
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
          args, // Arguments from settings are passed here
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
      - `buildDenoTask` function receives the `args` array, which can be influenced by `deno.codeLens.testArgs`, and directly passes it to `vscode.ProcessExecution`. This confirms that user-provided arguments are directly used in command execution without sanitization.

    - **File: `client/src/extension.ts` Function: `handleConfigurationChange`**
      ```typescript
      function handleConfigurationChange(event: vscode.ConfigurationChangeEvent) {
        if (
          [EXTENSION_NS, "javascript", "typescript"].some((s) =>
            event.affectsConfiguration(s)
          )
        ) {
          extensionContext.client?.sendNotification(
            "workspace/didChangeConfiguration",
            { settings: null },
          );
          extensionContext.maxTsServerMemory =
            vscode.workspace.getConfiguration(EXTENSION_NS).get(
              "maxTsServerMemory",
            ) ?? null;
          refreshEnableSettings(extensionContext);
          extensionContext.tsApi.refresh();
          extensionContext.statusBar.refresh(extensionContext);

          // restart when certain config changes
          if (
            event.affectsConfiguration("deno.enable") ||
            event.affectsConfiguration("deno.disablePaths") ||
            event.affectsConfiguration("deno.enablePaths") ||
            event.affectsConfiguration("deno.env") ||
            event.affectsConfiguration("deno.envFile") ||
            event.affectsConfiguration("deno.future") ||
            event.affectsConfiguration("deno.internalInspect") ||
            event.affectsConfiguration("deno.logFile") ||
            event.affectsConfiguration("deno.path") ||
            event.affectsConfiguration("deno.maxTsServerMemory")
          ) {
            vscode.commands.executeCommand("deno.client.restart");
          }
        }
      }
      ```
      - This function handles configuration changes but does not include any sanitization or validation of settings like `deno.codeLens.testArgs` or `deno.testing.args`. It simply restarts the language server on configuration changes.

  - Security Test Case:
    1. Create a new directory named `vscode_deno_test_exploit`.
    2. Inside `vscode_deno_test_exploit`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "deno.enable": true,
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; calc.exe &"
           ]
       }
       ```
       *(Note: `calc.exe` is used as a benign payload for demonstration on Windows. For other OS, use a similar harmless command like `xcalc` or `gnome-calculator` or `open /Applications/Calculator.app/` on macOS, or `touch /tmp/pwned` on Linux/macOS)*
    4. Inside `vscode_deno_test_exploit`, create a file named `test.ts` with the following content:
       ```typescript
       Deno.test("Vulnerability Test", () => {
           console.log("Test running");
       });
       ```
    5. Open the `vscode_deno_test_exploit` directory in VSCode. Ensure the Deno extension is enabled for this workspace.
    6. Open the `test.ts` file. You should see the "Run Test" code lens above the `Deno.test` definition.
    7. Click on the "Run Test" code lens.
    8. Observe that the calculator application (`calc.exe` or equivalent) is launched, demonstrating command injection.
