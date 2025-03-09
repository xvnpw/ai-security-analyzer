- Vulnerability Name: Arbitrary Command Injection via Test Arguments
- Description:
  - Attacker crafts a malicious workspace configuration.
  - In the workspace settings, the attacker sets `deno.testing.args` or `deno.codeLens.testArgs` to include malicious commands. For example, `["--allow-all", "; malicious_command; "]`.
  - The user opens a workspace with this malicious configuration.
  - The user runs tests using the Test Explorer or Code Lens.
  - The extension executes the `deno test` command with the attacker-injected arguments.
  - The malicious command is executed by the system.
- Impact: Arbitrary code execution. An attacker can execute arbitrary commands on the user's machine with the privileges of the user running VSCode.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations: None. The extension directly uses the arguments from the settings without any sanitization.
- Missing Mitigations:
  - Sanitize arguments from `deno.testing.args` and `deno.codeLens.testArgs` to prevent command injection.
  - Warn users about the risks of modifying workspace settings from untrusted sources.
- Preconditions:
  - User opens a workspace containing a malicious `.vscode/settings.json` or workspace settings.
  - Deno extension is enabled in the workspace.
  - User runs tests using Test Explorer or Code Lens.
- Source Code Analysis:
  - In `client\src\commands.ts`, function `test`:
    ```typescript
    export function test( ... ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        ...
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable line for Code Lens
          ...(config.get<string[]>("testing.args") ?? []),    // Vulnerable line for Test Explorer (typo in setting name in code, should be deno.testing.args)
        ];
        ...
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
        ...
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // args is used directly in ProcessExecution
          ...
        };
        ...
        const task = tasks.buildDenoTask(workspaceFolder, denoCommand, definition, ...);
        await vscode.tasks.executeTask(task);
        ...
      };
    }
    ```
    The code retrieves `codeLens.testArgs` and `testing.args` from the workspace configuration and directly uses it to construct the command arguments for `deno test`. There is no input validation or sanitization on these arguments. Note: there is a typo in the code, it uses `testing.args` instead of `deno.testing.args`.
- Security Test Case:
  - Test case 1 (Test Explorer):
    1. Create a new VSCode workspace.
    2. Create a file `test.ts` with a simple test:
       ```typescript
       Deno.test("simple test", () => {
         console.log("Test ran");
       });
       ```
    3. Create `.vscode/settings.json` in the workspace root with the following content to inject a malicious command into `deno.testing.args`:
       ```json
       {
           "deno.enable": true,
           "deno.testing.args": [
               "--allow-all",
               "; touch malicious_file_test_explorer.txt; "
           ]
       }
       ```
       For Windows, use `"; New-Item malicious_file_test_explorer.txt -ItemType file ;"` or `& cmd /c "echo vulnerable > malicious_file_test_explorer.txt"`
    4. Open VSCode Test Explorer.
    5. Run the test.
    6. Verify that a file named `malicious_file_test_explorer.txt` is created in the workspace root, confirming arbitrary command execution via Test Explorer.
  - Test case 2 (Code Lens):
    1. Repeat steps 1-2 from Test case 1.
    2. Create `.vscode/settings.json` in the workspace root with the following content to inject a malicious command into `deno.codeLens.testArgs`:
       ```json
       {
           "deno.enable": true,
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; touch malicious_file_codelens.txt; "
           ]
       }
       ```
       For Windows, use `"; New-Item malicious_file_codelens.txt -ItemType file ;"` or `& cmd /c "echo vulnerable > malicious_file_codelens.txt"`
    3. Open `test.ts` in VSCode.
    4. Observe the "Run Test" code lens above the test definition.
    5. Click "Run Test".
    6. Verify that a file named `malicious_file_codelens.txt` is created in the workspace root, confirming arbitrary command execution via Code Lens.
