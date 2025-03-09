### Vulnerability List

- Vulnerability Name: Command Injection via Deno Test Arguments

- Description:
    1. A threat actor creates a malicious repository.
    2. The malicious repository includes a `.vscode/settings.json` file.
    3. In the `.vscode/settings.json`, the threat actor sets the `deno.codeLens.testArgs` or `deno.testing.args` configuration to include malicious commands. For example:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; touch /tmp/pwned ; #"
           ]
       }
       ```
    4. A victim clones the malicious repository and opens it in VSCode with the Deno extension installed and enabled.
    5. The victim opens a Deno test file, and clicks "Run Test" code lens or runs tests via Test Explorer.
    6. The Deno extension executes the `deno test` command with the arguments from `deno.codeLens.testArgs` or `deno.testing.args`.
    7. Due to insufficient sanitization, the malicious commands injected in the settings are executed by the system.

- Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data exfiltration, or other malicious activities.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    No input sanitization or validation is implemented for `deno.codeLens.testArgs` and `deno.testing.args` settings. The arguments are directly passed to the `ProcessExecution` without any checks.

- Missing Mitigations:
    - Input validation and sanitization for `deno.codeLens.testArgs` and `deno.testing.args` settings.
    - Restrict allowed characters or commands in these settings.
    - Warn users when these settings are modified, especially in workspace settings.
    - Consider disallowing shell commands in these settings and only allow specific deno CLI arguments.

- Preconditions:
    1. Victim has VSCode with the Deno extension installed and enabled.
    2. Victim clones and opens a malicious repository containing a crafted `.vscode/settings.json`.
    3. Victim attempts to run Deno tests within the malicious repository using code lens or test explorer.

- Source Code Analysis:
    1. **File: client/src/commands.ts, Function: test**
       ```typescript
       export function test(
         _context: vscode.ExtensionContext,
         extensionContext: DenoExtensionContext,
       ): Callback {
         return async (uriStr: string, name: string, options: TestCommandOptions) => {
           const uri = vscode.Uri.parse(uriStr, true);
           const filePath = uri.fsPath;
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
           if (options?.inspect) {
             testArgs.push(getInspectArg(extensionContext.serverInfo?.version));
           }
           if (!testArgs.includes("--import-map")) {
             const importMap: string | undefined | null = config.get("importMap");
             if (importMap?.trim()) {
               testArgs.push("--import-map", importMap.trim());
             }
           }
           // ... env configuration ...
           const nameRegex = `/^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$/`;
           const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // Arguments are constructed here

           const definition: tasks.DenoTaskDefinition = {
             type: tasks.TASK_TYPE,
             command: "test",
             args, // Arguments are passed to task definition
             env,
           };
           // ... task execution ...
         };
       }
       ```
    2. **File: client/src/tasks.ts, Function: buildDenoTask**
       ```typescript
       export function buildDenoTask(
         target: vscode.WorkspaceFolder,
         process: string,
         definition: DenoTaskDefinition,
         name: string,
         args: string[], // Arguments are received here
         problemMatchers: string[],
       ): vscode.Task {
         const exec = new vscode.ProcessExecution(
           process,
           args, // Arguments are passed to ProcessExecution without sanitization
           definition,
         );

         return new vscode.Task(
           definition,
           target,
           name,
           TASK_SOURCE,
           exec, // ProcessExecution executes the command
           problemMatchers,
         );
       }
       ```
       The code shows that `deno.codeLens.testArgs` setting is read directly from VSCode configuration and passed as arguments to `deno test` command via `ProcessExecution` without any sanitization. This allows for command injection. The same applies for `deno.testing.args` which is used in Test Explorer.

- Security Test Case:
    1. Create a new directory named `vscode_deno_test_repo`.
    2. Inside `vscode_deno_test_repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; touch /tmp/vscode_deno_pwned ; #"
           ]
       }
       ```
    4. In `vscode_deno_test_repo`, create a file named `test.ts` with the following content:
       ```typescript
       import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

       Deno.test("command injection test", () => {
           assertEquals(1, 1);
       });
       ```
    5. Open the `vscode_deno_test_repo` directory in VSCode with the Deno extension enabled.
    6. Open the `test.ts` file.
    7. Click on the "Run Test" code lens above the `Deno.test` definition.
    8. After the test execution completes (it can be successful or failed), check if the file `/tmp/vscode_deno_pwned` exists on the system.
    9. If the file `/tmp/vscode_deno_pwned` exists, it confirms that the command injection vulnerability is present.
