- Command Injection in Deno Task Execution

Description:
A command injection vulnerability exists in the Deno task execution functionality. This vulnerability can be triggered when the extension executes Deno tasks defined in `tasks.json` or via code lens. Specifically, the arguments provided in the `tasks.json` or through the `deno.codeLens.testArgs` setting are not properly sanitized before being passed to the `ProcessExecution` constructor, which can lead to command injection if a malicious repository provides a crafted task configuration.

Step-by-step trigger:
1. An attacker creates a malicious repository.
2. In the malicious repository, the attacker creates a `.vscode/tasks.json` file.
3. In the `tasks.json` file, the attacker defines a Deno task with malicious arguments, for example:
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "type": "deno",
            "command": "run",
            "args": [
                "mod.ts",
                "--allow-read",
                "--allow-write",
                "--allow-net",
                "--allow-env",
                "--allow-sys",
                "--allow-hrtime",
                "--allow-ffi",
                "--unstable",
                "; malicious_command"
            ],
            "problemMatcher": [
                "$deno"
            ],
            "label": "deno: run malicious"
        }
    ]
}
```
4. The victim opens the malicious repository in VSCode with the Deno extension installed and enabled.
5. The attacker can trick the victim into running the malicious task (e.g., via the tasks sidebar or command palette).
6. When the task is executed, the `ProcessExecution` in `tasks.ts` uses the unsanitized arguments.
7. The Deno CLI executes the command, including the injected malicious command after the semicolon.

Impact:
Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's local machine, including data theft, malware installation, and further lateral movement within the victim's network if applicable.

Vulnerability Rank: critical

Currently implemented mitigations:
No input sanitization or validation is implemented for task arguments in `tasks.ts` or `commands.ts`. The code directly uses the arguments provided in the configuration.

Missing mitigations:
Input sanitization and validation are missing. The extension should sanitize all arguments passed to the `ProcessExecution` constructor to prevent command injection. Specifically, it should:
- Validate the `command` and `args` properties in `tasks.json` against a whitelist of allowed commands and arguments, or
- Properly escape or sanitize the arguments to prevent shell injection.
- Consider using `child_process.spawn` with the `shell: false` option to avoid shell interpretation of arguments, although this might require more careful handling of arguments.

Preconditions:
- Victim has VSCode with the Deno extension installed and enabled.
- Victim opens a malicious repository containing a crafted `.vscode/tasks.json` file.
- Victim is tricked into executing the malicious Deno task.

Source code analysis:
1. **File: `client/src/tasks.ts`**
   - Function `buildDenoTask` creates a `vscode.Task` with a `vscode.ProcessExecution`.
   - The `ProcessExecution` constructor takes `process` (deno command path) and `args` directly from the `definition.args`.
   ```typescript
   export function buildDenoTask(
       target: vscode.WorkspaceFolder,
       process: string,
       definition: DenoTaskDefinition,
       name: string,
       args: string[], // Arguments are passed directly here
       problemMatchers: string[],
   ): vscode.Task {
       const exec = new vscode.ProcessExecution(
           process,
           args, // Unsanitized arguments are used here
           definition,
       );
   ```
2. **File: `client/src/commands.ts`**
   - Function `test` in `commands.ts` constructs arguments for `deno test` command, including `deno.codeLens.testArgs` and `deno.unstable` settings. These are passed to `tasks.buildDenoTask`.
   ```typescript
   export function test(
       _context: vscode.ExtensionContext,
       extensionContext: DenoExtensionContext,
   ): Callback {
       return async (uriStr: string, name: string, options: TestCommandOptions) => {
           // ...
           const testArgs: string[] = [
               ...(config.get<string[]>("codeLens.testArgs") ?? []), // Potentially malicious args from settings
           ];
           const unstable = config.get("unstable") as string[] ?? [];
           // ...
           const args = ["test", ...testArgs, "--filter", nameRegex, filePath];

           const definition: tasks.DenoTaskDefinition = {
               type: tasks.TASK_TYPE,
               command: "test",
               args, // Arguments are passed to task definition
               env,
           };
           // ...
           const task = tasks.buildDenoTask( // buildDenoTask is called with unsanitized args
               workspaceFolder,
               denoCommand,
               definition,
               `test "${name}"`,
               args,
               ["$deno-test"],
           );
           // ...
       };
   }
   ```
3. **File: `client/src/tasks_sidebar.ts`**
   - Tasks in `tasks_sidebar.ts` are loaded from `deno.json` configurations via LSP request `deno/taskDefinitions`. These tasks are then executed using `buildDenoConfigTask`, which eventually also uses `buildDenoTask`.
   - Malicious tasks in `deno.json` could also be crafted and executed.

Security test case:
1. Create a malicious repository with the following structure:
   ```
   malicious-repo/
   ├── .vscode/
   │   └── tasks.json
   └── mod.ts
   ```
   - `mod.ts`: (can be empty or any valid Deno file)
     ```typescript
     console.log("Hello from mod.ts");
     ```
   - `.vscode/tasks.json`:
     ```json
     {
         "version": "2.0.0",
         "tasks": [
             {
                 "type": "deno",
                 "command": "run",
                 "args": [
                     "mod.ts",
                     "; calc.exe"
                 ],
                 "problemMatcher": [
                     "$deno"
                 ],
                 "label": "deno: run malicious"
             }
         ]
     }
     ```
2. Open the `malicious-repo` in VSCode with the Deno extension enabled.
3. Open the Command Palette (`Ctrl+Shift+P`) and run "Tasks: Run Task".
4. Select the "deno: run malicious" task.
5. Observe that `calc.exe` (or another OS command like `open /Applications/Calculator.app` on macOS or `xcalc` on Linux) is executed, demonstrating command injection.

- Command Injection in Deno Test Code Lens Arguments

Description:
Similar to the task execution vulnerability, a command injection vulnerability exists through the `deno.codeLens.testArgs` setting. If a malicious repository includes VSCode workspace settings that define malicious arguments in `deno.codeLens.testArgs`, these arguments will be passed unsanitized to the `deno test` command when running tests via code lens, leading to command injection.

Step-by-step trigger:
1. An attacker creates a malicious repository.
2. In the malicious repository, the attacker creates a `.vscode/settings.json` file.
3. In the `.vscode/settings.json` file, the attacker defines malicious arguments for `deno.codeLens.testArgs`, for example:
```json
{
    "deno.codeLens.testArgs": [
        "--allow-all",
        "; malicious_command"
    ]
}
```
4. In the malicious repository, create a test file (e.g., `test.ts`) with a Deno test:
```typescript
Deno.test("example test", () => {
  console.log("Running test");
});
```
5. The victim opens the malicious repository in VSCode with the Deno extension installed and enabled.
6. The victim opens the `test.ts` file and observes the "▶ Run Test" code lens above the `Deno.test` declaration.
7. The victim clicks on the "▶ Run Test" code lens to run the test.
8. When the test is executed, the `commands.test` function in `client/src/commands.ts` uses the unsanitized arguments from `deno.codeLens.testArgs`.
9. The Deno CLI executes the command, including the injected malicious command after the semicolon.

Impact:
Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine when the victim runs a test via code lens in a malicious repository.

Vulnerability Rank: critical

Currently implemented mitigations:
No input sanitization or validation is implemented for `deno.codeLens.testArgs` in `commands.ts`. The settings are directly used to construct the command.

Missing mitigations:
Input sanitization and validation are missing for `deno.codeLens.testArgs`. The extension should sanitize or validate these arguments to prevent command injection.

Preconditions:
- Victim has VSCode with the Deno extension installed and enabled.
- Victim opens a malicious repository containing a crafted `.vscode/settings.json` file with malicious `deno.codeLens.testArgs`.
- Victim clicks on the "▶ Run Test" code lens in a test file within the malicious repository.

Source code analysis:
1. **File: `client/src/commands.ts`**
   - Function `test` retrieves `deno.codeLens.testArgs` from VSCode configuration and uses it directly in the `deno test` command construction without sanitization.
   ```typescript
   export function test(
       _context: vscode.ExtensionContext,
       extensionContext: DenoExtensionContext,
   ): Callback {
       return async (uriStr: string, name: string, options: TestCommandOptions) => {
           // ...
           const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
           const testArgs: string[] = [
               ...(config.get<string[]>("codeLens.testArgs") ?? []), // Unsanitized testArgs from settings
           ];
           // ...
           const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
           // ...
           const definition: tasks.DenoTaskDefinition = {
               type: tasks.TASK_TYPE,
               command: "test",
               args,
               env,
           };
           // ...
       };
   }
   ```
2. **File: `client/src/tasks.ts`**
   - As analyzed in the previous vulnerability, `buildDenoTask` uses these arguments without sanitization.

Security test case:
1. Create a malicious repository with the following structure:
   ```
   malicious-repo/
   ├── .vscode/
   │   └── settings.json
   └── test.ts
   ```
   - `test.ts`:
     ```typescript
     Deno.test("example test", () => {
       console.log("Running test");
     });
     ```
   - `.vscode/settings.json`:
     ```json
     {
         "deno.codeLens.testArgs": [
             "--allow-all",
             "; calc.exe"
         ]
     }
     ```
2. Open the `malicious-repo` in VSCode with the Deno extension enabled.
3. Open `test.ts`.
4. Click on the "▶ Run Test" code lens above the `Deno.test` declaration.
5. Observe that `calc.exe` (or equivalent OS command) is executed, demonstrating command injection via `deno.codeLens.testArgs`.
