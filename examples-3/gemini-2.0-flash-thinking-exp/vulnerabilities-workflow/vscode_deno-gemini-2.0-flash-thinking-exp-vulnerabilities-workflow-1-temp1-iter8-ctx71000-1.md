### Vulnerability List:

- Vulnerability Name: **Command Injection via `deno.path` setting**
  - Description:
    1. A threat actor creates a malicious repository.
    2. Inside the malicious repository, the threat actor crafts a `.vscode/settings.json` file.
    3. In this `settings.json`, the threat actor sets the `deno.path` setting to a malicious command. For example: `"deno.path": "bash -c 'touch /tmp/pwned'"` or on Windows: `"deno.path": "cmd /c type C:\\windows\\system32\\calc.exe"`.
    4. The victim clones or opens the malicious repository in VSCode.
    5. If the Deno extension is activated for this workspace, it reads the `deno.path` setting from `.vscode/settings.json`.
    6. The `getDenoCommandPath` function in `client/src/util.ts` retrieves this setting.
    7. The extension attempts to start the Deno Language Server using the provided `deno.path` as the command.
    8. Due to insufficient sanitization of the `deno.path` setting, the malicious command is executed by the system shell instead of a legitimate Deno executable.
  - Impact: **Remote Code Execution (RCE)**. The threat actor can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. In the example, this could lead to creating files, running programs, or more malicious actions.
  - Vulnerability Rank: **Critical**
  - Currently implemented mitigations:
    - None. The code directly uses the value of `deno.path` setting to spawn a process.
    - `getDenoCommandPath` in `client/src/util.ts` only checks if the file exists but does not validate the content or sanitize the command.
  - Missing mitigations:
    - Input sanitization for the `deno.path` setting. The extension should validate that the provided path points to a legitimate Deno executable and does not contain any shell metacharacters or malicious commands.
    - Restrict the `deno.path` setting to be configurable only in user or remote settings, and disallow workspace settings to override it. This would prevent malicious repositories from injecting this setting.
    - Warn users when `deno.path` is set, especially if it is set in workspace settings.
  - Preconditions:
    - The victim must have the Deno extension installed and activated.
    - The victim must open a malicious repository in VSCode.
    - The `deno.enable` setting should be true for the workspace or implicitly enabled via `deno.json` detection.
  - Source code analysis:
    - In `client/src/util.ts`, `getDenoCommandPath` retrieves the `deno.path` setting:
      ```typescript
      function getWorkspaceConfigDenoExePath() {
        const exePath = workspace.getConfiguration(EXTENSION_NS)
          .get<string>("path");
        // ...
        return exePath;
      }

      export async function getDenoCommandPath() {
        const command = getWorkspaceConfigDenoExePath();
        // ...
        return command ?? await getDefaultDenoCommand();
      }
      ```
    - In `client/src/commands.ts`, `startLanguageServer` uses `getDenoCommandPath` to determine the command to execute:
      ```typescript
      export function startLanguageServer(
        context: vscode.ExtensionContext,
        extensionContext: DenoExtensionContext,
      ): Callback {
        return async () => {
          // ...
          const command = await getDenoCommandPath();
          if (command == null) {
            // ...
            return;
          }
          // ...
          const serverOptions: ServerOptions = {
            run: {
              command, // <= Malicious command from settings is used here
              args: ["lsp"],
              options: { env },
            },
            debug: {
              command, // <= Malicious command from settings is used here
              args: ["lsp"],
              options: { env },
            },
          };
          const client = new LanguageClient(
            LANGUAGE_CLIENT_ID,
            LANGUAGE_CLIENT_NAME,
            serverOptions,
            {
              outputChannel: extensionContext.outputChannel,
              middleware: { /* ... */ },
              ...extensionContext.clientOptions,
            },
          );
          // ...
          await client.start();
          // ...
        };
      }
      ```
    - The `command` variable, which can be controlled by the `deno.path` workspace setting, is directly used in `ServerOptions` to spawn the Language Server process without any sanitization, leading to command injection.

  - Security test case:
    1. Create a new folder named `vscode-deno-rce-test`.
    2. Inside `vscode-deno-rce-test`, create a subfolder named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
         "deno.path": "bash -c 'touch /tmp/vscode-deno-pwned'"
       }
       ```
       (For Windows, use: ` "deno.path": "cmd /c echo pwned > %TEMP%\\vscode-deno-pwned.txt" ` )
    4. Open the `vscode-deno-rce-test` folder in VSCode.
    5. Ensure the Deno extension is activated for this workspace (it should activate automatically if you have any `.js`, `.ts` file or a `deno.json` in the folder, or you can manually enable it via "Deno: Enable" command).
    6. Observe if the file `/tmp/vscode-deno-pwned` (or `%TEMP%\\vscode-deno-pwned.txt` on Windows) is created after VSCode loads the workspace and Deno extension starts.
    7. If the file is created, the command injection vulnerability is confirmed.

- Vulnerability Name: **Command Injection via `deno.task.args` in tasks.json**
  - Description:
    1. A threat actor creates a malicious repository with a crafted `.vscode/tasks.json` file.
    2. This `tasks.json` defines a Deno task where the `args` field contains malicious shell commands. For example:
       ```json
       {
         "version": "2.0.0",
         "tasks": [
           {
             "type": "deno",
             "command": "run",
             "args": [
               "`; touch /tmp/tasks-pwned; #`", // Malicious injection here
               "mod.ts"
             ],
             "problemMatcher": [
               "$deno"
             ],
             "label": "deno: run"
           }
         ]
       }
       ```
       (For Windows, use: `"args": ["\"; type C:\\windows\\system32\\calc.exe & echo \"]` )
    3. The victim clones or opens the malicious repository in VSCode.
    4. If the Deno extension is activated and the user attempts to run this task (e.g., via Tasks: Run Task or tasks sidebar if enabled), VSCode will execute the task.
    5. The `buildDenoTask` function in `client/src/tasks.ts` constructs a `ProcessExecution` using the provided `args` without sanitization.
    6. The system shell interprets and executes the injected malicious commands within the `args` array.
  - Impact: **Remote Code Execution (RCE)**.  The threat actor can execute arbitrary shell commands on the victim's machine when the victim runs the malicious task.
  - Vulnerability Rank: **High**
  - Currently implemented mitigations:
    - None. Task arguments are directly passed to `ProcessExecution`.
    - No input sanitization is performed on task arguments.
  - Missing mitigations:
    - Sanitize task arguments to prevent shell command injection. The extension should either disallow shell metacharacters or properly escape arguments before passing them to the shell.
    - Warn users about tasks from workspace settings, as they can be defined in malicious repositories.
  - Preconditions:
    - The victim must have the Deno extension installed and activated.
    - The victim must open a malicious repository containing a malicious `tasks.json`.
    - The victim must manually run the malicious task defined in `tasks.json`.
  - Source code analysis:
    - In `client/src/tasks.ts`, `buildDenoTask` function directly uses task `args` in `ProcessExecution`:
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
          args, // <= Unsanitized args from tasks.json
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
    - `args` from `DenoTaskDefinition`, which is populated from `tasks.json`, is used without sanitization, allowing for command injection if malicious arguments are provided.

  - Security test case:
    1. Create a new folder named `vscode-deno-tasks-rce-test`.
    2. Inside `vscode-deno-tasks-rce-test`, create a subfolder named `.vscode`.
    3. Inside `.vscode`, create a file named `tasks.json` with the following content:
       ```json
       {
         "version": "2.0.0",
         "tasks": [
           {
             "type": "deno",
             "command": "run",
             "args": [
               "`; touch /tmp/vscode-deno-tasks-pwned; #`",
               "mod.ts"
             ],
             "problemMatcher": [
               "$deno"
             ],
             "label": "deno: run with injection"
           }
         ]
       }
       ```
       (For Windows, use: `"args": ["\"; type C:\\windows\\system32\\calc.exe & echo \", "mod.ts"]` )
    4. Create an empty file `mod.ts` in `vscode-deno-tasks-rce-test`.
    5. Open the `vscode-deno-tasks-rce-test` folder in VSCode.
    6. Open the Command Palette (Ctrl+Shift+P) and run "Tasks: Run Task".
    7. Select the task "deno: run with injection".
    8. Observe if the file `/tmp/vscode-deno-tasks-pwned` (or `%TEMP%\\vscode-deno-pwned.txt` on Windows) is created after running the task.
    9. If the file is created, the command injection vulnerability in tasks is confirmed.
