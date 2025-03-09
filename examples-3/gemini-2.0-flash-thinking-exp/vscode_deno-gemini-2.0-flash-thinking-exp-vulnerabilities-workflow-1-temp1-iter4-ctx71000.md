### Combined Vulnerability List

- Vulnerability Name: **Command Injection via `deno.path` setting**
  - Description:
    1. A threat actor creates a malicious repository.
    2. Inside the malicious repository, the threat actor includes a `.vscode/settings.json` file.
    3. In this `settings.json`, the threat actor sets the `deno.path` setting to a malicious script. For example: `"deno.path": "malicious.bat"`. The `malicious.bat` script is also included in the repository and contains commands to execute arbitrary code on the victim's machine.
    4. A victim clones and opens this malicious repository in VSCode with the Deno extension installed.
    5. When the Deno extension tries to start the language server, it reads the `deno.path` setting from the workspace's `.vscode/settings.json`.
    6. Instead of executing the legitimate Deno CLI, the extension executes the malicious script specified in `deno.path`.
    7. The malicious script executes arbitrary commands on the victim's machine under the context of the VSCode process.
  - Impact: Remote Code Execution (RCE). An attacker can execute arbitrary code on the victim's machine when they open a malicious repository in VSCode.
  - Vulnerability Rank: Critical
  - Currently Implemented Mitigations:
    - None. The extension directly uses the path provided in the `deno.path` setting to execute the Deno CLI.
  - Missing Mitigations:
    - Input validation and sanitization for the `deno.path` setting to ensure it points to a legitimate Deno executable and not a malicious script.
    - Path validation to ensure the path is within expected Deno installation directories or user-configured safe paths.
    - Warning to the user when `deno.path` is configured within workspace settings, especially if it's unusual or points to a location within the workspace itself.
  - Preconditions:
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious repository containing a crafted `.vscode/settings.json` and a malicious script.
    - Deno extension is activated in the workspace.
  - Source Code Analysis:
    - File: `client/src/util.ts`
    ```typescript
    export async function getDenoCommandPath() {
      const command = getWorkspaceConfigDenoExePath();
      const workspaceFolders = workspace.workspaceFolders;
      if (!command || !workspaceFolders) {
        return command ?? await getDefaultDenoCommand();
      } else if (!path.isAbsolute(command)) {
        // if sent a relative path, iterate over workspace folders to try and resolve.
        for (const workspace of workspaceFolders) {
          const commandPath = path.resolve(workspace.uri.fsPath, command);
          if (await fileExists(commandPath)) {
            return commandPath;
          }
        }
        return undefined;
      } else {
        return command;
      }
    }

    function getWorkspaceConfigDenoExePath() {
      const exePath = workspace.getConfiguration(EXTENSION_NS)
        .get<string>("path");
      // it is possible for the path to be blank. In that case, return undefined
      if (typeof exePath === "string" && exePath.trim().length === 0) {
        return undefined;
      } else {
        return exePath;
      }
    }
    ```
    - The `getDenoCommandPath` function retrieves the `deno.path` setting from the workspace configuration.
    - If `deno.path` is set in workspace configuration (e.g., `.vscode/settings.json`), this function directly returns it, after resolving relative paths against workspace folder.
    - File: `client/src/commands.ts`
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

        const serverOptions: ServerOptions = {
          run: {
            command, // Vulnerable command execution
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // Vulnerable command execution
            // ...
            args: ["lsp"],
            options: { env },
          },
        };
        const client = new LanguageClient( // ...
        await client.start();
        // ...
      };
    }
    ```
    - In `startLanguageServer` function, the `command` variable, obtained from `getDenoCommandPath`, is directly used in `ServerOptions` for `run` and `debug`.
    - The `LanguageClient` then uses this `command` to spawn a process, leading to the execution of the potentially malicious script provided in `deno.path`.

  - Security Test Case:
    1. Create a new directory named `malicious-deno-repo`.
    2. Inside `malicious-deno-repo`, create a file named `malicious.bat` with the following content:
       ```bat
       @echo off
       echo Vulnerable > rce.txt
       ```
    3. Make `malicious.bat` executable.
    4. Inside `malicious-deno-repo`, create a directory named `.vscode`.
    5. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
         "deno.enable": true,
         "deno.path": "malicious.bat"
       }
       ```
    6. Open the `malicious-deno-repo` folder in VSCode.
    7. Observe that a file named `rce.txt` is created in the `malicious-deno-repo` directory after the extension initializes.
    8. Verify the `rce.txt` file contains the word "Vulnerable".

- Vulnerability Name: **Command Injection in Test Code Lens and Test Explorer via `deno.codeLens.testArgs` and `deno.testing.args` settings**
  - Description:
    1. A threat actor creates a malicious repository.
    2. Inside the malicious repository, the threat actor includes a `.vscode/settings.json` file.
    3. In this `settings.json`, the threat actor sets the `deno.codeLens.testArgs` or `deno.testing.args` setting to include malicious command arguments. For example: `"deno.codeLens.testArgs": ["--allow-read", "--allow-write", "; malicious_command"]`.
    4. The repository contains a Deno test file (e.g., `test.ts`).
    5. A victim clones and opens this malicious repository in VSCode with the Deno extension installed.
    6. The victim opens the Deno test file, and the "Run Test" code lens appears, or uses Test Explorer.
    7. When the victim clicks "Run Test" or runs tests via Test Explorer, the Deno extension executes the `deno test` command, incorporating the malicious arguments from `deno.codeLens.testArgs` or `deno.testing.args`.
    8. The malicious command injected through these settings is executed by the Deno CLI.
  - Impact: Command Injection. An attacker can inject arbitrary commands that will be executed when a victim runs tests in a malicious repository.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - None. The extension directly passes the arguments from `deno.codeLens.testArgs` and `deno.testing.args` settings to the `deno test` command.
  - Missing Mitigations:
    - Input validation and sanitization for `deno.codeLens.testArgs` and `deno.testing.args` settings to prevent injection of malicious command arguments.
    - Whitelisting of allowed arguments or characters for these settings.
    - Warning to the user when these settings are configured in workspace settings, especially if they contain suspicious characters or commands.
  - Preconditions:
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious repository containing a crafted `.vscode/settings.json` and a Deno test file.
    - Victim attempts to run a test using the "Run Test" code lens or Test Explorer.
  - Source Code Analysis:
    - File: `client/src/commands.ts`
    ```typescript
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // Vulnerable setting read
        ];
        // ...
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // Command construction
        // ...
        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // Vulnerable args are used here
          env,
        };
        // ...
        const task = tasks.buildDenoTask( // ...
          workspaceFolder,
          denoCommand,
          definition,
          `test "${name}"`,
          args, // Vulnerable args are passed to task execution
          ["$deno-test"],
        );
        // ...
      };
    }
    ```
    - The `test` command handler retrieves arguments from `deno.codeLens.testArgs` setting and `deno.testing.args` setting.
    - These arguments are directly included in the `args` array, which is then used to construct and execute the `deno test` command.

  - Security Test Case:
    1. Create a new directory named `malicious-deno-test-repo`.
    2. Inside `malicious-deno-test-repo`, create a directory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
         "deno.enable": true,
         "deno.codeLens.testArgs": ["--allow-read", "--allow-write", "; echo Vulnerable > rce_test.txt"]
       }
       ```
    4. Inside `malicious-deno-test-repo`, create a file named `test.ts` with the following content:
       ```typescript
       Deno.test("test", () => {
         console.log("Running test");
       });
       ```
    5. Open the `malicious-deno-test-repo` folder in VSCode.
    6. Open `test.ts`. Observe the "Run Test" code lens above `Deno.test`.
    7. Click "Run Test".
    8. After the test execution, verify that a file named `rce_test.txt` is created in the `malicious-deno-test-repo` directory and contains "Vulnerable".
    9. Repeat steps 3-8, but this time set `deno.testing.args` in `settings.json` and run the test via Test Explorer.

- Vulnerability Name: **Command Injection in Tasks defined in `tasks.json`**
  - Description:
    1. A threat actor can create a malicious VSCode workspace and include a `tasks.json` file.
    2. This `tasks.json` file defines a Deno task with a malicious command or arguments that include command injection payloads.
    3. When a victim opens this malicious workspace and navigates to the "Deno Tasks" sidebar, the malicious tasks will be listed.
    4. If the victim executes the malicious task from the sidebar or via command palette, the extension will execute the defined command.
    5. Because the task definition in `tasks.json` is attacker-controlled and contains malicious commands, this allows for arbitrary command execution on the victim's machine when the victim runs the task.
  - Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine if the victim runs a malicious task from the Deno Tasks sidebar or command palette.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations: None. The extension directly executes commands defined in `tasks.json` without sanitization.
  - Missing Mitigations:
    - Input validation for task definitions in `tasks.json`: The extension should validate task definitions, especially the `command` and `args` properties, to prevent command injection.
    - Display warning to user: When tasks from `tasks.json` are loaded, the extension could perform a basic security scan and display a warning to the user if potentially malicious commands or arguments are detected.
  - Preconditions:
    - Victim has VSCode with the Deno extension installed.
    - Victim opens a malicious workspace provided by the attacker containing a malicious `tasks.json` file.
    - Victim executes the malicious task from the Deno Tasks sidebar or using the command palette.
  - Source Code Analysis:
    - File: `client\src\tasks.ts`
    ```typescript
    export function buildDenoTask( ... , definition: DenoTaskDefinition, ...): vscode.Task {
      const exec = new vscode.ProcessExecution(
        process, // deno command path
        args,    // args from DenoTaskDefinition including command and args
        definition,
      );
      return new vscode.Task( ... , exec, ...);
    }
    ```
    - The `buildDenoTask()` function directly uses `definition.command` and `definition.args` from the `DenoTaskDefinition` to create a `ProcessExecution`.
  - Security Test Case:
    1. Create a new VSCode workspace.
    2. Inside the workspace root, create a `.vscode` directory and within it, create a `tasks.json` file with the following content:
        ```json
        {
          "version": "2.0.0",
          "tasks": [
            {
              "type": "deno",
              "command": "run",
              "args": ["-A",  "`; touch /tmp/vscode_deno_rce_tasks_json;`"]
            }
          ]
        }
        ```
    3. Open the Deno Tasks sidebar in VSCode.
    4. Find the task defined in `tasks.json`. Click the "Run Task" icon next to it.
    5. Check if the file `/tmp/vscode_deno_rce_tasks_json` is created.

- Vulnerability Name: **Command Injection via Deno Tasks in `deno.json`/`deno.jsonc`**
  - Description:
    1. A threat actor crafts a malicious repository containing a `deno.json` or `deno.jsonc` file.
    2. Within this configuration file, the threat actor defines a task with a malicious command.
    3. A victim user opens this malicious repository in Visual Studio Code with the "Deno for VSCode" extension enabled.
    4. The extension's Deno Tasks sidebar automatically fetches task definitions from the Deno Language Server, which parses and provides tasks from the `deno.json`/`deno.jsonc` file.
    5. If the victim executes this task from the Deno Tasks sidebar, the `vscode.tasks.executeTask` function in the extension directly executes the command string defined in the malicious task definition.
    6. This results in the execution of the attacker's arbitrary commands within the victim's system shell.
  - Impact: Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary commands on the victim's machine.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - None. The extension currently trusts task definitions provided by the Deno Language Server without additional validation or sanitization on the client side.
  - Missing Mitigations:
    - Input validation and sanitization: The Deno Language Server should sanitize task names and command strings from `deno.json`/`deno.jsonc` before providing them to the extension.
    - User confirmation for task execution: Before executing any task defined in `deno.json`/`deno.jsonc`, the extension should prompt the user for explicit confirmation, especially when working with untrusted repositories.
  - Preconditions:
    1. The victim must have the "Deno for VSCode" extension installed.
    2. The victim must open a workspace containing a malicious `deno.json` or `deno.jsonc` file.
    3. The malicious `deno.json` or `deno.jsonc` file must define at least one task with a command containing malicious shell instructions.
    4. The victim must interact with the Deno Tasks sidebar and explicitly execute the malicious task.
  - Source Code Analysis:
    - File: `client\src\tasks_sidebar.ts`, `DenoTasksTreeDataProvider.provideTasks` method retrieves task definitions by sending a `deno/taskDefinitions` request to the Deno Language Server.
    - File: `client\src\tasks.ts`, `buildDenoConfigTask` function constructs a `vscode.Task` object and uses the `command` property from the task definition directly in the `ProcessExecution`.
    - File: `client\src\tasks_sidebar.ts`, `DenoTasksTreeDataProvider.#runTask` calls `tasks.executeTask(task.task)` to execute the task.
  - Security Test Case:
    1. Create a new directory `malicious-repo`.
    2. Inside `malicious-repo`, create a file named `deno.json` with the following content:
    ```json
    {
      "tasks": {
        "evilTask": "echo 'PWNED' > /tmp/pwned.txt"
      }
    }
    ```
    3. Open VS Code and open the `malicious-repo` folder.
    4. Open the Deno Tasks sidebar.
    5. In the Deno Tasks sidebar, find the task named "evilTask". Click the "Run Task" icon next to "evilTask".
    6. Check for the file `/tmp/pwned.txt`. If the file `pwned.txt` exists and contains the text "PWNED", the command injection vulnerability is confirmed.
