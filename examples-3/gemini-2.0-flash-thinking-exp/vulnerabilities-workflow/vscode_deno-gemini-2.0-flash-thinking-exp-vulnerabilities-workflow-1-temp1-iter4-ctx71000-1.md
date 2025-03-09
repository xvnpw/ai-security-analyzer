### Vulnerability List

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
    - The `getDenoCommandPath` function in `client/src/util.ts` retrieves the `deno.path` setting from the workspace configuration using `getWorkspaceConfigDenoExePath`.
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
    - In `startLanguageServer` function in `client/src/commands.ts`, the `command` variable, which is obtained from `getDenoCommandPath`, is directly used in `ServerOptions` for `run` and `debug` configurations of `LanguageClient`.
    - The `LanguageClient` then uses this `command` to spawn a process, leading to the execution of the potentially malicious script provided in `deno.path`.

  - Security Test Case:
    1. Create a new directory named `malicious-deno-repo`.
    2. Inside `malicious-deno-repo`, create a file named `malicious.bat` (or `malicious.sh` for Linux/macOS) with the following content:
       ```bat
       @echo off
       echo Vulnerable > rce.txt
       ```
       (For `.sh`):
       ```sh
       #!/bin/bash
       echo Vulnerable > rce.txt
       ```
    3. Make `malicious.bat` (or `malicious.sh`) executable if needed (e.g., `chmod +x malicious.sh`).
    4. Inside `malicious-deno-repo`, create a directory named `.vscode`.
    5. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
         "deno.enable": true,
         "deno.path": "malicious.bat"
       }
       ```
       (For `.sh` on Linux/macOS, use `"deno.path": "./malicious.sh"`).
    6. Open the `malicious-deno-repo` folder in VSCode.
    7. Observe that a file named `rce.txt` is created in the `malicious-deno-repo` directory after the extension initializes (or restarts).
    8. Verify the `rce.txt` file contains the word "Vulnerable", confirming that the malicious script was executed.
- Vulnerability Name: **Command Injection in Test Code Lens via `deno.codeLens.testArgs` and `deno.testing.args` settings**
  - Description:
    1. A threat actor creates a malicious repository.
    2. Inside the malicious repository, the threat actor includes a `.vscode/settings.json` file.
    3. In this `settings.json`, the threat actor sets the `deno.codeLens.testArgs` or `deno.testing.args` setting to include malicious command arguments. For example: `"deno.codeLens.testArgs": ["--allow-read", "--allow-write", "; malicious_command"]`.
    4. The repository contains a Deno test file (e.g., `test.ts`).
    5. A victim clones and opens this malicious repository in VSCode with the Deno extension installed.
    6. The victim opens the Deno test file, and the "Run Test" code lens appears.
    7. When the victim clicks "Run Test", the Deno extension executes the `deno test` command, incorporating the malicious arguments from `deno.codeLens.testArgs` or `deno.testing.args`.
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
    - Victim attempts to run a test using the "Run Test" code lens.
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
    - The `test` command handler in `client/src/commands.ts` retrieves arguments from `deno.codeLens.testArgs` setting using `config.get<string[]>("codeLens.testArgs")`.
    - These arguments are directly included in the `args` array, which is then used to construct and execute the `deno test` command.
    - Similarly, `deno.testing.args` is used for tests run via the Test Explorer.

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
    8. After the test execution completes, verify that a file named `rce_test.txt` is created in the `malicious-deno-test-repo` directory and contains "Vulnerable". This confirms command injection via `deno.codeLens.testArgs`.
    9. Repeat steps 3-8, but this time set `deno.testing.args` in `settings.json` and run the test via Test Explorer to confirm command injection via `deno.testing.args`.
