### Vulnerability List

* **Vulnerability Name:** Command Injection in Test Code Lens and Test Task Arguments

* **Description:**
    1. The VSCode Deno extension allows users to configure arguments for the `deno test` command through the `deno.codeLens.testArgs` and `deno.testing.args` settings.
    2. These settings are directly used to construct the command line arguments for the `deno test` command executed by the extension when running tests via code lens or tasks.
    3. A malicious user can craft a repository with a `.vscode/settings.json` file that sets `deno.codeLens.testArgs` or `deno.testing.args` to include malicious commands.
    4. When a victim opens this malicious repository in VSCode with the Deno extension enabled and attempts to run tests using the "Run Test" code lens or via tasks, the malicious commands injected through `deno.codeLens.testArgs` or `deno.testing.args` will be executed by the system.

* **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine by injecting malicious commands into the `deno.codeLens.testArgs` or `deno.testing.args` settings.

* **Vulnerability Rank:** high

* **Currently Implemented Mitigations:**
    None. The code directly uses the values from `deno.codeLens.testArgs` and `deno.testing.args` without any sanitization or validation.

* **Missing Mitigations:**
    Input sanitization or validation for `deno.codeLens.testArgs` and `deno.testing.args`. The extension should either:
        - Sanitize the arguments to remove or escape shell-sensitive characters.
        - Warn users about the security risks of modifying these settings, especially when opening repositories from untrusted sources.
        - Ideally, avoid directly passing user-provided strings as command line arguments to shell commands. Consider using an array format for arguments and let `vscode.ProcessExecution` handle argument escaping.

* **Preconditions:**
    1. Victim has VSCode installed with the "Deno for VSCode" extension enabled.
    2. Victim opens a malicious repository that includes a `.vscode/settings.json` file with malicious commands in `deno.codeLens.testArgs` or `deno.testing.args`.
    3. Victim attempts to run tests using the "Run Test" code lens or via tasks.

* **Source Code Analysis:**
    1. `client/src/commands.ts`:
        - In the `test` function, configuration values for `deno.codeLens.testArgs` are retrieved:
          ```typescript
          const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []),
          ];
          ```
        - These `testArgs` are directly used in constructing the `args` array passed to `buildDenoTask`.
    2. `client/src/tasks.ts`:
        - In `buildDenoTask` function, `vscode.ProcessExecution` is used with user-controlled arguments:
          ```typescript
          const exec = new vscode.ProcessExecution(
            process,
            args,
            definition,
          );
          ```

* **Security Test Case:**
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a file named `.vscode/settings.json` with the following content:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-read",
               "--allow-write",
               "--allow-net",
               "--allow-run",
               "--allow-env",
               "--allow-hrtime",
               "--allow-ffi",
               "--unstable",
               "; touch /tmp/pwned ; #"
           ]
       }
       ```
       (This command injection attempts to create a file `/tmp/pwned` on Linux/macOS. For Windows, a similar command like `cmd /c type nul > %TEMP%\pwned.txt` could be used.)
    3. Inside `malicious-repo`, create a file named `test.ts` with the following content:
       ```typescript
       Deno.test("vulnerable test", () => {
         console.log("Running test");
       });
       ```
    4. Open VSCode and open the `malicious-repo` directory. Ensure the Deno extension is enabled for this workspace.
    5. Open `test.ts`. You should see the "Run Test" code lens above `Deno.test`.
    6. Click on "Run Test".
    7. After the test execution finishes, check if the file `/tmp/pwned` (or `%TEMP%\pwned.txt` on Windows) was created. If it was, the command injection is successful.

* **Vulnerability Name:** Command Injection via `deno.path` setting

* **Description:**
    1. A threat actor creates a malicious repository.
    2. Inside the malicious repository, the threat actor crafts a `.vscode/settings.json` file.
    3. In the `settings.json`, the threat actor sets the `deno.path` setting to a malicious executable path. For example: `"deno.path": "/path/to/malicious.sh"`. This path could point to a script within the malicious repository itself (e.g., `./malicious.sh`) or an absolute path if the attacker knows a predictable location on the victim's system.
    4. The victim clones the malicious repository and opens it in VSCode.
    5. If the victim has the vscode-deno extension installed and activated for the workspace, the extension attempts to execute the Deno CLI using the path specified in `deno.path`.
    6. Instead of executing the legitimate Deno CLI, the extension executes the malicious script provided by the attacker.
    7. The malicious script executes arbitrary commands on the victim's machine with the privileges of the VSCode process.

* **Impact:**
    Remote Code Execution (RCE). The threat actor can execute arbitrary commands on the victim's machine, potentially leading to data theft, malware installation, or full system compromise.

* **Vulnerability Rank:** Critical

* **Currently Implemented Mitigations:**
    None. The extension directly uses the path provided in the `deno.path` setting without any validation or sanitization.

* **Missing Mitigations:**
    - Input validation and sanitization for the `deno.path` setting. The extension should verify that the path is reasonable and does not contain malicious characters or patterns.
    - Path traversal prevention. Ensure that the resolved path stays within expected boundaries and does not allow escaping to arbitrary file system locations.
    - Check if the executable is actually a Deno executable.
    - Consider using a safer mechanism to configure the Deno CLI path, or restrict the setting to only accept paths to known safe locations.

* **Preconditions:**
    - Victim has vscode-deno extension installed and enabled for the workspace.
    - Victim opens a malicious repository in VSCode.
    - Malicious repository contains a `.vscode/settings.json` file with a malicious `deno.path` setting.

* **Source Code Analysis:**
    1. **File: `client/src/util.ts`**
        - Function `getDenoCommandPath()` retrieves the `deno.path` setting from VSCode configuration:
        ```typescript
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
        - This function directly retrieves the string value of the `deno.path` setting without any validation.
        - This path is then used to execute the Deno CLI in various parts of the extension.

    2. **File: `client/src/commands.ts`**
        - Function `startLanguageServer()` calls `getDenoCommandPath()` to get the Deno executable path:
        ```typescript
        const command = await getDenoCommandPath();
        if (command == null) {
          // ... error handling ...
          return;
        }
        // ...
        const serverOptions: ServerOptions = {
          run: {
            command, // <= Malicious path is used here
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // <= Malicious path is used here
            args: ["lsp"],
            options: { env },
          },
        };
        const client = new LanguageClient( ... );
        await client.start();
        ```
        - The `command` variable, which can be controlled by the malicious `deno.path` setting, is directly used as the `command` in `ServerOptions`, leading to command execution.

    3. **File: `client/src/tasks.ts`**
        - Function `buildDenoTask()` uses the provided `process` (which is the Deno command path) to create a `ProcessExecution`:
        ```typescript
        export function buildDenoTask(
          target: vscode.WorkspaceFolder,
          process: string, // <= Malicious path can be passed here
          definition: DenoTaskDefinition,
          name: string,
          args: string[],
          problemMatchers: string[],
        ): vscode.Task {
          const exec = new vscode.ProcessExecution(
            process, // <= Malicious path is used here
            args,
            definition,
          );
          // ...
        }
        ```
        - This function is called in `DenoTaskProvider.provideTasks()` and `DenoTaskProvider.resolveTask()` with `process` obtained from `getDenoCommandName()`.

    4. **File: `client/src/debug_config_provider.ts`**
        - Function `provideDebugConfigurations()` and `resolveDebugConfiguration()` use `getDenoCommandName()` to get the Deno executable path and use it in debug configurations:
        ```typescript
        async provideDebugConfigurations(): Promise<vscode.DebugConfiguration[]> {
          // ...
          const debugConfig: vscode.DebugConfiguration = {
            // ...
            runtimeExecutable: await getDenoCommandName(), // <= Malicious path is used here
            // ...
          };
          return [debugConfig];
        }
        ```

    5. **File: `client/src/upgrade.ts`**
        - Function `denoUpgradePromptAndExecute()` also uses `getDenoCommandName()` and `buildDenoTask()`:
        ```typescript
        assert(workspaceFolder);
        const denoCommand = await getDenoCommandName(); // <= Malicious path is used here
        const task = tasks.buildDenoTask(
          workspaceFolder,
          denoCommand, // <= Malicious path is used here
          definition,
          "upgrade",
          args,
          ["$deno"],
        );
        ```

    **Visualization:**

    ```
    User opens malicious repository -> .vscode/settings.json with malicious deno.path -> VSCode Deno extension reads deno.path -> extension calls getDenoCommandPath() -> returns malicious path -> malicious path used in ProcessExecution/LanguageClient -> Command Injection -> RCE
    ```

* **Security Test Case:**
    1. Create a new directory named `vscode_deno_test_repo`.
    2. Inside `vscode_deno_test_repo`, create a file named `.vscode/settings.json` with the following content:
        ```json
        {
            "deno.path": "./malicious.sh"
        }
        ```
    3. In `vscode_deno_test_repo`, create a file named `malicious.sh` with the following content:
        ```bash
        #!/bin/bash
        echo "Malicious script executed!" > malicious_output.txt
        echo "Vulnerable"
        ```
    4. Make `malicious.sh` executable: `chmod +x malicious.sh`.
    5. Open the `vscode_deno_test_repo` directory in VSCode. Ensure the vscode-deno extension is enabled for this workspace (you might need to run "Deno: Enable" command if not enabled by default).
    6. Open any JavaScript or TypeScript file in the workspace to trigger the extension's language server startup or execute any Deno command via the extension (e.g., "Deno: Cache").
    7. Check if a file named `malicious_output.txt` is created in the `vscode_deno_test_repo` directory. If the file exists and contains "Malicious script executed!", it confirms that the malicious script was executed due to the `deno.path` setting.
    8. Additionally, observe the output in the VSCode Output panel for "Deno Language Server". If "Vulnerable" is printed there, it further confirms the execution of the malicious script.
