### Vulnerability List:

#### 1. Command Injection via Malicious `deno.path` Setting

* Description:
    1. A threat actor crafts a malicious repository containing a `.vscode/settings.json` file.
    2. This `settings.json` file sets the `deno.path` setting to a malicious executable path. For example, `/tmp/malicious_deno`.
    3. The victim clones this repository and opens it in VSCode with the Deno extension installed.
    4. The Deno extension reads the workspace settings, including the malicious `deno.path`.
    5. When the extension tries to start the Deno Language Server (LSP), it uses the provided `deno.path` to execute the Deno CLI.
    6. If the malicious path points to an attacker-controlled executable, arbitrary code will be executed on the victim's machine with the privileges of the VSCode process.

* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - None. The extension directly uses the `deno.path` setting to execute the Deno CLI without any sanitization or validation.

* Missing Mitigations:
    - Input sanitization and validation for the `deno.path` setting.
    - Restricting the `deno.path` setting to only allow paths to known Deno executables or locations.
    - Displaying a warning message to the user when `deno.path` is changed, especially when set by workspace settings.

* Preconditions:
    - Victim must have the VSCode Deno extension installed.
    - Victim must open a malicious repository in VSCode.
    - The malicious repository must contain a `.vscode/settings.json` that sets a malicious `deno.path`.

* Source Code Analysis:
    - File: `client\src\commands.ts`
    - Function: `startLanguageServer`
    - Code Snippet:
      ```typescript
      const command = await getDenoCommandPath();
      if (command == null) {
          // ... error handling ...
          return;
      }
      const serverOptions: ServerOptions = {
        run: {
          command, // Unsanitized command from getDenoCommandPath()
          args: ["lsp"],
          options: { env },
        },
        debug: {
          command, // Unsanitized command from getDenoCommandPath()
          args: ["lsp"],
          options: { env },
        },
      };
      const client = new LanguageClient( ... );
      await client.start();
      ```
    - The `getDenoCommandPath()` function retrieves the path from the `deno.path` setting without any validation.
    - File: `client\src\util.ts`
    - Function: `getDenoCommandPath`
    - Code Snippet:
      ```typescript
      function getWorkspaceConfigDenoExePath() {
        const exePath = workspace.getConfiguration(EXTENSION_NS)
          .get<string>("path"); // Retrieving deno.path setting
        // ...
        return exePath;
      }

      export async function getDenoCommandPath() {
        const command = getWorkspaceConfigDenoExePath(); // Unsanitized value
        // ...
        return command ?? await getDefaultDenoCommand();
      }
      ```
    - The code directly retrieves the `deno.path` setting and uses it as the command to execute without any checks.

* Security Test Case:
    1. Create a malicious executable file (e.g., `malicious_deno.sh` on Linux/macOS, `malicious_deno.bat` on Windows) in `/tmp/malicious_deno` (or `C:\temp\malicious_deno.bat` on Windows).
    2. Make the malicious executable print a message and then act as a normal `deno` command (or just exit).
       - `malicious_deno.sh` (Linux/macOS):
         ```sh
         #!/bin/bash
         echo "[VULNERABILITY-DEMO] Malicious Deno Executable executed!"
         /usr/bin/env deno lsp "$@" # Assuming deno is in /usr/bin/env path, replace if needed
         ```
       - `malicious_deno.bat` (Windows):
         ```bat
         @echo off
         echo [VULNERABILITY-DEMO] Malicious Deno Executable executed!
         deno lsp %* # Assuming deno is in PATH
         ```
    3. Create a malicious repository with a `.vscode/settings.json` file containing:
       ```json
       {
           "deno.path": "/tmp/malicious_deno" // or "C:\\temp\\malicious_deno.bat" on Windows
       }
       ```
    4. Open this repository in VSCode with the Deno extension enabled.
    5. Observe the output. The "[VULNERABILITY-DEMO] Malicious Deno Executable executed!" message should be visible in the terminal or output panel, indicating that the malicious executable was run.
    6. To further confirm RCE, modify the malicious script to execute a more harmful command, like creating a file or opening a reverse shell, and observe the outcome.

---
#### 2. Command Injection via Malicious `deno.codeLens.testArgs` Setting

* Description:
    1. A threat actor crafts a malicious repository containing a `.vscode/settings.json` file.
    2. This `settings.json` file sets the `deno.codeLens.testArgs` setting to include malicious command arguments. For example, `["--allow-read", "--", "$(touch /tmp/pwned)"]`.
    3. The victim clones this repository and opens it in VSCode with the Deno extension installed.
    4. The Deno extension reads the workspace settings, including the malicious `deno.codeLens.testArgs`.
    5. When the victim uses the "Run Test" code lens, the extension executes the `deno test` command using the provided `deno.codeLens.testArgs` without sanitization.
    6. If the malicious `deno.codeLens.testArgs` contains command injection payloads, arbitrary code will be executed on the victim's machine when the test code lens is activated.

* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - None. The extension directly uses the `deno.codeLens.testArgs` setting to construct the `deno test` command without any sanitization or validation.

* Missing Mitigations:
    - Input sanitization and validation for the `deno.codeLens.testArgs` setting.
    - Restricting allowed arguments for `deno.codeLens.testArgs` to a safe subset.
    - Displaying a warning message to the user when `deno.codeLens.testArgs` is changed, especially when set by workspace settings.

* Preconditions:
    - Victim must have the VSCode Deno extension installed.
    - Victim must open a malicious repository in VSCode.
    - The malicious repository must contain a `.vscode/settings.json` that sets malicious `deno.codeLens.testArgs`.
    - Victim must click on the "Run Test" code lens in a Deno test file.

* Source Code Analysis:
    - File: `client\src\commands.ts`
    - Function: `test`
    - Code Snippet:
      ```typescript
      export function test( ... ): Callback {
        return async (uriStr: string, name: string, options: TestCommandOptions) => {
          // ...
          const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
          const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []), // Unsanitized testArgs
          ];
          // ...
          const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
          // ...
          const definition: tasks.DenoTaskDefinition = {
            type: tasks.TASK_TYPE,
            command: "test",
            args, // Args contains unsanitized testArgs
            env,
          };
          // ...
          const task = tasks.buildDenoTask( ... , definition, ... );
          await vscode.tasks.executeTask(task);
          // ...
        };
      }
      ```
    - The `codeLens.testArgs` are retrieved directly from the configuration and included in the `deno test` command arguments without sanitization.

* Security Test Case:
    1. Create a malicious repository with a `.vscode/settings.json` file containing:
       ```json
       {
           "deno.codeLens.testArgs": ["--allow-read", "--", "`touch /tmp/pwned_test_args`"] // or "`New-Item -ItemType file -Path C:\\temp\\pwned_test_args`" on Windows PowerShell
       }
       ```
    2. Create a Deno test file (e.g., `test.ts`) in the repository:
       ```typescript
       Deno.test("test example", () => {
           console.log("Running test");
       });
       ```
    3. Open this repository in VSCode with the Deno extension enabled.
    4. Open the `test.ts` file and click on the "▶ Run Test" code lens above the `Deno.test` definition.
    5. After the test execution, check if the file `/tmp/pwned_test_args` (or `C:\temp\pwned_test_args` on Windows) has been created. If it exists, it indicates successful command injection via `deno.codeLens.testArgs`.
