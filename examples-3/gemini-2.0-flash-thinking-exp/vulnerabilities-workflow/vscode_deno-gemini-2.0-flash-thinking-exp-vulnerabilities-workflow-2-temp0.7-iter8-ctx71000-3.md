- Vulnerability Name: Arbitrary Code Execution via Malicious Deno Path Configuration
- Description:
    1. An attacker could socially engineer a user to modify the `deno.path` setting in VS Code.
    2. The attacker would provide a path to a malicious executable, disguised as the legitimate Deno CLI.
    3. The user, believing they are configuring the Deno extension, sets `deno.path` to this malicious executable.
    4. When the VS Code Deno extension attempts to execute any Deno command (e.g., for caching, testing, linting, formatting, or language server operations), it will inadvertently run the attacker's malicious executable.
    5. This results in arbitrary code execution on the user's machine with the privileges of the VS Code process.
- Impact:
    - Critical: Successful exploitation allows the attacker to execute arbitrary code on the user's machine. This could lead to complete system compromise, including data theft, malware installation, and further malicious activities.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - The extension relies on the user to configure `deno.path` correctly. There is no input validation or sanitization on the `deno.path` setting within the extension's code.
    - The README.md provides a warning about the `deno.path` setting:
      ```
      > ⚠️ **Important:** You need to have a version of Deno CLI installed (v1.13.0 or
      > later). The extension requires the executable and by default will use the
      > environment path. You can explicitly set the path to the executable in Visual
      > Studio Code Settings for `deno.path`.
      ```
      However, this is just documentation and not a technical mitigation.
- Missing Mitigations:
    - Input validation for the `deno.path` setting. The extension should verify if the provided path points to a valid and expected executable (e.g., by checking file type, digital signature, or known safe locations).
    - Display a warning message to the user when `deno.path` is explicitly configured, emphasizing the security risks and recommending using the environment path instead.
    - Consider restricting the execution of Deno commands to a sandboxed environment, although this might be complex to implement within a VS Code extension.
- Preconditions:
    - The user must have the VS Code Deno extension installed.
    - The attacker must be able to convince the user to change the `deno.path` setting and provide a malicious executable path. This could be achieved through phishing, social engineering, or by compromising a system the user trusts and pre-configuring the malicious path.
- Source Code Analysis:
    1. `client\src\util.ts`: The `getDenoCommandPath()` function is responsible for resolving the Deno executable path.
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
    - `getWorkspaceConfigDenoExePath()` retrieves the `deno.path` setting directly from VS Code configuration without any validation.
    - `getDenoCommandPath()` prioritizes the configured path if it exists.
    - If `deno.path` is set to a malicious executable, `getDenoCommandPath()` will return the path to the malicious executable.

    2. `client\src\commands.ts`: The `startLanguageServer()` function uses `getDenoCommandPath()` to get the command and then executes it.
    ```typescript
    export function startLanguageServer(
      context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async () => {
        // ...
        const command = await getDenoCommandPath(); // Vulnerable point: Retrieves deno path without validation

        if (command == null) {
          // ... error handling ...
          return;
        }

        const serverOptions: ServerOptions = {
          run: {
            command, // Malicious command from deno.path will be used here
            args: ["lsp"],
            options: { env },
          },
          debug: {
            command, // Malicious command from deno.path will be used here
            args: ["lsp"],
            options: { env },
          },
        };
        const client = new LanguageClient( // ... creates language client with malicious command ...
          LANGUAGE_CLIENT_ID,
          LANGUAGE_CLIENT_NAME,
          serverOptions,
          {
            outputChannel: extensionContext.outputChannel,
            middleware: {
              // ... middleware ...
            },
            ...extensionContext.clientOptions,
          },
        );
        // ... client start ...
      };
    }
    ```
    - `startLanguageServer` directly uses the `command` obtained from `getDenoCommandPath()` in `serverOptions.run.command` and `serverOptions.debug.command`.
    - The `LanguageClient` then executes this command, leading to the execution of the malicious executable if `deno.path` is compromised.

    3. Other commands like `test` in `client\src\commands.ts` and tasks execution in `client\src\tasks.ts` also use `getDenoCommandName()` or `getDenoCommandPath()` to execute Deno commands, making them vulnerable as well.

- Security Test Case:
    1. **Preparation:**
        - Create a malicious executable file (e.g., `malicious-deno.sh` on Linux/macOS or `malicious-deno.bat` on Windows). This script should perform some identifiable action, like creating a file in the user's temporary directory (`/tmp/pwned.txt` on Linux/macOS or `%TEMP%\pwned.txt` on Windows) and logging "Malicious Deno Executed!" to the console.
        - Example `malicious-deno.sh`:
          ```bash
          #!/bin/bash
          echo "Malicious Deno Executed!"
          touch /tmp/pwned.txt
          ```
        - Example `malicious-deno.bat`:
          ```batch
          @echo off
          echo Malicious Deno Executed!
          type nul > %TEMP%\pwned.txt
          ```
        - Make the script executable (`chmod +x malicious-deno.sh`).
        - Place the malicious executable in a known location on your test machine (e.g., `/tmp/malicious-deno` or `C:\temp\malicious-deno.bat`).

    2. **VS Code Configuration:**
        - Open VS Code.
        - Open User Settings (or Workspace Settings).
        - Search for `deno.path`.
        - Set `deno.path` to the path of your malicious executable (e.g., `/tmp/malicious-deno` or `C:\temp\malicious-deno.bat`).

    3. **Trigger Extension Action:**
        - Open a JavaScript or TypeScript file in VS Code.
        - Ensure the Deno extension is enabled for the workspace. If not, run the "Deno: Enable" command.
        - Trigger any Deno extension feature that executes a Deno command. For example:
            - Run the "Deno: Cache" command.
            - Open a TypeScript file and wait for the language server to start.
            - Run a Deno test using the "Run Test" code lens (if tests are present).

    4. **Verification:**
        - Check if the malicious executable was executed:
            - Verify if the file `/tmp/pwned.txt` (or `%TEMP%\pwned.txt` on Windows) was created.
            - Observe the Output panel of VS Code, and check if "Malicious Deno Executed!" was logged (though output might be suppressed by the extension's execution context).
        - If the file is created, it confirms that the malicious executable was run when the Deno extension tried to invoke Deno, demonstrating arbitrary code execution.
