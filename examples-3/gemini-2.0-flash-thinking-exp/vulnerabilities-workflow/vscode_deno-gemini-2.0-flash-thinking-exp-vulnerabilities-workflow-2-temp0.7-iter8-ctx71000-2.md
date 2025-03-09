## Vulnerability List for VSCode Deno Extension

### Vulnerability 1: Command Injection via `deno.path` setting

*   **Vulnerability Name:** Command Injection in `deno.path` setting
*   **Description:**
    1.  An attacker crafts a malicious Deno project.
    2.  The malicious project includes a `.vscode/settings.json` file that sets the `deno.path` setting to a malicious executable path. For example, they could include backticks or command separators in the path.
    3.  When a developer opens this malicious project in VSCode with the Deno extension enabled, the extension attempts to resolve the Deno executable using the provided `deno.path`.
    4.  If the `deno.path` is not properly sanitized, the attacker can inject arbitrary commands that will be executed by the system when the extension tries to spawn the Deno Language Server or run Deno commands.
*   **Impact:** Arbitrary code execution on the developer's machine with the privileges of the VSCode process.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:** None observed in the provided code. The extension retrieves the `deno.path` setting and directly uses it to execute commands.
*   **Missing Mitigations:**
    *   Input sanitization of the `deno.path` setting. The extension should validate and sanitize the `deno.path` setting to prevent command injection. This could involve:
        *   Whitelisting allowed characters in the path.
        *   Using parameterized command execution if possible.
        *   Validating that the path points to an actual executable file.
    *   Display a warning to the user if `deno.path` is modified in workspace settings and requires extra attention.
*   **Preconditions:**
    1.  The attacker needs to create a malicious Deno project and convince a developer to open it in VSCode with the Deno extension enabled.
    2.  The developer must have the Deno extension enabled and allow workspace settings.
*   **Source Code Analysis:**
    1.  **File: `client/src/util.ts`:**
        *   The `getDenoCommandPath` function retrieves the `deno.path` setting from workspace configuration using `getWorkspaceConfigDenoExePath()`.
        *   It checks if the path is absolute and attempts to resolve relative paths against workspace folders.
        *   If the configured path is not absolute or resolvable within workspace, it falls back to `getDefaultDenoCommand()`.
    2.  **File: `client/src/commands.ts`:**
        *   The `startLanguageServer` function calls `getDenoCommandPath()` to obtain the Deno executable path.
        *   This path is then directly used in `serverOptions` to spawn the Language Server process:
            ```typescript
            const serverOptions: ServerOptions = {
              run: {
                command, // path from getDenoCommandPath()
                args: ["lsp"],
                options: { env },
              },
              debug: {
                command, // path from getDenoCommandPath()
                args: ["lsp"],
                options: { env },
              },
            };
            ```
        *   There is no sanitization or validation of the `command` variable before it's used in `LanguageClient`.

    **Visualization:**

    ```
    User Setting (deno.path) --> getWorkspaceConfigDenoExePath() --> getDenoCommandPath() --> command (in serverOptions) --> LanguageClient (process spawn) --> System Command Execution
    ```

*   **Security Test Case:**
    1.  Create a new directory named `malicious-deno-project`.
    2.  Inside `malicious-deno-project`, create a `.vscode` directory.
    3.  Inside `.vscode`, create a `settings.json` file with the following content:
        ```json
        {
            "deno.path": "`touch malicious.txt` & deno"
        }
        ```
        This malicious `deno.path` attempts to create a file named `malicious.txt` and then execute the legitimate `deno` command.
    4.  Open VSCode and open the `malicious-deno-project` folder.
    5.  Ensure the Deno extension is enabled for this workspace (you might need to run "Deno: Enable").
    6.  Observe if a file named `malicious.txt` is created in the `malicious-deno-project` directory.
    7.  If `malicious.txt` is created, it confirms that the command injection vulnerability exists.

### Vulnerability 2: Command Injection in Test Code Lens via `deno.codeLens.testArgs` and `deno.testing.args` settings

*   **Vulnerability Name:** Command Injection in Test Code Lens Arguments
*   **Description:**
    1.  An attacker crafts a malicious Deno project.
    2.  The malicious project includes a `.vscode/settings.json` file that sets the `deno.codeLens.testArgs` or `deno.testing.args` settings to include malicious commands. For example, they could inject arguments like `--allow-read /etc & touch malicious.txt`.
    3.  When a developer opens this malicious project in VSCode with the Deno extension enabled and clicks on a "Run Test" code lens, the extension executes the Deno test command using the provided arguments from `deno.codeLens.testArgs` or `deno.testing.args`.
    4.  If these settings are not properly sanitized, the attacker can inject arbitrary Deno CLI arguments, potentially leading to command injection or unintended file system access if `--allow-read`, `--allow-write`, etc., are misused.
*   **Impact:** Arbitrary code execution or unauthorized file system access on the developer's machine, depending on the injected arguments.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:** None observed in the provided code. The extension directly uses the values from `deno.codeLens.testArgs` and `deno.testing.args` settings.
*   **Missing Mitigations:**
    *   Input sanitization of the `deno.codeLens.testArgs` and `deno.testing.args` settings. The extension should validate and sanitize these settings to prevent command injection. This could involve:
        *   Whitelisting allowed Deno CLI arguments.
        *   Blacklisting dangerous arguments like `--allow-write`, `--allow-read` without specific paths (though this might limit legitimate use cases).
        *   Displaying a warning to the user if these settings are modified in workspace settings and require extra attention.
*   **Preconditions:**
    1.  The attacker needs to create a malicious Deno project and convince a developer to open it in VSCode with the Deno extension enabled.
    2.  The developer must have the Deno extension enabled and allow workspace settings.
    3.  The developer must click on the "Run Test" code lens in the malicious project.
*   **Source Code Analysis:**
    1.  **File: `client/src/commands.ts`:**
        *   The `test` function is responsible for handling test execution via code lens.
        *   It retrieves `deno.codeLens.testArgs` from workspace configuration:
            ```typescript
            const testArgs: string[] = [
              ...(config.get<string[]>("codeLens.testArgs") ?? []),
            ];
            ```
        *   It also retrieves `deno.testing.args` (though this seems to be deprecated as per `CHANGELOG.md` - `feat: remove dead "deno.testing.enable" setting (#912)` but still present in `extension.ts` as `deno.testing.args` config).
        *   These `testArgs` are directly passed to the `buildDenoTask` function, which then uses them to construct the command for `ProcessExecution`.
        *   There's no validation or sanitization of `testArgs` before command execution.

    **Visualization:**

    ```
    User Setting (deno.codeLens.testArgs / deno.testing.args) --> config.get() --> testArgs --> buildDenoTask() --> ProcessExecution (command with args) --> System Command Execution
    ```

*   **Security Test Case:**
    1.  Create a new directory named `malicious-deno-project-test`.
    2.  Inside `malicious-deno-project-test`, create a `.vscode` directory.
    3.  Inside `.vscode`, create a `settings.json` file with the following content:
        ```json
        {
            "deno.codeLens.testArgs": ["--allow-read", "/etc", "& touch malicious_test.txt"]
        }
        ```
        This malicious `deno.codeLens.testArgs` attempts to allow read access to `/etc` (potentially dangerous) and create a file named `malicious_test.txt`.
    4.  Inside `malicious-deno-project-test`, create a file named `test.ts` with a simple test:
        ```typescript
        Deno.test("simple test", () => {
          console.log("Test running");
        });
        ```
    5.  Open VSCode and open the `malicious-deno-project-test` folder.
    6.  Ensure the Deno extension is enabled.
    7.  Open `test.ts` and click on the "Run Test" code lens above `Deno.test`.
    8.  Observe if a file named `malicious_test.txt` is created in the `malicious-deno-project-test` directory.
    9.  If `malicious_test.txt` is created, and depending on OS, if read access to `/etc` is granted (or an error is shown indicating attempt), it confirms that the command injection vulnerability exists in test code lens arguments.
