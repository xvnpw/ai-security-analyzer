### Vulnerability List:

*   **Vulnerability Name:** Command Injection via `deno.codeLens.testArgs` and `deno.testing.args` settings in Test Code Lens and Tasks

    *   **Description:**
        1.  A threat actor crafts a malicious repository.
        2.  This repository includes workspace settings (e.g., `.vscode/settings.json`) that modify the `deno.codeLens.testArgs` or `deno.testing.args` settings within the VSCode Deno extension.
        3.  Specifically, the malicious settings inject shell commands into these arguments. For example, setting `deno.codeLens.testArgs` to `["--allow-read", "; $(malicious command)"]`.
        4.  A victim opens this malicious repository in VSCode with the Deno extension enabled.
        5.  When the victim attempts to run a test using the "Run Test" code lens, or executes a Deno task that uses `deno.testing.args`, the injected shell commands are executed due to insufficient sanitization of the `testArgs` or `testing.args` configuration values when constructing the Deno CLI command.

    *   **Impact:**
        Remote Code Execution (RCE). An attacker can execute arbitrary shell commands on the victim's machine with the privileges of the VSCode process by crafting malicious workspace settings. This can lead to complete compromise of the victim's local machine and sensitive data.

    *   **Vulnerability Rank:** critical

    *   **Currently Implemented Mitigations:**
        No specific mitigations are implemented in the code to sanitize or validate the `deno.codeLens.testArgs` and `deno.testing.args` settings. The values are directly passed as arguments to the Deno CLI command in `client/src/commands.ts` within the `test` function and potentially in tasks execution as well (needs further code review in task execution paths).

    *   **Missing Mitigations:**
        *   Input sanitization: The extension should sanitize the `deno.codeLens.testArgs` and `deno.testing.args` settings to prevent command injection. This could involve:
            *   Validating that each argument is safe and does not contain shell metacharacters.
            *   Using parameterized command execution if possible to separate commands from arguments. However, given the current code structure, simple sanitization might be more practical in the short term.

    *   **Preconditions:**
        1.  Victim has VSCode with the "vscode-deno" extension installed and enabled.
        2.  Victim opens a malicious repository in VSCode.
        3.  The malicious repository contains workspace settings that modify `deno.codeLens.testArgs` or `deno.testing.args` to include shell commands.
        4.  Victim attempts to run a Deno test using code lens or execute a Deno task that uses `deno.testing.args`.
        5.  The Deno CLI executable path is correctly configured or available in the system's PATH.

    *   **Source Code Analysis:**
        1.  **File:** `client/src/commands.ts`
        2.  **Function:** `test`
        3.  **Code Snippet:**
            ```typescript
            export function test(
              _context: vscode.ExtensionContext,
              extensionContext: DenoExtensionContext,
            ): Callback {
              return async (uriStr: string, name: string, options: TestCommandOptions) => {
                // ...
                const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
                const testArgs: string[] = [
                  ...(config.get<string[]>("codeLens.testArgs") ?? []),
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
        4.  **Vulnerability Flow:**
            *   The `test` function retrieves configuration settings using `vscode.workspace.getConfiguration(EXTENSION_NS, uri)`.
            *   It gets `deno.codeLens.testArgs` using `config.get<string[]>("codeLens.testArgs")`.
            *   The values from `testArgs` are directly spread into the `args` array: `const args = ["test", ...testArgs, "--filter", nameRegex, filePath];`.
            *   This `args` array is then used to create a `ProcessExecution` object, which executes the Deno CLI command without any sanitization or validation of the arguments.

    *   **Security Test Case:**
        1.  **Setup:**
            *   Create a new, empty VSCode workspace.
            *   Install and enable the "vscode-deno" extension.
            *   Ensure Deno CLI is installed and accessible in your PATH or `deno.path` setting.
        2.  **Malicious Repository Creation:**
            *   Create a new directory named `malicious-repo`.
            *   Inside `malicious-repo`, create a subdirectory named `.vscode`.
            *   Inside `.vscode`, create a file named `settings.json` with the following content:
                ```json
                {
                    "deno.enable": true,
                    "deno.codeLens.testArgs": [
                        "--allow-read",
                        "; touch /tmp/pwned ; #"
                    ]
                }
                ```
                *(Note: The `; touch /tmp/pwned ; #` is the command injection payload. `touch /tmp/pwned` will create an empty file named `pwned` in the `/tmp` directory on Linux/macOS. For Windows, you could use `"; type nul > %TEMP%\\pwned.txt & rem "`)*
            *   Create a file named `test.ts` in `malicious-repo` with simple test:
                ```typescript
                Deno.test("vulnerable test", () => {
                  console.log("Test running");
                });
                ```
        3.  **Victim Actions:**
            *   Open the `malicious-repo` directory as a workspace in VSCode.
            *   Wait for the Deno extension to activate.
            *   Open the `test.ts` file.
            *   Observe the "▶ Run Test" code lens above the `Deno.test` declaration.
            *   Click on "▶ Run Test".
        4.  **Verification:**
            *   After running the test, check if the file `/tmp/pwned` (or `%TEMP%\\pwned.txt` on Windows) exists.
            *   If the file exists, it confirms that the injected command `touch /tmp/pwned` (or equivalent) was executed, demonstrating command injection vulnerability.
