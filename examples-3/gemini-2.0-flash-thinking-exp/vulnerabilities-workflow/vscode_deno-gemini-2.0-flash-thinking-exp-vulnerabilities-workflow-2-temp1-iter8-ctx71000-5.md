### Vulnerability List

- Vulnerability Name: Command Injection in `deno.codeLens.testArgs` Setting
- Description:
    1. An attacker crafts a malicious workspace configuration file (`.vscode/settings.json`).
    2. In this configuration file, the attacker sets the `deno.codeLens.testArgs` setting to include arbitrary shell commands, for example, `["--allow-all", "; malicious_command;"]`.
    3. The victim opens the malicious workspace in Visual Studio Code with the Deno extension installed and enabled.
    4. The victim opens a test file (e.g., a TypeScript file containing `Deno.test` calls).
    5. The victim triggers the test runner by clicking the "Run Test" code lens above a test definition or using the Test Explorer.
    6. The Deno extension executes the `deno test` command, incorporating the arguments from the `deno.codeLens.testArgs` setting.
    7. Due to the lack of sanitization, the malicious commands injected by the attacker in `deno.codeLens.testArgs` are executed by the user's shell, leading to command injection.
- Impact:
    - Remote Code Execution (RCE): An attacker can execute arbitrary code on the user's machine with the permissions of the VS Code process.
    - Data Theft: The attacker could potentially steal sensitive data from the user's file system.
    - System Compromise: In severe scenarios, the attacker might be able to compromise the user's entire system depending on the injected commands and user permissions.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - None. The extension directly reads and uses the `deno.codeLens.testArgs` setting without any sanitization or validation.
- Missing Mitigations:
    - Input Sanitization and Validation: Implement validation for the `deno.codeLens.testArgs` setting to ensure it only contains legitimate arguments for the `deno test` command. Reject or sanitize any input that includes shell command separators (like `;`, `&`, `&&`, `||`, `|`, etc.) or other potentially dangerous characters.
    - Command Argument Escaping: Properly escape all arguments passed to the `deno test` command when constructing the execution command line. This will prevent shell injection even if malicious characters are present in the arguments.
    - User Warning: Display a warning message to the user if the extension detects potentially unsafe arguments in the `deno.codeLens.testArgs` setting, advising caution and the risks involved.
- Preconditions:
    - The user must have the Deno VS Code extension installed and enabled.
    - The user must open a workspace that contains a malicious `.vscode/settings.json` file that sets a malicious `deno.codeLens.testArgs` value.
    - The user must run tests within the malicious workspace using the extension's test runner (code lens or Test Explorer).
- Source Code Analysis:
    - File: `client\src\commands.ts`
    - Function: `test`

    ```typescript
    export function test(
      _context: vscode.ExtensionContext,
      extensionContext: DenoExtensionContext,
    ): Callback {
      return async (uriStr: string, name: string, options: TestCommandOptions) => {
        // ...
        const config = vscode.workspace.getConfiguration(EXTENSION_NS, uri);
        const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []), // [Vulnerable Code]: Reads user-provided arguments from configuration.
        ];
        // ...
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath]; // [Vulnerable Code]: User-provided arguments are directly added to the command.

        const definition: tasks.DenoTaskDefinition = {
          type: tasks.TASK_TYPE,
          command: "test",
          args, // [Vulnerable Code]: The command arguments, including user-provided ones, are passed to task execution.
          env,
        };

        // ... Task execution logic ...
      };
    }
    ```

    The code snippet above shows that the `test` function in `commands.ts` retrieves the `deno.codeLens.testArgs` configuration setting and directly incorporates it into the command arguments for `deno test`. There is no input validation or sanitization of the `testArgs` before they are used in command execution, creating a command injection vulnerability.

- Security Test Case:
    1. Create a new directory named `deno-vuln-test`.
    2. Inside `deno-vuln-test`, create a folder named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following malicious configuration:
        ```json
        {
          "deno.codeLens.testArgs": [
            "--allow-all",
            "; touch /tmp/pwned ;"
          ]
        }
        ```
    4. In `deno-vuln-test`, create a test file named `test_vuln.ts` with the following content:
        ```typescript
        import { assertEquals } from "https://deno.land/std/testing/asserts.ts";

        Deno.test("command injection test", () => {
          assertEquals(1, 1);
        });
        ```
    5. Open the `deno-vuln-test` directory in Visual Studio Code. Enable Deno for the workspace if prompted.
    6. Open the `test_vuln.ts` file.
    7. Locate the "▶ Run Test" code lens above the `Deno.test` definition and click it to run the test.
    8. After running the test, execute the following command in your terminal to check if the file `/tmp/pwned` was created:
        ```bash
        ls /tmp/pwned
        ```
    9. If the file `/tmp/pwned` exists, it confirms that the command injection was successful, and the malicious command from `deno.codeLens.testArgs` was executed.
