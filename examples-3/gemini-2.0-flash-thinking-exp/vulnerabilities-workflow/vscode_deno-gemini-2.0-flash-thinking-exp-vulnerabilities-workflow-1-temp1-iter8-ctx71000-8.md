### Vulnerability List:

- **Vulnerability Name:** Command Injection in Test Code Lens Arguments

- **Description:**
    A command injection vulnerability exists in the Deno VSCode extension due to insecure handling of arguments passed to the Deno CLI when running tests via the Test Code Lens feature. An attacker can craft a malicious repository with a specially crafted `deno.codeLens.testArgs` setting within `.vscode/settings.json`. When a victim opens this repository and attempts to run a test using the Code Lens, the attacker's malicious commands embedded in `deno.codeLens.testArgs` will be executed by the system.

- **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to full system compromise, data theft, or installation of malware.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
    No specific mitigations are implemented in the code to prevent command injection in `deno.codeLens.testArgs`. The code directly passes the arguments from the configuration to the Deno CLI process without sanitization or validation.

    - Source code snippet from `client\src\commands.ts`:
      ```typescript
      const testArgs: string[] = [
          ...(config.get<string[]>("codeLens.testArgs") ?? []),
      ];
      const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
      ```

- **Missing Mitigations:**
    - **Input Sanitization:** Implement robust sanitization and validation of all arguments obtained from `deno.codeLens.testArgs`. This should include preventing shell metacharacters and other potentially harmful inputs.
    - **Argument Quoting:** Properly quote all arguments passed to the Deno CLI execution to prevent interpretation of shell metacharacters. Consider using parameterized command execution if available.

- **Preconditions:**
    1. The victim must have the Deno VSCode extension installed.
    2. The victim must open a malicious repository in VSCode that contains a crafted `.vscode/settings.json` with malicious commands in `deno.codeLens.testArgs`.
    3. The victim must have Deno enabled for the workspace.
    4. The victim must attempt to run a test using the "Run Test" Code Lens provided by the extension.

- **Source Code Analysis:**

    1. **Configuration Retrieval:** In `client\src\commands.ts`, within the `test` function, the code retrieves the `deno.codeLens.testArgs` setting from the workspace configuration using `vscode.workspace.getConfiguration(EXTENSION_NS, uri).get<string[]>("codeLens.testArgs")`. This setting is user-configurable and can be defined in `.vscode/settings.json` within the workspace.

    2. **Command Construction:** The `testArgs` array, directly obtained from the configuration, is then spread into the `args` array used for executing the Deno CLI test command.

        ```typescript
        const testArgs: string[] = [
            ...(config.get<string[]>("codeLens.testArgs") ?? []),
        ];
        const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
        ```

    3. **Command Execution:** The `args` array, including the potentially malicious arguments from `deno.codeLens.testArgs`, is passed to `tasks.buildDenoTask` which creates a `vscode.Task` with `vscode.ProcessExecution`. This ultimately leads to the execution of the Deno CLI command with the unsanitized arguments using `vscode.tasks.executeTask(task)`.

    4. **Vulnerability:**  Because the `deno.codeLens.testArgs` are taken directly from the workspace settings without any sanitization, an attacker can inject arbitrary shell commands. When the `test` command is executed, these injected commands will be run by the system.

    **Visualization:**

    ```
    .vscode/settings.json --> vscode.workspace.getConfiguration() --> config.get("deno.codeLens.testArgs") --> testArgs Array --> args Array --> vscode.ProcessExecution --> Deno CLI Command Execution (VULNERABILITY)
    ```

- **Security Test Case:**

    1. **Attacker Setup:**
        - Create a new folder named `malicious-repo`.
        - Inside `malicious-repo`, create a subfolder named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json` with the following content to inject a command that creates a file named `pwned.txt` in the victim's home directory:
            ```json
            {
                "deno.codeLens.testArgs": [
                    "--allow-all",
                    "; touch ~\\pwned.txt ;"
                ]
            }
            ```
        - Create a file named `test.ts` in `malicious-repo` with a simple Deno test:
            ```typescript
            import { assertEquals } from "https://deno.land/std@0.218.2/assert/mod.ts";

            Deno.test("simple test", () => {
                assertEquals(1, 1);
            });
            ```

    2. **Victim Actions:**
        - Open the `malicious-repo` folder in VSCode.
        - If prompted, enable Deno for the workspace.
        - Open the `test.ts` file.
        - Observe the "Run Test" Code Lens above the `Deno.test` declaration.
        - Click on the "Run Test" Code Lens.

    3. **Verification:**
        - After running the test, check the victim's home directory for the presence of the `pwned.txt` file.
        - If `pwned.txt` exists, the command injection vulnerability is confirmed. The injected command `; touch ~/pwned.txt ;` has been successfully executed.
