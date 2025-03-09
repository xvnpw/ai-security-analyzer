### Vulnerability List

- Vulnerability Name: Command Injection via `deno.codeLens.testArgs`

- Description:
    1. An attacker creates a malicious workspace and configures the `deno.codeLens.testArgs` setting within the workspace's `.vscode/settings.json` file.
    2. The attacker includes malicious commands within the `deno.codeLens.testArgs` setting, for example: `["--allow-all", "; malicious_command;"]`.
    3. A victim opens the malicious workspace in Visual Studio Code with the Deno extension installed.
    4. The victim attempts to run a test using the "Run Test" code lens provided by the Deno extension.
    5. The Deno extension executes the `deno test` command, incorporating the attacker-controlled arguments from `deno.codeLens.testArgs`.
    6. Due to insufficient sanitization, the malicious commands injected by the attacker are executed by the system shell.

- Impact:
    - Arbitrary command execution on the victim's machine with the privileges of the VS Code process.
    - Potential for data exfiltration, installation of malware, or other malicious activities depending on the injected commands.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None. The code directly uses the configuration value in command execution without sanitization.

- Missing Mitigations:
    - Input sanitization of the `deno.codeLens.testArgs` configuration. Arguments should be validated and sanitized to prevent command injection.  Consider disallowing shell metacharacters or using a safer method to pass arguments to the Deno CLI that avoids shell interpretation.
    - Documentation warning: Add a security warning in the extension documentation about the risks of modifying workspace settings from untrusted sources, especially regarding `deno.codeLens.testArgs` and `deno.testing.args`.

- Preconditions:
    - Victim must have the Deno extension for VS Code installed.
    - Victim must open a malicious workspace containing a crafted `.vscode/settings.json` file.
    - Victim must attempt to run a test using the code lens feature.

- Source Code Analysis:
    1. File: `client/src/commands.ts`
    2. Function: `test`
    3. Line:
       ```typescript
       const testArgs: string[] = [
         ...(config.get<string[]>("codeLens.testArgs") ?? []),
       ];
       ```
       This line retrieves the value of `deno.codeLens.testArgs` from the workspace configuration without any sanitization or validation.
    4. Line:
       ```typescript
       const args = ["test", ...testArgs, "--filter", nameRegex, filePath];
       ```
       This line constructs the command arguments array, directly embedding the unsanitized `testArgs`.
    5. File: `client/src/tasks.ts`
    6. Function: `buildDenoTask`
    7. Line:
       ```typescript
       const exec = new vscode.ProcessExecution(
         process,
         args, // Unsanitized args are passed to ProcessExecution
         definition,
       );
       ```
       The `args` array, containing potentially malicious commands, is directly passed to `vscode.ProcessExecution`. `ProcessExecution` will execute the command via the system shell, leading to command injection if `testArgs` contains malicious commands.

- Security Test Case:
    1. Create a new folder named `malicious-deno-workspace`.
    2. Inside `malicious-deno-workspace`, create a subfolder named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "deno.codeLens.testArgs": [
               "--allow-all",
               "; open /Applications/Calculator.app"
           ]
       }
       ```
       *(Note: Replace `/Applications/Calculator.app` with a command suitable for your operating system to demonstrate command execution, e.g., `start calc` on Windows or `gnome-calculator` on Linux. For security reasons, avoid destructive commands and use harmless commands like opening a calculator application.)*
    4. Open the `malicious-deno-workspace` folder in Visual Studio Code.
    5. Create a file named `test.ts` in `malicious-deno-workspace` with the following content:
       ```typescript
       Deno.test("vulnerable test", () => {
         console.log("This is a test.");
       });
       ```
    6. Ensure the Deno extension is enabled for this workspace.
    7. In the `test.ts` file, above the `Deno.test` definition, you should see the "▶ Run Test" code lens.
    8. Click on "▶ Run Test".
    9. Observe that the calculator application (or the command you injected) is executed, demonstrating command injection. The test will also likely fail or not run correctly due to the injected command.

This test case demonstrates that arbitrary commands can be executed by injecting them into the `deno.codeLens.testArgs` setting and triggering a test run via code lens.
