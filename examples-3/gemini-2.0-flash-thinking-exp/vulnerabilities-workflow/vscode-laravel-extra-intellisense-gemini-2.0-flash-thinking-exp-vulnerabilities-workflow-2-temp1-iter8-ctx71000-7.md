- Vulnerability Name: **Command Injection via `phpCommand` configuration**
- Description:
    - The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which specifies the command used to execute PHP code.
    - This setting is intended to allow users to customize the PHP execution environment, for example, when using Docker or other virtualized environments.
    - However, the extension does not perform sufficient validation or sanitization of this user-provided command.
    - A malicious user can inject arbitrary shell commands into the `phpCommand` setting.
    - When the extension executes PHP code using `Helpers.runPhp`, it substitutes the `{code}` placeholder in the user-provided `phpCommand` with the generated PHP code and executes the resulting command in a shell.
    - If the `phpCommand` contains malicious shell commands, these commands will be executed along with the intended PHP code.
- Impact:
    - **Critical**. Arbitrary command execution on the machine running VSCode and the Laravel application.
    - An attacker can gain full control over the user's system and the Laravel application environment.
    - This can lead to data theft, modification, application compromise, and further system exploitation.
- Vulnerability Rank: **Critical**
- Currently Implemented Mitigations:
    - None. The extension directly uses the user-provided `phpCommand` without validation or sanitization.
- Missing Mitigations:
    - **Input validation and sanitization:** The extension must validate and sanitize the `phpCommand` setting to prevent command injection.
    - **Restrict command execution:** Instead of using `cp.exec`, which executes commands in a shell, consider using `cp.spawn` with explicit arguments to avoid shell injection vulnerabilities. If `cp.exec` must be used, ensure the `phpCommand` is strictly validated and constructed in a safe manner.
    - **Principle of least privilege:**  The extension should ideally not execute arbitrary shell commands at all. Explore alternative methods to gather necessary data without resorting to shell command execution if possible.
- Preconditions:
    - The attacker needs to be able to modify the VSCode settings for the Laravel project. This could be achieved if:
        - The attacker has direct access to the user's machine.
        - The user is tricked into opening a malicious Laravel project provided by the attacker, which includes a malicious `.vscode/settings.json` file with a crafted `phpCommand`.
- Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\""); // Line 157: Basic escaping for double quotes in PHP code. INSUFFICIENT for shell injection.
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$"); // Line 159-162: More escaping for unix-like systems. Still INSUFFICIENT for shell injection.
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Line 164: Retrieves user-configurable phpCommand.
        let command = commandTemplate.replace("{code}", code); // Line 165: Substitutes {code} with the PHP code. VULNERABILITY: No sanitization of commandTemplate.
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Line 171: Executes the command using cp.exec. VULNERABILITY: Shell command injection possible due to unsanitized 'command'.
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ...
                }
            );
        });
        return out;
    }
    ```

    **Explanation:**
    1. The `runPhp` function takes PHP code as input and executes it.
    2. It retrieves the `phpCommand` from the user's VSCode configuration.
    3. It replaces the `{code}` placeholder in `phpCommand` with the PHP code.
    4. **VULNERABILITY:** It uses `cp.exec(command, ...)` to execute the command. `cp.exec` executes commands in a shell, which interprets shell metacharacters. If the `phpCommand` setting contains malicious shell commands, these will be executed.
    5. The limited escaping performed on the PHP code itself (lines 157-162) is insufficient to prevent shell injection because the vulnerability is in the `phpCommand` setting, not in the PHP code.

- Security Test Case:
    1. **Precondition:**
        - Have VSCode installed with the Laravel Extra Intellisense extension enabled.
        - Open a Laravel project in VSCode.
    2. **Steps to reproduce:**
        - Open VSCode settings (File -> Preferences -> Settings, or Code -> Settings -> Settings on macOS).
        - Go to Workspace settings.
        - Search for "LaravelExtraIntellisense: Php Command".
        - Modify the `phpCommand` setting to the following malicious command:
          ```json
          "LaravelExtraIntellisense.phpCommand": "php -r '{code}' && touch /tmp/pwned"
          ```
          *(For Windows, use `php -r '{code}' && type nul > C:\\Windows\\Temp\\pwned`)*
        - Open any PHP or Blade file in the Laravel project.
        - Trigger autocompletion (e.g., by typing `route('` ). This will cause the extension to execute PHP code.
    3. **Expected result:**
        - The autocompletion should function as normal (the extension still gathers data).
        - **VULNERABILITY PROVEN:** A file named `pwned` should be created in the `/tmp/` directory (or `C:\\Windows\\Temp\\` on Windows). This indicates that the `touch /tmp/pwned` command (or `type nul > C:\\Windows\\Temp\\pwned`) injected into `phpCommand` was successfully executed by the shell when the extension ran the PHP code.
    4. **Cleanup (for testing multiple times):**
        - Delete the `/tmp/pwned` file (or `C:\\Windows\\Temp\\pwned` on Windows).
        - Restore the `phpCommand` setting to a safe value, e.g., the default `"php -r \"{code}\""`.

This test case demonstrates that arbitrary shell commands can be injected and executed via the `phpCommand` configuration setting, confirming the command injection vulnerability.
