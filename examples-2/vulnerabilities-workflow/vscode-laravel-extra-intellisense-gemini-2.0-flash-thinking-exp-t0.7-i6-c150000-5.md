## Vulnerability List for Laravel Extra Intellisense VSCode Extension

### 1. Command Injection in `phpCommand` setting

- **Vulnerability Name:** Command Injection in `phpCommand` setting
- **Description:**
    1. A threat actor crafts a malicious Laravel repository.
    2. Within this repository, the attacker creates a `.vscode` directory and a `settings.json` file inside it.
    3. In `settings.json`, the attacker maliciously modifies the `LaravelExtraIntellisense.phpCommand` setting to inject arbitrary commands. For example:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; touch /tmp/pwned"
    }
    ```
    This crafted command first executes the intended PHP code (`{code}`) and then, using the `;` separator, executes an additional command (`touch /tmp/pwned`).
    4. The victim, intending to work on a Laravel project, opens this malicious repository in VSCode, having the "Laravel Extra Intellisense" extension installed.
    5. Upon opening the workspace, the extension activates and reads the workspace-specific settings from `.vscode/settings.json`, including the attacker's malicious `phpCommand`.
    6. Subsequently, when the extension attempts to provide autocompletion suggestions, it uses the configured `phpCommand` to execute PHP code.
    7. Due to the command injection, not only is the intended PHP code executed, but also the attacker's injected command. In the example, `touch /tmp/pwned` is executed, creating a file named `pwned` in the `/tmp` directory, demonstrating arbitrary command execution.

- **Impact:** Remote Code Execution (RCE). By injecting system commands, an attacker can achieve full control over the victim's machine, potentially leading to data theft, malware installation, or further system compromise.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. While the extension performs escaping on the `{code}` part of the command, it does not sanitize or validate the `phpCommand` template itself, allowing for injection through the template configuration.
- **Missing Mitigations:**
    - **Input Sanitization/Validation:** Implement robust sanitization or validation of the `phpCommand` setting. Restrict the allowed characters and command structure to prevent the injection of arbitrary commands. Ideally, parse and validate the command structure to ensure it adheres to the expected format and does not contain command separators or other injection vectors.
    - **User Warning:** Display a clear warning to users when they modify the `phpCommand` setting, highlighting the security risks associated with custom commands and advising them to only use trusted commands.
    - **Use `child_process.spawn`:** Migrate from `cp.exec` to `child_process.spawn` and utilize arguments array instead of a command string. This approach inherently avoids shell injection vulnerabilities by directly passing arguments to the process without shell interpretation.
- **Preconditions:**
    - The victim must have VSCode installed with the "Laravel Extra Intellisense" extension enabled.
    - The victim must open a malicious Laravel repository provided by the attacker in VSCode.
    - The malicious repository must contain a `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious command.
- **Source Code Analysis:**
    - **File:** `src/helpers.ts`
    - **Function:** `Helpers.runPhp(code: string, description: string|null = null)`
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        let command = commandTemplate.replace("{code}", code);
        // ... cp.exec(command, ...)
    }
    ```
    The vulnerability lies in the line `let command = commandTemplate.replace("{code}", code);`. While the `code` variable is escaped to prevent injection into the PHP code itself, the `commandTemplate` (obtained from user settings) is not validated or sanitized. This allows an attacker to inject commands through the `commandTemplate` by manipulating the `LaravelExtraIntellisense.phpCommand` setting. The `cp.exec(command, ...)` then executes the constructed command string, including the injected parts, leading to command injection.
- **Security Test Case:**
    1. **Setup:** Create a new, empty directory to simulate a Laravel project. Inside this directory, create a `.vscode` subdirectory.
    2. **Malicious Settings File:** Within the `.vscode` directory, create a `settings.json` file with the following content to inject a command that creates a marker file in the `/tmp` directory:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; touch /tmp/pwned_by_vscode_extension"
    }
    ```
    3. **Open Malicious Workspace:** Open the directory created in step 1 in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    4. **Trigger Autocompletion:** Open any file type (e.g., create an empty `test.php` file and open it). Trigger any autocompletion feature of the extension that would cause it to execute PHP code (e.g., type `route('` in the `test.php` file).
    5. **Verify Command Execution:** Check if the marker file `/tmp/pwned_by_vscode_extension` has been created. On Linux/macOS, use the command `ls /tmp/pwned_by_vscode_extension`. If the file exists, the command injection vulnerability is confirmed.
    6. **Expected Result:** The file `/tmp/pwned_by_vscode_extension` should be created, indicating successful execution of the injected command and thus confirming the command injection vulnerability.
