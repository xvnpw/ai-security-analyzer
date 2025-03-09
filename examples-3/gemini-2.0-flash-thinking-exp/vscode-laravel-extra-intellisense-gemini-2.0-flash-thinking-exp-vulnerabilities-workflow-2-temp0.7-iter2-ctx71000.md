## Vulnerability: Command Injection via `phpCommand` Setting

This vulnerability in the `Laravel Extra Intellisense` VS Code extension allows for arbitrary code execution on a developer's machine. By crafting a malicious workspace configuration, an attacker can inject commands into the `phpCommand` setting, which the extension uses to execute PHP code. When the extension attempts to gather information about a Laravel project, it executes these injected commands, leading to critical security implications.

### Description:
1.  The `Laravel Extra Intellisense` extension allows users to customize the PHP command used by the extension via the `LaravelExtraIntellisense.phpCommand` setting in VS Code's workspace configuration (`.vscode/settings.json`).
2.  This setting is intended to support environments like Docker or Laravel Sail, where the standard `php` command might not be directly accessible, allowing users to specify the correct path or command for PHP execution.
3.  The extension utilizes this `phpCommand` setting to execute PHP code snippets for various features, such as gathering project routes, views, and configurations, which are essential for providing autocompletion and other intelligent code assistance features.
4.  The extension replaces the placeholder `{code}` within the user-defined `phpCommand` with the actual PHP code it needs to execute to gather project information.
5.  A malicious actor can exploit this by creating or modifying a `.vscode/settings.json` file within a Laravel project to inject arbitrary commands into the `phpCommand` setting. This can be achieved by tricking a developer into opening a project containing this malicious configuration, for example, through a cloned repository or a downloaded project.
6.  Upon opening the project in VS Code, the extension reads and applies the workspace settings, including the attacker-controlled `phpCommand`. Subsequently, when the extension attempts to use PHP (e.g., for autocompletion), it executes the attacker's injected commands along with the intended PHP code.
7.  This results in arbitrary code execution on the developer's machine with the same privileges as the VS Code process, effectively compromising the developer's environment.

### Impact:
- Arbitrary code execution on the developer's machine, granting full control over their workstation.
- Potential for sensitive data exfiltration, including source code, credentials, and other confidential information stored on the developer's machine.
- Installation of malware, backdoors, or ransomware, leading to further system compromise and potential supply chain attacks if the compromised machine is used for software development and deployment.
- Lateral movement within internal networks accessible from the developer's machine.

### Vulnerability Rank: Critical

### Currently Implemented Mitigations:
- There are no code-level mitigations implemented to prevent command injection.
- The extension's `README.md` file includes a "Security Note" that warns users about the extension running their Laravel application and suggests temporarily disabling it when working with sensitive code in service providers. This warning is purely informational and does not provide any technical safeguards against the vulnerability.

### Missing Mitigations:
- **Input sanitization and validation for `phpCommand` setting:** The extension should implement robust input validation and sanitization for the `phpCommand` setting to prevent the injection of malicious commands. This could involve disallowing shell metacharacters or validating the command structure.
- **Hardcoding or whitelisting allowed commands:** Instead of relying on user-configurable `phpCommand`, the extension should consider hardcoding a safe default PHP command or whitelisting specific, safe command structures.
- **Secure code execution mechanisms:** Exploring safer mechanisms for executing PHP code, such as using secure sandboxes or APIs provided by VS Code for extension execution, could mitigate the risk of command injection.
- **User warnings and confirmation prompts:** The extension should display a clear and prominent warning to the user when a workspace configuration with a custom `phpCommand` is detected, especially if it deviates from a safe default. Prompting for explicit user confirmation before using a custom `phpCommand` would also enhance security awareness.

### Preconditions:
- The victim developer must have the `Laravel Extra Intellisense` extension installed in VS Code.
- The attacker must be able to influence the workspace configuration used by the developer. This is typically achieved by:
    - Social engineering tactics to trick the developer into opening a project containing a malicious `.vscode/settings.json` file (e.g., through a malicious repository or project download).
    - Convincing the developer to manually modify their workspace settings to include a malicious `phpCommand`.

### Source Code Analysis:
1.  **File: `src/helpers.ts` Function: `runPhp(code: string, description: string|null = null)`**
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
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command,
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    if (err == null) {
                        if (description != null) {
                            Helpers.outputChannel?.info("Laravel Extra Intellisense Resolved: " + description);
                        }
                        resolve(stdout);
                    } else {
                        const errorOutput = stderr.length > 0 ? stderr : stdout;
                        Helpers.outputChannel?.error("Laravel Extra Intellisense Error:\n " + (description ?? '') + '\n\n' + errorOutput);
                        Helpers.showErrorPopup();
                        error(errorOutput);
                    }
                }
            );
        });
        return out;
    }
    ```
    - The `runPhp` function is responsible for executing PHP commands. It retrieves the `phpCommand` setting from the VS Code workspace configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
    - The code attempts to sanitize the `$code` variable (which contains PHP code to be executed) by escaping double quotes and, on Unix-like systems, escaping dollar signs, single quotes and double quotes again. However, this sanitization is insufficient to prevent command injection because it does not sanitize the `commandTemplate` itself, which is directly taken from user configuration and can contain arbitrary commands.
    - The line `let command = commandTemplate.replace("{code}", code);` constructs the final command by simply replacing `{code}` in the `commandTemplate` with the (partially sanitized) `$code`.
    - `cp.exec(command, ...)` then executes this constructed `command` string using `child_process.exec`, which runs the command in a shell. This execution method makes the application vulnerable to command injection if `commandTemplate` is attacker-controlled.
    - **Vulnerability:** The core issue is the lack of sanitization or validation of the `commandTemplate` obtained from user configuration. By injecting malicious commands into the `phpCommand` setting in `.vscode/settings.json`, an attacker can execute arbitrary shell commands on the developer's machine.

2.  **File: `src/helpers.ts` Function: `runLaravel(code: string, description: string|null = null)`**
    ```typescript
    static runLaravel(code: string, description: string|null = null) : Promise<string> {
        // ... (code for bootstrapping Laravel application and constructing PHP command) ...
        return new Promise(function (resolve, error) {
            self.runPhp(command, description)
                .then(function (result: string) {
                    // ... (code for parsing and resolving output) ...
                })
                .catch(function (e : Error) {
                    error(e);
                });
        });
        // ...
    }
    ```
    - The `runLaravel` function is designed to execute Laravel-specific commands by bootstrapping the Laravel application and then executing the provided `$code` within the Laravel environment.
    - Critically, it calls `Helpers.runPhp(command, description)` to execute the constructed PHP command. This means that the command injection vulnerability in `runPhp` is directly exploitable through `runLaravel` as well, because the `phpCommand` setting influences how `runPhp` executes commands, regardless of whether it's called directly or indirectly via `runLaravel`.

### Security Test Case:
1.  **Prerequisites:**
    - Ensure VS Code is installed with the `Laravel Extra Intellisense` extension enabled.
    - Create a new, empty project folder to simulate a new Laravel project.
    - Open this empty project folder in VS Code.

2.  **Steps:**
    - Create a `.vscode` directory at the root of the project.
    - Inside the `.vscode` directory, create a `settings.json` file.
    - Add the following JSON content to `settings.json` to inject a malicious command that will create a file named `pwned.txt` in the project root:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch pwned.txt\"); {code}'"
        }
        ```
    - Open any PHP file within the project (or create a dummy PHP file and open it). This action will trigger the `Laravel Extra Intellisense` extension to activate and execute PHP commands based on the configured `phpCommand` setting.
    - After a short delay, check the project root directory.

3.  **Expected Result:**
    - A new file named `pwned.txt` should be present in the project root directory. This indicates that the injected command `touch pwned.txt` was successfully executed due to the command injection vulnerability in the `phpCommand` setting.
    - The successful creation of `pwned.txt` confirms that arbitrary commands can be executed on the developer's machine by manipulating the `LaravelExtraIntellisense.phpCommand` setting, demonstrating a critical Remote Code Execution vulnerability.
