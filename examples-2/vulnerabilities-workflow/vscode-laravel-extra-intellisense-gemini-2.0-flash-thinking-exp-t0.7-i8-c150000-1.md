## Vulnerability List

### 1. Command Injection via `phpCommand` configuration

- Description:
    1. An attacker crafts a malicious Laravel repository.
    2. Within this repository, the attacker creates or modifies the VSCode workspace settings file (`.vscode/settings.json`).
    3. In this settings file, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command. For example: `"LaravelExtraIntellisense.phpCommand": "php -r '{code}'; touch /tmp/pwned"`. This crafted command will execute the intended PHP code and then proceed to execute an additional, malicious command (e.g., `touch /tmp/pwned` which creates a file named `pwned` in the `/tmp` directory).
    4. A victim, who has the "Laravel Extra Intellisense" extension installed in VSCode, opens this malicious Laravel repository.
    5. Upon opening the repository, the extension reads the workspace settings, including the attacker's malicious `phpCommand`.
    6. When the extension attempts to provide autocompletion suggestions (for routes, views, configs, etc.), it uses the configured `phpCommand` to execute PHP code within the Laravel application environment.
    7. Due to insufficient sanitization of the `phpCommand` configuration, the attacker's injected command (e.g., `touch /tmp/pwned`) is executed on the victim's system via `child_process.exec`.

- Impact:
    - Remote Code Execution (RCE). The attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data theft, installation of malware, and other malicious activities.

- Vulnerability Rank: critical

- Currently implemented mitigations:
    - None. The extension directly uses the `phpCommand` from the user configuration without any sanitization or validation. The code in `helpers.ts` that escapes double quotes in the `{code}` part does not prevent command injection through the `phpCommand` template itself.

- Missing mitigations:
    - Input sanitization for `phpCommand` configuration: The extension should sanitize or validate the `phpCommand` configuration to prevent command injection. Ideally, instead of allowing a completely custom command template, the extension should offer structured configuration options (e.g., path to PHP executable, Docker command, etc.) and construct the execution command internally in a safe manner.
    - Restrict command template:  Instead of allowing users to define the entire command, the extension should provide specific configuration options, and internally construct the command with fixed, safe templates. For example, allow setting the PHP executable path and options for Docker/Sail/Laradock, but not the core command structure.

- Preconditions:
    - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim must open a malicious Laravel repository provided by the attacker in VSCode.
    - The attacker must be able to modify or provide a malicious `.vscode/settings.json` file within the repository to set a malicious `LaravelExtraIntellisense.phpCommand`.

- Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - Vulnerable code snippet:
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

            cp.exec(command, // <-- Command Injection Vulnerability
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ...
                }
            );
        });
        return out;
    }
    ```
    - The `runPhp` function retrieves the `phpCommand` from the extension's configuration.
    - It replaces the `{code}` placeholder in the `commandTemplate` with the `$code` argument.
    - Critically, it then directly executes this constructed `command` using `cp.exec()`. There is no sanitization or validation of the `commandTemplate` itself, allowing an attacker to inject arbitrary commands.

- Security test case:
    1. Create a new directory to serve as a malicious Laravel project repository.
    2. Inside this directory, create a `.vscode` subdirectory.
    3. Within the `.vscode` directory, create a `settings.json` file with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '{code}'; touch /tmp/pwned"
    }
    ```
    4. Open this malicious project directory in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    5. Open any PHP file (e.g., create an empty `test.php` file in the project root and open it). This action should trigger the extension to attempt to gather Laravel project information, thus executing the configured `phpCommand`.
    6. After a short delay (to allow the extension to run), check if a file named `pwned` has been created in the `/tmp` directory of your system.
    7. If the file `/tmp/pwned` exists, this confirms that the command injection vulnerability is present and exploitable.
