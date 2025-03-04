## Vulnerability List

### Vulnerability 1: Command Injection in `phpCommand` setting

- Description:
    - An attacker can achieve command injection by manipulating the `LaravelExtraIntellisense.phpCommand` setting in VSCode.
    - The extension uses the value of this setting to construct and execute shell commands via `child_process.exec` to run PHP code for Laravel project analysis.
    - If a malicious user or a compromised workspace configuration provides a crafted `phpCommand` value, it's possible to inject arbitrary shell commands.
    - Steps to trigger vulnerability:
        1. The victim installs the "Laravel Extra Intellisense" VSCode extension.
        2. The attacker provides a malicious Laravel project to the victim (e.g., via a public repository).
        3. The malicious project includes a `.vscode/settings.json` file that overrides the user's `LaravelExtraIntellisense.phpCommand` setting with a malicious command. For example:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('calc');\""
        }
        ```
        4. The victim opens the malicious Laravel project in VSCode.
        5. The VSCode loads the workspace settings, overriding the `phpCommand` setting.
        6. When the extension attempts to provide autocompletion (e.g., when the user starts typing `route(` in a PHP or Blade file), it executes PHP code using the modified `phpCommand`.
        7. The injected `system('calc')` command is executed, demonstrating command injection by launching the calculator application.

- Impact:
    - Remote Code Execution (RCE).
    - An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to complete system compromise, data theft, malware installation, and other malicious activities.

- Vulnerability rank: high

- Currently implemented mitigations:
    - None. The extension directly retrieves and uses the `phpCommand` setting from VSCode configuration without any sanitization or validation.

- Missing mitigations:
    - Input sanitization for the `phpCommand` setting. The extension should validate and sanitize the `phpCommand` setting to prevent command injection.
    - Ideally, the extension should avoid using `child_process.exec` with user-configurable strings if possible. If it's necessary, consider using safer alternatives or implement robust input validation.
    - A warning in the extension's documentation and settings description about the security implications of modifying `phpCommand` would be beneficial.

- Preconditions:
    1. Victim has installed the "Laravel Extra Intellisense" VSCode extension.
    2. Victim opens a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file.
    3. Workspace settings in `.vscode/settings.json` are configured to override user settings for `LaravelExtraIntellisense.phpCommand`.

- Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [VULNERABLE LINE] - Retrieves phpCommand from configuration
        let command = commandTemplate.replace("{code}", code); // Constructs the command string
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [VULNERABLE LINE] - Executes the command using child_process.exec
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) { ... }
            );
        });
        return out;
    }
    ```
    - The code directly uses `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')` to fetch the `phpCommand` setting.
    - It then uses `replace("{code}", code)` to insert the PHP code into the command template.
    - Finally, `cp.exec(command)` executes the constructed command string, which is vulnerable if `phpCommand` is maliciously crafted.

- Security test case:
    1. Create a new directory named `laravel-project-test`.
    2. Inside `laravel-project-test`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('calc');\""
    }
    ```
    4. Open VSCode and open the `laravel-project-test` directory.
    5. Create a new file named `test.php` in `laravel-project-test` with the following content:
    ```php
    <?php

    Route::get('/test', function () {
        //
    });
    ```
    6. In `test.php`, type `route(` to trigger autocompletion.
    7. Observe that the Windows Calculator application (or equivalent on other OS) is launched. This confirms command injection vulnerability.
    8. To further verify, modify `settings.json` to execute a more harmful command, like creating a file:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('echo vulnerable > pwnd.txt');\""
    }
    ```
    9. Repeat steps 4-6 and check if a file named `pwnd.txt` with the content "vulnerable" is created in the `laravel-project-test` directory. This further confirms the RCE vulnerability.
