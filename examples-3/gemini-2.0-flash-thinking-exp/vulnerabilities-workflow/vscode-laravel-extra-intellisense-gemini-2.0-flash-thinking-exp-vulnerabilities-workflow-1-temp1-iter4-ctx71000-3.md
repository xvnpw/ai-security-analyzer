## Vulnerability List:

### 1. Command Injection in `phpCommand` setting

- **Vulnerability Name:** Command Injection in `phpCommand` setting
- **Description:**
    1. A threat actor creates a malicious Laravel repository.
    2. Within this repository, the threat actor crafts a `.vscode/settings.json` file.
    3. This `settings.json` file is configured to maliciously override the `LaravelExtraIntellisense.phpCommand` setting. The malicious command injected into `phpCommand` is designed to execute arbitrary system commands when the extension attempts to run PHP code. For example, the setting could be configured as follows:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/pwned\"); {code}'"
        }
        ```
    4. A victim user opens this malicious repository in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    5. When the extension is triggered to provide autocompletion (e.g., when the user opens a PHP or Blade file in the workspace and starts typing code that activates the extension's features), the extension executes PHP code using the command specified in `LaravelExtraIntellisense.phpCommand`.
    6. Due to the malicious configuration, instead of just running PHP code related to Laravel autocompletion, the `system("touch /tmp/pwned")` command (or any other command specified by the attacker) is executed on the victim's system before the intended PHP code `{code}` is run.
    7. This results in arbitrary command execution on the victim's machine, effectively allowing the threat actor to compromise the victim's system if the victim opens the malicious repository.

- **Impact:**
    - **Remote Code Execution (RCE):** Successful exploitation allows the threat actor to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data exfiltration, malware installation, and other malicious activities.
- **Vulnerability Rank:** High
- **Currently implemented mitigations:**
    - The extension performs some escaping of double quotes (`"`) in the PHP code snippet (`code`) before substituting it into the `phpCommand`. However, this is insufficient to prevent command injection because the user-controlled `phpCommand` setting itself is not sanitized or validated.  The escaping applied to `{code}` is irrelevant as the attacker controls the surrounding command structure within `phpCommand`.
- **Missing mitigations:**
    - **Restrict or Sanitize `phpCommand`:** The most critical missing mitigation is to prevent users from directly controlling the command execution template. The extension should either:
        - **Remove user configurability of `phpCommand`:**  Hardcode a safe execution command within the extension and do not allow user overrides.
        - **Sanitize and Validate `phpCommand`:** If configurability is necessary, strictly sanitize and validate the `phpCommand` setting to ensure it cannot be used for command injection. This might involve whitelisting allowed commands and options or using secure command construction methods that prevent injection.
        - **Warn Users:** If `phpCommand` configurability is retained without robust sanitization, display a clear and prominent warning to users about the security risks of modifying this setting, especially when opening workspaces from untrusted sources.
- **Preconditions:**
    - **Victim opens a malicious repository:** The victim must open a workspace in VSCode that contains a malicious `.vscode/settings.json` file.
    - **Malicious `settings.json`:** The `.vscode/settings.json` file within the malicious repository must configure the `LaravelExtraIntellisense.phpCommand` setting to include malicious system commands.
    - **Extension installed and activated:** The "Laravel Extra Intellisense" extension must be installed and activated in the victim's VSCode instance.
    - **Workspace enabled extension:** The extension needs to be enabled for the opened workspace.

- **Source code analysis:**
    1. **`src/helpers.ts:runPhp(code: string, description: string|null = null)`**:
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\""); // Basic escaping of double quotes in PHP code
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Retrieve phpCommand setting, default is "php -r \"{code}\""
            let command = commandTemplate.replace("{code}", code); // Substitute {code} placeholder with user-provided PHP code (after basic escaping)
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Execute the constructed command using child_process.exec
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                    function (err, stdout, stderr) {
                        // ... handle command execution and errors ...
                    }
                );
            });
            return out;
        }
        ```
        - The `runPhp` function is responsible for executing PHP code.
        - It retrieves the `phpCommand` setting from the workspace configuration.
        - It substitutes the `{code}` placeholder in the `phpCommand` with the provided `$code`.
        - It then uses `cp.exec` to execute the resulting command.
        - **Vulnerability point:** The lack of sanitization or validation of the `phpCommand` setting allows for command injection. If a malicious user provides a crafted `phpCommand`, they can inject arbitrary commands that will be executed by `cp.exec`.

- **Security test case:**
    1. **Setup Malicious Repository:**
        - Create a new directory named `malicious-laravel-repo`.
        - Inside `malicious-laravel-repo`, create a `.vscode` directory.
        - Inside `.vscode`, create a file named `settings.json`.
        - Add the following content to `settings.json`:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/pwned-by-laravel-intellisense\"); {code}'"
            }
            ```
        - You do not need to create a full Laravel project; a minimal directory structure with the malicious settings file is sufficient to demonstrate the vulnerability.

    2. **Open Malicious Repository in VSCode:**
        - Open VSCode.
        - Open the `malicious-laravel-repo` directory as a workspace (File -> Open Folder...).
        - Ensure the "Laravel Extra Intellisense" extension is installed and enabled for this workspace.

    3. **Trigger Extension Activity:**
        - Create a new file named `test.php` in the `malicious-laravel-repo` directory.
        - Add the following PHP code to `test.php`:
            ```php
            <?php

            route('welcome');
            ```
        - Opening `test.php` or typing `route(` should trigger the Laravel Extra Intellisense extension to run PHP code to provide route autocompletion.

    4. **Verify Command Injection:**
        - After triggering the extension (by opening `test.php` or typing `route(`), check if the file `/tmp/pwned-by-laravel-intellisense` has been created on your system.
        - **If the file `/tmp/pwned-by-laravel-intellisense` exists, the command injection vulnerability is confirmed.** This indicates that the `system("touch /tmp/pwned-by-laravel-intellisense")` command injected through the malicious `phpCommand` setting was successfully executed.

This test case demonstrates how a malicious repository can leverage the `LaravelExtraIntellisense.phpCommand` setting to achieve command injection and execute arbitrary code on a victim's machine simply by having them open the repository in VSCode with the extension installed.
