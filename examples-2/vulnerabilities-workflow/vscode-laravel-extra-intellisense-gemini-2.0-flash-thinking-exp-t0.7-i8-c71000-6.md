### Vulnerability List

*   **Vulnerability Name:** Command Injection via `phpCommand` setting

*   **Description:**
    The `Laravel Extra Intellisense` extension allows users to configure the command used to execute PHP code via the `LaravelExtraIntellisense.phpCommand` setting. This setting is used in the `Helpers.runPhp` function to execute arbitrary PHP code by spawning a child process using `cp.exec`. If a malicious workspace is opened in VSCode, an attacker can manipulate the workspace settings to inject arbitrary commands into the `phpCommand`. When the extension subsequently executes PHP code using `Helpers.runPhp`, the injected commands will be executed by the system.

    Steps to trigger the vulnerability:
    1.  An attacker creates a malicious Laravel project repository.
    2.  In the malicious repository, the attacker creates a `.vscode/settings.json` file.
    3.  In the `settings.json` file, the attacker sets the `LaravelExtraIntellisense.phpCommand` setting to inject malicious commands, for example: `"LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"malicious command\")'"` or `"LaravelExtraIntellisense.phpCommand": "php -r \"; {code}; system(\"malicious command\")\""`.
    4.  The attacker hosts this malicious repository publicly (e.g., on GitHub).
    5.  A victim user clones or downloads the malicious repository and opens it in VSCode with the `Laravel Extra Intellisense` extension installed.
    6.  The extension automatically starts and attempts to gather Laravel project information by executing PHP code using `Helpers.runPhp`.
    7.  Due to the manipulated `phpCommand` setting, the injected malicious command is executed on the victim's machine with the privileges of the VSCode process.

*   **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine. This can lead to complete compromise of the victim's system, including data theft, malware installation, and further propagation of attacks.

*   **Vulnerability Rank:** critical

*   **Currently Implemented Mitigations:**
    No mitigations are currently implemented in the project to prevent command injection via the `phpCommand` setting. The extension directly uses the user-provided `phpCommand` setting in `cp.exec` without any sanitization or validation. The README.md contains a "Security Note" warning users that the extension executes their Laravel application, but it does not specifically warn about the command injection vulnerability or how to mitigate it.

*   **Missing Mitigations:**
    The extension should implement the following mitigations:
    *   **Input Sanitization:** Sanitize the `phpCommand` setting to prevent injection of arbitrary commands.  A simple approach would be to only allow `php -r "{code}"` and disallow any modifications to the base command structure. Alternatively, the extension could parse the provided command and verify it conforms to an expected safe format.
    *   **Parameterization:** Instead of directly embedding the `{code}` into the command string, consider using parameterized execution if the underlying `child_process` API supports it (though `cp.exec` does not directly support parameterization in the same way as database prepared statements).
    *   **Warning to User:** When using a custom `phpCommand`, display a clear warning to the user about the security risks and the importance of using trusted commands.
    *   **Principle of Least Privilege:** While not directly related to code, ensure the extension itself and any spawned processes run with the minimum necessary privileges.

*   **Preconditions:**
    *   The victim user must have the `Laravel Extra Intellisense` extension installed in VSCode.
    *   The victim user must open a workspace in VSCode that contains a malicious `.vscode/settings.json` file (or have workspace/user settings that are maliciously configured).
    *   The malicious workspace must be a Laravel project or be structured in a way that the extension attempts to execute PHP code.

*   **Source Code Analysis:**

    1.  **`src/helpers.ts:runPhp(code, description)`:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [VULNERABLE]: Retrieves phpCommand from settings
            let command = commandTemplate.replace("{code}", code); // [VULNERABLE]:  Direct string replacement without sanitization
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // [VULNERABLE]: Executes command using cp.exec
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
        The `runPhp` function retrieves the `phpCommand` from the extension's configuration. It then performs a simple string replacement to insert the `$code` into the command.  Critically, it does not sanitize the `phpCommand` template itself, allowing for injection. The resulting command is then executed using `cp.exec`.

    2.  **Usage of `Helpers.runPhp`:**
        The `Helpers.runPhp` function is used throughout the extension to execute PHP code for various features like route, view, config, translation, and model autocompletion. Any of these calls can trigger the vulnerability if the `phpCommand` is malicious. For example, `AuthProvider.ts`, `BladeProvider.ts`, `ConfigProvider.ts`, `EloquentProvider.ts`, `MiddlewareProvider.ts`, `RouteProvider.ts`, `TranslationProvider.ts`, and `ViewProvider.ts` all use `Helpers.runLaravel`, which in turn uses `Helpers.runPhp`.


*   **Security Test Case:**

    1.  **Setup:**
        *   Install the `Laravel Extra Intellisense` extension in VSCode.
        *   Create a new directory named `malicious-laravel-project`.
        *   Inside `malicious-laravel-project`, create a `.vscode` directory.
        *   Inside `.vscode`, create a `settings.json` file with the following content to inject a command that creates a file named `pwned.txt` in the root of the workspace:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r '{code}; touch pwned.txt'"
            }
            ```
        *   Create a dummy `artisan` file in `malicious-laravel-project` to trick the extension into thinking it's a Laravel project:
            ```bash
            touch artisan
            ```
        *   Optionally, create a `vendor` and `bootstrap` directory with empty files to satisfy the extension's checks, or rely on the fact that the vulnerability triggers even if the Laravel project is not fully valid as long as `artisan` exists.

    2.  **Execution:**
        *   Open the `malicious-laravel-project` directory in VSCode.
        *   Wait for the `Laravel Extra Intellisense` extension to activate (this might take a few seconds). The extension will attempt to run Laravel commands to gather data.

    3.  **Verification:**
        *   Check the `malicious-laravel-project` directory for a new file named `pwned.txt`.
        *   If `pwned.txt` exists, it indicates that the injected command `touch pwned.txt` was successfully executed, confirming the command injection vulnerability.

This test case demonstrates that a malicious workspace can indeed inject and execute arbitrary commands through the `phpCommand` setting, leading to RCE.
