### Vulnerability List:

* Vulnerability Name: Command Injection in `phpCommand` configuration
* Description:
    1. The "Laravel Extra Intellisense" VSCode extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which specifies the command used to execute PHP code for Laravel application interaction.
    2. This setting is intended to allow users to customize the PHP execution environment, for example, when using Docker or other virtualized environments.
    3. However, the extension directly uses this user-provided command in `child_process.exec` without sufficient sanitization.
    4. A malicious repository can include a `.vscode/settings.json` file that overrides the `phpCommand` setting with a malicious command.
    5. When a victim opens this malicious repository in VSCode and the "Laravel Extra Intellisense" extension activates, the malicious command from the `phpCommand` setting will be executed on the victim's system.
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data theft, malware installation, and other malicious activities.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations: None. The extension directly uses the `phpCommand` setting without any sanitization or validation.
* Missing Mitigations:
    * Input sanitization: The extension should sanitize the `phpCommand` setting to prevent command injection. This could involve escaping shell metacharacters or using parameterized execution methods if possible. However, due to the nature of the setting and the need for shell execution, full sanitization might be complex.
    * User warning:  A clear warning should be displayed to the user when they configure or modify the `phpCommand` setting, emphasizing the security risks associated with executing arbitrary commands, especially from untrusted sources. The warning should advise users to only use trusted and well-understood commands.
    * Principle of least privilege:  Consider if the extension truly needs to execute arbitrary commands. Explore alternative approaches to gather necessary information from the Laravel application that do not involve executing shell commands or allow for less risky command execution.
* Preconditions:
    1. The victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    2. The victim opens a malicious Laravel repository in VSCode.
    3. The malicious repository contains a `.vscode/settings.json` file that sets a malicious command in the `LaravelExtraIntellisense.phpCommand` setting.
    4. The extension activates and attempts to use the `phpCommand` setting, which typically happens when the extension tries to provide autocompletion features in a PHP or Blade file within the project.
* Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - This line retrieves the `phpCommand` setting from the VSCode configuration.
    4. Line: `let command = commandTemplate.replace("{code}", code);` - This line constructs the command string by replacing `{code}` placeholder with the PHP code to be executed. **Crucially, no sanitization is performed on `commandTemplate` which originates from user configuration.**
    5. Line: `cp.exec(command, ...)` - This line executes the constructed command using `child_process.exec`.  The `command` variable, which includes the potentially malicious `phpCommand` from user settings, is passed directly to `cp.exec`, leading to command injection.
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [VULNERABLE LINE] - User controlled input
        let command = commandTemplate.replace("{code}", code); // [VULNERABLE LINE] - Command construction without sanitization
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [VULNERABLE LINE] - Command execution
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

* Security Test Case:
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned_by_laravel_intellisense'"
    }
    ```
    4. Open VSCode and open the `malicious-repo` directory.
    5. Create a new file named `test.php` in the `malicious-repo` directory with the following content:
    ```php
    <?php

    Route::get('test', function () {
        return view('welcome');
    });
    ```
    6. Open the `test.php` file in the editor. This action should trigger the "Laravel Extra Intellisense" extension to activate and attempt to provide route autocompletion, which will execute the configured `phpCommand`.
    7. After a short delay (to allow the extension to execute), open a terminal and check if the file `/tmp/pwned_by_laravel_intellisense` exists by running the command `ls /tmp/pwned_by_laravel_intellisense`.
    8. If the file `/tmp/pwned_by_laravel_intellisense` exists, the command injection vulnerability is confirmed. The malicious command from `settings.json` was successfully executed by the extension.
