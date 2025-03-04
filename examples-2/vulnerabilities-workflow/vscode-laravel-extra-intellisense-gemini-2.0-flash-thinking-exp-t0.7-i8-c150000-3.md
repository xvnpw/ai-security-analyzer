### Vulnerability List for vscode-laravel-extra-intellisense

* Vulnerability Name: Command Injection via `phpCommand` configuration
* Description:
    1. A threat actor crafts a malicious Laravel repository.
    2. Within this repository, they create a `.vscode/settings.json` file.
    3. This settings file is designed to override the `LaravelExtraIntellisense.phpCommand` setting with a malicious command. For example, it could be set to: `"LaravelExtraIntellisense.phpCommand": "bash -c '{code}'"`.
    4. A victim unknowingly opens this malicious repository in VSCode and activates the Laravel Extra Intellisense extension.
    5. The extension reads the VSCode settings, inadvertently loading the attacker's malicious `phpCommand`.
    6. Subsequently, when the extension requires executing PHP code—for tasks such as fetching routes or configurations—it utilizes the `Helpers.runPhp` function.
    7. The `Helpers.runPhp` function, in turn, employs the now-maliciously configured `phpCommand` to execute the intended PHP code.
    8. Due to the manipulated `phpCommand`, the `{code}` placeholder is no longer treated as PHP code for `php -r`, but as a shell command for `bash -c`.
    9. This allows the attacker to inject arbitrary shell commands by carefully crafting the PHP code that the extension attempts to execute. For instance, if the extension tries to run `echo 1;`, the malicious command becomes `bash -c 'echo 1;'`.
    10. Consequently, the injected shell command gets executed directly on the victim's machine, outside the intended PHP execution environment.
* Impact:
    Remote Code Execution (RCE). By opening a specially crafted Laravel repository, a victim can unknowingly grant an attacker the ability to execute arbitrary shell commands on their machine through the VSCode extension.
* Vulnerability Rank: high
* Currently implemented mitigations:
    None. The extension directly uses the user-configurable `phpCommand` without any form of sanitization or validation.
* Missing mitigations:
    - Implement robust sanitization for the `phpCommand` configuration to prevent command injection. A possible approach is to strictly validate the `phpCommand` to ensure it only permits the execution of `php` and its legitimate arguments, effectively disallowing shell commands like `bash -c`.
    - Consider removing the user-configurability of `phpCommand` altogether. Instead, the extension could rely on a fixed, secure command structure, such as always using `php -r "{code}"`, which would eliminate the risk of user-introduced malicious commands.
    - Incorporate a security warning within the extension's documentation and potentially within VSCode itself upon activation in a workspace. This warning should alert users to the risks associated with opening untrusted repositories, especially concerning VSCode settings that can execute code.
* Preconditions:
    - The victim must open a malicious Laravel repository within VSCode.
    - The Laravel Extra Intellisense extension must be installed and activated in VSCode.
    - The malicious repository must include a `.vscode/settings.json` file that maliciously overrides the `LaravelExtraIntellisense.phpCommand` setting.
* Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp`
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
    - The vulnerability lies in the line `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\";`, where `phpCommand` is directly retrieved from user configuration and used to construct the command executed by `cp.exec`.
* Security test case:
    1. Create a new folder to represent a malicious Laravel repository.
    2. Inside this folder, create a subfolder named `.vscode`.
    3. Within the `.vscode` folder, create a file named `settings.json` with the following content to override the `phpCommand` setting:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "bash -c 'touch command_injection_test.txt; {code}'"
        }
        ```
    4. Open this malicious repository folder in VSCode with the Laravel Extra Intellisense extension activated.
    5. Open any PHP file within the repository (or create a dummy PHP file if none exists).
    6. In the PHP file, initiate an autocompletion request that triggers the execution of a Laravel command. For example, in a Blade template, type `route('`. This action should invoke the extension's functionality that relies on `Helpers.runLaravel` and subsequently `Helpers.runPhp`.
    7. After triggering the autocompletion, check the root of the malicious repository folder.
    8. Verify if a file named `command_injection_test.txt` has been created. If this file exists, it confirms that the command injection was successful, as the `touch` command was executed via the maliciously configured `phpCommand`.
