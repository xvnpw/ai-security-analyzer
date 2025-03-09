### Vulnerability List for Laravel Extra Intellisense VSCode Extension

* Vulnerability Name: Command Injection via `phpCommand` Configuration

* Description:
    1. The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code for Laravel application interaction. This setting is intended for customization to support various environments like Docker or Laravel Sail.
    2. The extension utilizes `child_process.exec` in the `runPhp` function (located in `src/helpers.ts`) to execute this configured command. The placeholder `{code}` within the `phpCommand` is replaced with dynamically generated PHP code by the extension, which is used to fetch autocompletion data from the Laravel application.
    3. A malicious actor can create a workspace containing a crafted `.vscode/settings.json` file (or manipulate user settings directly). This malicious configuration modifies `LaravelExtraIntellisense.phpCommand` to inject arbitrary shell commands. For instance, an attacker could set the command to `php -r 'system("<malicious command>"); {code}'` or `php -r \"{code}\" && calc.exe`.
    4. When the extension attempts to provide autocompletion suggestions or perform other tasks requiring Laravel application interaction, it executes PHP code using the attacker-controlled `phpCommand`. This execution results in the injected shell commands being executed on the victim's machine.

* Impact:
    Remote Code Execution (RCE). Successful exploitation grants an attacker the ability to execute arbitrary commands on the machine running VSCode, with the same privileges as the VSCode process. This can lead to severe consequences, including:
    - Complete compromise of the user's system.
    - Unauthorized exfiltration of sensitive data from the victim's machine or projects.
    - Installation of malware, backdoors, or other malicious software.
    - Unauthorized modification or deletion of critical files and system configurations.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - **Security Note in README.md:** The extension's README.md file includes a "Security Note" that alerts users about the inherent risks associated with the extension automatically executing their Laravel application. It advises caution and suggests temporarily disabling the extension when working with sensitive code, particularly in service providers.  However, this is a warning, not a technical mitigation.
    - **Basic escaping of double quotes in PHP code:** The `runPhp` function in `src/helpers.ts` attempts to escape double quotes (`"`) within the dynamically generated PHP code by replacing them with escaped double quotes (`\"`). Additionally, on Unix-like systems, it attempts to escape `$` and further escape single and double quotes.  However, these basic escaping attempts are insufficient to prevent command injection through the `phpCommand` configuration itself and don't address various other shell injection vectors.

* Missing Mitigations:
    - **Robust Input Validation and Sanitization of `phpCommand`:** The extension lacks proper validation and sanitization of the `phpCommand` configuration setting.  This is crucial to prevent the injection of shell-sensitive characters and commands.  Effective sanitization could involve:
        - Implementing a strict whitelist of allowed characters within the `phpCommand`.
        - Robustly escaping all shell-sensitive characters using appropriate escaping mechanisms for the target shell environment.
        - Ideally, enforcing a predefined, safe command structure and tightly controlling which parts of the command can be user-configured.
    - **Secure Command Execution via `child_process.spawn`:** The extension should replace the usage of `child_process.exec`, which executes commands through a shell and is inherently vulnerable to command injection, with `child_process.spawn`.  `child_process.spawn` allows passing command arguments as an array, bypassing shell interpretation and significantly reducing the risk of command injection.
    - **Principle of Least Privilege & Sandboxing:** Explore options to execute the PHP code in a more isolated or sandboxed environment with reduced privileges. This would limit the potential damage from successful command injection.
    - **Prominent Security Warning in VSCode UI:** Implement a more prominent security warning displayed directly within the VSCode UI when the extension is activated in a workspace. This warning should clearly highlight the security risks associated with custom `phpCommand` configurations and avoid relying solely on the README.md, which users may not always read. Consider prompting for user confirmation when a workspace setting overrides the `phpCommand`, especially if the workspace originates from an external source.

* Preconditions:
    - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim must open a workspace in VSCode that contains a malicious configuration, either through a compromised `.vscode/settings.json` file within the workspace or manipulated user settings. This malicious configuration must set a malicious `LaravelExtraIntellisense.phpCommand`.
    - The Laravel Extra Intellisense extension must be activated for the opened workspace.
    - The extension must perform an action that triggers the execution of PHP code using the `runLaravel` or `runPhp` functions. This typically occurs automatically during normal extension usage to provide features like autocompletion for routes, views, configs, etc., when editing PHP or Blade files.

* Source Code Analysis:
    1. **`src/helpers.ts` - `runPhp` function:**
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
        - The `runPhp` function retrieves the `phpCommand` setting from the VSCode configuration. This setting is user-configurable and can be defined in workspace settings (`.vscode/settings.json`) or user settings.
        - Basic and insufficient escaping is performed on the `code` variable, which is intended to contain PHP code. This escaping attempts to handle double quotes and, on Unix-like systems, dollar signs and more complex quote escaping. However, it does not sanitize the `commandTemplate` (the `phpCommand` setting itself), which is the primary source of the command injection vulnerability.
        - The `command` variable is constructed by replacing the `{code}` placeholder in the `commandTemplate` with the `$code`. Critically, the `commandTemplate` originates from the user-controlled `phpCommand` configuration.
        - `cp.exec(command, ...)` executes the constructed `command`. The use of `child_process.exec` is the root cause of the vulnerability. `exec` executes commands within a shell environment. If the `command` string contains shell-sensitive characters or commands (introduced via the malicious `phpCommand` setting), these will be interpreted by the shell, leading to command injection.

    2. **Configuration Loading:**
        - VSCode loads configuration settings from multiple sources, with workspace settings having precedence over user settings when a workspace is opened. Workspace settings are typically stored in `.vscode/settings.json` within the workspace root.
        - This configuration loading mechanism allows a malicious user to embed a compromised `.vscode/settings.json` file within a Laravel project. When a victim opens this project in VSCode, the extension loads the malicious workspace settings, including the injected `phpCommand`.

    3. **Extension Features Triggering PHP Execution:**
        - Various features of the extension, such as autocompletion for Laravel-specific elements (routes, views, configs, translations), trigger the execution of PHP code to gather necessary data from the Laravel application.
        - For example, the `loadRoutes()` function in `src/RouteProvider.ts` calls `Helpers.runLaravel(...)`, which in turn utilizes `runPhp` to execute PHP code and retrieve route information.  Similar patterns exist for other features relying on backend Laravel application data.

* Security Test Case:
    1. **Setup:**
        - Create a new directory to serve as a VSCode workspace (or utilize an existing one for testing purposes).
        - Inside the workspace directory, create a `.vscode` folder if it doesn't already exist.
        - Create a `settings.json` file within the `.vscode` folder.
        - Add the following JSON content to `settings.json` to define a malicious `phpCommand` that will create a file in the `/tmp` directory as a proof of concept:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/pwned_by_laravel_intellisense\"); {code}'"
            }
            ```
            *(Alternatively, for Windows testing, you could use a command like `"php -r \\"{code}\\" && calc.exe"` to launch the calculator application)*
        - Open VSCode and open the workspace directory created in step 1.
        - Ensure that the Laravel Extra Intellisense extension is installed and activated for this workspace.
        - Create a dummy PHP file within the workspace, for instance, `test.php`, with the following content to trigger view autocompletion:
            ```php
            <?php

            Route::get('', function () {
                view('welcome'); // Trigger view autocompletion
            });
            ```
            *(Note: A fully functional Laravel project is not required for this test; a workspace and a PHP file are sufficient)*

    2. **Trigger Vulnerability:**
        - Open the `test.php` file in the VSCode editor.
        - Place the text cursor inside the `view('')` function call, specifically between the single quotes.
        - Initiate autocompletion by typing within the quotes or by manually triggering autocompletion (usually with `Ctrl+Space`). This action will prompt the extension to execute PHP code to fetch view suggestions, employing the malicious `phpCommand` from `settings.json`.

    3. **Verify Exploitation:**
        - After triggering autocompletion, check for the existence of the file `/tmp/pwned_by_laravel_intellisense` on your system.
        - On Linux or macOS, use the command `ls /tmp/pwned_by_laravel_intellisense` in a terminal. On Windows, check `C:\tmp` or the appropriate temporary directory if `/tmp` is not directly accessible. If you used the `calc.exe` payload on Windows, verify that the Calculator application has launched.
        - The successful creation of the `pwned_by_laravel_intellisense` file in `/tmp` (or the execution of `calc.exe` on Windows) confirms that the injected `system()` command within the malicious `phpCommand` was executed. This demonstrates successful command injection and Remote Code Execution vulnerability exploitation.
