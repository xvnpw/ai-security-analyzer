## Combined Vulnerability List for vscode-laravel-extra-intellisense

This document combines multiple reports detailing a critical vulnerability within the vscode-laravel-extra-intellisense extension. All reports consistently identify a Command Injection vulnerability stemming from the insecure handling of the `LaravelExtraIntellisense.phpCommand` configuration setting.

* Vulnerability Name: Command Injection in `phpCommand` Configuration
    * Description:
        1. The "Laravel Extra Intellisense" VSCode extension allows users to customize the command used to execute PHP code by configuring the `LaravelExtraIntellisense.phpCommand` setting. This feature is intended to support diverse development environments, including Docker and Laravel Sail.
        2. The extension leverages this configurable `phpCommand` within the `runPhp` function in `src/helpers.ts` to execute PHP code necessary for providing core features like autocompletion, route discovery, and view analysis.
        3. A threat actor can exploit this by crafting a malicious Laravel project and embedding a `.vscode/settings.json` file within it.
        4. This malicious `settings.json` file redefines the `LaravelExtraIntellisense.phpCommand` setting to inject arbitrary shell commands alongside the legitimate PHP execution.  For instance, an attacker could set `phpCommand` to execute commands like `touch /tmp/pwned` or even more harmful payloads.
        5. When a victim, who has the "Laravel Extra Intellisense" extension installed, opens this malicious Laravel project in VSCode, the extension reads the workspace settings, including the attacker-controlled `phpCommand`.
        6. Subsequently, whenever the extension attempts to gather information for features like autocompletion, it executes PHP code using the compromised `phpCommand`. This triggers the execution of the injected shell commands due to insufficient sanitization within the extension.
        7. This results in a command injection vulnerability, granting the attacker the ability to execute arbitrary commands on the victim's machine with the privileges of the VSCode process.

    * Impact:
        * **Remote Code Execution (RCE).** Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the victim's machine. This can lead to severe consequences, including:
            * **Full System Compromise:** Attackers can gain complete control over the victim's system.
            * **Data Theft:** Sensitive data, including source code, credentials, and personal files, can be exfiltrated.
            * **Malware Installation:** Malware, ransomware, or other malicious software can be installed on the victim's machine.
            * **Further Malicious Activities:** The compromised system can be used as a staging point for attacks on other systems or networks.

    * Vulnerability Rank: Critical

    * Currently Implemented Mitigations:
        * None. The extension directly utilizes the `phpCommand` setting as provided in the workspace configuration without any form of sanitization or validation.
        * While the `README.md` file includes a "Security Note" advising users about potential risks associated with executing their Laravel application within the extension, it does not specifically address or mitigate the command injection vulnerability stemming from the `phpCommand` configuration.
        * Some basic escaping of double quotes and certain characters for Unix-like systems is present within the `runPhp` function when handling the `{code}` placeholder replacement. However, this escaping is insufficient to prevent command injection via the `phpCommand` setting itself.

    * Missing Mitigations:
        * **Input Sanitization and Validation for `phpCommand`:** The extension must implement robust sanitization and validation of the `LaravelExtraIntellisense.phpCommand` setting. This should include:
            * **Strict Whitelisting:** Define a whitelist of allowed characters and command structures for the `phpCommand` setting, rejecting any input that deviates from the expected format.
            * **Parameterized Command Execution:**  Explore safer alternatives to `child_process.exec`, such as `child_process.spawn` with carefully constructed command arguments, to prevent shell interpretation of metacharacters.
            * **Validation of Command Path:** Ensure that the configured command is indeed a PHP interpreter and not an arbitrary executable.
        * **Security Warning to User:** Implement clear and prominent security warnings within the extension:
            * **Workspace Trust Warning:** Display a warning message to the user when a workspace with a custom `phpCommand` setting is opened, especially if the workspace is from an untrusted source. This warning should explicitly highlight the potential security risks of command injection and RCE.
            * **Settings Description Warning:** Add a clear warning within the settings description for `LaravelExtraIntellisense.phpCommand` in VSCode, emphasizing the security implications of modifying this setting and advising users to only modify it if they fully understand the risks.
        * **Restrict Configuration Scope:** Consider restricting the scope of the `phpCommand` setting to user settings only, disallowing workspace-level configurations. If workspace settings are necessary, implement a mechanism for users to review and approve workspace setting changes, particularly for security-sensitive configurations like `phpCommand`.
        * **Principle of Least Privilege:** Explore alternative, safer methods for executing PHP code or interacting with the Laravel application to gather necessary data, minimizing reliance on shell commands and `child_process.exec`.

    * Preconditions:
        * The victim user must have the "Laravel Extra Intellisense" extension installed in VSCode.
        * The victim user must open a malicious Laravel repository in VSCode.
        * The malicious repository must contain a crafted `.vscode/settings.json` file that sets a malicious `LaravelExtraIntellisense.phpCommand`.
        * The "Laravel Extra Intellisense" extension must be activated within the opened workspace. This typically occurs automatically when opening a Laravel project or files associated with Laravel development.
        * An action that triggers the extension to execute PHP code must be performed (e.g., opening a Blade template, triggering autocompletion features).

    * Source Code Analysis:
        1. **File:** `src/helpers.ts`
        2. **Function:** `runPhp(code: string, description: string|null = null)`
        3. **Vulnerable Code Snippet:**
            ```typescript
            static async runPhp(code: string, description: string|null = null) : Promise<string> {
                code = code.replace(/\"/g, "\\\"");
                if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                    code = code.replace(/\$/g, "\\$");
                    code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                    code = code.replace(/\\\\"/g, '\\\\\\\\\"');
                }
                let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [VULNERABLE LINE] - Retrieves user-controlled phpCommand from configuration
                let command = commandTemplate.replace("{code}", code); // [VULNERABLE LINE] - Constructs command string via simple string replacement, no sanitization of commandTemplate
                let out = new Promise<string>(function (resolve, error) {
                    if (description != null) {
                        Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                    }

                    cp.exec(command, // [VULNERABLE LINE] - Executes the command string using child_process.exec, vulnerable to command injection
                        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                        function (err, stdout, stderr) {
                            // ...
                        }
                    );
                });
                return out;
            }
            ```
        4. **Explanation:**
            * The `runPhp` function is responsible for executing PHP code within the extension.
            * It fetches the `phpCommand` setting from VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`. This setting is directly controlled by the user, including through workspace settings in `.vscode/settings.json`.
            * The code then constructs the command to be executed by simply replacing the `{code}` placeholder in the `commandTemplate` with the `$code` argument. **Crucially, there is no sanitization or validation performed on the `commandTemplate` itself before this replacement or before execution.**
            * Finally, the constructed `command` string is passed to `cp.exec()`. `cp.exec()` executes commands in a shell environment. If the `phpCommand` setting contains shell metacharacters or malicious commands, these will be interpreted and executed by the shell, leading to command injection. The limited escaping applied to the `$code` variable is insufficient to mitigate this vulnerability because the attack vector is within the `commandTemplate` itself, which is user-configurable and unsanitized.

    * Security Test Case:
        1. **Setup Malicious Repository:**
            * Create a new directory to represent a malicious Laravel project (e.g., `malicious-laravel-repo`).
            * Inside `malicious-laravel-repo`, create a `.vscode` directory.
            * Within `.vscode`, create a `settings.json` file.
            * Add the following JSON content to `settings.json` to inject a command that will create a file `/tmp/pwned_vscode_laravel_ext` and execute the intended PHP code:
                ```json
                {
                    "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned_vscode_laravel_ext' && php -r \"{code}\""
                }
                ```
            * Initialize a minimal Laravel project structure (or simply ensure the extension activates by including some PHP or Blade files). A minimal `artisan` file and basic directory structure are sufficient for testing.
        2. **Open the Malicious Repository in VSCode:**
            * Open the `malicious-laravel-repo` directory in VSCode with the "Laravel Extra Intellisense" extension installed and enabled.
        3. **Trigger Extension Activity:**
            * Open any PHP file or Blade template in the workspace. This will trigger the extension to initialize and potentially execute the `phpCommand`. Actions like triggering autocompletion (e.g., typing `route('` in a Blade file) will also invoke `phpCommand`.
        4. **Check for Vulnerability:**
            * **Verify File Creation:** After triggering extension activity, check if the file `/tmp/pwned_vscode_laravel_ext` has been created on your system. Use the command `ls -l /tmp/pwned_vscode_laravel_ext` in a terminal.
            * **Success Condition:** If the file `/tmp/pwned_vscode_laravel_ext` exists, it confirms that the injected command `touch /tmp/pwned_vscode_laravel_ext` from the malicious `phpCommand` setting was executed. This successfully demonstrates the command injection vulnerability, proving that arbitrary shell commands can be executed by a malicious workspace via the `LaravelExtraIntellisense.phpCommand` setting.
