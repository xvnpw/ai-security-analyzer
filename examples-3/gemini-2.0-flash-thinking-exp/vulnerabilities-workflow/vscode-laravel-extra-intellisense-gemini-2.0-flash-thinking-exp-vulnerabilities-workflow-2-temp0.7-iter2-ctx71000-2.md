- Vulnerability Name: Remote Code Execution via Malicious `phpCommand` Workspace Setting
- Description:
    1. An attacker crafts a malicious Laravel project.
    2. Within this project, the attacker creates a `.vscode/settings.json` file.
    3. In `settings.json`, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command, for example: `"bash -c 'malicious_command' {code}"` or `"malicious_script.sh {code}"`. This command is designed to execute arbitrary code when the extension invokes PHP.
    4. The attacker distributes this malicious Laravel project, tricking a developer into opening it in VSCode with the "Laravel Extra Intellisense" extension installed.
    5. Upon opening the project, VSCode automatically applies the workspace settings from `.vscode/settings.json`, including the malicious `phpCommand`.
    6. When the extension attempts to provide autocompletion or any other feature that requires executing PHP code (e.g., fetching routes, views, configs using `Helpers.runLaravel` or `Helpers.runPhp`), it uses the configured `phpCommand`.
    7. The extension substitutes `{code}` in the malicious `phpCommand` with the PHP code it intends to execute. However, the attacker-controlled base command (e.g., `bash -c 'malicious_command'`) can ignore or misuse the `{code}` part.
    8. The system executes the attacker-specified command, achieving Remote Code Execution (RCE) on the developer's machine with the privileges of the VSCode process.

- Impact:
    - **Critical**. Successful exploitation allows the attacker to execute arbitrary commands on the developer's machine. This can lead to:
        - Full control over the developer's workstation.
        - Theft of source code, credentials, and other sensitive information.
        - Installation of malware, backdoors, or ransomware.
        - Further attacks on internal networks accessible from the developer's machine.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - **Security Note in README.md**: The extension's README.md includes a "Security Note" that advises users about the risks of running the extension and executing their Laravel application automatically. However, this is only a documentation-level warning and does not prevent the vulnerability. It states: "<b>Please read the [security note](#security-note) and [how to configure](#sample-config-to-use-docker) before using the extension.</b>" and later "<b>Security Note</b> This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete. So if you have any unknown errors in your log make sure the extension not causing it. Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing." This note is present in `README.md` file.

- Missing Mitigations:
    - **Input validation for `phpCommand` setting**: The extension lacks validation of the `phpCommand` setting to ensure it is safe. It should verify that the command does not contain potentially malicious code or shell injection vulnerabilities.
    - **Ignoring workspace settings for sensitive commands or user warning**: The extension should either ignore workspace-level settings for `phpCommand` and rely on a default safe command, or display a prominent warning to the user when a workspace setting overrides the default `phpCommand`, especially if the command looks suspicious or deviates from expected patterns.
    - **Sandboxing or least privilege execution**: Consider executing the `phpCommand` in a sandboxed environment or with the least privileges necessary to minimize the impact of potential RCE.

- Preconditions:
    - The victim developer must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim developer must open a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `phpCommand`.
    - The victim must trigger a feature of the extension that executes PHP code, such as opening a PHP or Blade file that initiates autocompletion.

- Source Code Analysis:
    - **`src/helpers.ts` - `runPhp` function**:
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
        - The `runPhp` function retrieves the `phpCommand` from the VSCode configuration (`vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`).
        - It uses this `phpCommand` as a template and substitutes `{code}` with the provided PHP code string.
        - The resulting `command` is then executed using `cp.exec()`.
        - **Vulnerability**: There is no validation or sanitization of the `commandTemplate` retrieved from the configuration. A malicious project can inject any command into this setting via `.vscode/settings.json`.

- Security Test Case:
    1. **Create a malicious Laravel project**: Set up a basic Laravel project structure.
    2. **Create malicious `.vscode/settings.json`**: In the root of the project, create a folder named `.vscode` and inside it a file named `settings.json`. Add the following content to `settings.json`:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/laravel_extra_intellisense_pwned && php -r \"{code}\"'"
        }
        ```
        This malicious command will first attempt to create a file named `laravel_extra_intellisense_pwned` in the `/tmp` directory and then proceed to execute the intended PHP code.
    3. **Open the malicious project in VSCode**: Open the created Laravel project in VSCode with the "Laravel Extra Intellisense" extension activated.
    4. **Trigger extension functionality**: Open any `.php` or `.blade.php` file in the project. This should trigger the extension to run PHP commands for autocompletion. For example, open `routes/web.php` or create and open a new blade file in `resources/views`.
    5. **Verify RCE**: After a short delay (to allow the extension to execute its commands), check if the file `/tmp/laravel_extra_intellisense_pwned` has been created.
        - **Success**: If the file `/tmp/laravel_extra_intellisense_pwned` exists, it confirms that the malicious `phpCommand` from `.vscode/settings.json` was executed, and thus, Remote Code Execution is possible.
        - **Failure**: If the file does not exist, re-examine the steps and ensure the extension is properly activated and triggered. Also, check for any error messages in the VSCode output or developer console.

This test case demonstrates that by setting a malicious `phpCommand` in workspace settings, an attacker can achieve arbitrary code execution when the extension attempts to use its configured PHP command.
