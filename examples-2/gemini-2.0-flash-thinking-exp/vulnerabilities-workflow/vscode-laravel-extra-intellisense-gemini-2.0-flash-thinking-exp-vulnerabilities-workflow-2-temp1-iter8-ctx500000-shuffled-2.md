- Vulnerability Name: Command Injection via `LaravelExtraIntellisense.phpCommand` setting
- Description:
    1. A user installs the "Laravel Extra Intellisense" VSCode extension.
    2. The extension relies on executing PHP commands within the user's Laravel project to provide autocompletion features.
    3. The command used to execute PHP code is configurable through the `LaravelExtraIntellisense.phpCommand` setting.
    4. A malicious actor can trick a user into setting a harmful PHP command in their VSCode settings for `LaravelExtraIntellisense.phpCommand`. For example, setting the command to `bash -c "{code}"`.
    5. When the extension attempts to gather information about the Laravel project (e.g., routes, views, configs), it replaces the `{code}` placeholder in the user-configured `phpCommand` with generated PHP code.
    6. Due to the lack of input sanitization, if a malicious command like `bash -c "{code}"` is configured, the extension will execute `bash -c "generated php code"` instead of just `php -r "generated php code"`.
    7. The attacker can leverage this to inject arbitrary shell commands by crafting specific PHP code that, when embedded into the `bash -c "{code}"` command, executes malicious commands on the user's system.
- Impact:
    - **High/Critical**: If successfully exploited, this vulnerability allows an attacker to execute arbitrary commands on the user's system with the same privileges as the VSCode process. This could lead to:
        - **Unauthorized Access**: Attacker gaining access to sensitive files, environment variables, and other project resources.
        - **Data Breach**: Exfiltration of source code, database credentials, and other sensitive data.
        - **System Compromise**: Full control over the user's development environment, potentially leading to further attacks on other systems or networks.
        - **Malware Installation**: Installation of malware, backdoors, or ransomware on the user's machine.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - **Security Note in README.md**: The README.md file includes a "Security Note" that warns users about the extension running their Laravel application and suggests disabling the extension if sensitive code exists. This is a weak mitigation as it relies on user awareness and does not prevent the vulnerability itself.
- Missing Mitigations:
    - **Input Sanitization**: The extension should sanitize or validate the `LaravelExtraIntellisense.phpCommand` setting to prevent execution of arbitrary commands. It should ensure that the command only executes PHP using the `php -r` command.
    - **Parameter Validation**:  Validate the generated `{code}` before embedding it into the command to prevent code injection within the PHP execution itself.
    - **Principle of Least Privilege**: Consider if the extension needs to execute shell commands at all. If possible, explore alternative ways to gather Laravel project information without relying on shell execution, or use safer methods like direct PHP parsing within the extension's process if feasible and secure.
    - **Content Security Policy (CSP) for Settings**: VSCode extensions can define CSP for their settings. Consider using CSP to restrict the `LaravelExtraIntellisense.phpCommand` setting to only allow safe commands. However, VSCode settings CSP might be limited in what it can effectively restrict for shell commands.
    - **User Permission Warning**: When the extension detects a potentially dangerous configuration of `LaravelExtraIntellisense.phpCommand` (e.g., not starting with "php -r"), display a prominent warning to the user, highlighting the security risks and recommending safe configurations.
- Preconditions:
    1. User has installed the "Laravel Extra Intellisense" VSCode extension.
    2. User has a Laravel project open in VSCode.
    3. User, or someone with access to their VSCode settings (e.g., through settings sync in a compromised account or a social engineering attack), configures the `LaravelExtraIntellisense.phpCommand` setting to a malicious command like `bash -c "{code}"`.
- Source Code Analysis:
    1. **`helpers.ts` - `Helpers.runPhp(code: string, description: string|null = null)` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\""); // Line 1
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) { // Line 2
                code = code.replace(/\$/g, "\\$"); // Line 3
                code = code.replace(/\\\\'/g, '\\\\\\\\\''); // Line 4
                code = code.replace(/\\\\"/g, '\\\\\\\\\"'); // Line 5
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Line 6
            let command = commandTemplate.replace("{code}", code); // Line 7
            let out = new Promise<string>(function (resolve, error) { // Line 8
                if (description != null) { // Line 9
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description); // Line 10
                } // Line 11

                cp.exec(command, // Line 12
                    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined }, // Line 13
                    function (err, stdout, stderr) { // Line 14
                        if (err == null) { // Line 15
                            if (description != null) { // Line 16
                                Helpers.outputChannel?.info("Laravel Extra Intellisense Resolved: " + description); // Line 17
                            } // Line 18
                            resolve(stdout); // Line 19
                        } else { // Line 20
                            const errorOutput = stderr.length > 0 ? stderr : stdout; // Line 21
                            Helpers.outputChannel?.error("Laravel Extra Intellisense Error:\n " + (description ?? '') + '\n\n' + errorOutput); // Line 22
                            Helpers.showErrorPopup(); // Line 23
                            error(errorOutput); // Line 24
                        } // Line 25
                    } // Line 26
                ); // Line 27
            }); // Line 28
            return out; // Line 29
        }
        ```
        - **Line 6**: Retrieves the `phpCommand` setting from VSCode configuration. If not set, defaults to `"php -r \"{code}\""`.
        - **Line 7**:  Replaces the `{code}` placeholder in the retrieved `commandTemplate` with the `$code` parameter, which contains the PHP code generated by the extension.
        - **Line 12**: Executes the constructed `command` using `child_process.exec()`.
        - **Vulnerability**: There is no validation or sanitization of the `commandTemplate` retrieved from user settings. If a user sets `LaravelExtraIntellisense.phpCommand` to a malicious command like `bash -c "{code}"`, the extension will directly execute it, leading to command injection when `{code}` is replaced with PHP code, which can be crafted to inject shell commands.

    2. **`helpers.ts` - `Helpers.runLaravel(code: string, description: string|null = null)` function:**
        - This function calls `Helpers.runPhp` after wrapping the provided `$code` with Laravel bootstrapping code. Any vulnerability in `Helpers.runPhp` is directly exploitable through `Helpers.runLaravel`.

    3. **Providers (`ConfigProvider.ts`, `RouteProvider.ts`, etc.):**
        - All providers use `Helpers.runLaravel` to execute PHP code within the Laravel application context.
        - For example, `ConfigProvider.ts` uses `Helpers.runLaravel("echo json_encode(config()->all());", "Configs")` to fetch configuration values.
        - If `LaravelExtraIntellisense.phpCommand` is maliciously configured, every feature of the extension that relies on these providers becomes a potential trigger for command injection.
- Security Test Case:
    1. **Prerequisites:**
        - VSCode with "Laravel Extra Intellisense" extension installed.
        - Open a Laravel project in VSCode (a dummy project is sufficient).
    2. **Setup Malicious `phpCommand`:**
        - Open VSCode settings (File -> Preferences -> Settings -> Settings or Code -> Settings -> Settings).
        - Search for "Laravel Extra Intellisense PHP Command".
        - In the "Laravel-extra-intellisense: Php Command" setting, enter the following malicious command: `bash -c "{code}"`. This will execute the code through bash instead of directly with PHP.
    3. **Trigger Extension Feature:**
        - Open any PHP or Blade file in the Laravel project.
        - Type `config('app.` or `route('` or `view('` to trigger autocompletion for configs, routes, or views, respectively. This will cause the extension to execute a PHP command using the malicious `phpCommand` setting.
    4. **Verify Command Injection:**
        - Observe the system behavior. A simple way to verify command injection is to inject a command that creates a file in the project directory. Modify the malicious `phpCommand` to: `bash -c "{code} && touch pwnd.txt"`.
        - Repeat step 3.
        - Check if a file named `pwnd.txt` has been created in the project's root directory. If yes, it confirms successful command injection.
        - Alternatively, observe the "Laravel Extra Intellisense" output channel in VSCode (View -> Output, select "Laravel Extra Intellisense" in the dropdown). Error messages or unusual output may also indicate command injection or failed PHP execution due to the modified command.
    5. **Cleanup:**
        - Reset the "Laravel-extra-intellisense: Php Command" setting back to the default value: `php -r "{code}"`.
        - Delete the `pwnd.txt` file if it was created.
