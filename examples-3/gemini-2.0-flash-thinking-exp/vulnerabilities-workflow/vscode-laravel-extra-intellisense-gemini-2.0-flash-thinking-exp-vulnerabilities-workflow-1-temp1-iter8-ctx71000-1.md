## Vulnerability List for vscode-laravel-extra-intellisense

### 1. Command Injection in `phpCommand` configuration

- **Vulnerability Name:** Command Injection in `phpCommand` configuration
- **Description:**
    1. A threat actor crafts a malicious Laravel repository.
    2. The attacker creates a `.vscode/settings.json` file within the repository.
    3. In `.vscode/settings.json`, the attacker defines a malicious `LaravelExtraIntellisense.phpCommand` configuration. This command is designed to execute arbitrary shell commands when the extension uses it. For example, the command could be: `echo '; __VSCODE_LARAVEL_EXTRA_INTELLISENSE_VULNERABILITY_START__; whoami; __VSCODE_LARAVEL_EXTRA_INTELLISENSE_VULNERABILITY_END__; php -r "{code}"'`.
    4. The victim clones and opens this malicious repository in VSCode, with the "Laravel Extra Intellisense" extension installed and activated.
    5. When the extension initializes or performs actions requiring PHP execution (like autocompletion), it reads the `LaravelExtraIntellisense.phpCommand` from the workspace settings.
    6. The extension uses `child_process.exec` in `src/helpers.ts` to execute the command defined in `phpCommand`, without sufficient sanitization or validation.
    7. Because the attacker controls the `phpCommand` setting, they can inject and execute arbitrary shell commands on the victim's machine. In the example above, the `whoami` command will be executed, and its output will be captured.
- **Impact:** Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data theft, malware installation, and other malicious activities.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:** None. The extension directly uses the `phpCommand` string from the configuration without sanitization. The code in `src/helpers.ts` attempts to escape double quotes and some characters for Unix-like systems within the `{code}` placeholder replacement, but it does not sanitize the `phpCommand` itself.
- **Missing Mitigations:**
    - **Input Sanitization:** The extension must sanitize the `phpCommand` configuration value to prevent command injection. This could involve:
        - Whitelisting allowed characters or commands.
        - Parameterizing the command execution to separate commands from arguments.
        - Validating that the configured command is actually a PHP interpreter.
    - **Security Warning:** Display a clear warning to the user when a custom `phpCommand` is configured, especially for workspace settings, highlighting the security risks of executing arbitrary commands.
    - **Restricting Configuration Scope:** Consider restricting the scope of `phpCommand` configuration to user settings only, and disallow workspace settings to prevent malicious repositories from automatically setting a dangerous command. If workspace settings are to be supported, provide a mechanism for users to review and approve workspace settings changes, especially for security-sensitive configurations like `phpCommand`.
    - **Alternative Execution Methods:** Explore safer alternatives to `child_process.exec` for executing PHP code, such as using a more restricted or sandboxed environment, or communicating with a dedicated PHP process in a controlled manner.
- **Preconditions:**
    - The victim has the "Laravel Extra Intellisense" VSCode extension installed.
    - The victim opens a malicious Laravel repository in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.phpCommand`.
    - The extension is activated and attempts to execute a PHP command, triggering the vulnerability.
- **Source Code Analysis:**
    - **File:** `src/helpers.ts`
    - **Function:** `runPhp(code: string, description: string|null = null)`
    - **Lines:**
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
                    function (err, stdout, stderr) { ... }
                );
            });
            return out;
        }
        ```
    - **Explanation:**
        - The `runPhp` function constructs the command to be executed by taking the `phpCommand` from the extension's configuration (`vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`).
        - It replaces the `{code}` placeholder in the configured command with the `$code` argument, which is intended to be the PHP code to execute.
        - **Vulnerability:** The `commandTemplate` (obtained from user configuration) is directly used in `cp.exec(command, ...)` without any sanitization. If a malicious user provides a `phpCommand` that includes shell commands, these commands will be executed by `cp.exec`. The escaping applied to the `$code` variable is insufficient to prevent command injection because the vulnerability lies in the `commandTemplate` itself, which is attacker-controlled via workspace settings.
- **Security Test Case:**
    1. **Setup Malicious Repository:**
        - Create a new empty directory for a dummy Laravel project.
        - Inside this directory, create a `.vscode` folder.
        - Inside `.vscode`, create a `settings.json` file.
        - Add the following JSON content to `settings.json` to inject a command that will write to a file and echo a marker:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "echo '; __VSCODE_LARAVEL_EXTRA_INTELLISENSE_VULNERABILITY_START__; touch /tmp/vscode-laravel-extra-intellisense-vulnerable; echo \"VULNERABLE\"; __VSCODE_LARAVEL_EXTRA_INTELLISENSE_VULNERABILITY_END__; php -r \\\"{code}\\\""
            }
            ```
        - Initialize a dummy Laravel project (you don't need a full Laravel setup, just enough to trigger the extension, e.g., create an `artisan` file and minimal `composer.json`). Or simply ensure the extension activates by having some PHP or blade files in the workspace.
    2. **Open the Repository in VSCode:**
        - Open the directory created in step 1 in VSCode with the "Laravel Extra Intellisense" extension installed and enabled.
        - Open any PHP file or Blade template in the workspace to trigger the extension's functionality and potentially the execution of `phpCommand`.
    3. **Check for Vulnerability:**
        - **Check Output Channel:** Examine the "Laravel Extra Intellisense" output channel in VSCode. If the vulnerability is triggered, you should see the output "VULNERABLE" between `__VSCODE_LARAVEL_EXTRA_INTELLISENSE_VULNERABILITY_START__` and `__VSCODE_LARAVEL_EXTRA_INTELLISENSE_VULNERABILITY_END__`.
        - **Check File System:** Check if the file `/tmp/vscode-laravel-extra-intellisense-vulnerable` has been created. If it exists, it confirms that the `touch` command injected via `phpCommand` was executed, demonstrating command injection.

This test case demonstrates that a malicious repository can inject arbitrary shell commands via the `LaravelExtraIntellisense.phpCommand` setting, leading to Remote Code Execution.
