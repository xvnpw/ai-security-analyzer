### Vulnerability List:

* Vulnerability Name: Command Injection via `phpCommand` setting

* Description:
    1. A threat actor creates a malicious Laravel project.
    2. The malicious project includes a `.vscode/settings.json` file.
    3. In `.vscode/settings.json`, the threat actor sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command, for example: `bash -c "touch /tmp/pwned" && php -r "{code}"`. This command will first execute `touch /tmp/pwned` and then the original php command.
    4. The victim opens this malicious Laravel project in VSCode with the "Laravel Extra Intellisense" extension installed.
    5. When the extension activates and attempts to run any Laravel command (e.g., to fetch routes, views, configs), it will use the maliciously crafted `phpCommand` from the project's settings.
    6. Due to insufficient sanitization of the `phpCommand` setting, the system command injection occurs, and the attacker's injected command (`bash -c "touch /tmp/pwned"`) is executed on the victim's machine before the intended PHP command.

* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode user. This can lead to full system compromise, data exfiltration, installation of malware, and other malicious activities.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - No specific mitigations are implemented in the code to prevent command injection via the `phpCommand` setting. The extension relies on the user-provided `phpCommand` as is, and executes it using `child_process.exec`.

* Missing Mitigations:
    - Input sanitization: The extension should sanitize the `phpCommand` setting to remove or escape potentially dangerous characters and commands. A whitelist of allowed characters or a strict format for the command could be enforced.
    - User warning: The extension should display a clear warning message to the user when a custom `phpCommand` is detected in the workspace settings, highlighting the security risks associated with executing arbitrary commands.
    - Principle of least privilege: Instead of directly using `php -r`, the extension could consider using a more secure way to execute PHP code or interact with the Laravel application, possibly through safer APIs if available, or by limiting the scope of the executed commands.

* Preconditions:
    - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim must open a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.phpCommand` setting.
    - The extension must be activated in the opened workspace, which typically happens automatically upon opening a Laravel project.

* Source Code Analysis:
    1. **File:** `src/helpers.ts`
    2. **Function:** `runPhp(code: string, description: string|null = null)`
    3. **Line:**
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
    4. **Vulnerability Point:** The code retrieves the `phpCommand` from the VSCode configuration (`vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`). This configuration is directly used to construct the command executed by `cp.exec(command, ...)`.
    5. **Lack of Sanitization:** While there are some `replace` operations on the `code` variable, these are insufficient to prevent command injection in the `phpCommand` setting itself. If a user (attacker, in this scenario) provides a malicious command string in the `phpCommand` setting, it will be used verbatim in the `cp.exec` call. The code only escapes double quotes and dollar signs in the `{code}` part, not in the command template itself.
    6. **`cp.exec` Usage:** The `cp.exec` function executes a command in a shell, which is known to be vulnerable to command injection if user-controlled input is not properly sanitized. In this case, the `phpCommand` setting is user-controlled via workspace settings.

* Security Test Case:
    1. **Setup Malicious Project:**
        - Create a new directory named `malicious-laravel-project`.
        - Inside `malicious-laravel-project`, create a `.vscode` directory.
        - Inside `.vscode`, create a `settings.json` file with the following content:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned_by_vscode_extension' && php -r \"{code}\""
          }
          ```
        - Ensure you have a valid Laravel project structure in `malicious-laravel-project` (even a minimal one will suffice, with `artisan` file, `vendor` directory and `bootstrap/app.php`). If you don't have a Laravel project, you can quickly create one using `composer create-project laravel/laravel malicious-laravel-project-content` and move the content to `malicious-laravel-project`.
    2. **Open Project in VSCode:**
        - Open the `malicious-laravel-project` folder in VSCode.
        - Ensure that the "Laravel Extra Intellisense" extension is activated for this workspace.
    3. **Trigger Extension Activity:**
        - Open any PHP file within the project (e.g., a controller or route file). This should trigger the extension to run a Laravel command in the background to gather code completion data.
    4. **Verify Command Injection:**
        - After a short delay (give the extension time to activate and run), check if the file `/tmp/pwned_by_vscode_extension` exists on your system.
        - On Linux/macOS, you can use the command `ls -l /tmp/pwned_by_vscode_extension`. If the file exists, it confirms that the injected command `touch /tmp/pwned_by_vscode_extension` was executed successfully, proving the command injection vulnerability.

This test case demonstrates that by crafting a malicious `phpCommand` within a project's `.vscode/settings.json`, an attacker can achieve arbitrary command execution on the machine of a user who opens the project in VSCode with the vulnerable extension installed.
