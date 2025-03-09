### Vulnerability List for Laravel Extra Intellisense VSCode Extension

* Vulnerability Name: Command Injection via `phpCommand` setting
* Description:
    1. The "Laravel Extra Intellisense" extension allows users to configure the `phpCommand` setting, which defines the command used to execute PHP code for Laravel application interaction.
    2. This setting is intended to allow users to customize the PHP execution environment, for example, to use Docker or other specific PHP setups.
    3. However, the extension directly substitutes the user-provided `phpCommand` setting with the PHP code to be executed without proper sanitization.
    4. A malicious user can craft a workspace settings file (e.g., `.vscode/settings.json` in a repository) that overrides the `phpCommand` setting with a command containing malicious shell directives. For example, they could inject commands like `php -r '{code}; system("malicious_command");'`.
    5. When a victim opens a project containing this malicious workspace setting and the extension attempts to run PHP code (which happens automatically to provide autocompletion features), the injected shell commands will be executed by `child_process.exec`.
    6. This results in command injection, allowing the attacker to execute arbitrary commands on the victim's machine with the same privileges as the VSCode process.
* Impact:
    Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's system. This can lead to full system compromise, data theft, malware installation, and other malicious activities.
* Vulnerability Rank: critical
* Currently Implemented Mitigations:
    None. The extension's code directly uses the `phpCommand` setting without any validation or sanitization. The README.md file includes a "Security Note" warning users about potential risks but does not provide any technical mitigation within the extension itself.
* Missing Mitigations:
    - Input validation and sanitization for the `phpCommand` setting to prevent injection of shell commands.
    - Displaying a warning to the user when workspace settings override the default `phpCommand`, especially if it deviates from the expected format.
    - Ideally, avoid using `child_process.exec` with user-configurable strings to execute PHP code. Explore safer alternatives for running PHP code programmatically if possible, or restrict the `phpCommand` to only accept the path to the PHP executable and handle code execution in a more controlled manner.
* Preconditions:
    1. The victim must have the "Laravel Extra Intellisense" VSCode extension installed.
    2. The victim must open a malicious Laravel project in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.phpCommand` setting.
    3. The extension must activate within the opened project, which typically happens automatically when a PHP or Blade file is opened in a recognized Laravel project.
* Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";` - Retrieves the `phpCommand` setting from VSCode configuration. If not set, defaults to `php -r "{code}"`.
    4. Line: `let command = commandTemplate.replace("{code}", code);` -  Constructs the final command string by directly replacing `{code}` in the `commandTemplate` with the `$code` argument. **This is where the vulnerability lies as there is no sanitization of `commandTemplate`**.
    5. Line: `cp.exec(command, ...)` - Executes the constructed `command` using `child_process.exec`.
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        let command = commandTemplate.replace("{code}", code); // VULNERABLE: Command Injection
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
* Security Test Case:
    1. **Setup Malicious Repository:**
        - Create a new Laravel project directory.
        - Inside the project root, create a folder named `.vscode`.
        - Inside `.vscode`, create a file named `settings.json`.
        - Add the following JSON content to `settings.json` to inject a malicious command into the `phpCommand` setting:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"echo ';PWNED!'; > pwned.txt\");'"
          }
          ```
        - Initialize a Git repository, commit the project with the malicious settings, and make it publicly accessible (e.g., on GitHub).
    2. **Victim Steps:**
        - Install the "Laravel Extra Intellisense" extension in VSCode.
        - Clone the malicious repository to your local machine.
        - Open the cloned repository in VSCode.
        - Open any PHP file within the project (e.g., `routes/web.php`). This action will trigger the extension to activate and execute PHP code.
    3. **Verification:**
        - After opening the PHP file, check the project directory for a new file named `pwned.txt`.
        - If `pwned.txt` exists and contains the string `;PWNED!;`, the command injection is successful, and arbitrary code execution is confirmed. This is because the `system("echo ';PWNED!'; > pwned.txt")` part of the malicious `phpCommand` setting was executed.
