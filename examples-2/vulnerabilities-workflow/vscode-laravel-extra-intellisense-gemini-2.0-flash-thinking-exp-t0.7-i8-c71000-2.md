## Vulnerability List for Laravel Extra Intellisense VSCode Extension

### 1. Command Injection via `phpCommand` Setting

- **Description:**
    1. The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code.
    2. This setting is intended to allow customization for different environments like Docker or Laravel Sail.
    3. The extension uses this setting in the `runPhp` function in `src/helpers.ts` to execute arbitrary PHP code required for providing autocompletion features.
    4. The `runPhp` function directly substitutes the user-provided PHP code into the configured `phpCommand` template using string replacement.
    5. A malicious repository can include a `.vscode/settings.json` file that modifies the `phpCommand` setting to inject arbitrary shell commands.
    6. When the extension attempts to execute a Laravel command (e.g., to fetch routes or views), the injected shell commands will be executed along with the intended PHP code.
    7. This allows a threat actor to achieve command injection on the victim's machine.

- **Impact:**
    - Remote Code Execution (RCE) on the victim's machine. An attacker can execute arbitrary commands with the privileges of the VSCode user. This can lead to data theft, system compromise, or further malicious activities.

- **Vulnerability Rank:** critical

- **Currently Implemented Mitigations:**
    - None. While the `runPhp` function attempts to escape double quotes and dollar signs in the PHP code itself, it does not sanitize or validate the `phpCommand` setting, making it vulnerable to injection when the setting is maliciously modified.

- **Missing Mitigations:**
    - **Input validation and sanitization:** The extension should validate and sanitize the `phpCommand` setting to ensure it only contains expected commands and arguments. It should prevent users from injecting arbitrary shell commands through this setting.
    - **Restrict command execution:** Instead of directly executing shell commands based on user configuration, the extension should explore safer alternatives for running PHP code, possibly through a more controlled API or by limiting the scope of executable commands.
    - **Warning to user:** If customization of `phpCommand` is necessary, the extension should display a clear warning to the user about the security risks associated with modifying this setting, especially when opening projects from untrusted sources.

- **Preconditions:**
    - The victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim opens a malicious Laravel repository in VSCode.
    - The malicious repository contains a `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` setting to include malicious shell commands.
    - The extension is triggered to execute a Laravel command, for example, by opening a PHP or Blade file that requires autocompletion features.

- **Source Code Analysis:**
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
        let command = commandTemplate.replace("{code}", code); // VULNERABLE LINE: Direct string replacement without sanitization
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Executes the constructed command
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
    - The `commandTemplate.replace("{code}", code)` line is vulnerable because it directly substitutes the `{code}` placeholder in the `commandTemplate` with the `$code` variable without any sanitization or validation of the `commandTemplate` itself. If a malicious user provides a crafted `commandTemplate` (e.g., via `.vscode/settings.json`), they can inject arbitrary shell commands.

- **Security Test Case:**
    1. Create a new folder for a malicious Laravel project (or use an existing empty folder and initialize it as a git repository).
    2. Inside the project folder, create a `.vscode` folder.
    3. Inside the `.vscode` folder, create a `settings.json` file with the following content to override the `phpCommand` setting:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo '[VULNERABLE] Command Injection Successful';"
        }
        ```
    4. Open the project folder in VSCode with the "Laravel Extra Intellisense" extension enabled.
    5. Open any PHP file (e.g., create a simple `test.php` file with `<?php `). This action should trigger the extension to run a Laravel command in the background.
    6. Open the "Output" panel in VSCode (View -> Output) and select "Laravel Extra Intellisense" from the dropdown menu in the Output panel's header.
    7. Check the output in the "Laravel Extra Intellisense" output channel. If you see the line `[VULNERABLE] Command Injection Successful`, it confirms that the command injection vulnerability is present. The injected `echo` command was executed after the intended PHP command.
