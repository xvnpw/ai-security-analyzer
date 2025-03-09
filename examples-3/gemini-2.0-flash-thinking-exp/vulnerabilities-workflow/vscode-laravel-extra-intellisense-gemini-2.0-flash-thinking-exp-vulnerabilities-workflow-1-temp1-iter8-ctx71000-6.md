### Vulnerability List for Laravel Extra Intellisense VSCode Extension

*   #### Command Injection via `phpCommand` setting

    *   **Description:**
        1.  The "Laravel Extra Intellisense" VSCode extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which specifies the command used to execute PHP code to gather autocompletion data from a Laravel application.
        2.  This setting is intended to allow customization for environments like Docker or remote servers. However, the extension uses `child_process.exec` in `helpers.ts` to execute this command without sufficient sanitization of the user-provided `phpCommand` setting.
        3.  A malicious user can craft a workspace configuration (e.g., `.vscode/settings.json`) that sets `LaravelExtraIntellisense.phpCommand` to inject arbitrary shell commands.
        4.  When the extension activates or performs autocompletion tasks, it executes PHP code by running the command specified in `phpCommand`. If this command is malicious, it will execute the injected commands on the victim's machine.
        5.  For example, an attacker could set `phpCommand` to `php -r "{code}; whoami > /tmp/malicious_output"`. When the extension runs a PHP command, the `whoami` command will also be executed, and its output will be redirected to `/tmp/malicious_output`.

    *   **Impact:**
        *   **Remote Code Execution (RCE):** An attacker can execute arbitrary shell commands on the machine where the victim has opened the malicious workspace. This can lead to complete compromise of the victim's system, including data theft, malware installation, and further propagation of attacks.

    *   **Vulnerability Rank:** critical

    *   **Currently Implemented Mitigations:**
        *   None. The extension directly uses the user-provided `phpCommand` setting in `child_process.exec` without sanitization. The `README.md` contains a "Security Note" warning users about potential issues, but this is not a technical mitigation.

    *   **Missing Mitigations:**
        *   **Input Sanitization:** The extension should sanitize the `phpCommand` setting to prevent command injection. This could involve:
            *   Whitelisting allowed characters or command structures.
            *   Using parameterized execution methods if available in `child_process` to separate commands from arguments.
            *   Ideally, avoid using `child_process.exec` with user-controlled strings directly. Consider using `child_process.spawn` and carefully constructing the command and arguments array, ensuring no shell injection is possible.
        *   **Security Warnings:**  If full sanitization is not feasible, the extension should display a prominent warning to the user upon workspace opening if a custom `phpCommand` is detected, especially when the workspace is from an untrusted source.

    *   **Preconditions:**
        1.  Victim has the "Laravel Extra Intellisense" VSCode extension installed.
        2.  Victim opens a malicious workspace in VSCode that contains a `.vscode/settings.json` file with a manipulated `LaravelExtraIntellisense.phpCommand` setting.
        3.  The extension attempts to run a PHP command (e.g., during autocompletion or initial workspace analysis).

    *   **Source Code Analysis:**
        1.  **File:** `src/helpers.ts`
        2.  **Function:** `Helpers.runPhp(code: string, description: string|null = null)`
        3.  **Code Snippet:**
            ```typescript
            static async runPhp(code: string, description: string|null = null) : Promise<string> {
                code = code.replace(/\"/g, "\\\"");
                if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                    code = code.replace(/\$/g, "\\$");
                    code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                    code = code.replace(/\\\\"/g, '\\\\\\\\\"');
                }
                let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
                let command = commandTemplate.replace("{code}", code); // Vulnerable line - user controlled phpCommand is concatenated with php code using simple string replacement
                let out = new Promise<string>(function (resolve, error) {
                    if (description != null) {
                        Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                    }

                    cp.exec(command, // Vulnerable line - command is executed using child_process.exec
                        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                        function (err, stdout, stderr) {
                            // ...
                        }
                    );
                });
                return out;
            }
            ```
        4.  **Vulnerability Flow:**
            *   The `runPhp` function retrieves the `phpCommand` setting from VSCode configuration using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
            *   It then constructs the full command string by using `.replace("{code}", code)` on the `commandTemplate`. This is a simple string concatenation, and does not properly sanitize the `phpCommand` setting.
            *   The concatenated command is then directly passed to `cp.exec()`.
            *   `cp.exec()` executes the command in a shell, which is vulnerable to command injection if the `phpCommand` setting contains malicious shell metacharacters. The attempt to escape quotes and dollar signs is insufficient and easily bypassed.

    *   **Security Test Case:**
        1.  Create a new directory named `malicious-laravel-workspace`.
        2.  Inside `malicious-laravel-workspace`, create a subdirectory named `.vscode`.
        3.  Inside `.vscode`, create a file named `settings.json` with the following content:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r '{code}; touch /tmp/rce_vulnerability_proof'"
            }
            ```
        4.  Open VSCode and open the `malicious-laravel-workspace` folder.
        5.  Wait for the "Laravel Extra Intellisense" extension to activate.
        6.  Open any PHP file or Blade file within the workspace. This will trigger the extension to run a PHP command.
        7.  **Verification:** Check if the file `/tmp/rce_vulnerability_proof` has been created. If the file exists, it confirms that the injected command `touch /tmp/rce_vulnerability_proof` was successfully executed, proving the command injection vulnerability.
