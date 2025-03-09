## Vulnerability List:

- Vulnerability Name: **Command Injection via `phpCommand` Configuration**
  - Description:
    - The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which specifies the command used to execute PHP code within the Laravel application.
    - This setting is used in the `runPhp` function in `helpers.ts` to execute arbitrary PHP code.
    - A malicious actor can provide a crafted repository with a `.vscode/settings.json` file that modifies the `LaravelExtraIntellisense.phpCommand` setting to inject arbitrary shell commands.
    - When a victim opens this malicious repository in VS Code and the extension activates, the injected commands will be executed on the victim's machine with the privileges of the VS Code process.
  - Impact: **RCE (Remote Code Execution)**
    - A threat actor can execute arbitrary commands on the victim's machine, potentially leading to full system compromise, data theft, malware installation, and other malicious activities.
  - Vulnerability Rank: **Critical**
  - Currently Implemented Mitigations:
    - None. The extension directly uses the configured `phpCommand` setting without sanitization or validation.
  - Missing Mitigations:
    - **Input Sanitization and Validation:** The extension must sanitize and validate the `phpCommand` configuration setting to prevent command injection. It should restrict allowed characters and patterns in the command string.
    - **Principle of Least Privilege:**  While directly executing PHP is necessary for the extension's functionality, consider if there are ways to limit the privileges of the executed PHP process. However, for command injection in the `phpCommand` itself, this is less relevant than sanitization.
    - **Warning to User:**  The "Security Note" in the README provides a general warning about the extension executing the Laravel application. However, it does not explicitly warn about the command injection vulnerability in `phpCommand` configuration. A more specific warning about the risks of modifying `phpCommand` and trusting external repositories is needed.
  - Preconditions:
    - Victim opens a malicious repository in VS Code that contains a `.vscode/settings.json` file.
    - Victim has the "Laravel Extra Intellisense" extension installed and activated in VS Code.
    - The malicious `.vscode/settings.json` overrides the `LaravelExtraIntellisense.phpCommand` setting to include malicious commands.
  - Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`

    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\""); // Line 169: Basic escaping of double quotes in PHP code. Ineffective against command injection.
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$"); // Line 171-174: Platform-specific escaping, still ineffective for command injection.
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // Line 175: Retrieves phpCommand from configuration, defaults to "php -r \"{code}\"".
        let command = commandTemplate.replace("{code}", code); // Line 176: Constructs the command by replacing "{code}" with the PHP code, WITHOUT SANITIZATION of commandTemplate.
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // Line 181: Executes the constructed command using child_process.exec.
                { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                function (err, stdout, stderr) {
                    // ... (rest of the function)
                }
            );
        });
        return out;
    }
    ```

    - **Vulnerability Flow:**
        1. The `runPhp` function takes PHP code as input (`code`).
        2. It retrieves the `phpCommand` setting from the extension's configuration.
        3. It constructs the final command string by replacing the `{code}` placeholder in `phpCommand` with the provided `code`. **Crucially, it does not sanitize the `phpCommand` itself**.
        4. It executes this command using `child_process.exec()`.
        5. If a malicious actor can control the `phpCommand` setting (e.g., via `.vscode/settings.json`), they can inject arbitrary shell commands into the execution path.

  - Security Test Case:
    1. Create a new Laravel project (or any directory that VS Code recognizes as a workspace).
    2. Install the "Laravel Extra Intellisense" extension in VS Code.
    3. Create a `.vscode` directory at the root of the project.
    4. Inside `.vscode`, create a `settings.json` file with the following content to inject a malicious command:

    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"calc.exe\");'"
    }
    ```
    *(Note: `calc.exe` is used as a harmless payload for testing. A real attacker would use more malicious commands.)*

    5. Open any PHP or Blade file within the project. This should trigger the extension to run, which will execute the modified `phpCommand`.
    6. Observe that the `calc.exe` application (or equivalent calculator application on the victim's OS) is launched, demonstrating successful command injection.
    7. To further confirm, you can replace `system(\"calc.exe\")` with commands like `system(\"whoami > output.txt\")` and check for the output in the workspace to verify arbitrary command execution and output redirection.

- Vulnerability Name: **Code Injection via `phpCommand` Configuration (PHP Code Context)**
  - Description:
    - Even if a threat actor doesn't inject shell commands, they can still inject arbitrary PHP code through the `phpCommand` configuration within the PHP code context itself.
    - The extension executes PHP code by substituting the `{code}` placeholder in the `phpCommand` with extension-generated PHP code.
    - If the `phpCommand` is manipulated to include additional PHP code outside of the `{code}` placeholder, this extra code will also be executed alongside the intended extension code, leading to code injection within the PHP environment.
  - Impact: **Code Injection**
    - A threat actor can execute arbitrary PHP code within the Laravel application's context. This can be used to bypass application logic, access sensitive data, modify application behavior, or potentially escalate to RCE if the injected PHP code interacts with other system components unsafely.
  - Vulnerability Rank: **High**
  - Currently Implemented Mitigations:
    - None.
  - Missing Mitigations:
    - **Restrict `phpCommand` to only `php -r "{code}"`**:  The simplest mitigation is to disallow users from customizing the `phpCommand` at all and enforce the use of `php -r "{code}"`. This would eliminate the injection point.  If customization is deemed necessary, strict validation is crucial.
    - **Input Validation on `phpCommand`**:  If customization is allowed, strictly validate the `phpCommand` setting.  Ensure it starts with `php` and only allows `-r "{code}"` or a similar safe pattern. Reject any `phpCommand` that contains other commands or attempts to execute external programs.
  - Preconditions:
    - Same as Command Injection vulnerability: Victim opens a malicious repository with a crafted `.vscode/settings.json` that modifies `LaravelExtraIntellisense.phpCommand`.
  - Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    -  (Code snippet is the same as in Command Injection vulnerability analysis - see above).

    - **Vulnerability Flow:**
        1. The `runPhp` function takes PHP code as input (`code`) which is generated by the extension itself.
        2. It retrieves the `phpCommand` setting from configuration.
        3. It directly substitutes `{code}` in the configured `phpCommand` with the extension-generated `code`.
        4. If the attacker sets `LaravelExtraIntellisense.phpCommand` to something like `php -r '<?php malicious_php_code(); ?> {code}'`, then the `malicious_php_code()` will be executed before the intended extension code.

  - Security Test Case:
    1. Create a new Laravel project and install the extension.
    2. Create a `.vscode/settings.json` file with the following malicious `phpCommand`:

    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "php -r '<?php echo \"INJECTED_CODE_EXECUTION\"; ?> {code}'"
    }
    ```

    3. Open any PHP or Blade file.
    4. Examine the "Laravel Extra Intellisense" output channel. If code injection is successful, you will see "INJECTED_CODE_EXECUTION" printed in the output before the regular extension output, confirming the execution of attacker-injected PHP code.
