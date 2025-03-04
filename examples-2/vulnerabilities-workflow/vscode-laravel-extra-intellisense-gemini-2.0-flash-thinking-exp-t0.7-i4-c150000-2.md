- Vulnerability name: Command Injection via `phpCommand` setting
- Description:
    - The `LaravelExtraIntellisense.phpCommand` setting allows users to customize the command used to execute PHP code by the extension.
    - This setting is directly used in the `cp.exec` function in `helpers.ts` without any sanitization.
    - A malicious user can craft a VSCode workspace settings file (`.vscode/settings.json`) within a repository that modifies this setting to inject arbitrary shell commands.
    - When a victim opens this malicious repository in VSCode and the Laravel Extra Intellisense extension is activated (and attempts to use the `phpCommand`), the injected shell commands will be executed on the victim's machine.
- Impact:
    - Remote Code Execution (RCE).
    - An attacker can execute arbitrary commands on the victim's machine with the same privileges as the VSCode process.
    - This could allow the attacker to steal sensitive data, install malware, or compromise the victim's system.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The extension directly uses the `phpCommand` setting as provided by the user. There is a security note in the README.md, but it is not a mitigation.
    - The README.md contains a "Security Note" warning users about potential issues, but this is not a technical mitigation and relies on user awareness.
- Missing mitigations:
    - Input validation and sanitization of the `phpCommand` setting.
    - The extension should not directly execute user-provided strings as shell commands.
    - Ideally, the extension should avoid using `cp.exec` with user-configurable commands for security-sensitive operations.
    - Consider using safer alternatives for executing PHP code or restrict the characters allowed in the `phpCommand` setting to prevent command injection.
- Preconditions:
    - The victim has the Laravel Extra Intellisense extension installed in VSCode.
    - The victim opens a malicious Laravel repository in VSCode.
    - The malicious repository is crafted to include a `.vscode/settings.json` file that defines a malicious `LaravelExtraIntellisense.phpCommand`.
- Source code analysis:
    - File: `src/helpers.ts`
    - Function: `runPhp(code: string, description: string|null = null)`
    - The `runPhp` function is responsible for executing PHP code.
    - It retrieves the `phpCommand` setting from VSCode configuration:
        ```typescript
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        ```
    - It then constructs the command to be executed by replacing `{code}` in the `commandTemplate` with the provided `$code`:
        ```typescript
        let command = commandTemplate.replace("{code}", code);
        ```
    - Finally, it executes the command using `child_process.exec`:
        ```typescript
        cp.exec(command, ...);
        ```
    - There is no input validation or sanitization performed on either the `phpCommand` setting or the `$code` variable before executing the command. This allows for command injection if a malicious `phpCommand` setting is provided.
- Security test case:
    1. Create a new directory for the malicious repository, e.g., `malicious-repo`.
    2. Navigate into the `malicious-repo` directory in your terminal: `cd malicious-repo`.
    3. Create a `.vscode` directory: `mkdir .vscode`.
    4. Create a `settings.json` file inside the `.vscode` directory: `touch .vscode/settings.json`.
    5. Open `malicious-repo/.vscode/settings.json` in a text editor and add the following malicious configuration:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/pwned_{RANDOM}'"
        }
        ```
        Replace `{RANDOM}` with a random string to ensure unique file creation for each test run (e.g., `pwned_test123`).
    6. Save the `settings.json` file.
    7. Open the `malicious-repo` directory in VSCode with the Laravel Extra Intellisense extension installed and activated.
    8. Trigger any feature of the extension that executes PHP code (e.g., open a Blade file, trigger route autocompletion). This will cause the extension to execute the `phpCommand`.
    9. In your terminal, check if the file `/tmp/pwned_{RANDOM}` (e.g., `/tmp/pwned_test123`) has been created: `ls /tmp/pwned_{RANDOM}`.
    10. If the file exists, the command injection vulnerability is confirmed. The extension executed the injected command from the `phpCommand` setting.
