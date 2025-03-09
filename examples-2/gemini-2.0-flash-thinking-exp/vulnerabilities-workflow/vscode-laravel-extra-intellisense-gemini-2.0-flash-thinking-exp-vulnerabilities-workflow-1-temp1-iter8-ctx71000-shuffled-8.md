### Vulnerability List:

#### 1. Command Injection via `phpCommand` setting

- **Vulnerability Name:** Command Injection in `phpCommand` setting
- **Description:**
    The `Laravel Extra Intellisense` extension allows users to customize the command used to execute PHP code through the `LaravelExtraIntellisense.phpCommand` setting. This setting is directly used in the `runPhp` function in `helpers.ts` to execute PHP commands for collecting project information. By providing a malicious `phpCommand` containing shell commands, an attacker can achieve command injection when the extension executes PHP code. This can be triggered when the extension attempts to gather autocompletion data, which happens automatically and periodically.
    Step-by-step trigger:
    1.  An attacker creates a malicious Laravel repository.
    2.  The attacker includes a `.vscode/settings.json` file in the repository.
    3.  In the `.vscode/settings.json`, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "php -r 'echo \"\"; system(\"whoami\"); echo \"\"; {code}'"`. This command will execute `whoami` system command in addition to the PHP code intended by the extension.
    4.  The attacker shares this malicious repository with a victim (e.g., via GitHub).
    5.  The victim clones and opens the malicious repository in VSCode with the `Laravel Extra Intellisense` extension installed.
    6.  The extension automatically starts and attempts to gather project information to provide autocompletion features. This triggers the execution of PHP code using the user-defined `phpCommand`.
    7.  The malicious command injected in `phpCommand` (e.g., `system("whoami")`) is executed by the system.

- **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary system commands on the victim's machine with the same privileges as the VSCode process. This could lead to:
    -   Data exfiltration: Accessing and stealing sensitive files from the victim's file system.
    -   Malware installation: Installing malware on the victim's machine.
    -   System compromise: Gaining full control over the victim's machine.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    No effective mitigations are implemented. The `runPhp` function in `helpers.ts` performs some basic string replacements on the `$code` parameter, but it does not sanitize the `phpCommand` itself, which is the source of the injection vulnerability.
    The existing code in `Helpers.ts` has these replacements, which are insufficient to prevent command injection via `phpCommand` setting:
    ```typescript
    code = code.replace(/\"/g, "\\\"");
    if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
        code = code.replace(/\$/g, "\\$");
        code = code.replace(/\\\\'/g, '\\\\\\\\\'');
        code = code.replace(/\\\\"/g, '\\\\\\\\\"');
    }
    ```
    These replacements target the `{code}` part, not the `phpCommand` template itself.

- **Missing Mitigations:**
    -   **Restrict `phpCommand` configuration:** Ideally, remove the option for users to customize the `phpCommand` entirely. If customization is deemed necessary, provide only predefined, safe configurations (e.g., for Docker Sail or Laradock) and prevent users from entering arbitrary commands.
    -   **Input Validation:** If `phpCommand` customization is kept, strictly validate the user-provided command. Ensure it only starts with "php" and contains only allowed safe options. Blacklisting or regular expression-based validation is likely insufficient and whitelisting of safe commands is recommended. However, even with validation, ensuring complete safety for arbitrary command templates is complex and risky.
    -   **Parameterization/Escaping for `cp.exec`:** Instead of string concatenation to build the command, consider using methods that properly handle command parameters and escaping, if available for `child_process.exec`. However, even with parameterization of the `{code}` part, if the `phpCommand` template itself is under attacker control, injection is still possible.
    -   **Security Warning:** Enhance the "Security Note" in the README to explicitly and strongly warn users against modifying the `phpCommand` setting due to the high risk of command injection. Recommend using the default setting or only using provided safe examples.

- **Preconditions:**
    1.  Victim has the `Laravel Extra Intellisense` extension installed in VSCode.
    2.  Victim opens a workspace that contains a malicious `.vscode/settings.json` file pre-configured with a malicious `LaravelExtraIntellisense.phpCommand`. Or the victim manually configures this setting to a malicious value.
    3.  The opened workspace must be a Laravel project (or at least appear to be, to trigger extension activity).

- **Source Code Analysis:**
    1.  **File:** `src/helpers.ts`
    2.  **Function:** `Helpers.runPhp(code: string, description: string|null = null)`
    3.  **Line:**
        ```typescript
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        ```
        This line retrieves the `phpCommand` setting from VSCode configuration. If the user has not set it, it defaults to `"php -r \"{code}\""`.
    4.  **Line:**
        ```typescript
        let command = commandTemplate.replace("{code}", code);
        ```
        This line substitutes the `{code}` placeholder in the `commandTemplate` with the `$code` parameter, which contains the PHP code generated by the extension.
    5.  **Line:**
        ```typescript
        cp.exec(command,
            { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
            function (err, stdout, stderr) { ... }
        );
        ```
        This line executes the constructed `command` using `child_process.exec`. The `command` variable is directly built using string concatenation with user-controlled input (`phpCommand` setting) and extension-generated code (`code`). There is no proper sanitization or validation of the `phpCommand` to prevent command injection.

- **Security Test Case:**
    1.  **Setup:**
        -   Ensure you have VSCode installed with the `Laravel Extra Intellisense` extension.
        -   Create a new empty directory to act as a malicious Laravel project (no actual Laravel project is needed to trigger this).
    2.  **Create Malicious Settings:**
        -   Inside the empty directory, create a folder named `.vscode`.
        -   Inside the `.vscode` folder, create a file named `settings.json`.
        -   Add the following content to `settings.json` to inject a command that will create a file named `pwned.txt` in the root of the opened directory using the `touch` command (works on Linux/macOS; for Windows, you can use `cmd /c echo pwned > pwned.txt` or similar):
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r 'echo \"\"; system(\"touch pwned.txt\"); echo \"\"; {code}'"
            }
            ```
            For Windows, use:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "cmd /c php -r 'echo \"\"; system(\"echo pwned > pwned.txt\"); echo \"\"; {code}'"
            }
    3.  **Open Malicious Project:**
        -   Open the empty directory you created in VSCode.
        -   VSCode will load the settings from `.vscode/settings.json`.
    4.  **Trigger Autocompletion:**
        -   Create a new file, for example `test.blade.php`, in the root of the directory. Set language mode to `Blade`.
        -   Inside `test.blade.php`, type `@route('`. This will trigger the route autocompletion feature of the extension, which in turn executes PHP code using `phpCommand`.
    5.  **Verify Command Injection:**
        -   Check the root directory of your opened project.
        -   You should find a new file named `pwned.txt` that has been created by the injected `system("touch pwned.txt")` command (or `pwned.txt` with content "pwned" on Windows).
        -   This confirms that the command injection through `phpCommand` is successful and arbitrary system commands can be executed.
