- Vulnerability Name: Remote Code Execution via `phpCommand` setting
- Description:
    1. An attacker crafts a malicious `.vscode/settings.json` file.
    2. Within this file, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command. For example: `"LaravelExtraIntellisense.phpCommand": "echo '; system(\\'whoami\\');' | php"`. This command, when executed by the extension, will run the `whoami` system command.
    3. The attacker then tricks a victim into opening a VS Code workspace that includes this malicious `.vscode/settings.json` file. This could be achieved by sending the victim a zip file of a Laravel project containing the malicious settings, or by compromising a public repository and adding the malicious settings.
    4. Once the workspace is opened and the Laravel Extra Intellisense extension is active, the extension automatically attempts to gather autocompletion data.
    5. During this process, the extension executes PHP code using the command specified in `LaravelExtraIntellisense.phpCommand`.
    6. Because the attacker has modified this setting to include `system('whoami')`, the `whoami` command (or any other command the attacker injects) is executed on the victim's machine with the privileges of the VS Code process.
- Impact:
    Successful exploitation of this vulnerability allows the attacker to achieve Remote Code Execution (RCE) on the victim's machine. The attacker can execute arbitrary system commands, potentially leading to:
    - Full compromise of the victim's machine.
    - Data theft, including source code, credentials, and other sensitive information.
    - Installation of malware.
    - Lateral movement within the victim's network if applicable.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - No mitigations are implemented in the provided code to prevent execution of arbitrary commands via the `phpCommand` setting. The extension directly uses the user-provided string as part of the command executed by `child_process.exec`.
    - The README.md file includes a "Security Note" that warns users about the extension running their Laravel application and suggests disabling the extension if sensitive code is present in service providers. However, this is a documentation warning and not a technical mitigation. It relies on the user's awareness and action, which is not a reliable security measure.
- Missing Mitigations:
    - Input sanitization of the `phpCommand` setting. The extension should validate and sanitize the user-provided command to prevent injection of arbitrary system commands.
    - Command validation. Instead of directly using the user-provided string, the extension could have a predefined set of allowed commands or options and validate the user input against this set.
    - Principle of least privilege. While not directly a mitigation for this vulnerability, running the PHP commands with reduced privileges could limit the impact of RCE. However, in the context of VS Code extensions, this might not be easily achievable.
    - Sandboxing or isolation. Running the PHP execution in a sandboxed environment could prevent or limit the impact of RCE.
- Preconditions:
    - The victim must have the "Laravel Extra Intellisense" extension installed and activated in VS Code.
    - The victim must open a workspace in VS Code that contains a malicious `.vscode/settings.json` file crafted by the attacker.
    - The workspace must be a Laravel project or a project that the extension attempts to analyze as a Laravel project (e.g., by containing an `artisan` file).
- Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. This function is responsible for executing PHP code.
    4. Line 128: `let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";`
        - This line retrieves the `phpCommand` setting from the VS Code configuration. If the user has not set a custom command, it defaults to `"php -r \"{code}\""`.
    5. Line 129: `let command = commandTemplate.replace("{code}", code);`
        - This line constructs the final command string by replacing the `{code}` placeholder in the `commandTemplate` with the `$code` parameter, which contains the PHP code to be executed. **Crucially, there is no sanitization or validation of the `code` variable at this point.**
    6. Line 136: `cp.exec(command, ...)`
        - This line uses `child_process.exec` to execute the constructed `command` string. Because the `code` variable is directly inserted into the command without sanitization, and the `commandTemplate` itself is user-configurable, an attacker can inject arbitrary system commands by manipulating either the `code` variable indirectly or directly by controlling `commandTemplate` via settings.

    **Visualization:**

    ```
    User-provided settings (in .vscode/settings.json)
        |
        V
    vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')
        |
        V
    commandTemplate (e.g., "malicious_command {code}")
        |
        V
    command = commandTemplate.replace("{code}", code)  // No sanitization of 'code'
        |
        V
    cp.exec(command)  // Executes the command, including injected malicious parts
        |
        V
    Remote Code Execution
    ```

- Security Test Case:
    1. Create a new directory named `laravel-vuln-test`.
    2. Inside `laravel-vuln-test`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
    ```json
    {
        "LaravelExtraIntellisense.phpCommand": "echo '; system(\"whoami > /tmp/pwned.txt\"); echo \\\"___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___\\\" ; echo \\\"___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___\\\" ;' | php"
    }
    ```
        - This malicious command will execute `whoami` and redirect the output to `/tmp/pwned.txt`. The `echo` commands are added to mimic the extension's output handling and avoid parse errors in the extension's logic.
    4. Open VS Code and open the `laravel-vuln-test` folder as a workspace.
    5. Ensure the "Laravel Extra Intellisense" extension is installed and activated.
    6. Create an empty PHP file named `test.php` in the `laravel-vuln-test` directory. No specific content is needed as the vulnerability triggers when the extension attempts to provide autocompletion, regardless of the file content.
    7. Open `test.php` in the editor. This action, or any other action that triggers the extension's autocompletion features (like typing in a blade file), should cause the extension to execute the malicious command.
    8. After a short delay (to allow the extension to run and the command to execute), open a terminal in VS Code (or use an external terminal) and check if the file `/tmp/pwned.txt` exists and contains the output of the `whoami` command.
    9. If the file `/tmp/pwned.txt` exists and contains the username of the user running VS Code, this confirms that the Remote Code Execution vulnerability is successfully exploited.
