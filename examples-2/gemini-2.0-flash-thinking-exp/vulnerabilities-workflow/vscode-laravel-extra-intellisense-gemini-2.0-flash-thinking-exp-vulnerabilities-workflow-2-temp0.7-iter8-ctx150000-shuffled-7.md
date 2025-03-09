* Vulnerability name: Command Injection via `phpCommand` Configuration
* Description:
    1. The extension allows users to configure the command used to execute PHP code via the `LaravelExtraIntellisense.phpCommand` setting. This setting is intended to allow users to customize the PHP execution environment, for example when using Docker or other virtualized environments.
    2. The extension utilizes this `phpCommand` setting to run PHP scripts in the user's Laravel application. These scripts are designed to extract necessary information like routes, configurations, and views, which are then used to provide autocompletion features within the VS Code editor.
    3. The extension's code directly substitutes the `{code}` placeholder within the configured `phpCommand` with the PHP code it intends to execute. This substitution is performed without any sanitization or validation of the `phpCommand` string itself.
    4. A malicious user, or an attacker who gains control over the user's VS Code settings (e.g., through a compromised workspace configuration file), can craft a `phpCommand` that injects arbitrary shell commands. This can be achieved by manipulating the structure of the command around the `{code}` placeholder, inserting shell command delimiters and malicious commands.
    5. When the extension subsequently executes PHP code using this maliciously crafted `phpCommand`, the injected shell commands will be executed by the system shell. This occurs because `child_process.exec` in `helpers.ts` directly runs the constructed command string.
* Impact:
    - Arbitrary command execution on the system where VS Code and the Laravel project are running.
    - Successful exploitation allows an attacker to execute any command with the privileges of the user running VS Code.
    - This can lead to severe security breaches, including but not limited to:
        - Data exfiltration: Sensitive project files, environment variables, and database credentials could be accessed and sent to a remote attacker.
        - System compromise: Attackers could install malware, create new user accounts, or modify system configurations to maintain persistent access or further compromise the system.
        - Denial of service: Attackers could execute commands that consume system resources, leading to a denial of service.
        - Lateral movement: In a networked environment, a compromised development machine can be used as a stepping stone to attack other systems on the network.
* Vulnerability rank: Critical
* Currently implemented mitigations:
    - None. The code does not include any sanitization or validation of the `phpCommand` configuration.
    - The "Security Note" in the `README.md` file serves as a warning to users but does not technically mitigate the vulnerability. It states: "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete... if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing." This note highlights a potential risk but does not prevent command injection.
* Missing mitigations:
    - Input sanitization: The extension should sanitize or validate the `phpCommand` setting to prevent injection of shell commands. This could involve:
        - Disallowing shell metacharacters in the `phpCommand`.
        - Parsing and validating the structure of the `phpCommand` to ensure it conforms to an expected format.
    - Alternative command execution methods: Instead of using `child_process.exec` with a user-configurable command string, consider safer alternatives such as:
        - Using `child_process.spawn` with arguments array instead of a command string, which reduces the risk of shell injection.
        - Restricting the configurable parts of the command to only the PHP executable path, and hardcoding the `-r "{code}"` part to prevent modification of the command structure.
        - Sandboxing the PHP execution environment to limit the impact of potential vulnerabilities.
    - Principle of least privilege: The extension should ideally operate with the minimum necessary privileges to reduce the potential impact of a compromise. However, in the context of a VS Code extension interacting with a local project, this might be less applicable to the command injection vulnerability itself.
* Preconditions:
    - The user must have the "Laravel Extra Intellisense" extension installed in VS Code.
    - The user must have a Laravel project opened in VS Code.
    - An attacker needs to influence the `LaravelExtraIntellisense.phpCommand` configuration setting. This could be achieved if:
        - The attacker has direct access to the user's VS Code settings (e.g., if the attacker has already compromised the user's machine).
        - The attacker can trick the user into manually changing the `phpCommand` setting through social engineering.
        - The attacker can compromise a workspace configuration file (e.g., `.vscode/settings.json` in the Laravel project) that is committed to a repository and shared with other users. If a user opens a project with a compromised workspace settings file, the malicious `phpCommand` could be automatically applied.
* Source code analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. Line:
        ```typescript
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        ```
        This line retrieves the `phpCommand` setting from the VS Code configuration. If the user has not configured this setting, it defaults to `php -r "{code}"`.
    4. Line:
        ```typescript
        let command = commandTemplate.replace("{code}", code);
        ```
        This line performs a simple string replacement to insert the `$code` (PHP code to be executed) into the `commandTemplate`. Critically, there is no sanitization or escaping of the `$code` or the `commandTemplate` at this point. If the `commandTemplate` itself contains shell-executable code or if the `$code` could somehow be manipulated to break out of the intended context, it could lead to command injection. However, in the current code, the `$code` is generated by the extension and is not directly user-controlled. The primary injection point is through the `commandTemplate` itself, which is derived from the `phpCommand` user setting.
    5. Line:
        ```typescript
        cp.exec(command,
            { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
            function (err, stdout, stderr) { ... }
        );
        ```
        This line uses `child_process.exec` to execute the `$command` string. `cp.exec` executes a command in a shell, which is necessary for features like globbing and variable interpolation in shell commands, but it also makes it vulnerable to command injection if the command string is not carefully constructed, especially when parts of the command are derived from user input or configuration, as is the case with `phpCommand`.
    **Visualization:**

    ```
    User Configuration (settings.json)
    |
    |-->  "LaravelExtraIntellisense.phpCommand":  "php -r 'system(\\'{code}\\');'"  (Maliciously crafted phpCommand)
        |
        |
        src/helpers.ts:runPhp()
        |
        |--> commandTemplate = "php -r 'system(\\'{code}\\');'"
        |
        |--> code =  "echo json_encode(config()->all());" (Example PHP code from extension)
        |
        |--> command = commandTemplate.replace("{code}", code)
        |     command becomes: "php -r 'system(\\'echo json_encode(config()->all());\\');'"
        |
        |--> cp.exec(command, ...)  // Executes the command in shell
            |
            |--> Shell executes: php -r 'system(\\'echo json_encode(config()->all());\\');'
                |
                |--> system('echo json_encode(config()->all());') is executed.
                    In a malicious scenario, if phpCommand was  "php -r 'system(\\'{code}\\'); <malicious_command>'"
                    then system('{code}') and <malicious_command> would be executed sequentially.
    ```

* Security test case:
    1. **Setup:**
        - Ensure you have VS Code installed.
        - Install the "Laravel Extra Intellisense" extension.
        - Open any folder in VS Code (it doesn't need to be a Laravel project for this test, but having a PHP file is helpful to trigger the extension).
    2. **Modify User Settings:**
        - Open VS Code settings (File -> Preferences -> Settings, or Code -> Settings -> Settings on macOS).
        - Switch to the JSON settings editor by clicking the "Open Settings (JSON)" icon in the top-right corner of the Settings editor.
        - Add the following lines to your `settings.json` file:
            ```json
            "LaravelExtraIntellisense.phpCommand": "php -r 'system(\\'{code}\\');'"
            ```
            This configuration replaces the default `phpCommand` with a malicious one. It will execute `system('{code}')` which will pass the `{code}` content as a shell command.
        - Save the `settings.json` file.
    3. **Trigger Extension Activity:**
        - Open any PHP file in VS Code (or create a new empty file and set its language mode to PHP).
        - Type `config(` or `route(` or `view(` to trigger the autocompletion provided by the extension. This action will cause the extension to execute PHP code using the configured `phpCommand`.
    4. **Verify Command Injection:**
        - After triggering autocompletion, check for the execution of the injected command. In this test case, we used `system('{code}')`. To make it more visible and verifiable, let's modify the malicious `phpCommand` to write to a file.
        - Modify your `settings.json` to the following to test for command execution:
            ```json
            "LaravelExtraIntellisense.phpCommand": "php -r 'system(\\'echo pwned > /tmp/pwned.txt\\'); system(\\'{code}\\');'"
            ```
            (For Windows, use: `"php -r 'system(\\'echo pwned > C:\\\\pwned.txt\\'); system(\\'{code}\\');'"` and ensure the path `C:\pwned.txt` is writable).
        - Repeat step 3 to trigger the extension.
        - **Check for file creation:** After triggering the extension, check if the file `/tmp/pwned.txt` (or `C:\pwned.txt` on Windows) has been created and contains the word "pwned".
        - **Success:** If the file `/tmp/pwned.txt` (or `C:\pwned.txt`) exists and contains "pwned", this confirms that the injected `system('echo pwned > ...')` command was successfully executed, demonstrating command injection through the `phpCommand` configuration.
