- **Vulnerability Name:** Remote Code Execution via `phpCommand` setting - Command Injection
- **Description:**
    - The extension allows users to configure the `phpCommand` setting, which is used to execute PHP code within the Laravel project.
    - A malicious Laravel project can trick a developer into using a crafted `phpCommand` that injects system commands.
    - When the extension executes PHP code using this crafted `phpCommand`, the injected system commands are executed on the developer's machine.
- **Impact:**
    - **Critical:** An attacker can achieve remote code execution on the developer's machine.
    - This allows the attacker to perform arbitrary actions, such as stealing credentials, installing malware, or compromising the developer's system and potentially the projects they work on.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. The extension directly uses the user-provided `phpCommand` setting without any sanitization or validation.
- **Missing Mitigations:**
    - **Input Sanitization:** Sanitize the `phpCommand` setting to prevent the injection of arbitrary system commands.
    - **Command Parameterization:** Use parameterized commands instead of string interpolation to prevent command injection.
    - **Restrict Command Execution:**  Ideally, avoid executing arbitrary PHP code altogether. If necessary, restrict the commands to only the strictly required operations and use safer alternatives to `exec` or `shell_exec`.
    - **Principle of Least Privilege:**  If command execution is unavoidable, ensure the executed commands run with the minimum necessary privileges.
- **Preconditions:**
    - A developer must open a malicious Laravel project in VSCode.
    - The developer must have the Laravel Extra Intellisense extension installed and activated.
    - The malicious Laravel project must provide a crafted `.vscode/settings.json` file that overrides the `LaravelExtraIntellisense.phpCommand` setting with a malicious command.
    - The developer must allow VSCode to apply workspace settings (usually enabled by default or easily accepted).
- **Source Code Analysis:**
    - **`src/helpers.ts` - `runPhp` function:**
        ```typescript
        static async runPhp(code: string, description: string|null = null) : Promise<string> {
            code = code.replace(/\"/g, "\\\"");
            if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
                code = code.replace(/\$/g, "\\$");
                code = code.replace(/\\\\'/g, '\\\\\\\\\'');
                code = code.replace(/\\\\"/g, '\\\\\\\\\"');
            }
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            let command = commandTemplate.replace("{code}", code); // Vulnerability: User-controlled 'phpCommand' and 'code' are directly concatenated.
            let out = new Promise<string>(function (resolve, error) {
                if (description != null) {
                    Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                }

                cp.exec(command, // Executes the constructed command string.
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
        - The `runPhp` function constructs the command to execute PHP code by directly replacing `{code}` in the `commandTemplate` with the provided `code`.
        - `commandTemplate` is derived from the `LaravelExtraIntellisense.phpCommand` setting, which is user-configurable.
        - There is no sanitization of either `phpCommand` or the `code` variable before executing the command using `cp.exec`.
        - This allows an attacker to inject arbitrary shell commands by crafting a malicious `phpCommand` setting within a malicious Laravel project.

    - **Configuration Loading:**
        - VSCode automatically loads workspace settings from `.vscode/settings.json` when a project is opened, if the user allows it.
        - A malicious Laravel project can include a `.vscode/settings.json` file to override the `phpCommand` setting.

- **Security Test Case:**
    1. **Prepare a Malicious Laravel Project:**
        - Create a new Laravel project.
        - Create a `.vscode` folder in the project root.
        - Create a `settings.json` file inside the `.vscode` folder with the following content:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/pwned\"); {code}'"
            }
            ```
            - This malicious `phpCommand` will execute `touch /tmp/pwned` before executing the intended PHP code. This command creates an empty file named `pwned` in the `/tmp` directory (in Linux/macOS). For Windows, you could use `cmd /c echo pwned > %TEMP%\\pwned.txt`.
        -  **Important:** For testing on Windows, the command should be adapted to Windows syntax, for example:
           ```json
           {
               "LaravelExtraIntellisense.phpCommand": "cmd /c \"echo pwned > %TEMP%\\pwned.txt & php -r \\\"{code}\\\""
           }
           ```
           This command uses `cmd /c` to execute a shell command first, then executes the PHP command. `echo pwned > %TEMP%\\pwned.txt` will create a file named `pwned.txt` in the temporary directory.

    2. **Open the Malicious Project in VSCode:**
        - Open the prepared malicious Laravel project in VSCode with the Laravel Extra Intellisense extension installed and activated.
        - VSCode may prompt to apply workspace settings. Allow it.

    3. **Trigger Extension Autocompletion:**
        - Open any PHP or Blade file within the malicious Laravel project (e.g., a controller or a view file).
        - Start typing a Laravel function that triggers the extension's autocompletion (e.g., `route('`, `config('`, `view('`). This will cause the extension to execute PHP code using the malicious `phpCommand`.

    4. **Verify Remote Code Execution:**
        - **Linux/macOS:** Check if the file `/tmp/pwned` has been created. You can use the terminal command `ls /tmp/pwned`. If the file exists, the command injection was successful.
        - **Windows:** Check if the file `%TEMP%\\pwned.txt` (e.g., `C:\Users\<YourUsername>\AppData\Local\Temp\pwned.txt`) has been created and contains "pwned". You can check this using File Explorer or the command line `type %TEMP%\\pwned.txt`. If the file exists and contains "pwned", the command injection was successful.

This test case demonstrates that an attacker can achieve remote code execution by crafting a malicious `phpCommand` within a Laravel project's workspace settings, which is then executed by the Laravel Extra Intellisense extension.
