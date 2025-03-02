## Vulnerability List:

- Vulnerability Name: Code Injection via Malicious `basePathForCode`

- Description:
    1. A threat actor crafts a malicious Laravel repository.
    2. Within this repository, the attacker creates malicious `vendor/autoload.php` and `bootstrap/app.php` files containing arbitrary PHP code intended for remote code execution.
    3. The attacker distributes this malicious repository and socially engineers a victim to clone and open it using VSCode.
    4. The attacker further tricks the victim into configuring the `LaravelExtraIntellisense.basePathForCode` setting in VSCode to point to a directory within the malicious repository that contains the crafted `vendor/autoload.php` and `bootstrap/app.php` files. This could be achieved through misleading instructions in the repository's README or other documentation, for example, by advising the user to set `LaravelExtraIntellisense.basePathForCode` to a relative path like `./malicious-laravel-files`, assuming the malicious files are placed within a `malicious-laravel-files` directory in the repository root.
    5. Upon extension activation or when any feature of the extension that relies on `Helpers.runLaravel` is triggered, the extension will execute a PHP command.
    6. `Helpers.runLaravel` function utilizes `require_once` to include `vendor/autoload.php` and `bootstrap/app.php`, using file paths constructed based on the user-configured `basePathForCode`. Due to the manipulated `basePathForCode`, these paths now point to the attacker's malicious files.
    7. Consequently, the malicious PHP code embedded within the attacker's `vendor/autoload.php` and `bootstrap/app.php` files is executed within the VSCode extension's process, leading to code injection.

- Impact: Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary code on the victim's machine with the same privileges as the VSCode process. This could lead to complete system compromise, data theft, or further malicious activities.

- Vulnerability Rank: High

- Currently Implemented Mitigations: None. The extension directly utilizes the user-provided `basePathForCode` configuration to construct file paths used in `require_once` statements without any validation or sanitization.

- Missing Mitigations:
    - Input validation and sanitization for the `basePathForCode` setting. The extension should validate that the configured path is within the workspace folder and prevent users from setting it to arbitrary locations, especially outside the workspace.
    - Avoid using `require_once` with paths that are derived from user configurations. Consider alternative, safer methods for executing Laravel commands or retrieving necessary data from the Laravel application that do not involve directly including files based on user-defined paths.
    - Enhance the security warning in the README.md to specifically mention the risks associated with misconfiguring `basePathForCode` and strongly advise users against setting it to untrusted directories or locations outside of their intended Laravel project.

- Preconditions:
    1. The victim must open a malicious Laravel repository in VSCode.
    2. The victim must be successfully tricked into manually setting the `LaravelExtraIntellisense.basePathForCode` configuration to a path controlled by the attacker, typically within the malicious repository itself.

- Source Code Analysis:
    - File: `src/helpers.ts`
    - Function: `runLaravel(code: string, description: string|null = null)`

    ```typescript
    static runLaravel(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
        if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
            var command =
                "define('LARAVEL_START', microtime(true));" +
                "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" + // Vulnerability Point 1: Path is derived from user config basePathForCode
                "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" + // Vulnerability Point 2: Path is derived from user config basePathForCode
                "..."
    ```

    - The lines marked as "Vulnerability Point 1" and "Vulnerability Point 2" are where the vulnerability is located. The `Helpers.projectPath(..., true)` function is used to construct the paths to `vendor/autoload.php` and `bootstrap/app.php`. When the second argument `forCode` is set to `true`, `Helpers.projectPath` uses the `basePathForCode` configuration setting.
    - If a malicious actor can influence the `basePathForCode` setting to point to a malicious directory, the `require_once` statements will load and execute the attacker's malicious PHP files instead of the legitimate Laravel project files.

- Security Test Case:
    1. **Setup Malicious Repository:**
        a. Create a new directory named `malicious-repo`.
        b. Navigate into `malicious-repo`: `cd malicious-repo`.
        c. Create a directory named `malicious-laravel-files`: `mkdir malicious-laravel-files`.
        d. Inside `malicious-laravel-files`, create the directory `vendor`: `mkdir malicious-laravel-files/vendor`.
        e. Inside `malicious-laravel-files/vendor`, create the file `autoload.php` with the following malicious PHP code:

        ```php
        <?php
        file_put_contents('/tmp/rce_laravel_extra_intellisense.txt', 'RCE_VULNERABILITY_TRIGGERED');
        ```

        f. Inside `malicious-laravel-files`, create the directory `bootstrap`: `mkdir malicious-laravel-files/bootstrap`.
        g. Inside `malicious-laravel-files/bootstrap`, create the file `app.php` with the following minimal Laravel bootstrap code:

        ```php
        <?php
        return new class() {
            public function register($provider) {}
            public function boot() {}
        };
        ```
        h. Create a `README.md` file in the root of `malicious-repo` with instructions to set `LaravelExtraIntellisense.basePathForCode` to `./malicious-laravel-files`. For example:

        ```markdown
        # Malicious Laravel Repository

        **Security Warning:**

        To make this repository work with Laravel Extra Intellisense extension, please configure the `LaravelExtraIntellisense.basePathForCode` setting in VSCode to point to `./malicious-laravel-files`.

        This is for demonstration purposes only and should not be done with untrusted repositories.
        ```

    2. **Victim Setup:**
        a. Clone the `malicious-repo` to a test machine.
        b. Open the cloned `malicious-repo` in VSCode.
        c. Follow the instructions in `README.md` to configure `LaravelExtraIntellisense.basePathForCode` to `./malicious-laravel-files`. This can be done by opening VSCode settings (File -> Preferences -> Settings -> Settings or Code -> Settings -> Settings), searching for "LaravelExtraIntellisense.basePathForCode", and setting the value to `./malicious-laravel-files`.

    3. **Trigger Vulnerability:**
        a. Open any PHP file within the `malicious-repo` in VSCode. This action should trigger the Laravel Extra Intellisense extension to activate and execute `Helpers.runLaravel` as part of its functionality (e.g., to provide autocompletion).

    4. **Verify Exploitation:**
        a. Check if the file `/tmp/rce_laravel_extra_intellisense.txt` exists on the test machine.
        b. If the file exists and contains the text "RCE_VULNERABILITY_TRIGGERED", it confirms that the malicious code from `malicious-laravel-files/vendor/autoload.php` was executed, demonstrating the Remote Code Execution vulnerability.

This test case, if successful, will prove that a malicious repository can achieve Remote Code Execution by manipulating the `basePathForCode` setting and providing malicious Laravel bootstrap files.
