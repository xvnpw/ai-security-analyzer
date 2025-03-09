- **Vulnerability Name:** Insecure PHP Code Execution via Laravel Bootstrapping
  - **Description:**
    The extension frequently calls the helper function `Helpers.runLaravel` to obtain autocompletion data (e.g. for Blade directives, routes, translations, etc.). In doing so, it dynamically builds a PHP command by concatenating:
    - Bootstrapping code (including paths to `"vendor/autoload.php"` and `"bootstrap/app.php"`)
    - A service provider definition (e.g. `VscodeLaravelExtraIntellisenseProvider`)
    - A PHP code snippet provided by various providers (such as those in `BladeProvider`, `RouteProvider`, etc.)

    **Step-by-step trigger:**
    1. An attacker gains the ability to modify files in the Laravel project (for example, via compromised dependencies or a malicious commit).
    2. The attacker injects a PHP payload into a file that is automatically loaded during Laravel’s boot process (e.g. in a service provider).
    3. The extension—when performing autocompletion—calls `Helpers.runLaravel`, which boots the Laravel application and includes the altered file.
    4. The malicious PHP code executes in the context of the developer’s machine.

  - **Impact:**
    Successful exploitation results in Remote Code Execution (RCE), potentially allowing full control over the developer’s system, data exfiltration, and arbitrary command execution.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - A security note in the README advises users to disable the extension when working with sensitive code.
    - The PHP command is defined via a user‐controlled setting, allowing knowledgeable developers to review or adjust the behavior.

  - **Missing Mitigations:**
    - **Sandboxing:** No technical isolation (e.g., containerization) is applied when executing the assembled PHP code.
    - **Input Validation/Sanitization:** The PHP code snippets and bootstrapping chain are not validated or sanitized before execution.
    - **Integrity Checks:** There are no mechanisms to verify the authenticity or integrity of the Laravel project files before they’re loaded.

  - **Preconditions:**
    - The Laravel project must be compromised such that malicious PHP payloads are present (e.g., injected into a service provider).
    - The extension is active and automatically executes PHP commands to load autocompletion data.
    - The developer’s system trusts the Laravel code that is booted and executed.

  - **Source Code Analysis:**
    - In `helpers.ts`, the `runLaravel` method builds the PHP command by concatenating strings. For example:
      ```js
      "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
      "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
      "class VscodeLaravelExtraIntellisenseProvider extends \\Illuminate\\Support\\ServiceProvider { … }" +
      "$app->register(new VscodeLaravelExtraIntellisenseProvider($app));" +
      ...
      "echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" + code +
      "echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';"
      ```
    - The variable `code` (supplied by various providers, e.g. from `BladeProvider.loadCustomDirectives`) is inserted without sanitization.
    - The complete command is executed using Node’s `cp.exec`, meaning that any malicious payload introduced into the boot sequence is executed immediately.

  - **Security Test Case:**
    1. **Setup:**
       - Create or use an existing Laravel project configured for use with the extension in VSCode.
       - Inject a PHP payload (for example, a snippet that writes a file or logs a unique marker) into a service provider (e.g., `app/Providers/AppServiceProvider.php`).
    2. **Trigger:**
       - Open a Blade file (or any other file that triggers autocompletion) in VSCode, causing the extension to invoke `Helpers.runLaravel`.
    3. **Observation:**
       - Verify whether the payload is executed by checking for the presence of the file, log entry, or any observable action defined by the payload.
    4. **Result:**
       - If the payload executes, it confirms that unsanitized PHP code is being run, thereby verifying the vulnerability.

- **Vulnerability Name:** Command Injection via Configurable PHP Command Template
  - **Description:**
    The extension allows users to specify the PHP command used to execute code via the `LaravelExtraIntellisense.phpCommand` setting. The default template is similar to:
    ```bash
    php -r "{code}"
    ```
    In the helper method `runPhp` (in `helpers.ts`), the extension retrieves this template and replaces the `{code}` placeholder with the generated PHP code. Minimal escaping (such as replacing double quotes) is applied. If an attacker can modify this configuration setting (for example, by compromising VSCode settings or altering a configuration file), they can inject additional shell commands.

    **Step-by-step trigger:**
    1. An attacker modifies the VSCode configuration (or associated configuration file) so that `phpCommand` includes a malicious payload (e.g., appending an extra shell command).
    2. When the extension executes, it replaces `{code}` in the compromised command template with the PHP snippet.
    3. The final command that is executed now includes the unintended payload alongside the intended PHP execution.

  - **Impact:**
    This vulnerability may lead to arbitrary shell command execution, compromising sensitive data and system integrity on the developer’s machine.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The extension applies a basic replacement of double quotes in the PHP code prior to insertion.
    - The PHP command template is user-configurable, allowing advanced users to adjust settings as needed.

  - **Missing Mitigations:**
    - **Robust Sanitization:** There is no comprehensive sanitization or validation of the entire command template to prevent the inclusion of unsafe shell metacharacters or additional commands.
    - **Safe Argument Handling:** The extension does not employ safer APIs (like passing arguments as arrays) that mitigate command injection risks.
    - **Whitelisting/Validation:** No mechanism verifies that the command template conforms to a whitelist of safe command formats.

  - **Preconditions:**
    - The attacker must have the ability to modify the `phpCommand` configuration (e.g., through compromised VSCode settings or shared configuration files).
    - The developer utilizes the default or a misconfigured command template that lacks safe handling.

  - **Source Code Analysis:**
    - In `helpers.ts`, the following code is used:
      ```js
      let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
      code = code.replace(/\"/g, "\\\"");
      // Additional escaping for Unix platforms is applied (e.g., replacing $ signs).
      let command = commandTemplate.replace("{code}", code);
      cp.exec(command, { cwd: … }, function (err, stdout, stderr) { … });
      ```
    - The code only replaces double quotes in the PHP code, with no validation of the user-supplied `phpCommand` template, leaving room for injection of unintended shell commands.

  - **Security Test Case:**
    1. **Setup:**
       - Modify the VSCode settings for `LaravelExtraIntellisense.phpCommand` to a malicious value; for example:
         ```bash
         php -r "{code}"; echo 'COMPROMISED';
         ```
       - Save the configuration changes.
    2. **Trigger:**
       - Initiate an extension feature that relies on the PHP command (such as triggering autocompletion for routes or Blade directives by calling `Helpers.runPhp`).
    3. **Observation:**
       - Check the output of the command execution for the string `COMPROMISED`.
    4. **Result:**
       - If the output includes the injected marker, it confirms that the command template was altered and injected, demonstrating a command injection vulnerability.
