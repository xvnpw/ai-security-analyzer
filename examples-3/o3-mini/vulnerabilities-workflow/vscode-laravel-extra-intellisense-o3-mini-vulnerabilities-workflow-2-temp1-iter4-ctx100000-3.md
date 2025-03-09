- **Vulnerability Name:** Insecure PHP Code Execution via Automatic Laravel Bootstrapping

  - **Description:**
    - The extension automatically runs PHP code on the developer’s machine by embedding PHP snippets inside a command that boots the Laravel application.
    - An attacker who can insert a malicious payload into the Laravel project’s bootstrapping routines (for example, within the project’s `bootstrap/app.php`, a custom service provider, or even improperly vetted route definitions) can cause the malicious code to be loaded when the extension calls the PHP command.
    - When a user opens a Laravel project in VSCode, the extension checks for the “artisan” file and then executes a command using the user’s configured PHP command (by default, `php -r "{code}"`).
    - Because the command is constructed by concatenating bootstrapping steps (e.g. including `vendor/autoload.php` and `bootstrap/app.php`) with a generated PHP snippet, any malicious payload embedded in these bootstrapping files will be executed without isolation.
    - An attacker might therefore hide or smuggle an arbitrary PHP payload into a service provider or a route definition so that when the extension calls `Helpers.runLaravel`, that malicious payload runs automatically on the developer’s machine.

  - **Impact:**
    - Full arbitrary code execution on the developer’s machine in the context of the local PHP runtime.
    - The attacker may perform operations such as file manipulation, network communications, data exfiltration, or even altering the developer’s working environment.
    - Since the extension’s execution is triggered automatically on project load, detection and prevention become more challenging for an unaware developer.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The extension’s README contains a security note that warns users about the risk of running unknown or sensitive code from service providers. It advises disabling the extension temporarily if sensitive code is present.
    - There is no runtime sandboxing or additional code integrity checking inside the execution path; instead, the extension relies on the developer’s trust in their own Laravel project files.

  - **Missing Mitigations:**
    - Lack of sandboxing: The PHP execution runs in the local environment without isolation from the developer’s operating system.
    - No integrity or signature checks: The bootstrapping files (e.g. `bootstrap/app.php` or service provider files) are not verified before being loaded.
    - No user confirmation: The extension automatically executes code without requiring user approval when bootstrapping files are loaded.
    - No restrictions are in place to limit the commands or code run by the PHP runtime based on the context of data used solely for autocomplete.

  - **Preconditions:**
    - The developer is working on a Laravel project that includes standard bootstrapping files (such as `vendor/autoload.php` and `bootstrap/app.php`).
    - An attacker (or a malicious supply chain actor) is able to embed a payload in one or more of these bootstrapping files or in one of the auto-loaded service providers/route definitions.
    - The extension is enabled and functioning so that it automatically executes the PHP command (via `Helpers.runLaravel`) as part of generating autocomplete data.

  - **Source Code Analysis:**
    - In **helpers.ts**, the `runLaravel` function first checks for the existence of both `vendor/autoload.php` and `bootstrap/app.php` by using `Helpers.projectPath(…)`.
    - A command string is built that first includes and executes the Laravel bootstrap:
      - It defines a constant (`LARAVEL_START`) and then requires the autoloader.
      - It sets up the application by calling `require_once` on `bootstrap/app.php`, assigns it to `$app`, and registers a custom service provider.
      - It calls the Laravel kernel’s `handle` method with CLI input/output objects.
    - When the kernel returns a zero status, it echoes a marker string, appends the PHP code passed as the `code` parameter (provided by other providers), then echoes an end marker.
    - Because the command string executes the entire Laravel bootstrap process, any malicious change in the bootstrapping files (or in an early-registered provider) is executed with no further checks. The extension treats the project files as trusted and runs all embedded PHP code.
    - The lack of sanitization or sandboxing means that if an attacker embeds malicious PHP code in these files, it will execute in the context of the developer’s workspace when the extension runs the PHP command.

  - **Security Test Case:**
    - **Setup:**
      1. Create or use a Laravel project that the extension will work with.
      2. Modify the project’s bootstrap file (for example, insert PHP code into `bootstrap/app.php` or add a new service provider) so that the first line of the bootstrapping routine writes a known file (e.g., writes a file `malicious.txt` with distinctive content) or logs a specific message.
         - For instance, add a line such as:
           ```php
           file_put_contents(__DIR__.'/../malicious.txt', 'EXPOSURE DETECTED');
           ```
    - **Execution:**
      1. Open the modified Laravel project in VSCode with the Laravel Extra Intellisense extension enabled.
      2. Trigger an action (such as invoking route autocomplete or any feature that calls `Helpers.runLaravel`) so that the extension automatically executes the PHP command.
    - **Verification:**
      1. After the extension has run the PHP command, check if the file `malicious.txt` is created in the project root (or verify via log output that the payload has been executed).
      2. Confirm that the content of the file matches the expected “EXPOSURE DETECTED” string.
      3. Document that the malicious payload embedded in the Laravel project bootstrapping routine was executed by the extension without the developer’s explicit consent.
