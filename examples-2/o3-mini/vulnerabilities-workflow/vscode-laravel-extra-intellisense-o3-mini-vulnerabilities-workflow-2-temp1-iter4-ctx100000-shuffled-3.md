- **Vulnerability Name:** Arbitrary Code Execution via Malicious Laravel Project Files

  - **Description:**
    An attacker who can supply or modify Laravel project files (for example, by inserting a malicious service provider or altering route definitions) can force the extension to automatically execute dangerous PHP code. Here’s how an attacker could trigger the vulnerability:
    - The extension periodically gathers Laravel routes, controllers, configurations, views, translations, etc. by calling helper functions that run a PHP command.
    - The function `Helpers.runLaravel()` (found in `src/helpers.ts`) builds a command string based on a configurable template (defaulting to `php -r "{code}"`). This command string bootstraps the Laravel application (by requiring the vendor autoload and bootstrap files) and registers a custom service provider.
    - If an attacker has introduced a malicious Laravel file (for instance, a service provider that performs harmful actions) into the project directory, it will be loaded during this bootstrapping.
    - When the extension calls this command, the embedded malicious code is executed on the developer’s machine under the context of the PHP process.

  - **Impact:**
    If successfully exploited, the attacker can achieve arbitrary PHP code execution on the machine where the extension runs. This may lead to:
    - Execution of system commands.
    - Data exfiltration or alteration.
    - Complete compromise of the developer’s machine and development environment.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The extension’s README contains a **Security Note** that warns users:
      > “Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing.”

      This is a manual, documentation-based mitigation meant to alert users who work on sensitive projects.

  - **Missing Mitigations:**
    - There is no technical or programmatic sandboxing of the PHP code that is executed.
    - No validation or sanitization is applied to the PHP code that is bootstrapped when running `Helpers.runLaravel()`.
    - The extension does not isolate or restrict the execution context of the Laravel project, so any malicious code present in untrusted project files is executed with full privileges.

  - **Preconditions:**
    - The developer uses this extension with a Laravel project that is not fully trusted (or a project that may have been tampered with).
    - The project contains malicious modifications (for example, in a service provider, route file, or custom directive) that execute harmful PHP code when the Laravel application boots.
    - The extension is configured to run the PHP command automatically (using the default or a misconfigured `phpCommand`).

  - **Source Code Analysis:**
    - In `src/helpers.ts`, the method `Helpers.runLaravel(code, description)` constructs a PHP command string by concatenating:
      - A requirement of the Laravel autoloader (`vendor/autoload.php`),
      - Loading the bootstrap file (`bootstrap/app.php`),
      - Registering a custom service provider (which does little on its own but is part of bootstrapping),
      - Inserting the arbitrary PHP code passed via the `{code}` placeholder.
    - The command string is then executed using Node’s `child_process.exec` (in the `Helpers.runPhp()` method) without sandboxing or strict validation.
    - Since the extension automatically runs this command to obtain data (like routes, views, configs, etc.), any malicious PHP code placed in the Laravel project (e.g., via a compromised service provider) will be executed.
    - The configurable setting `"LaravelExtraIntellisense.phpCommand"` further means that if the configuration is tampered with (or if an attacker can influence the file system or settings), it might be manipulated to include extra command–injection payloads.

  - **Security Test Case:**
    1. **Setup a Test Laravel Project:**
       - Create or use a Laravel project.
       - Add a new service provider (or modify an existing one) with a PHP payload that performs an identifiable malicious action (for testing, for example, writing a unique artifact file to a known location or outputting a unique string to the logs).
    2. **Configure the Extension:**
       - Open the project in Visual Studio Code with the Laravel Extra Intellisense extension enabled.
       - Ensure the default configuration is active (i.e. using the default `phpCommand` such as `php -r "{code}"`).
    3. **Trigger the Extension's Auto Execution:**
       - Perform an action that triggers the extension’s refresh (such as editing a PHP file to force the file watchers to notice a change, or restarting VSCode).
       - The extension will call `Helpers.runLaravel()` in order to fetch routes, controllers, and other project data.
    4. **Observe the Outcome:**
       - Check the developer’s machine for the artifact produced by the malicious code (for example, the file written by the payload).
       - Alternatively, review the output channel (if configured to log such messages) for evidence of the malicious payload execution.
    5. **Validate Arbitrary Code Execution:**
       - If the payload’s effect is observed, this proves that an attacker could control code execution via malicious Laravel files injected into the project.
