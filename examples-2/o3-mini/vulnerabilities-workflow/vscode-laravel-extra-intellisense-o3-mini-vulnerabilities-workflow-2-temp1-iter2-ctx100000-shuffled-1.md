- **Vulnerability Name:** Arbitrary PHP Code Execution via Unsanitized PHP Command Execution

  - **Description:**
    This vulnerability stems from the way the extension dynamically builds and executes PHP commands to “talk” to the Laravel application. In short, the extension uses a configurable command template (via the setting `LaravelExtraIntellisense.phpCommand`) that embeds a dynamically generated PHP payload (built inside methods such as `Helpers.runLaravel`). The command is constructed by simply performing a string replacement on the placeholder `{code}` without any sanitization or escaping.
    **Step-by-step trigger scenario:**
    1. An attacker manages to inject a malicious PHP payload into one of the Laravel application files that the extension uses. For example, the attacker could modify a service provider or a configuration file in the Laravel project (e.g., by introducing a modified version of a trusted file in a shared repository or container environment).
    2. The extension’s file watchers (set up in files such as `ConfigProvider.ts`, `RouteProvider.ts`, etc.) detect changes in the Laravel project and trigger a refresh. In doing so, the extension calls functions like `Helpers.runLaravel`, which in turn constructs a PHP command to run.
    3. The unsanitized payload from the modified Laravel file becomes part of the dynamic PHP code string.
    4. The extension then retrieves the setting `LaravelExtraIntellisense.phpCommand` (defaulting to something like `php -r "{code}"`) and performs a simple replacement—substituting `{code}` with the generated payload.
    5. Finally, the extension passes the full command string to Node’s `cp.exec` (see `Helpers.runPhp` in *src/helpers.ts*) where it is executed without further sanitization.
    6. Because the attacker-controlled payload is executed in the shell, arbitrary PHP code (and possibly even shell commands, if the payload escapes the intended context) can run on the developer’s system.

  - **Impact:**
    Exploitation of this vulnerability would allow an attacker to execute arbitrary PHP code on the developer’s machine. Given that the extension runs in the context of the local development environment, this could lead to privilege escalation, data exfiltration, file system compromise, or any other actions that a local attacker (or an attacker able to inject code into the Laravel project) could perform.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - The README includes a security note warning developers that if writing any sensitive code in service providers, they should temporarily disable the extension.
    - The `phpCommand` is user-configurable, which at least forces the developer to be aware of the command being executed (though this relies on the developer’s diligence and does not add runtime sanitization).

  - **Missing Mitigations:**
    - **Input Sanitization:** There is no validation, escaping, or sanitization of the dynamically generated PHP code before it is embedded into the command template.
    - **Sandboxing:** The command is executed using Node’s `cp.exec` directly in the shell; no sandbox or restricted execution environment is used.
    - **User Confirmation:** There is no additional prompt or confirmation when running code that might originate from modified Laravel application files.
    - **Integrity Checks:** The extension does not verify the integrity or origin of the Laravel application files and their contents before including them in the command.

  - **Preconditions:**
    - The developer is using the extension with a Laravel project whose files (e.g., service providers, configuration files) can be modified either directly or via a shared/compromised environment (for example, a network share or container-based development environment).
    - The attacker has the ability to modify or inject malicious payloads into the Laravel application files that the extension relies on.
    - The extension is enabled and configured to execute PHP commands (i.e., the default or custom `phpCommand` is in use).

  - **Source Code Analysis:**
    1. In *src/helpers.ts*, the function `Helpers.runPhp` retrieves the user’s configured command template:
       ```ts
       let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
       ```
    2. The template is then processed with a simple string replacement:
       ```ts
       let command = commandTemplate.replace("{code}", code);
       ```
       The variable `code` is generated (for example, in `Helpers.runLaravel`) by concatenating a series of PHP commands:
       - It loads the Laravel bootstrap files (from paths determined via `Helpers.projectPath`).
       - It then appends the dynamic PHP payload (which may include code from Laravel service providers, models, routes, etc.).
    3. The constructed command is passed directly to `cp.exec`:
       ```ts
       cp.exec(command, { cwd: ... }, function (err, stdout, stderr) { ... });
       ```
       Here the command is sent directly to the shell without any sanitization.
    4. Because the PHP code inserted into `{code}` may contain attacker-controlled fragments (if a Laravel file was maliciously altered), and because no escaping is applied, the final command string may execute unintended commands.
    5. This design creates an attack vector where modifications to Laravel files (which the extension loads automatically) result in malicious PHP payloads being executed on the developer machine.

  - **Security Test Case:**
    1. **Setup:**
       - Create (or use) a Laravel project and install the extension with the default configuration (`phpCommand` as `php -r "{code}"`).
       - In the Laravel project, add a new service provider (or modify an existing one) that contains a “payload” PHP snippet. For testing purposes, the payload can be a benign command, such as writing a specific file or outputting a unique string.
       - For example, in a service provider’s `boot` method, insert:
         ```php
         file_put_contents('/tmp/test_injection.txt', 'injection successful');
         ```
    2. **Execution:**
       - Open the Laravel project in VSCode so that the extension activates.
       - Trigger an operation that forces the extension to re-run Laravel commands. For instance, modify a configuration or view file (or simply wait for a periodic refresh) so that one of the providers (e.g., `ConfigProvider` or `RouteProvider`) calls `Helpers.runLaravel`.
    3. **Observation:**
       - Verify that the file `/tmp/test_injection.txt` is created with the expected content ("injection successful").
       - Check the output channel (if enabled) for any unexpected messages.
    4. **Conclusion:**
       - If the file is present, it confirms that the malicious PHP code from the altered Laravel file was executed via the unsanitized command. This demonstrates that an attacker with the ability to modify Laravel files can achieve arbitrary code execution on the developer’s system.
    5. **Cleanup:**
       - Remove the test file and revert any changes made to the Laravel project after the test.
