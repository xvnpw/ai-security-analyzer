- **Vulnerability Name:** Insecure PHP Command Execution via Configurable `phpCommand` Setting

  - **Description:**
    The extension retrieves a user‑configurable PHP command template from the setting
    `LaravelExtraIntellisense.phpCommand` (which defaults to
    `php -r "{code}"`). In the helper function `runPhp`, a generated PHP snippet replaces the `{code}`
    placeholder and is then executed using Node’s `cp.exec()`. Although some basic escaping is applied (for example, escaping double quotes and, on Unix platforms, dollar signs), the code is concatenated into a shell command without a robust sanitization or use of safer APIs.
    **Step by step trigger:**
    1. An attacker gains the ability to modify the extension’s settings (for example, via a malicious workspace configuration file or a supply‑chain attack on the configuration resource).
    2. The attacker changes the `phpCommand` configuration value to inject additional shell commands (or otherwise modify the expected behavior).
    3. When the extension generates PHP code (for example, to extract routes or model information) and calls `runPhp`, the injected payload is inserted into the command string.
    4. The modified command is executed by `cp.exec()`, resulting in arbitrary shell command execution on the host machine.

  - **Impact:**
    Critical. An attacker who successfully exploits this vulnerability can execute unauthorized shell commands—potentially allowing full compromise of a user’s system, unauthorized access to sensitive data, and potential lateral movement in a networked environment.

  - **Vulnerability Rank:**
    Critical

  - **Currently Implemented Mitigations:**
    - Basic escaping is performed in `runPhp` (e.g. replacing double quotes and, on Unix, dollar signs) before assembling the command.
    - The extension defaults to a command string that appears benign if left unmodified.

  - **Missing Mitigations:**
    - Comprehensive sanitization and validation of the injected PHP code before it is embedded into a shell command.
    - Use of safer APIs (for example, spawning the PHP process with an argument array rather than relying on string concatenation) to prevent shell interpretation.
    - Access control or integrity checks on the configuration settings to ensure that only trusted users can modify them.

  - **Preconditions:**
    - The attacker must be able to modify the VSCode extension’s configuration (either via a compromised workspace settings file, misconfiguration or another coupled vulnerability).
    - The extension must be running with sufficient privileges to execute shell commands.

  - **Source Code Analysis:**
    1. In `Helpers.runPhp`, the provided PHP code is first processed by replacing double quotes and (on Unix) dollar signs; however, no further safe‑handling is applied.
    2. The command template is fetched via
       ```js
       vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')
       ```
       and `{code}` is replaced using simple string replacement without further sanitization.
    3. The assembled command is then executed with `cp.exec()` without invoking techniques (such as argument arrays) that would prevent shell interpolation.

  - **Security Test Case:**
    1. Open VSCode with the Laravel Extra Intellisense extension installed.
    2. In the VSCode settings (or a workspace settings file), modify the `LaravelExtraIntellisense.phpCommand` setting to a value such as:
       ```
       php -r "echo 'Safe execution'; system('id');"
       ```
    3. Trigger one of the extension’s autocompletion features (for example, by editing a PHP or Blade file in a Laravel project).
    4. Monitor the VSCode output channel and/or system logs to verify whether the injected shell command (`id` in this case) is executed.
    5. A deviation from the expected behavior—namely, evidence of the injected command’s output—confirms that command injection is possible.

---

- **Vulnerability Name:** Arbitrary PHP Code Injection via Malicious Laravel File Modification

  - **Description:**
    For autocompletion, the extension calls `Helpers.runLaravel()` to bootstrap the Laravel application. In doing so, it constructs a PHP command that includes requiring Laravel’s autoload and bootstrap files (e.g. `vendor/autoload.php` and `bootstrap/app.php`) and then appends generated PHP code to output necessary data. If an attacker can modify key Laravel files (such as service providers or route definitions), the injected malicious PHP code—embedded in these files—will be executed when the extension runs `runLaravel()`.
    **Step by step trigger:**
    1. The attacker gains write access to the Laravel project (for instance, through a separate web vulnerability, compromised SCM repository, or insider attack).
    2. The attacker injects harmless‑appearing yet malicious PHP code (for example, in a service provider or route file) that performs a harmful action (such as writing to a sensitive file or opening a reverse shell).
    3. The extension periodically runs `Helpers.runLaravel()` to obtain autocompletion data.
    4. During the Laravel bootstrap process, the injected malicious code is executed without any integrity or signing checks, resulting in arbitrary PHP execution.

  - **Impact:**
    Critical. The execution of attacker‑controlled PHP code within the Laravel bootstrap process can lead to full compromise of the local system. This may result in leakage of sensitive data, persistent backdoor installation, or unauthorized remote code execution.

  - **Vulnerability Rank:**
    Critical

  - **Currently Implemented Mitigations:**
    - The extension’s README includes a security note advising users to disable the extension if working with sensitive code (although this is only a user warning and does not prevent execution).
    - The extension locates Laravel files using predefined paths (such as via `Helpers.projectPath()`), thereby only “targeting” files in expected locations.

  - **Missing Mitigations:**
    - There is no sandboxing or isolation when bootstrapping the Laravel application, so all code (even if malicious) runs with full access.
    - No integrity verification, code signing, or safe‑execution checks are in place to ensure that only trusted Laravel code is executed.
    - Input validation or configuration checks to block unexpected or suspicious file modifications are absent.

  - **Preconditions:**
    - The attacker must be able to modify files inside the Laravel project (for example, by exploiting a vulnerability in Laravel itself, compromising the SCM, or obtaining local write access).
    - The extension must be active and configured to run Laravel commands via `Helpers.runLaravel()`.

  - **Source Code Analysis:**
    1. In `Helpers.runLaravel()`, the function checks for and then requires both `vendor/autoload.php` and `bootstrap/app.php` to bootstrap the Laravel app.
    2. It constructs a PHP command string that registers a service provider (via an anonymous class) and then executes the user‑provided code.
    3. Because the bootstrap process loads all service providers and route definitions without verifying their integrity, any malicious PHP code injected into these files will be executed.
    4. No sanitization or isolation is introduced between the autoloaded Laravel code and the generated PHP snippet.

  - **Security Test Case:**
    1. In a controlled and isolated test Laravel project, modify (or add) a service provider or a route definition file to include a benign payload (for example, PHP code that writes a specific marker string into a temporary file).
    2. Open the Laravel project in VSCode with the Laravel Extra Intellisense extension active so that autocompletion triggers a call to `Helpers.runLaravel()`.
    3. Check for the presence of the marker file or review the output logs to see if the benign payload was executed.
    4. The successful execution of the injected payload confirms that arbitrary PHP code in Laravel files is executed by the extension, thereby validating the vulnerability.
