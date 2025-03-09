## Vulnerability List

### 1. PHP Code Injection via `phpCommand` Configuration Manipulation

- **Description:**
  An attacker can modify the workspace (or shared project) settings to supply a malicious value for the `LaravelExtraIntellisense.phpCommand` configuration. For example, instead of using the default
  `php -r "{code}"`
  an attacker could set the value to something like
  `php -r "{code}; system('malicious_command');"`
  When the extension later calls the helper function to run Laravel code, it retrieves this configuration without strict validation. The helper function then replaces the `{code}` placeholder with dynamically generated PHP code and executes the resulting command using Node’s `cp.exec`. This replacement is done after only basic escaping (mostly of quotes), and no checks are performed to ensure that no extra commands have been appended. Thus, the malicious commands are executed as part of the same shell call, allowing arbitrary PHP (or even shell) commands to run on the developer’s machine.

- **Impact:**
  - **Arbitrary Command Execution:** The attacker’s injected commands run on the local environment, which may lead to the execution of any malicious operations (e.g., opening unwanted applications, modifying files, or exfiltrating data).
  - **Compromise of Developer Environment:** Since the extension operates in the developer’s machine context, the attacker might elevate privileges or gain access to sensitive information defined in the Laravel application or the developer’s system.
  - **Potential Cascade of Attacks:** Unintended execution of Laravel code might lead to further unintended side effects within the locally bootstrapped Laravel application (for example, unintentionally running administrative migrations or configuration changes).

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The extension uses a default value (`php -r "{code}"`) if no configuration is explicitly provided.
  - In `Helpers.runPhp`, a basic escaping mechanism is applied to the PHP code (e.g., replacing `"` with `\"`) and additional OS-specific escaping for Unix-like platforms.

- **Missing Mitigations:**
  - **No Strict Sanitization or Validation:** There is no validation of the overall structure of the `phpCommand` setting. The code only replaces a known placeholder without verifying that no extra commands have been appended.
  - **Lack of Whitelisting:** The extension does not restrict the command to a safe pattern (for example, enforcing that only a single PHP command with no concatenated additional shell instructions is permitted).
  - **No User Warning or Safe-Mode:** There is no runtime check that warns users if the configured command deviates from a known safe template.

- **Preconditions:**
  - The attacker must be able to influence the workspace or project configuration (for example, by providing a malicious settings file that is loaded automatically or tricking a user into applying such settings).
  - The extension is running in an environment where the default configuration can be overridden (e.g., shared settings in a team project or misconfigured VSCode settings).

- **Source Code Analysis:**
  - In the helper function `Helpers.runPhp` (see *helpers.ts*), the extension retrieves the command template from configuration:
    ```ts
    let commandTemplate = vscode.workspace
        .getConfiguration("LaravelExtraIntellisense")
        .get<string>('phpCommand') ?? "php -r \"{code}\"";
    ```
  - The provided PHP code (generated elsewhere) is pre-processed with minimal escaping:
    ```ts
    code = code.replace(/\"/g, "\\\"");
    // Additional escaping applied for Unix-based platforms...
    ```
  - The placeholder `{code}` is then replaced without further checks:
    ```ts
    let command = commandTemplate.replace("{code}", code);
    ```
    This means that if an attacker has set the configuration to include additional shell commands beyond the `{code}` placeholder (for example, appending `; system('malicious_command');`), the complete command string will include these malicious parts.
  - Finally, the command is executed using `cp.exec` without further sanitization. This lack of validation opens the door to PHP (and shell) code injection.

- **Security Test Case:**
  1. **Preparation:**
     - Modify (or create) a VSCode workspace settings file to include a malicious `phpCommand` value. For example, in your workspace `settings.json` add:
       ```json
       {
         "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('echo Vulnerable');\""
       }
       ```
       (On Windows, you might substitute `system('calc');` or another benign command for testing.)
  2. **Triggering the Vulnerability:**
     - Open a Laravel project in VSCode that uses this extension.
     - Trigger an autocomplete provider that internally calls the `Helpers.runLaravel` function (for example, invoking route or view autocompletion that relies on Laravel’s runtime information).
  3. **Observation:**
     - Monitor the output channel of the extension or any side effects on the system. You should see evidence that the injected command was executed (e.g., the output “Vulnerable” is printed to the console or the calculator application starts if using a test payload).
  4. **Validation:**
     - Confirm that the malicious command was executed as a result of the manipulated configuration value. This demonstrates the arbitrary PHP (and shell) code execution risk.
