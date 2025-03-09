- **Vulnerability Name:** Insecure PHP Command Injection via `phpCommand` Configuration

  **Description:**
  The extension reads the PHP execution command from the user’s VS Code configuration (`LaravelExtraIntellisense.phpCommand`) and substitutes the placeholder `{code}` with dynamically generated PHP code. The resultant command is executed using Node’s `cp.exec` function. An attacker who can modify this setting—via a malicious workspace configuration or compromised user settings—can inject arbitrary PHP or even shell commands.
  **Step-by-step trigger:**
  1. **Configuration Access:** An attacker gains write access to the extension’s configuration (for example, through a modified workspace settings file or a compromised extension).
  2. **Malicious Template Injection:** The attacker sets the `phpCommand` value to a malicious command template, such as:
     `php -r "{code}"; echo 'INJECTION_SUCCESS';`
     This template appends extra shell commands.
  3. **Command Construction:** When the extension executes a PHP-related action (for instance, during autocompletion or provider refresh), it retrieves the malicious template and replaces `{code}` with auto-generated PHP code.
  4. **Command Execution:** The final command, containing the injected commands, is passed directly to the shell via `cp.exec` and executed.
  5. **Arbitrary Code Execution:** The injected commands run with the privileges of the developer’s environment.

  **Impact:**
  - **Execution of Arbitrary Code:** Allows the attacker to run malicious PHP scripts or system-level shell commands.
  - **Compromise of the Development Environment:** The attacker could modify, delete files, install malware, or perform other harmful actions on the developer’s system.
  - **Security Boundary Bypass:** Enables the attacker to escalate privileges from the VS Code extension to the host environment.

  **Vulnerability Rank:** Critical

  **Currently Implemented Mitigations:**
  - The project’s README includes a security notice advising users to disable this extension when working on sensitive code.
    *However, this is an advisory only and does not enforce technical protection such as input sanitization or safe process spawning.*

  **Missing Mitigations:**
  - **Input/Configuration Sanitization:** There is no validation or sanitization on the user-provided `phpCommand` setting.
  - **Safe Process Spawning:** The extension uses `cp.exec` (which invokes a shell) instead of a safer API (e.g., `spawn` with argument lists) that could prevent command injection.
  - **Whitelisting or Hardcoded Commands:** The command template is not restricted to a safe, known pattern.
  - **Runtime Integrity Checks:** No mechanism exists to verify the safety of the constructed command before execution.

  **Preconditions:**
  - The attacker must be able to alter the `LaravelExtraIntellisense.phpCommand` setting. This could be achieved through:
    - A malicious or compromised workspace settings file.
    - A compromised extension or environment that can modify user configurations.
  - The extension must trigger the execution path (e.g., during autocompletion or Laravel command execution).

  **Source Code Analysis:**
  - In `helpers.ts`, the function (e.g., `runPhp`) retrieves the PHP command configuration:
    ```js
    let commandTemplate = vscode.workspace
                             .getConfiguration("LaravelExtraIntellisense")
                             .get<string>('phpCommand');
    ```
  - The default command is typically set as:
    `php -r "{code}"`
  - The template is then used to form the final command:
    ```js
    let command = commandTemplate.replace("{code}", code);
    ```
    No validation or escaping is performed on either the configuration value or the generated PHP code.
  - The command is executed via:
    ```js
    cp.exec(command, { cwd: <project_folder> }, function (err, stdout, stderr) { … });
    ```
  - **Visualization of the Exploit Process:**
    1. **Configuration Read:**
       `maliciousTemplate = "php -r \"{code}\"; echo 'INJECTION_SUCCESS';"`
    2. **Code Substitution:**
       `finalCommand = "php -r \"<dynamic PHP code>\"; echo 'INJECTION_SUCCESS';"`
    3. **Execution:**
       The shell executes `finalCommand`, thereby triggering both the intended PHP code execution and the injected command.

  **Security Test Case:**
  1. **Preparation:**
     - Open VS Code with a Laravel project using this extension in a controlled test environment (e.g., a virtual machine).
  2. **Modify the Configuration:**
     - In the workspace or user settings file (typically JSON), set:
       ```json
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo 'INJECTION_SUCCESS';"
       ```
  3. **Trigger the Vulnerability:**
     - Initiate an action (such as refreshing autocompletion) that causes the extension to execute PHP code, thereby constructing and running the command.
  4. **Monitor the Output:**
     - Check the extension’s output channel or terminal for the string “INJECTION_SUCCESS”.
  5. **Confirm Exploitation:**
     - The appearance of “INJECTION_SUCCESS” confirms that the injected shell command was executed.
  6. **Cleanup:**
     - Restore the original settings after the test.
