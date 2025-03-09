- **Vulnerability Name:** Command Injection via phpCommand Configuration
  **Description:**
  1. The extension allows users to configure the `LaravelExtraIntellisense.phpCommand` setting, which specifies the command to execute PHP code.
  2. This command is directly interpolated into a shell command without input validation or sanitization.
  3. An attacker could manipulate this setting to include malicious payloads, such as `docker exec ...; rm -rf /` to execute arbitrary shell commands.
  4. The extension uses this command in `Helpers.runPhp()` to execute PHP code during operations like fetching routes or configuration data.

  **Impact:**
  - Allows arbitrary command execution on the victim's machine.
  - Potential for complete system compromise if the extension runs with elevated privileges.

  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - None. The extension does not validate or sanitize the `phpCommand` value.
  **Missing Mitigations:**
  - Lack of validation/sanitization for `phpCommand`.
  - No restrictions on command syntax or characters.
  **Preconditions:**
  - User must configure `phpCommand` with malicious input (e.g., via a malicious repository's documentation or compromised settings).

  **Source Code Analysis:**
  - **File:** `src/helpers.ts`
    - `runPhp()` constructs the command using `commandTemplate.replace("{code}", code)`, where `commandTemplate` is the user-configurable `phpCommand`.
    - Example vulnerable code:
      ```typescript
      let command = commandTemplate.replace("{code}", code); // No sanitization
      cp.exec(command, ...);
      ```
  - **File:** `README.md`
    - The `phpCommand` configuration is user-editable and lacks warnings about command injection risks.

  **Security Test Case:**
  1. Configure `LaravelExtraIntellisense.phpCommand` to:
     ```json
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('echo VULNERABLE > /tmp/exploit.txt')\""
     ```
  2. Trigger any operation that uses `runPhp()` (e.g., fetching routes or middleware).
  3. Verify that `/tmp/exploit.txt` is created, indicating command execution.

---

- **Vulnerability Name:** Arbitrary Code Execution via Malicious Laravel Project Files
  **Description:**
  1. The extension executes PHP code within the context of the Laravel project (via `runLaravel()`).
  2. Malicious project files (e.g., models, middleware) could contain PHP code that executes during extension operations.
  3. Attackers can trick victims into opening a malicious Laravel repository containing payloads.

  **Impact:**
  - Runs attacker-controlled code in the victim's environment.
  - Could lead to data theft or system compromise.

  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The **Security Note** warns users about executing untrusted code.
  **Missing Mitigations:**
  - No runtime code analysis to block malicious operations.
  - No sandboxing or execution restrictions for Laravel processes.
  **Preconditions:**
  - Victim opens a malicious Laravel repository with payloads in project files (e.g., `app/Http/Controllers` or `routes/web.php`).

  **Source Code Analysis:**
  - **File:** `src/helpers.ts`
    - `runLaravel()` bootstraps Laravel and executes project code to gather data.
    ```typescript
    // Executes Laravel app to fetch routes/models/middleware
    Helpers.runLaravel("...", "...")
    ```

  **Security Test Case:**
  1. Create a malicious Laravel project with a model file containing `system('echo PAYLOAD > /tmp/exploit.txt');`.
  2. Open this project in VSCode and enable the extension.
  3. Verify that `/tmp/exploit.txt` is created due to model execution during extension operations.
