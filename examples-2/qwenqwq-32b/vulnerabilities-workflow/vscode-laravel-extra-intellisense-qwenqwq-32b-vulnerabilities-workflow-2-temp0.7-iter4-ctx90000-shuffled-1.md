- **Vulnerability Name**: Arbitrary Command Execution via phpCommand Configuration
  **Description**:
  The extension allows users to configure the `phpCommand` setting, which is used to execute PHP code. This setting is directly interpolated into shell commands without validation. An attacker could set `phpCommand` to a malicious value that injects arbitrary PHP code or system commands when the extension executes PHP code.
  **Step-by-step Exploitation**:
  1. An attacker sets `phpCommand` configuration to `php -r "system('id'); echo '{code}'"`.
  2. The extension runs PHP code via `Helpers.runPhp()`, which appends the user's PHP `{code}` to the attacker-controlled command.
  3. The injected `system('id')` executes, revealing system information.
  **Impact**: Remote Code Execution (RCE) on the developer's machine. An attacker could gain full control over the system, steal data, or execute malicious payloads.
  **Vulnerability Rank**: Critical
  **Currently Implemented Mitigations**: None. The configuration is accepted as-is without validation or sanitization.
  **Missing Mitigations**:
  - Input validation/sanitization for `phpCommand`.
  - Escaping or whitelisting allowed commands.
  **Preconditions**:
  - User must configure a malicious `phpCommand` value.
  - The extension must execute PHP code (e.g., during route, view, or configuration parsing).
  **Source Code Analysis**:
  In `src/helpers.ts`:
  ```typescript
  // The user-configurable `phpCommand` is directly used without validation
  let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
  let command = commandTemplate.replace("{code}", code); // Malicious {code} injection possible
  cp.exec(command, ...); // Executes the command
  ```
  The `runPhp` function constructs shell commands using unvalidated user input from `phpCommand`, allowing arbitrary command injection.
  **Security Test Case**:
  1. Configure the VSCode extension with `phpCommand`:
     ```json
     "LaravelExtraIntellisense.phpCommand": "php -r \"system('echo Compromised > /tmp/exploit.txt');{code}\""
     ```
  2. Trigger PHP execution via the extension (e.g., edit a Blade template to auto-complete a route).
  3. Check `/tmp/exploit.txt` for the "Compromised" string, indicating successful RCE.

- **Vulnerability Name**: Path Traversal via basePath/basePathForCode Configuration
  **Description**:
  The `basePath` and `basePathForCode` configurations are used to set the Laravel project path but are not validated for traversal attacks. An attacker could set these values to traverse directories (e.g., `../../malicious-path`) to access restricted files.
  **Step-by-step Exploitation**:
  1. Set `basePathForCode` to `../../../../../etc` to access system files.
  2. The extension uses this path to load files (e.g., `projectPath("passwd")` resolves to `/etc/passwd`).
  **Impact**: Unauthorized access to sensitive files on the developer's system.
  **Vulnerability Rank**: High
  **Currently Implemented Mitigations**: None. Paths are accepted verbatim.
  **Missing Mitigations**:
  - Validation to prevent path traversal (e.g., `../`).
  - Restricting paths to within the workspace.
  **Preconditions**:
  - User must configure malicious `basePath`/`basePathForCode` values.
  **Source Code Analysis**:
  In `src/helpers.ts`:
  ```typescript
  static projectPath(path:string, forCode: boolean = false) : string {
    // Directly uses basePathForCode without validating for traversal
    let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
    return basePathForCode + path;
  }
  ```
  **Security Test Case**:
  1. Configure `basePathForCode` to `"../../../../../etc"`.
  2. Trigger a file access operation (e.g., loading `projectPath("passwd")`).
  3. Verify the extension accesses `/etc/passwd`.
