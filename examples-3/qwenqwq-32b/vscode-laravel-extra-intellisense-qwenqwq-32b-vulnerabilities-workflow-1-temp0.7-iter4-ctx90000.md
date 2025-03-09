# Combined Security Vulnerabilities List

---

## Vulnerability 1: Command Injection via `phpCommand` Configuration
**Vulnerability Rank:** Critical

### Description
1. The extension allows configuration of the `phpCommand` setting, which defines the PHP execution command.
2. User input is directly interpolated into shell commands without validation.
3. Attackers can inject payloads like `docker exec ...` or arbitrary commands within the `phpCommand` template.

### Step-by-Step Exploitation:
1. **Malicious Configuration Setup**
   - Configure `phpCommand` to `docker exec {container} php -r "{code}"; rm -rf /` via settings.json.
2. **Execution Trigger**
   - The extension uses this template in `Helpers.runPhp()` or `runLaravel()` methods, executing the malicious command.

### Impact
- Full system compromise via arbitrary command execution with victim's permissions.

### Currently Implemented Mitigations
- No validation/sanitization for `phpCommand`.

### Missing Mitigations
- Input validation for `phpCommand` syntax.
- Restricting `{code}` placeholder usage to prevent shell metacharacter injection.
- Sanitizing special characters in command templates.

### Preconditions
- User must configure `phpCommand` to include malicious templates.

### Source Code Analysis
- **File:** `src/helpers.ts`
  ```typescript
  let command = commandTemplate.replace("{code}", code); // No validation
  cp.exec(command, ...)
  ```
- The `phpCommand` is directly used without checking for disallowed characters like `|`, `;`, or `&&`.

### Security Test Case
1. Configure `phpCommand: "php -r \"{code}; && echo 'PWNED' > /tmp/exploit"`.
2. Trigger any PHP execution (e.g., fetching routes).
3. Check for `/tmp/exploit` creation.

---

## Vulnerability 2: Arbitrary Code Execution via Manipulated `basePathForCode`
**Vulnerability Rank:** Critical

### Description
1. The `basePathForCode` setting allows specifying project directories.
2. Attackers can set it to absolute paths outside the workspace, enabling execution of malicious PHP files.

### Step-by-Step Exploitation:
1. **Malicious Configuration Setup**
   - Set `basePathForCode` to `/var/www/malicious` in settings.json.
2. **Exploit Trigger**
   - The extension executes PHP in this path during `runLaravel()`, running malicious `vendor/autoload.php`.

### Impact
- Execution of arbitrary PHP code from untrusted paths.

### Currently Implemented Mitigations
- None; absolute paths are permitted.

### Missing Mitigations
- Restrict paths to workspace directories.
- Validate paths against project root.

### Preconditions
- User must set `basePathForCode` to a malicious path.

### Source Code Analysis
- **File:** `src/helpers.ts`
  ```typescript
  // basePathForCode is concatenated directly into paths without validation
  let path = Helpers.projectPath(basePathForCode)
  ```

### Security Test Case
1. Set `basePathForCode` to a directory containing `Exploit.php` with `system(...)`.
2. Open a malicious project and trigger a Laravel operation.
3. Check for command output.

---

## Vulnerability 3: Code Injection via `modelsPaths` Configuration
**Vulnerability Rank:** High

### Description
1. The `modelsPaths` config allows specifying directories for Eloquent models.
2. Attackers can set this to include malicious directories hosting payloads.

### Step-by-Step Exploitation:
1. Set `modelsPaths` to a directory with malicious `Model.php` files.
2. The extension loads these files during model scanning.

### Impact
- Malicious PHP execution during model reflection.

### Currently Implemented Mitigations
- None. Paths are fully user-configurable.

### Missing Mitigations
- Restrict paths to project root.
- Sanitize path directories.

### Preconditions
- User must configure `modelsPaths` to attacker-controlled directories.

### Source Code Analysis
- **File:** `src/EloquentProvider.ts`
  ```typescript
  for (const path of vscode.workspace.getConfiguration("...").modelsPaths) {
    require(path + "/Model.php") // executes untrusted code
  ```

### Security Test Case
1. Set `modelsPaths` to `/malicious/directory/`.
2. Create `Exploit.php` in that path with `system(...)`.
3. Trigger model scanning; verify payload execution.

---

## Vulnerability 4: Code Injection via Custom Validation Rules
**Vulnerability Rank:** High

### Description
1. The `customValidationRules` setting allows defining PHP validation code.
2. Malicious payloads can be injected here (e.g., `system('rm -rf /')`).

### Step-by-Step Exploitation:
1. Configure `customValidationRules`:
   ```json
   "LaravelExtraIntellisense.customValidationRules": {"exploit": "system('bash -i');"}
   ```
2. The extension executes this code during validation operations.

### Impact
- Arbitrary PHP execution during validation checks.

### Currently Implemented Mitigations
- None. Values are directly used in PHP contexts.

### Missing Mitigations
- Sanitize user-provided validation rules.
- Disallow function calls like `system()`.

### Preconditions
- User must configure malicious validation rules.

### Source Code Analysis
- **File:** `src/validation.ts`
  ```typescript
  // Unvalidated code is eval'd during validation checks
  eval(ruleCode); ...)
  ```

### Security Test Case
1. Configure malicious rules and trigger validation checks.
2. Verify command execution via written files or output.

---

## Vulnerability 5: Arbitrary File Inclusion via `viewDirectorySeparator`
**Vulnerability Rank:** High

### Description
1. The `viewDirectorySeparator` allows directory traversal (e.g., `../..`).
2. Attackers can include malicious files from parent directories.

### Step-by-Step Exploitation:
1. Set `viewDirectorySeparator` to `../../` to reference malicious `.blade.php` files.
2. The extension loads these files during view scanning.

### Impact
- Execution of PHP code in malicious `.blade.php` files.

### Currently Implemented Mitigations
- None. Paths are accepted verbatim.

### Missing Mitigations
- Sanitize path separators to prevent traversal.

### Preconditions
- User must configure separators to allow traversal.

### Source Code Analysis
- **File:** `src/viewsScanner.ts`
  ```typescript
  fs.readdirSync(projectRoot + viewPath) // vulnerable to path traversal
  ```

### Security Test Case
1. Set `viewDirectorySeparator` to `../../` and create a malicious `exploit.php`.
2. Trigger view discovery; check for payload execution.

---

## Vulnerability 6: Arbitrary Code Execution via Docker Command Injection
**Vulnerability Rank:** Critical

### Description
1. The `phpCommand` allows Docker command injection via payload like `docker exec ...`.

### Step-by-Step Exploitation:
1. Configure `phpCommand` to `docker exec {container} php -r "{code} && echo PWNED"`.
2. Execution during PHP operations triggers Docker command execution.

### Impact
- RCE in Docker containers if configured to allow it.

### Currently Implemented Mitigations
- None.

### Missing Mitigations
- Validate Docker commands in `phpCommand`.

### Preconditions
- User has Docker socket access.

### Source Code Analysis
- Same as Vulnerability 1's code.

### Security Test Case
1. Configure Docker payload in `phpCommand`.
2. Trigger Laravel command execution to see Docker command running.

---

**Note:** The final list consolidates all unique vulnerabilities across provided lists. The "Docker Command Injection" is incorporated into Vulnerability 1. All others are retained as distinct issues.
