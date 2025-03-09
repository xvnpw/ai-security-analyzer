# Vulnerability Report

## Vulnerability 1: Arbitrary Command Execution via phpCommand Configuration
**Vulnerability Name**: Arbitrary Command Execution via phpCommand Configuration
**Description**:
The extension allows users to configure the `phpCommand` setting, which is used to execute PHP code. This setting is directly interpolated into shell commands without validation. An attacker can set `phpCommand` to a malicious value, leading to arbitrary command execution when the extension executes PHP code.

**Step-by-step Exploitation**:
1. An attacker sets `phpCommand` to a template like `php -r \"{code}; system('id')\"`.
2. The extension uses this template in `Helpers.runPhp()`, appending user PHP code.
3. The malicious shell command (e.g., `system('id')`) executes, revealing system information or executing arbitrary code.

**Impact**: Remote Code Execution (RCE) on the developer’s machine, potentially leading to full system compromise, data theft, or service disruption.
**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**: None. The configuration is accepted verbatim without validation.
**Missing Mitigations**:
- Input validation/sanitization for `phpCommand`.
- Escaping or whitelisting allowed commands.

**Preconditions**:
- The user must configure a malicious `phpCommand` value.
- The extension must execute PHP code (e.g., during route parsing or autocompletion).

**Source Code Analysis**:
In `src/helpers.ts`, the `phpCommand` value is directly used to construct shell commands:
```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
cp.exec(command, ...); // Executes the command
```
The lack of validation allows attackers to inject arbitrary shell commands outside the `{code}` placeholder.

**Security Test Case**:
1. Set `phpCommand` to `"php -r \"{code}\"; touch /tmp/ATTACK"`.
2. Trigger PHP execution (e.g., editing a Blade template).
3. Verify `/tmp/ATTACK` exists, confirming RCE.

---

## Vulnerability 2: Path Traversal via basePath/basePathForCode Configuration
**Vulnerability Name**: Path Traversal via basePath/basePathForCode Configuration
**Description**: The `basePath` and `basePathForCode` configurations are not validated for traversal attacks. Attackers can set these values to traverse directories (e.g., `../../../../../etc`), allowing unauthorized access to sensitive system files.

**Step-by-step Exploitation**:
1. Set `basePathForCode` to `../../../../../etc`.
2. The extension uses this path to resolve files like `projectPath("passwd")`, accessing `/etc/passwd`.

**Impact**: Unauthorized access to sensitive files (e.g., `/etc/passwd`, private keys).
**Vulnerability Rank**: High

**Currently Implemented Mitigations**: None. Paths are accepted verbatim.
**Missing Mitigations**:
- Validation to block traversal patterns (e.g., `../`).
- Restricting paths to the workspace/project directory.

**Preconditions**:
- The user must configure malicious `basePath`/`basePathForCode` values.

**Source Code Analysis**:
In `src/helpers.ts`, paths are concatenated without validation:
```typescript
static projectPath(path: string, forCode: boolean = false): string {
  let basePathForCode = vscode.workspace.getConfiguration(...).get<string>('basePathForCode');
  return basePathForCode + path; // Direct path concatenation enables traversal
}
```

**Security Test Case**:
1. Configure `basePathForCode` to `"../../../../../etc"`.
2. Trigger a file access operation (e.g., loading `projectPath("passwd")`).
3. Verify the extension reads `/etc/passwd`.

---

## Vulnerability 3: Path Traversal via basePathForCode Leading to Arbitrary File Inclusion
**Vulnerability Name**: Path Traversal via basePathForCode Leading to Arbitrary File Inclusion
**Description**: The `basePathForCode` configuration is used in PHP code execution paths (e.g., `require_once`). Attackers can set it to a malicious directory to include and execute arbitrary PHP files (e.g., a modified `bootstrap/app.php`).

**Step-by-step Exploitation**:
1. Create a malicious directory with a file like `bootstrap/app.php` containing `system('echo HACKED')`.
2. Set `basePathForCode` to the malicious directory path.
3. The extension executes PHP code, loading the malicious `app.php` and executing attacker code.

**Impact**: Arbitrary code execution via malicious PHP files.
**Vulnerability Rank**: High

**Currently Implemented Mitigations**: None.
**Missing Mitigations**:
- Validate `basePathForCode` points to a valid Laravel project directory.
- Restrict paths to the user’s workspace.

**Preconditions**:
- The attacker must control the malicious directory path.

**Source Code Analysis**:
Malicious paths are used directly in PHP includes:
```typescript
// In EloquentProvider.loadModels()
Helpers.runLaravel("...dynamic PHP code...", basePathForCode + "/malicious/file");
```

**Security Test Case**:
1. Create `/malicious-path/bootstrap/app.php` with `echo "ATTACK"; exit;`.
2. Set `basePathForCode` to `/malicious-path`.
3. Trigger a scan (e.g., loading routes).
4. Observe the malicious output in logs.

---

## Vulnerability 4: Code Injection via Model or View Files
**Vulnerability Name**: Code Injection via Model or View Files
**Description**: The extension executes PHP code dynamically generated from project files (e.g., Blade views or Eloquent models). Attackers can inject malicious code into these files, which is then executed by the extension.

**Step-by-step Exploitation**:
1. Add malicious PHP code (e.g., `<?php system('touch /tmp/ATTACK'); ?>`) to a Blade view or model file.
2. The extension’s autocompletion or introspection features process the file, executing the injected code.

**Impact**: Arbitrary code execution in the context of the extension’s privileges.
**Vulnerability Rank**: High

**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Sanitization of user-controlled files before execution.

**Preconditions**:
- The attacker must modify project files (e.g., via compromised source control).

**Source Code Analysis**:
In `ViewProvider` and `EloquentProvider`, PHP code is executed without validation:
```typescript
Helpers.runPhp("...dynamic code from user files..."); // Executes malicious code
```

**Security Test Case**:
1. Add `<?php system('touch /tmp/ATTACK'); ?>` to a Blade view.
2. Trigger autocompletion (e.g., editing the view).
3. Verify `/tmp/ATTACK` exists.
