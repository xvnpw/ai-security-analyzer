# Combined Vulnerability Report

## Vulnerability Name: Arbitrary Command Execution via phpCommand Configuration
**Description**:
The extension allows user-defined `phpCommand` configurations to execute PHP code for metadata gathering. Attackers can inject arbitrary shell commands before/after the `{code}` placeholder. For example, setting `"bash -c '{code}; rm -rf /'"` would execute malicious commands alongside legitimate PHP code. The template is not validated/sanitized.

**Impact**:
**Critical** - Full system compromise, including command execution, data destruction, or unauthorized access.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**:
- A security note advises safe configurations (e.g., Docker), but default command (`php -r "{code}"`) remains unsafe.

**Missing Mitigations**:
- No input validation/sanitization for `phpCommand`.
- No restrictions on allowed commands or execution sandboxing.

**Preconditions**:
- User configures `phpCommand` with malicious templates (e.g., via `settings.json`).

**Source Code Analysis**:
In `helpers.ts`, `commandTemplate.replace("{code}", code)` directly substitutes the placeholder without validation:
```typescript
let commandTemplate = vscode.workspace.getConfiguration("...").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
cp.exec(command, ...); // executes unvalidated command
```

**Security Test Case**:
1. Set `"LaravelExtraIntellisense.phpCommand": "bash -c '{code}; echo HACKED > /tmp/exploit.txt'"`.
2. Trigger metadata collection (e.g., autocomplete).
3. Verify `/tmp/exploit.txt` contains "HACKED".

---

## Vulnerability Name: Path Traversal via basePath Configuration
**Description**:
The `basePath` configuration specifies the project directory. Attackers can set it to traverse outside the workspace (e.g., `"../../"`), exposing sensitive files (e.g., `.env`).

**Impact**:
**High** - Unauthorized access to sensitive files outside the project.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**:
- None. No validation for traversal sequences (`../`).

**Missing Mitigations**:
- Input validation to block traversal.
- Enforce `basePath` within the workspace.

**Preconditions**:
- User configures `basePath` with malicious paths (e.g., `"../../"`).

**Source Code Analysis**:
`projectPath()` resolves paths without validation:
```typescript
return path ? path.startsWith('/') ? path : join(basePath!, path) : basePath!;
```

**Security Test Case**:
1. Set `"LaravelExtraIntellisense.basePath": "../../"`.
2. Trigger access to `/etc/passwd`.
3. Verify the extension reads arbitrary files.

---

## Vulnerability Name: Insecure Execution of User-Supplied PHP Code
**Description**:
The extension executes PHP code extracted from project files (e.g., Blade templates, routes) to gather metadata. Malicious code in these files (e.g., `exec()` calls) executes without validation.

**Impact**:
**High** - PHP code execution leading to data leaks or system access.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**:
- A warning in the README, but no technical safeguards.

**Missing Mitigations**:
- Validation of project file contents before execution.
- Execution sandboxing.

**Preconditions**:
- Attackers control project files (e.g., malicious Blade directives).

**Source Code Analysis**:
Malicious Blade directives execute when parsed:
```typescript
Helpers.runPhp(`require '${projectPath}/bootstrap/app.php'; ...`);
```

**Security Test Case**:
1. Add `Blade::directive('hax', function() { exec('echo HACKED > /tmp/exploit.txt'); });` to `BladeServiceProvider.php`.
2. Activate the extension.
3. Verify `/tmp/exploit.txt` contains "HACKED".

---

## Vulnerability Name: Arbitrary Code Execution via User-Provided Model File Inclusion
**Description**:
The extension includes all PHP files in configured model directories (e.g., `app/Models`). Malicious model files (e.g., `<?php system('id'); ?>`) execute during metadata loading.

**Impact**:
**Critical** - Full remote code execution (RCE) due to unvalidated file inclusion.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**:
- None. Files are executed unconditionally.

**Missing Mitigations**:
- Parse metadata without executing files.
- Restrict allowed filenames (e.g., `*.model.php`).

**Preconditions**:
- Malicious model file exists in `modelsPaths`.

**Source Code Analysis**:
```typescript
include_once base_path(...); // executes all files in modelsPaths
```

**Security Test Case**:
1. Create `App/Models/Exploit.php` with `file_put_contents('/tmp/rce_exploit', 'PWNED');`.
2. Ensure `modelsPaths` includes the directory.
3. Verify `/tmp/rce_exploit` is created.

---

## Vulnerability Name: Remote Code Execution via Laravel Application Execution
**Description**:
The extension boots the user’s Laravel application when gathering metadata, executing all startup code (e.g., service providers). Malicious code in these components runs during initialization.

**Impact**:
**Critical** - RCE due to untrusted Laravel application execution.

**Vulnerability Rank**: Critical

**Currently Implemented Mitigations**:
- None. No sandboxing or validation.

**Missing Mitigations**:
- Avoid executing the Laravel app; use static analysis instead.
- Provide isolated execution environments.

**Preconditions**:
- Malicious Laravel project is opened with the extension.

**Source Code Analysis**:
```typescript
runLaravel() // bootstraps the full Laravel application
```

**Security Test Case**:
1. Add `file_put_contents('/tmp/rce_exploit', 'PWNED');` to a service provider’s `boot()` method.
2. Open the project in VS Code.
3. Verify `/tmp/rce_exploit` exists.

---

## Vulnerability Name: Path Traversal via basePathForCode Configuration
**Description**:
The `basePathForCode` setting specifies paths for PHP `require_once` statements. Attackers can set it to external paths (e.g., `../malicious_dir`), enabling unauthorized file inclusion.

**Impact**:
**High** - Execution of arbitrary PHP files outside the project directory.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**:
- None. Paths are used directly without validation.

**Missing Mitigations**:
- Validate `basePathForCode` against workspace boundaries.

**Preconditions**:
- Malicious configuration points to external directories.

**Source Code Analysis**:
```typescript
return basePathForCode + path; // unvalidated path concatenation
```

**Security Test Case**:
1. Set `"LaravelExtraIntellisense.basePathForCode": "../malicious_dir"`.
2. Place `malicious_dir/exploit.php` with `echo 'PWNED' > /tmp/exploit`.
3. Verify the file executes.

---

## Vulnerability Name: Lack of Sanitization for Generated PHP Code
**Description**:
Variables (e.g., environment values) are unsafe concatenated into generated PHP code. Attackers can inject PHP via environment variables (e.g., `APP_NAME="\"; system('id'); //"`).

**Impact**:
**High** - Arbitrary PHP code execution in generated scripts.

**Vulnerability Rank**: High

**Currently Implemented Mitigations**:
- Minimal escaping (e.g., quotes).

**Missing Mitigations**:
- Sanitize all variables in generated code.

**Preconditions**:
- Attackers control environment variables or other inputs.

**Source Code Analysis**:
```typescript
let command = "...require_once '" + Helpers.projectPath(...) + "'";
```

**Security Test Case**:
1. Set `APP_NAME="\"; system('id'); //`.
2. Trigger code generation including `APP_NAME`.
3. Verify `id` output appears in logs.
