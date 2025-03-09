### Vulnerability Name: Arbitrary Command Execution via phpCommand Configuration

#### Description
The extension allows configuration of the `phpCommand`, which is used to execute PHP code for metadata gathering. Since the command template is user-defined and not sanitized, attackers can inject arbitrary commands before or after the `{code}` placeholder. For example, setting the configuration to `"php -r \"{code}\"; rm -rf /"` would execute the malicious command alongside legitimate code. The extension blindly replaces `{code}` without validating the surrounding template.

#### Impact
**Critical** - Attackers can execute arbitrary system commands, leading to full system compromise, data destruction, or unauthorized access.

#### Currently Implemented Mitigations
- Security note advising users to configure the command safely (e.g., via Docker).
- Default command (`php -r "{code}"`) is safe but does not block malicious templates.

#### Missing Mitigations
- No input validation/sanitization for `phpCommand`.
- No restrictions on allowed commands or execution sandboxing.

#### Preconditions
- User has configured `phpCommand` with a malicious template (e.g., via a compromised project's `settings.json`).
- Extension is active and periodically runs configured commands.

#### Source Code Analysis
In `helpers.ts`:
```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
cp.exec(command, ...);
```
An attacker can prepend/append malicious commands (e.g., `"php -r \"{code}\" && echo 'HACKED' > /tmp/exploit.txt"`), which execute alongside the generated code.

#### Security Test Case
1. Create a malicious `settings.json` with:
   ```json
   "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && echo 'HACKED' > /tmp/exploit.txt"
   ```
2. Open the project in VSCode with the extension enabled.
3. The extension will execute the command during metadata collection.
4. Verify `/tmp/exploit.txt` contains "HACKED".

---

### Vulnerability Name: Path Traversal via basePath Configuration

#### Description
The `basePath` configuration specifies the Laravel project directory. If manipulated to point to arbitrary paths (e.g., `../../malicious`), the extension reads/writes files outside the intended project scope, exposing sensitive data or enabling unauthorized access to files.

#### Impact
**High** - Attackers can access sensitive files like `.env`, `storage/framework/cache`, or execute code from unauthorized directories.

#### Currently Implemented Mitigations
- No validation on `basePath` input.

#### Missing Mitigations
- No input validation to block traversal sequences (`../`).
- No checks to enforce `basePath` within the workspace.

#### Preconditions
- User has configured `basePath` to traverse directories (e.g., via a malicious `settings.json`).

#### Source Code Analysis
In `helpers.ts`:
```typescript
static projectPath(path: string, forCode: boolean = false): string {
  let basePath = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePath');
  return path ? path.startsWith('/') ? path : join(basePath!, path) : basePath!;
}
```
Setting `basePath` to `../../` bypasses intended project boundaries. For example, `projectPath("config.php")` becomes `../../config.php`.

#### Security Test Case
1. Create a malicious `settings.json` with:
   ```json
   "LaravelExtraIntellisense.basePath": "../../"
   ```
2. Trigger the extension to access a file like `.env` (located outside the project).
3. Verify the extension reads the file contents (e.g., via logs or autocompletion).

---

### Vulnerability Name: Insecure Execution of User-Supplied PHP Code

#### Description
The extension executes PHP code generated from project files (e.g., routes, Blade templates) to gather metadata. If an attacker modifies project files (e.g., adding malicious Blade directives or artisan commands), the extension will execute this code during analysis, leading to arbitrary PHP code execution in the user’s environment.

#### Impact
**High** - Attackers can execute PHP code within the extension’s context, potentially leaking secrets, modifying files, or escalating privileges.

#### Currently Implemented Mitigations
- Security note warns users about executing Laravel code.
- No mitigations for malicious project content.

#### Missing Mitigations
- No validation of project file contents before execution.
- No sandboxing to restrict execution scope.

#### Preconditions
- Attacker controls the project files (e.g., malicious Blade directives or artisan scripts).

#### Source Code Analysis
In `BladeProvider.ts`:
```typescript
// Example: Loading Blade directives from project files
Helpers.runPhp(`require '${projectPath}/bootstrap/app.php'; app()->make('blade.compiler')->compileString('...')`);
```
A malicious Blade directive like:
```php
Blade::directive('exec', function ($command) { exec($command); });
```
will execute when the extension parses Blade templates.

#### Security Test Case
1. Create a Laravel project with a malicious Blade directive:
   ```php
   // app/Providers/BladeServiceProvider.php
   Blade::directive('hax', function () { exec('echo "HACKED" > /tmp/exploit.txt'); });
   ```
2. Activate the extension in this project.
3. The extension parses Blade templates, triggering the malicious directive.
4. Verify `/tmp/exploit.txt` contains "HACKED".

---

### Summary of Valid Vulnerabilities
| Vulnerability Name | Rank       | Impact                                                                 |
|--------------------|------------|------------------------------------------------------------------------|
| Arbitrary Command Execution via phpCommand Configuration | Critical | Execute arbitrary system commands.                           |
| Path Traversal via basePath Configuration              | High     | Access sensitive files outside project directory.            |
| Insecure Execution of User-Supplied PHP Code            | High     | Execute malicious PHP code from project files.               |

All vulnerabilities are realistic attack vectors with high/critical severity, require no theoretical assumptions, and are clearly exploitable via documented test cases.
