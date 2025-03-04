# Vulnerabilities in Laravel Extra Intellisense

## 1. Command Injection through LaravelExtraIntellisense.phpCommand Setting

### Vulnerability Name
Command Injection via phpCommand configuration

### Description
The Laravel Extra Intellisense extension executes PHP code to gather information from Laravel applications to provide auto-completion functionality. The extension uses a user-configurable setting `LaravelExtraIntellisense.phpCommand` to define how PHP code is executed. By default, this is set to `php -r "{code}"`, where `{code}` is replaced with PHP code to be executed.

A malicious actor could create a repository with a customized `.vscode/settings.json` file containing a manipulated `LaravelExtraIntellisense.phpCommand` setting that includes shell metacharacters or additional commands. When a victim opens this repository in VSCode, the extension will use this malicious command template to execute PHP code, leading to arbitrary command execution on the victim's machine.

Step by step process:
1. Attacker creates a malicious repository with a modified `.vscode/settings.json`
2. Victim clones and opens the repository in VSCode
3. Laravel Extra Intellisense extension activates automatically
4. Extension reads the malicious `phpCommand` configuration
5. When the extension executes PHP code to gather Laravel information, it uses the malicious command template
6. Arbitrary commands are executed on the victim's system

### Impact
An attacker can execute arbitrary commands with the privileges of the VSCode user. This could lead to data theft, installation of malware, lateral movement within the network, or complete compromise of the developer's system.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension implements some basic sanitization:
- Escapes double quotes in the PHP code with `code = code.replace(/\"/g, "\\\"");`
- On Unix-like systems, escapes dollar signs and backslashes
- Extracts output using marker strings

However, these mitigations do not prevent command injection through the phpCommand setting itself.

### Missing Mitigations
1. The extension should validate the `phpCommand` setting to ensure it only contains safe characters and doesn't include any shell metacharacters
2. The extension should use safer methods to execute PHP code, such as spawning a process directly rather than using shell execution
3. The extension should warn users when it detects potentially dangerous configurations

### Preconditions
1. Victim must open a malicious repository in VSCode
2. The Laravel Extra Intellisense extension must be installed
3. The victim must have PHP installed on their system

### Source Code Analysis
In `helpers.ts`, the `runPhp` method executes PHP code via the command line:

```typescript
static runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
        code = code.replace(/\$/g, "\\$");
        code = code.replace(/\\\\'/g, '\\\\\\\\\'');
        code = code.replace(/\\\\"/g, '\\\\\\\\\"');
    }
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);
    let out = new Promise<string>(function (resolve, error) {
        // ...
        cp.exec(command, { cwd: ... }, function (err, stdout, stderr) {
            // ...
        });
    });
    return out;
}
```

The vulnerability exists because:
1. The `commandTemplate` is obtained directly from user configuration without validation
2. The command is executed using `cp.exec()` which spawns a shell, making it vulnerable to command injection
3. There's no validation that the `commandTemplate` only contains the expected `{code}` placeholder

### Security Test Case
1. Create a malicious repository with the following `.vscode/settings.json` file:
```json
{
  "LaravelExtraIntellisense.phpCommand": "echo 'PWNED' > /tmp/hacked && php -r \"{code}\""
}
```

2. Create a simple Laravel project structure in the repository with at least:
   - An `artisan` file at the root
   - A `vendor/autoload.php` file
   - A `bootstrap/app.php` file

3. Have the victim clone and open the repository in VSCode with Laravel Extra Intellisense extension installed

4. The extension will activate and try to read Laravel configuration, executing the malicious command

5. Check for the existence of `/tmp/hacked` file on the victim's system to confirm the vulnerability

## 2. Code Injection through LaravelExtraIntellisense.basePathForCode Setting

### Vulnerability Name
Code Injection via basePathForCode configuration

### Description
The Laravel Extra Intellisense extension uses a setting `LaravelExtraIntellisense.basePathForCode` to determine where to look for Laravel project files when executing PHP code. A malicious repository can set this value to a path containing malicious PHP files, which will then be included and executed when the extension runs.

Step by step process:
1. Attacker creates a malicious repository with a modified `.vscode/settings.json` pointing to a controlled location
2. The attacker places malicious PHP files in a location that matches Laravel's expected structure
3. Victim opens the repository in VSCode
4. The extension loads Laravel project files from the malicious path specified in settings
5. Malicious PHP code gets executed when the extension bootstraps Laravel

### Impact
This vulnerability allows attackers to execute arbitrary PHP code on the victim's system. The code runs with the same privileges as the VSCode process, potentially allowing attackers to access sensitive information, modify files, or establish persistence on the victim's machine.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension does some basic path sanitization and resolves relative paths correctly, but it doesn't validate that the specified basePathForCode is safe or within the project directory.

### Missing Mitigations
1. The extension should validate that the basePathForCode is within the workspace directory
2. It should warn users when the basePathForCode points to a location outside the current project
3. It should implement a sandbox or other security controls to limit the execution environment

### Preconditions
1. Victim must open a malicious repository in VSCode
2. Laravel Extra Intellisense extension must be installed
3. The attacker must be able to place malicious PHP files in a location accessible to the victim's machine

### Source Code Analysis
In `helpers.ts`, the `projectPath` method is used to resolve file paths:

```typescript
static projectPath(path:string, forCode: boolean = false) : string {
    if (path[0] !== '/') {
        path = '/' + path;
    }

    let basePath = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePath');
    // ...

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

This method is used in `runLaravel` to include PHP files:

```typescript
"require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
"$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
```

The vulnerability exists because:
1. The `basePathForCode` value is obtained directly from user configuration without adequate validation
2. The extension doesn't validate that the path is within the workspace directory
3. PHP files from this path are included and executed

### Security Test Case
1. Create a malicious repository with the following `.vscode/settings.json` file:
```json
{
  "LaravelExtraIntellisense.basePathForCode": "/tmp/malicious-laravel"
}
```

2. Create a malicious Laravel-like structure in `/tmp/malicious-laravel` with:
```
/tmp/malicious-laravel/
  ├── vendor/
  │   └── autoload.php  # Contains malicious code
  └── bootstrap/
      └── app.php       # Contains malicious code
```

3. In `autoload.php`, add code like:
```php
<?php
file_put_contents('/tmp/pwned.txt', 'System compromised');
// Regular autoload code to avoid errors
```

4. Have the victim open the repository in VSCode with Laravel Extra Intellisense extension installed

5. The extension will activate and try to bootstrap Laravel from the malicious path

6. Check for the existence of `/tmp/pwned.txt` to confirm successful exploitation
