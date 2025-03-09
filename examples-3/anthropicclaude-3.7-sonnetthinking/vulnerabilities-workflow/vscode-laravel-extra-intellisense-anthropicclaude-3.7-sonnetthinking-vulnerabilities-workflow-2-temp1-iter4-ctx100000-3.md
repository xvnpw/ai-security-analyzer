# Vulnerabilities in Laravel Extra Intellisense VSCode Extension

## Command Injection Through Malicious Laravel Project

### Vulnerability Name
Command Injection via PHP Code Execution

### Description
The Laravel Extra Intellisense extension executes PHP code to extract information from Laravel projects for autocomplete features. When a user opens a Laravel project in VSCode, the extension automatically runs PHP commands to interact with the Laravel application. If an attacker creates a malicious Laravel project and a developer opens it in VSCode, the extension could execute harmful code.

The vulnerability exists in the `runPhp` method in `helpers.ts` which uses Node.js `child_process.exec()` to execute PHP code:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Some escaping logic...
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    // Execute the command
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ?
               vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        function (err, stdout, stderr) {
            // Handle output...
        }
    );
}
```

When the extension loads a Laravel project, it uses the `runLaravel` method which bootstraps the Laravel application and executes code within that context. This happens for each provider (routes, views, configs, etc.) to get information for autocomplete suggestions.

### Impact
An attacker who convinces a developer to open a malicious Laravel project could execute arbitrary code on the developer's machine with the same privileges as the VSCode process. This could lead to:

- Data theft (accessing sensitive files on the developer's machine)
- Malware installation
- Lateral movement within the developer's network
- Access to development credentials and tokens

### Vulnerability Rank
High

### Currently Implemented Mitigations
1. The extension includes a security note in the README warning users about the risks:
   ```
   This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete.

   [...] if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing.
   ```

2. Some basic escaping is applied to the PHP code before execution:
   ```typescript
   code = code.replace(/\"/g, "\\\"");
   if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
       code = code.replace(/\$/g, "\\$");
       code = code.replace(/\\\\'/g, '\\\\\\\\\'');
       code = code.replace(/\\\\"/g, '\\\\\\\\\"');
   }
   ```

### Missing Mitigations
1. No sandboxing of PHP code execution - the extension could run PHP in a more restricted environment
2. No validation or sanitization of Laravel project files before execution
3. No option to prompt the user before executing PHP code for new/unknown projects
4. No explicit opt-in required for allowing PHP execution (it happens automatically)
5. No detailed documentation on how to verify the safety of a Laravel project before opening it

### Preconditions
1. The target must have VSCode with the Laravel Extra Intellisense extension installed
2. The target must open a malicious Laravel project in VSCode
3. The extension must be enabled and configured to run PHP commands

### Source Code Analysis
The command injection vulnerability occurs through this sequence:

1. When a Laravel project is opened or files are changed, various providers (RouteProvider, ViewProvider, ConfigProvider, etc.) call their respective loading methods:

```typescript
// In RouteProvider.ts
loadRoutes() {
    // ...
    Helpers.runLaravel(
        "echo json_encode(array_map(function ($route) {" +
        // PHP code to extract route information
        "}, app('router')->getRoutes()->getRoutes()));",
        "HTTP Routes"
    )
    // ...
}
```

2. These load methods call `Helpers.runLaravel()`, which creates a PHP script and passes it to `runPhp()`:

```typescript
// In helpers.ts
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    // ...
    var command =
        "define('LARAVEL_START', microtime(true));" +
        "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
        "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
        // More Laravel bootstrap code...
        "if ($status == 0) {" +
        "   echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_OUTPUT___';" +
            code +
        "   echo '___VSCODE_LARAVEL_EXTRA_INSTELLISENSE_END_OUTPUT___';" +
        "}"
    // ...
    self.runPhp(command, description)
    // ...
}
```

3. The `runPhp()` method executes the PHP code using Node.js `child_process.exec()`:

```typescript
// In helpers.ts
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    // ...
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    cp.exec(command, { cwd: /* ... */ }, function (err, stdout, stderr) {
        // ...
    });
    // ...
}
```

The vulnerability exists because when the extension loads the Laravel application, it executes PHP code that requires and processes files from the project. If those files contain malicious code, it will be executed during the bootstrap process.

A malicious Laravel project could include:
- A modified `bootstrap/app.php` that executes harmful code
- Service providers that run malicious code during registration
- Route definitions that execute code when processed
- Eloquent model definitions with harmful code in static initializers

### Security Test Case
1. Create a malicious Laravel project with a modified `bootstrap/app.php` file:

```php
<?php
// Normal Laravel bootstrap code...

// Malicious payload
file_put_contents('/tmp/pwned.txt', 'This system has been compromised');
// On Windows: file_put_contents('C:\\temp\\pwned.txt', 'This system has been compromised');

// Return the application instance like normal
$app = new Illuminate\Foundation\Application(
    $_ENV['APP_BASE_PATH'] ?? dirname(__DIR__)
);
// Rest of normal Laravel bootstrap code...
return $app;
```

2. Share this project with a developer (e.g., through a GitHub repository)

3. When the developer opens the project in VSCode with Laravel Extra Intellisense installed:
   - The extension will automatically execute the Laravel application
   - During bootstrap, the malicious code in `bootstrap/app.php` will run
   - The file `/tmp/pwned.txt` will be created, demonstrating code execution

4. Verify code execution by checking for the existence of the `/tmp/pwned.txt` file

A more sophisticated attack could:
- Execute a reverse shell
- Steal SSH keys or other credentials
- Install persistent malware
- Access Git configuration to steal repository access tokens
