# Vulnerabilities

## 1. Arbitrary PHP Code Execution via Automatic Laravel Application Bootstrapping

### Description
The Laravel Extra Intellisense extension automatically executes PHP code from the Laravel application when a project is opened in VS Code. This execution happens without user interaction to gather information for autocompletion features. If a developer opens a malicious Laravel project (perhaps from GitHub or received from a colleague), any harmful code in that project's files (particularly in service providers or bootstrap files) will be executed automatically on the developer's machine.

The extension periodically runs the Laravel application by:
1. Including the application's autoloader and bootstrap files
2. Setting up a Laravel service provider
3. Running the application to extract data
4. Executing custom PHP code to get information about routes, views, etc.

### Impact
An attacker can create a malicious Laravel project with harmful code that executes automatically when opened in VS Code with this extension installed. The code runs with the same permissions as the VS Code process, allowing attackers to:
- Access, modify, or delete files on the user's system
- Exfiltrate sensitive data
- Execute additional malicious commands
- Establish persistence on the developer's machine

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension includes a security note in the README:
> "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete. [...] if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing."

However, this mitigation relies on user awareness and doesn't protect against malicious projects from external sources.

### Missing Mitigations
- No sandbox or isolation for PHP code execution
- No explicit user consent required before executing code from newly opened projects
- No validation or sanitization of PHP code being executed
- No execution with reduced privileges
- No option to disable automatic execution for untrusted projects

### Preconditions
- The user must have the Laravel Extra Intellisense extension installed in VS Code
- The user must open a malicious Laravel project in VS Code
- The user's system must have PHP installed and accessible

### Source Code Analysis
The vulnerability is in the `helpers.ts` file in the `runLaravel` and `runPhp` methods:

```typescript
// From helpers.ts
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            "class VscodeLaravelExtraIntellisenseProvider extends \\Illuminate\\Support\\ServiceProvider" +
            "{" +
            // ... provider definition ...
            "}" +
            "$app->register(new VscodeLaravelExtraIntellisenseProvider($app));" +
            // ... more bootstrap code ...
            code +  // <-- User-supplied code is inserted here
            // ... finalization code ...

        // This command is then passed to runPhp
    }
}

static runPhp(code: string, description: string|null = null) : Promise<string> {
    // ... code preparation ...
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    // Execute the PHP command using child_process.exec
    cp.exec(command, { ... });
}
```

The extension watches for file changes and automatically runs this code to refresh its data. This means any malicious code in the Laravel application will be executed as soon as the project is opened, and whenever certain files are modified.

This automatic execution happens in various provider classes like `ConfigProvider.ts`, `RouteProvider.ts`, etc., which all use `Helpers.runLaravel()` to extract information from the Laravel application.

### Security Test Case
To demonstrate this vulnerability:

1. Create a malicious Laravel project with this code in `app/Providers/AppServiceProvider.php`:
   ```php
   public function register()
   {
       // Create a file to demonstrate code execution
       file_put_contents('/tmp/vscode_laravel_exploit.txt', 'Arbitrary code execution successful!');

       // More harmful actions could be performed here
   }
   ```

2. Open the project in VS Code with the Laravel Extra Intellisense extension installed

3. Without any additional user interaction, verify that the file `/tmp/vscode_laravel_exploit.txt` has been created

4. The exploitation happens automatically because:
   - The extension watches for file changes in `RouteProvider.ts`, `ViewProvider.ts`, etc.
   - When files change or when the project is opened, `loadRoutes()`, `loadViews()`, etc. are called
   - These methods call `Helpers.runLaravel()` which executes PHP code
   - This execution includes the Laravel bootstrap process, which runs service providers
   - The malicious code in the service provider is executed

This demonstrates that simply opening a project in VS Code can lead to arbitrary code execution without any further user interaction.
