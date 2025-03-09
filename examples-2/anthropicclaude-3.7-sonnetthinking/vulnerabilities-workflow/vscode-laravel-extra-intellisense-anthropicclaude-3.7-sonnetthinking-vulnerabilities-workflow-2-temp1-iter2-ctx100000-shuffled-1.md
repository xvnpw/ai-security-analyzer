# Laravel Extra Intellisense Security Vulnerabilities

## 1. Remote Code Execution Through Malicious Laravel Project

### Description
The VSCode Laravel Extra Intellisense extension periodically runs PHP code from the user's Laravel project to gather information needed for autocomplete functionality. This creates a serious vulnerability where a malicious Laravel project can include code that executes automatically when a developer opens the project with this extension enabled.

The extension automatically executes PHP code at regular intervals by loading the Laravel application through its bootstrapping process, which includes loading files from the project. If these files contain malicious code, it will be executed with the permissions of the VSCode user.

### Impact
Critical - This vulnerability allows for arbitrary code execution on the developer's machine. An attacker could:
- Access sensitive files on the developer's system
- Install backdoors or malware
- Access credentials stored on the developer's machine
- Potentially move laterally within an organization's network

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension includes a security note in the README.md that warns users about the extension running their Laravel application automatically. However, this warning might be overlooked by users and doesn't prevent the actual execution.

### Missing Mitigations
1. The extension doesn't implement any sandboxing or isolation mechanisms for the PHP code execution.
2. No validation or sanitization of the loaded PHP files before execution.
3. No option to require explicit user consent before executing PHP code from a newly opened project.
4. No allowlist for specific files or functions that can be executed.

### Preconditions
1. The VSCode user has the Laravel Extra Intellisense extension installed and enabled.
2. The user opens a malicious Laravel project in VSCode.

### Source Code Analysis
The vulnerability is primarily in the `runLaravel` method in `helpers.ts`:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // ... additional code ...
            "$kernel = $app->make(Illuminate\\Contracts\\Console\\Kernel::class);" +
            "$status = $kernel->handle(" +
                "$input = new Symfony\\Component\\Console\\Input\\ArgvInput," +
                "new Symfony\\Component\\Console\\Output\\ConsoleOutput" +
            ");" +
            // ... executes the provided code parameter ...
```

This function:
1. Loads the Laravel autoloader and bootstrap files from the user's project
2. Instantiates the Laravel application
3. Executes the PHP code provided as a parameter

Various provider classes in the extension call this method periodically to gather data:
- `RouteProvider.loadRoutes()`: Loads route information
- `ViewProvider.loadViews()`: Loads view information
- `ConfigProvider.loadConfigs()`: Loads configuration information

What makes this particularly dangerous is the automated nature of execution. When the extension is initialized in `extension.ts`, it creates instances of these providers, which then start loading data immediately and periodically refresh that data.

A key issue is that the extension loads and executes arbitrary PHP files from the project without validation:
```typescript
"require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';"
"$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';"
```

If a malicious actor had modified either of these files or any files they include (such as service providers, middleware, etc.), the malicious code would be executed.

### Security Test Case
1. Create a malicious Laravel project with the following modifications:
   - Add a malicious service provider in `app/Providers/MaliciousServiceProvider.php`:
     ```php
     <?php
     namespace App\Providers;

     use Illuminate\Support\ServiceProvider;

     class MaliciousServiceProvider extends ServiceProvider
     {
         public function register()
         {
             // This code will execute when the extension loads the Laravel application
             // For demonstration, just create a file to prove execution
             file_put_contents('/tmp/vscode_laravel_exploit.txt', 'Code execution successful');

             // In a real attack, this could be more harmful:
             // - Exfiltrate sensitive data
             // - Install a backdoor
             // - Execute system commands
         }
     }
     ```

   - Register the service provider in `config/app.php`:
     ```php
     'providers' => [
         // Other providers...
         App\Providers\MaliciousServiceProvider::class,
     ],
     ```

2. Package this project and share it with a target (e.g., as an open-source project, in a pull request, etc.).

3. When the target opens the project in VSCode with the Laravel Extra Intellisense extension enabled, the malicious code will execute automatically without any user interaction.

4. Verify the attack by checking for the presence of the file `/tmp/vscode_laravel_exploit.txt` on the target system.

This attack requires no special configuration and would work against any user of the extension, demonstrating the critical nature of this vulnerability.
