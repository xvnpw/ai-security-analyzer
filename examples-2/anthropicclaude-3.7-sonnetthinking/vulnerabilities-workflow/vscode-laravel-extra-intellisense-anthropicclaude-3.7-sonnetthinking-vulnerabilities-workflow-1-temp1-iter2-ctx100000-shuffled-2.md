# Vulnerabilities in Laravel Extra Intellisense VSCode Extension

## Vulnerability 1: Command Injection via phpCommand Configuration

### Vulnerability Name
Command Injection via User-Configurable PHP Command

### Description
The Laravel Extra Intellisense extension executes PHP code to load Laravel application data by using a user-configurable `phpCommand` setting. This setting can be manipulated by a malicious repository to execute arbitrary commands on the victim's system.

Step by step exploitation:
1. Create a malicious repository containing a Laravel project
2. Include a `.vscode/settings.json` file with a crafted value for `LaravelExtraIntellisense.phpCommand` that includes command injection
3. When a victim opens this repository in VSCode with the Laravel Extra Intellisense extension installed, the extension will use the malicious command execution template
4. The extension automatically and periodically runs PHP commands to gather Laravel data, which will trigger the injected command

### Impact
This vulnerability allows for arbitrary command execution on the victim's system with the same privileges as the VSCode process. The attacker can execute any command, potentially leading to:
- Full system compromise
- Data exfiltration
- Installation of persistent backdoors
- Lateral movement within the victim's network

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension does include a security note in the README warning users:
> "This extension runs your Laravel application automatically and periodically to get the information needed to provide autocomplete. So if you have any unknown errors in your log make sure the extension not causing it. Also if you writing any sensitive code in your service providers, disable the extension temporarily to prevent unwanted application executing."

However, this warning does not specifically mention the risk of opening untrusted repositories.

### Missing Mitigations
- No validation or sanitization of the `phpCommand` setting
- No warning when opening a repository that changes critical configuration settings
- No sandboxing or isolation when executing commands
- No default restriction on the commands that can be executed

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a repository containing the malicious configuration
- The extension must be enabled for the current workspace

### Source Code Analysis
The vulnerability exists in the `runPhp` method in `helpers.ts`:

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
    let out = new Promise<string>(function (resolve, error) {
        // ...
        cp.exec(command,
            { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
            function (err, stdout, stderr) {
                // ...
            }
        );
    });
    return out;
}
```

The issue is that a malicious repository can specify any command to be run through the `LaravelExtraIntellisense.phpCommand` setting. The extension retrieves this setting using `vscode.workspace.getConfiguration` and directly incorporates it into a command that is executed via `cp.exec()`. This allows for command injection.

The extension triggers PHP commands automatically through multiple providers like `RouteProvider`, `ViewProvider`, and others. Each of these providers calls `Helpers.runLaravel()`, which in turn calls `Helpers.runPhp()`. This occurs periodically and when files change, ensuring that the injected command will be executed.

### Security Test Case
1. Create a malicious repository with a Laravel project structure (can be a minimal project)
2. Add a `.vscode/settings.json` file with the following content:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "echo 'VULNERABLE' > /tmp/pwned && php -r \"{code}\""
   }
   ```

   For Windows:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "cmd /c \"echo VULNERABLE > %TEMP%\\pwned.txt\" && php -r \"{code}\""
   }
   ```

3. Convince a victim to open this repository in VSCode with the Laravel Extra Intellisense extension installed
4. The extension will automatically try to analyze the Laravel project and execute the malicious command
5. Verify that the file `/tmp/pwned` (Linux/macOS) or `%TEMP%\pwned.txt` (Windows) has been created

For more severe exploitation, an attacker could replace the command with one that downloads and executes malware, establishes reverse shells, or exfiltrates sensitive data.

## Vulnerability 2: Code Execution via Malicious Laravel Project Files

### Vulnerability Name
Remote Code Execution via Malicious Laravel Project Files

### Description
The extension loads and executes PHP code from the Laravel project to extract information about routes, views, models, etc. A malicious repository can contain specially crafted Laravel files that, when loaded by the extension, will execute arbitrary PHP code on the victim's system.

Step by step exploitation:
1. Create a malicious repository with Laravel project structure
2. Include crafted PHP files that contain malicious code in locations where the extension looks for information:
   - Routes in `app/Http/Controllers/` or in route files
   - Models in the configured model paths
   - Views, translations, and other Laravel resources
3. When a victim opens this repository in VSCode, the extension automatically loads and executes these files

### Impact
This vulnerability allows for arbitrary PHP code execution on the victim's system. The attacker can:
- Execute any PHP code with the same permissions as the PHP process
- Access the file system
- Make network connections
- Install backdoors
- Exfiltrate data

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension includes a general security note in the README about the extension running the Laravel application, but does not specifically warn about untrusted repositories.

### Missing Mitigations
- No sandboxing or isolation when executing PHP code from the project
- No validation or filtering of the PHP code that is executed
- No option to require explicit permission before analyzing untrusted repositories

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a repository containing the malicious Laravel files
- The extension must be enabled for the current workspace
- PHP must be installed and accessible on the victim's system

### Source Code Analysis
The issue is present in the `runLaravel` method in `helpers.ts`:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // ... more code ...
            code +
            // ... more code ...

        return new Promise(function (resolve, error) {
            self.runPhp(command, description)
                // ...
        });
    }
    return new Promise((resolve, error) => resolve(""));
}
```

This method loads files from the Laravel project, including `vendor/autoload.php` and `bootstrap/app.php`, which can be maliciously crafted. Additionally, the extension calls various provider classes that load and execute code from multiple parts of the Laravel project:

1. In `RouteProvider.ts`, `loadRoutes()` executes code that loads all routes
2. In `ModelProvider.ts`, `loadModels()` includes all model files
3. In `ViewProvider.ts`, `loadViews()` processes blade files

Each of these operations can be abused by placing malicious code in the corresponding Laravel files. The extension will automatically execute this code as it analyzes the project.

### Security Test Case
1. Create a malicious Laravel repository with a specially crafted bootstrap file:
   - Create `bootstrap/app.php` with the following content:
     ```php
     <?php
     // Create a file as evidence of execution
     file_put_contents('/tmp/pwned_via_laravel', 'Code execution proof');

     // Return a valid Laravel application to avoid errors
     return new Illuminate\Foundation\Application(
         $_ENV['APP_BASE_PATH'] ?? dirname(__DIR__)
     );
     ```

2. Convince a victim to open this repository in VSCode with the Laravel Extra Intellisense extension
3. The extension will automatically load the Laravel application, executing the malicious code
4. Verify that the file `/tmp/pwned_via_laravel` has been created on the victim's system

More sophisticated attacks could use this vulnerability to execute stealthier code, exfiltrate data, or establish persistence.
