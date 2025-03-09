# Vulnerabilities in Laravel Extra Intellisense

## Vulnerability 1: Remote Code Execution via phpCommand Setting

### Vulnerability Name
Remote Code Execution via Custom phpCommand Setting

### Description
The Laravel Extra Intellisense extension allows users to configure a custom PHP command via the `LaravelExtraIntellisense.phpCommand` setting. This setting is used to execute PHP code in order to interact with Laravel and extract metadata for autocomplete functionality. A malicious actor can craft a repository with a custom `.vscode/settings.json` file that contains a manipulated `phpCommand` setting which injects arbitrary system commands.

Steps to trigger:
1. Create a malicious repository containing a Laravel project
2. Add a `.vscode/settings.json` file with a specially crafted `phpCommand` setting
3. Share the repository with a victim
4. When the victim opens the repository in VSCode with the Laravel Extra Intellisense extension installed, the malicious command will execute

### Impact
An attacker can execute arbitrary code on the victim's system with the same privileges as the VSCode process. This could lead to data theft, malware installation, or full system compromise.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to escape quotes and dollar signs in the PHP code that gets inserted into the command:

```typescript
code = code.replace(/\"/g, "\\\"");
if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
    code = code.replace(/\$/g, "\\$");
    code = code.replace(/\\\\'/g, '\\\\\\\\\'');
    code = code.replace(/\\\\"/g, '\\\\\\\\\"');
}
```

However, this only protects the PHP code portion, not the command template itself.

### Missing Mitigations
1. Validation of the `phpCommand` setting to ensure it only contains allowed commands (e.g., php, docker)
2. Sandboxing the execution of commands
3. Prompting for user confirmation before executing commands with custom phpCommand configurations
4. Using a safer execution method instead of `cp.exec()`

### Preconditions
1. The victim must have the Laravel Extra Intellisense extension installed
2. The victim must open a project containing the malicious `.vscode/settings.json` file
3. The extension must be active

### Source Code Analysis
In `helpers.ts`, the `runPhp` method shows how the command is constructed and executed:

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
    let out = new Promise<string>(function (resolve, error) {
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

The vulnerability exists because:
1. The `commandTemplate` is read directly from user configuration with no validation
2. The `commandTemplate` can contain arbitrary shell commands
3. The `cp.exec()` function executes commands in a shell, allowing for command chaining and injection
4. The command is executed in the context of the VSCode process

### Security Test Case
1. Create a new directory with a basic Laravel project structure
2. Create a `.vscode/settings.json` file with the following content:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "echo 'VULNERABILITY_EXPLOITED' > proof.txt && php -r \"{code}\""
   }
   ```
3. Open the project in VSCode with the Laravel Extra Intellisense extension installed
4. Verify that a file named `proof.txt` is created in the project directory containing the text "VULNERABILITY_EXPLOITED"

For a more sophisticated test, the command could be replaced with one that establishes a reverse shell or executes other malicious payloads.

## Vulnerability 2: Command Injection via Inadequate Escaping

### Vulnerability Name
Command Injection due to Inadequate Escaping in PHP Code Execution

### Description
The extension attempts to escape certain characters in the PHP code before passing it to the command execution, but the escaping logic is insufficient to prevent all command injection vectors. A malicious repository could contain specially crafted code that breaks out of the PHP code context and executes arbitrary system commands.

Steps to trigger:
1. Create a malicious repository with code that exploits the inadequate escaping
2. When the victim opens the repository, the extension will execute PHP commands to extract metadata
3. The malicious code will break out of the PHP code context and execute arbitrary commands

### Impact
An attacker can execute arbitrary code on the victim's system, potentially leading to data theft, malware installation, or system compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension attempts to escape some characters:
```typescript
code = code.replace(/\"/g, "\\\"");
if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
    code = code.replace(/\$/g, "\\$");
    code = code.replace(/\\\\'/g, '\\\\\\\\\'');
    code = code.replace(/\\\\"/g, '\\\\\\\\\"');
}
```

### Missing Mitigations
1. More comprehensive escaping of all potential command injection characters
2. Using PHP's built-in argument passing mechanisms instead of string concatenation
3. Using a safer execution method like `execFile` that doesn't invoke a shell
4. Implementing proper input validation for all PHP code that will be executed

### Preconditions
1. The victim must have the extension installed
2. The victim must open a malicious Laravel project

### Source Code Analysis
The vulnerability stems from the way PHP code is executed in `helpers.ts`:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            // more PHP code
            code +
            // more PHP code

        var self = this;

        return new Promise(function (resolve, error) {
            self.runPhp(command, description)
                // ...
        });
    }
    return new Promise((resolve, error) => resolve(""));
}
```

This code:
1. Takes user code and embeds it directly into a larger PHP script
2. Performs minimal escaping
3. Executes the result via `runPhp`

The escaping in `runPhp` doesn't handle all possible command injection vectors, such as backticks, semi-colons, or other shell metacharacters.

### Security Test Case
1. Create a Laravel project with a service provider that contains malicious code
2. The code should attempt to break out of the PHP execution context, for example:
   ```php
   <?php
   // In a Laravel service provider or similar file
   class MaliciousServiceProvider extends ServiceProvider {
       public function register() {
           // Code that will be executed by the extension
           system("echo 'INJECTION_SUCCESSFUL' > injection_proof.txt");
       }
   }
   ```
3. Open the project in VSCode with the extension installed
4. Verify that a file named `injection_proof.txt` is created containing "INJECTION_SUCCESSFUL"
