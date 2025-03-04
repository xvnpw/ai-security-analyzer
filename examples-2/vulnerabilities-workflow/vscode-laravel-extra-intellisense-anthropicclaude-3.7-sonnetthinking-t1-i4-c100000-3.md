# Laravel Extra Intellisense Extension Vulnerabilities

## Vulnerability 1: Command Injection via phpCommand Configuration

### Description
The Laravel Extra Intellisense extension allows users to configure the command used to execute PHP code through the `LaravelExtraIntellisense.phpCommand` setting. This setting is consumed without proper validation and directly passed to Node.js's `child_process.exec()`. A malicious repository could include a specifically crafted `.vscode/settings.json` file that modifies this configuration to execute arbitrary commands on the victim's system.

A threat actor can create a repository with a malicious `.vscode/settings.json` file containing a weaponized `phpCommand` configuration. When a victim opens this repository in VSCode with the Laravel Extra Intellisense extension installed, the extension will automatically use this configuration to execute commands, leading to arbitrary command execution.

The vulnerable code is in `helpers.ts`:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Some escaping for Unix platforms...
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);
    let out = new Promise<string>(function (resolve, error) {
        // ...
        cp.exec(command, // This executes the potentially malicious command
            { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ?
                  vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
            function (err, stdout, stderr) {
                // ...
            }
        );
    });
    return out;
}
```

### Impact
An attacker can execute arbitrary commands with the same privileges as the VSCode process on the victim's machine. This could lead to data theft, malware installation, lateral movement within networks, or complete system compromise.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to escape quotes in the PHP code that will be executed, but does not validate or sanitize the `phpCommand` configuration itself.

### Missing Mitigations
- Validate the `phpCommand` configuration to ensure it only contains allowed patterns
- Use safer execution methods like `child_process.spawn` with explicit arguments instead of passing a command string
- Implement a default deny policy for suspicious command patterns
- Add a warning when non-standard configurations are detected

### Preconditions
1. Victim must have VSCode installed with the Laravel Extra Intellisense extension
2. Victim must open a repository containing a malicious `.vscode/settings.json` configuration
3. Extension must be enabled and automatically execute when opening Laravel project files

### Source Code Analysis
The vulnerability exists in the `runPhp` method of `helpers.ts`. When the extension needs to execute PHP code to gather Laravel information:

1. It retrieves the user-configured `phpCommand` setting without validation
2. It performs a simple string replacement, putting the PHP code in place of `{code}`
3. It passes the resulting string directly to `child_process.exec()`

A malicious configuration like `"LaravelExtraIntellisense.phpCommand": "cmd.exe /c malicious_command & php -r \"{code}\""` would cause the extension to execute `malicious_command` alongside any PHP code.

This is triggered automatically when the extension activates and attempts to gather information for its autocomplete functionality. The command execution happens as soon as the victim opens a Laravel file, with no user interaction required beyond opening the malicious repository.

### Security Test Case
1. Create a test repository with the following `.vscode/settings.json`:
   ```json
   {
       "LaravelExtraIntellisense.phpCommand": "cmd.exe /c calc.exe & php -r \"{code}\""
   }
   ```

2. Ensure the repository appears to be a valid Laravel project with minimal files like `artisan` and necessary directory structure

3. Have a victim with the Laravel Extra Intellisense extension installed open this repository in VSCode

4. Without any further interaction, observe that the calculator application opens, demonstrating successful command execution

5. In a real attack, the command would typically be more harmful - establishing a reverse shell, exfiltrating data, or installing persistent malware

## Vulnerability 2: PHP Code Injection via modelsPaths Configuration

### Description
The Laravel Extra Intellisense extension uses the `modelsPaths` configuration value directly in constructing PHP code that is executed to gather information about Laravel models. This configuration value is embedded in PHP code without proper sanitization or validation, potentially allowing PHP code injection.

### Impact
An attacker can execute arbitrary PHP code on the victim's system when the extension attempts to gather model information for autocomplete functionality.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The configuration values are used directly in PHP code construction without validation.

### Missing Mitigations
- Validate that `modelsPaths` only contains valid directory path patterns
- Sanitize user-controlled input before embedding it in PHP code
- Use prepared statements or parameterized functions rather than direct string concatenation

### Preconditions
1. Victim must have VSCode installed with the Laravel Extra Intellisense extension
2. Victim must open a repository containing a malicious `.vscode/settings.json` with crafted `modelsPaths`
3. The repository must appear to be a valid Laravel project to trigger the extension's functionality

### Source Code Analysis
In `EloquentProvider.ts`, the `loadModels` method constructs PHP code using the `modelsPaths` configuration:

```typescript
Helpers.runLaravel(
    "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
    // More PHP code that uses $modelPath
    // ...
    "echo json_encode($output);",
    "Eloquent Attributes and Relations"
)
```

The vulnerability occurs because:

1. The `modelsPaths` configuration is retrieved and directly embedded in PHP code
2. The array values are joined with `', '` and placed into PHP code without validation
3. A malicious configuration could inject PHP syntax that changes the intended execution flow

If an attacker sets `modelsPaths` to something like `["app', 'app/Models'); system('malicious_command'); //"]`, the resulting PHP code would execute the attacker's command.

### Security Test Case
1. Create a test repository with the following `.vscode/settings.json`:
   ```json
   {
       "LaravelExtraIntellisense.modelsPaths": ["app', 'app/Models'); system('calc.exe'); //"]
   }
   ```

2. Ensure the repository appears to be a valid Laravel project with minimal required files

3. Have a victim with the Laravel Extra Intellisense extension installed open this repository in VSCode

4. When the extension activates and tries to gather model information, it will execute the injected PHP code, launching the calculator application

5. In a real attack, the PHP code could be used for more malicious purposes such as establishing a backdoor, stealing sensitive data, or executing additional malware

## Vulnerability 3: Code Injection via basePathForCode Configuration

### Description
The Laravel Extra Intellisense extension uses the `basePathForCode` configuration to construct file paths for PHP's `require_once` statements. This configuration value is directly embedded in PHP code without proper validation, potentially allowing code injection by including malicious PHP files.

### Impact
An attacker can cause the extension to include malicious PHP files from the victim's filesystem, leading to arbitrary code execution when the extension executes PHP code.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None identified. The path from configuration is used directly to construct file paths for PHP inclusion.

### Missing Mitigations
- Validate that `basePathForCode` contains only valid path patterns
- Use path normalization to prevent directory traversal attacks
- Add integrity checks for included files

### Preconditions
1. Victim must have VSCode installed with the Laravel Extra Intellisense extension
2. Victim must open a repository containing a malicious `.vscode/settings.json` with a crafted `basePathForCode`
3. The attacker must be able to place malicious PHP files in a location accessible to the victim's system

### Source Code Analysis
In `helpers.ts`, the `runLaravel` method constructs PHP code that includes files using paths built with the `basePathForCode` configuration:

```typescript
var command =
    "define('LARAVEL_START', microtime(true));" +
    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
    // ...
```

The `projectPath` method uses the `basePathForCode` configuration:

```typescript
static projectPath(path:string, forCode: boolean = false) : string {
    // ...
    let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
    if (forCode && basePathForCode && basePathForCode.length > 0) {
        // ... some path resolution ...
        return basePathForCode + path;
    }
    // ...
}
```

The vulnerability occurs because:

1. The `basePathForCode` configuration is used to construct file paths for PHP `require_once` statements
2. There is no validation that the path is safe or points to legitimate Laravel files
3. An attacker can set this to point to malicious PHP files that will be executed when included

### Security Test Case
1. Create a malicious repository with the following `.vscode/settings.json`:
   ```json
   {
       "LaravelExtraIntellisense.basePathForCode": "/path/to/malicious/directory"
   }
   ```

2. Place malicious PHP files at the expected locations relative to that path:
   - `/path/to/malicious/directory/vendor/autoload.php`
   - `/path/to/malicious/directory/bootstrap/app.php`

3. The malicious PHP files should contain code that executes the attacker's desired commands

4. Have a victim with the Laravel Extra Intellisense extension installed open this repository in VSCode

5. When the extension activates, it will include the malicious PHP files, executing the attacker's code
