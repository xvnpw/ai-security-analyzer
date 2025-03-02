# Laravel Extra Intellisense Extension Vulnerabilities

## 1. Command Injection via LaravelExtraIntellisense.phpCommand Setting

### Description
The extension uses a user-configurable setting (`LaravelExtraIntellisense.phpCommand`) to execute PHP code via the command line. This setting is used directly in command execution without proper validation or sanitization. When a victim opens a malicious repository with a crafted `.vscode/settings.json` file, the attacker can inject arbitrary commands that will be executed when the extension runs.

Step by step exploitation:
1. Attacker creates a repository with a `.vscode/settings.json` file containing a malicious `LaravelExtraIntellisense.phpCommand` value.
2. Victim opens the repository in VSCode with Laravel Extra Intellisense extension installed.
3. The extension automatically loads the project settings.
4. When the extension tries to get data from the Laravel application, it uses the malicious command template.
5. The injected commands are executed on the victim's system.

### Impact
An attacker can execute arbitrary code on the victim's machine with the same privileges as the VSCode process. This allows for complete compromise of the victim's system, including access to all files readable by the user, installation of malware, and potential lateral movement within the network.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There is some basic escaping of double quotes and dollar signs in the `runPhp` method in `helpers.ts`, but this is insufficient to prevent command injection attacks.

### Missing Mitigations
1. The extension should validate the `LaravelExtraIntellisense.phpCommand` setting to ensure it only contains allowed characters and patterns.
2. The extension should use safer command execution methods like `child_process.execFile` instead of `child_process.exec`.
3. The extension should implement a whitelist of allowed commands rather than accepting arbitrary command templates.
4. VSCode settings from untrusted workspaces should not be used for command execution without explicit user approval.

### Preconditions
1. The victim must have the Laravel Extra Intellisense extension installed.
2. The victim must open a repository containing a malicious `.vscode/settings.json` file.
3. The victim's VSCode must be configured to allow workspace settings (default behavior).

### Source Code Analysis
In `helpers.ts`, the `runPhp` method constructs and executes commands based on the user-configurable `phpCommand` setting:

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

    cp.exec(command, {
        cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ?
            vscode.workspace.workspaceFolders[0].uri.fsPath : undefined
    }, function (err, stdout, stderr) { /* ... */ });
}
```

The vulnerability occurs because:
1. The `commandTemplate` is obtained directly from the user configuration without validation.
2. The template is used to construct a command string that's passed to `cp.exec()`.
3. If the template contains command separators like `&`, `;`, or `|`, additional commands will be executed.

### Security Test Case
1. Create a new repository with the following file structure:
   - `.vscode/settings.json` containing:
     ```json
     {
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo 'PWNED' > /tmp/pwned.txt"
     }
     ```
   - Create a minimal Laravel-like structure (empty `vendor/autoload.php` and `bootstrap/app.php` files) so the extension attempts to load the Laravel application.

2. Open the repository in VSCode with Laravel Extra Intellisense extension installed.

3. Wait for the extension to activate and attempt to load Laravel information.

4. Verify that `/tmp/pwned.txt` has been created, indicating that the command injection was successful.

## 2. PHP Code Execution via Malicious Laravel Files

### Description
The extension loads and executes PHP files from the user's project, including `vendor/autoload.php` and `bootstrap/app.php`. These files can contain arbitrary PHP code that will be executed when the extension runs. A threat actor can create a malicious repository with crafted versions of these files to execute arbitrary PHP code on the victim's machine.

Step by step exploitation:
1. Attacker creates a repository with malicious versions of `vendor/autoload.php` and/or `bootstrap/app.php`.
2. Victim opens the repository in VSCode with Laravel Extra Intellisense extension installed.
3. When providing autocomplete suggestions, the extension loads and executes these malicious files.
4. The malicious PHP code is executed on the victim's machine.

### Impact
An attacker can execute arbitrary PHP code on the victim's machine. This allows for running commands, accessing files, and potentially achieving full remote code execution if the PHP environment is properly configured.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The extension loads and executes PHP files from the user's project without any validation or sandboxing.

### Missing Mitigations
1. The extension should run PHP code in a sandboxed environment.
2. The extension should validate the content of loaded PHP files for potentially malicious code.
3. The extension should prompt the user for confirmation before executing code from untrusted workspaces.
4. The extension could implement a content-hash verification system for critical files.

### Preconditions
1. The victim must have the Laravel Extra Intellisense extension installed.
2. The victim must open a repository containing malicious versions of `vendor/autoload.php` and/or `bootstrap/app.php`.
3. The victim must have PHP installed on their system.

### Source Code Analysis
In `helpers.ts`, the `runLaravel` method loads and executes PHP files from the user's project:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
    if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
        var command =
            "define('LARAVEL_START', microtime(true));" +
            "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
            "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
            // ... more PHP code that will be executed ...
            code +
            // ... more PHP code ...
    }
    // This command is then passed to runPhp which executes it
    return new Promise(function (resolve, error) {
        self.runPhp(command, description)
            .then(function (result: string) { /* ... */ })
            .catch(function (e : Error) { /* ... */ });
    });
}
```

The vulnerability occurs because:
1. The method loads `vendor/autoload.php` and `bootstrap/app.php` from the user's project without validation.
2. If these files contain malicious code, it will be executed when the extension runs.
3. The PHP code is executed with the same privileges as the PHP process, which typically has the same file system access as the user.

### Security Test Case
1. Create a new repository with the following file structure:
   - `vendor/autoload.php` containing:
     ```php
     <?php
     file_put_contents('/tmp/php_rce_proof.txt', 'Executed malicious PHP code');
     // Fake autoload functionality to avoid errors
     function autoload($class) {}
     spl_autoload_register('autoload');
     return true;
     ```
   - `bootstrap/app.php` containing minimal code to avoid errors
   - Basic Laravel-like structure to make the extension recognize it as a Laravel project

2. Open the repository in VSCode with Laravel Extra Intellisense extension installed.

3. Wait for the extension to activate and attempt to load Laravel information.

4. Verify that `/tmp/php_rce_proof.txt` has been created, indicating that the malicious PHP code was executed.

## 3. PHP Code Execution via Included Model Files

### Description
The extension includes and executes PHP files from the user's project, specifically from directories specified in the `LaravelExtraIntellisense.modelsPaths` setting (default: `['app', 'app/Models']`). A threat actor can create a malicious repository with PHP files in these directories containing arbitrary code that will be executed when the extension runs.

Step by step exploitation:
1. Attacker creates a repository with malicious PHP files in the `app/Models` directory.
2. Victim opens the repository in VSCode with Laravel Extra Intellisense extension installed.
3. When providing model autocomplete suggestions, the extension includes and executes these malicious files.
4. The malicious PHP code is executed on the victim's machine.

### Impact
An attacker can execute arbitrary PHP code on the victim's machine, potentially leading to full remote code execution, data theft, and system compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None. The extension includes and executes PHP files from the user's project without any validation or sandboxing.

### Missing Mitigations
1. The extension should run PHP code in a sandboxed environment.
2. The extension should validate the content of PHP files before including them.
3. The extension should prompt for user confirmation before executing code from untrusted workspaces.
4. The extension could implement static analysis to detect potentially malicious code patterns.

### Preconditions
1. The victim must have the Laravel Extra Intellisense extension installed.
2. The victim must open a repository containing malicious PHP files in the directories specified by `LaravelExtraIntellisense.modelsPaths`.
3. The victim must have PHP installed on their system.

### Source Code Analysis
In `EloquentProvider.ts`, the `loadModels` method includes PHP files from the user's project:

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
    "}" +
    // ... more PHP code ...
)
```

The vulnerability occurs because:
1. The method includes all PHP files from the directories specified in `modelsPaths` without validation.
2. If these files contain malicious code, it will be executed when included.
3. The code is executed with the privileges of the PHP process, which typically has the same file system access as the user.

### Security Test Case
1. Create a new repository with the following file structure:
   - `app/Models/MaliciousModel.php` containing:
     ```php
     <?php
     file_put_contents('/tmp/model_rce_proof.txt', 'Executed malicious model code');
     // Fake model class to make it look legitimate
     class MaliciousModel extends \Illuminate\Database\Eloquent\Model {}
     ```
   - Basic Laravel-like structure including minimal `vendor/autoload.php` and `bootstrap/app.php` files

2. Open the repository in VSCode with Laravel Extra Intellisense extension installed.

3. Wait for the extension to activate and attempt to provide model autocomplete suggestions.

4. Verify that `/tmp/model_rce_proof.txt` has been created, indicating that the malicious model code was executed.

## 4. PHP Code Injection via Translation File Names

### Description
The Laravel Extra Intellisense extension reads translation files from the Laravel project to provide autocompletion. When processing these files, it uses file and directory names to construct PHP code that is later executed. The extension does not properly validate or escape these names before using them in PHP code construction, allowing for PHP code injection if an attacker can control translation file or directory names.

Step by step exploitation:
1. An attacker creates a malicious repository with a specially crafted translation file name containing PHP code
2. The victim opens this repository in VSCode with Laravel Extra Intellisense extension
3. The extension scans the translation files and directories
4. When constructing PHP code to retrieve translations, the malicious filename is incorporated without proper escaping
5. The constructed PHP code with the injected malicious code is executed on the victim's machine

### Impact
This vulnerability allows an attacker to execute arbitrary PHP code on the victim's machine. Since the PHP code is executed with the same privileges as the VSCode process, this could lead to system compromise, data theft, or further attacks.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension attempts to sanitize some inputs and uses JSON encoding for some data, but it does not consistently validate or escape all file and directory names used in PHP code construction.

### Missing Mitigations
- Proper escaping of all file and directory names used in PHP code construction
- Use of prepared statements or other secure methods to build PHP code
- Validation of file and directory names against a whitelist of safe patterns
- Implementation of a sandbox environment for PHP code execution

### Preconditions
- The victim must have VSCode with Laravel Extra Intellisense extension installed
- The victim must open a repository with malicious translation file names
- The extension must be enabled for the workspace

### Source Code Analysis
In `TranslationProvider.ts`, the extension builds a PHP command using translation group names:

```typescript
Helpers.runLaravel("echo json_encode([" + translationGroups.map((transGroup: string) => "'" + transGroup + "' => __('" + transGroup + "')").join(",") + "]);", "Translations inside namespaces")
```

These translation groups are derived from file and directory names in the project:

```typescript
fs.readdirSync(langPath).forEach(function (langDir) {
    var path:any = langPath + '/' + langDir;
    if (fs.existsSync(path) && fs.lstatSync(path).isDirectory()) {
        fs.readdirSync(path).forEach(function (subDirectory) {
            let subDirectoryPath = path + '/' + subDirectory;
            if (fs.existsSync(subDirectoryPath) && fs.lstatSync(subDirectoryPath).isDirectory()) {
                let nestedDirectories = nestedTranslationGroups(path, subDirectory);
                for (let nestedDirectory of nestedDirectories) {
                    translationGroups.push(nestedDirectory);
                }
            }
        });
    }
});
```

The vulnerability exists because:
1. Translation file and directory names are not properly validated or escaped
2. These names are directly used to construct PHP code
3. If a file name contains something like `'); system('malicious_command'); //'`, it would be executed

### Security Test Case
1. Create a test Laravel project with the following structure:
   ```
   /resources/lang/en/
   ```

2. In the `/resources/lang/en/` directory, create a file with a malicious name:
   ```
   \')); system("echo PHP_CODE_INJECTION_SUCCESS > injection_proof.txt"); ((\'.php
   ```

3. Open the project in VSCode with Laravel Extra Intellisense extension installed
4. Wait for the extension to scan translation files
5. Check for the existence of a file named `injection_proof.txt` containing "PHP_CODE_INJECTION_SUCCESS"
6. If the file exists with the expected content, the vulnerability has been successfully exploited

## 5. Code Injection via LaravelExtraIntellisense.basePathForCode Setting

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
