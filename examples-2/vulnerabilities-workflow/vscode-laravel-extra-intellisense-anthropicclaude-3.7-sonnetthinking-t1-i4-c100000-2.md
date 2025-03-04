# Laravel Extra Intellisense Extension Vulnerabilities

## 1. Command Injection via phpCommand Setting

### Vulnerability Name
Command Injection in phpCommand Configuration

### Description
The Laravel Extra Intellisense extension allows users to configure a custom PHP command to execute code and interact with Laravel applications. This command is specified through the `LaravelExtraIntellisense.phpCommand` setting. The extension does not properly validate or sanitize this setting before passing it to Node.js's `cp.exec()` function. An attacker can craft a malicious repository with a specially crafted phpCommand setting that includes shell command separators, allowing arbitrary command execution on the victim's machine.

### Step by Step Trigger Process
1. An attacker creates a malicious repository containing a `.vscode/settings.json` file with a command injection payload in the `LaravelExtraIntellisense.phpCommand` setting
2. The attacker convinces a victim to open this repository in VSCode where Laravel Extra Intellisense is installed
3. Upon opening the repository, the extension automatically reads the custom settings
4. The extension periodically executes PHP code to gather information about Laravel components
5. When executing PHP code, it uses the malicious phpCommand setting, which causes arbitrary command execution

### Impact
The impact is critical. This vulnerability allows an attacker to execute arbitrary system commands with the same privileges as the VSCode process. This could lead to full system compromise, data theft, installation of malware, or using the victim's machine as a pivot point for further attacks.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to escape double quotes in the PHP code being executed, but it does not validate or sanitize the phpCommand setting itself. There is a security note in the README file warning users about the extension running Laravel application code automatically, but it doesn't specifically warn about the risks of malicious repositories.

### Missing Mitigations
- The extension should validate and sanitize the phpCommand setting to prevent command injection
- The extension should prompt users for confirmation before using custom phpCommand settings from newly opened repositories
- The extension should implement a whitelist approach for acceptable command formats
- The extension should isolate code execution in a more restricted environment

### Preconditions
- The victim must have VSCode with the Laravel Extra Intellisense extension installed
- The victim must open a repository containing malicious settings
- The extension must be enabled for the workspace

### Source Code Analysis
In `helpers.ts`, the `runPhp` method constructs and executes a shell command:

```typescript
static runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Some additional escaping for Unix platforms
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    // Execute the command
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        function (err, stdout, stderr) {
            // Handle results
        }
    );
}
```

The vulnerability exists because:
1. The user-configurable `phpCommand` setting is directly used to create a command string
2. No validation or sanitization is performed on this setting
3. Command separators (`;`, `&`, `|`, etc.) in the phpCommand setting would allow executing additional commands
4. This command is passed directly to `cp.exec()`, which spawns a shell process

### Security Test Case
1. Create a new directory for a fake Laravel project with minimal structure:
   ```
   /artisan
   /vendor/autoload.php
   /bootstrap/app.php
   /.vscode/settings.json
   ```

2. In the `.vscode/settings.json` file, include the following payload:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo 'COMMAND_INJECTION_SUCCESS' > command_injection_proof.txt"
   }
   ```

3. Open the repository in VSCode with Laravel Extra Intellisense extension installed
4. Wait for a few seconds as the extension starts to analyze the project
5. Check for the existence of a file named `command_injection_proof.txt` in the project directory or workspace
6. If the file exists and contains "COMMAND_INJECTION_SUCCESS", the vulnerability has been successfully exploited

## 2. PHP Code Injection via Translation File Names

### Vulnerability Name
PHP Code Injection through Translation Files

### Description
The Laravel Extra Intellisense extension reads translation files from the Laravel project to provide autocompletion. When processing these files, it uses file and directory names to construct PHP code that is later executed. The extension does not properly validate or escape these names before using them in PHP code construction, allowing for PHP code injection if an attacker can control translation file or directory names.

### Step by Step Trigger Process
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
