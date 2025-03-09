# VSCode Laravel Extra Intellisense Vulnerabilities

## Command Injection through phpCommand Setting

### Description
The extension uses the `phpCommand` setting to execute PHP code to interact with Laravel applications for autocomplete features. This setting is user-configurable and is used directly in shell commands without proper sanitization. An attacker can create a malicious repository with custom VSCode settings that include shell command delimiters, allowing arbitrary command execution when a victim opens the repository.

Step by step:
1. Attacker creates a repository containing a Laravel project
2. Attacker adds a `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.phpCommand` value
3. When victim opens the repository, the extension automatically runs to gather autocomplete data
4. The malicious command in the settings is executed on the victim's system

### Impact
An attacker can execute arbitrary commands with the privileges of the VSCode process. This could lead to full system compromise, data theft, installation of malware, or lateral movement within the victim's network.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension attempts to sanitize quotes and dollar signs in the code portion of the command, but it does not sanitize the command template itself:

```typescript
code = code.replace(/\"/g, "\\\"");
if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
    code = code.replace(/\$/g, "\\$");
}
```

### Missing Mitigations
- No validation or sanitization of the `phpCommand` setting itself
- No use of safer execution methods like shell argument arrays
- No sandbox or restriction on command execution

### Preconditions
- Victim must open a repository with malicious `.vscode/settings.json` in VSCode
- The Laravel Extra Intellisense extension must be installed and enabled
- The victim's workspace must contain a Laravel project structure with an artisan file to trigger the extension

### Source Code Analysis
In `src/helpers.ts`, the `runPhp` method constructs and executes the command:

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
            function (err, stdout, stderr) { /*...*/ }
        );
    });
    return out;
}
```

The vulnerability occurs because the extension:
1. Reads the `phpCommand` template from user settings
2. Replaces `{code}` in the template with the sanitized code
3. Executes the resulting command using `cp.exec` without any validation

If an attacker sets `phpCommand` to `php -r "{code}" & malicious_command`, the malicious command will be executed alongside the legitimate PHP code.

### Security Test Case
1. Create a malicious repository with a Laravel project structure
2. Add a `.vscode/settings.json` file with:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo 'PWNED' > /tmp/pwned.txt"
   }
   ```
3. Share the repository with a victim
4. When the victim opens the repository in VSCode, the extension will activate
5. Check for the existence of `/tmp/pwned.txt` on the victim's system, which would confirm the command injection

On Windows, the attack could be:
```json
{
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo PWNED > %TEMP%\\pwned.txt"
}
```

## Remote Code Execution via Malicious Laravel Project Files

### Description
The extension loads and executes code from the Laravel project to gather autocomplete data. An attacker can create a malicious Laravel project with code in critical files that will be executed when the extension runs.

Step by step:
1. Attacker creates a repository with a valid Laravel project structure
2. Attacker injects malicious code into `vendor/autoload.php`, `bootstrap/app.php`, or other files loaded by the extension
3. When the victim opens the repository, the extension loads these files and executes the malicious code

### Impact
The malicious code will execute with the same privileges as the VSCode process, potentially leading to system compromise, data theft, or further attacks.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension includes a security note in the README warning users about potential risks, but does not implement technical mitigations against malicious project files.

### Missing Mitigations
- No sandboxing or isolation of the PHP execution
- No validation of project files before execution
- No option to restrict which projects the extension will process

### Preconditions
- Victim must open a repository with malicious Laravel project files in VSCode
- The Laravel Extra Intellisense extension must be installed and enabled

### Source Code Analysis
In `src/helpers.ts`, the `runLaravel` method loads and executes code from the project:

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
1. Create a malicious repository containing a Laravel project structure
2. In `vendor/autoload.php`, add:
   ```php
   <?php
   // Original autoload code followed by:
   file_put_contents('/tmp/rce-proof.txt', 'RCE successful');
   // Rest of the original autoload code
   ```
3. Share the repository with a victim
4. When the victim opens the repository in VSCode, the extension will activate and execute the code
5. Check for the existence of `/tmp/rce-proof.txt` on the victim's system to confirm successful exploitation
