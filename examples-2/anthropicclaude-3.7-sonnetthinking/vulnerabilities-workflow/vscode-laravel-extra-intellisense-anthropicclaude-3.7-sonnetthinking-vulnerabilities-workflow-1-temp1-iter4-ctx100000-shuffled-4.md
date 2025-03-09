# Vulnerabilities in Laravel Extra Intellisense VSCode Extension

## 1. Remote Code Execution through Custom PHP Command Configuration

### Description
The extension allows users to configure a custom PHP command through the `LaravelExtraIntellisense.phpCommand` setting. An attacker can create a malicious repository with a crafted `.vscode/settings.json` file that includes a command injection payload in this setting. When a victim opens this repository in VSCode with the extension installed, the malicious command will execute on the victim's machine during the extension's autocomplete operations.

The vulnerability exists in the `runPhp` method in `helpers.ts`, which takes the custom PHP command and executes it using Node.js's `child_process.exec()` without adequate validation or sanitization:

### Impact
An attacker can achieve remote code execution on the victim's machine with the same privileges as the VSCode process. This allows for data theft, installation of malware, lateral movement within the network, and other malicious activities.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The code performs basic escaping of double quotes and dollar signs, but this is insufficient to prevent command injection.

### Missing Mitigations
- Input validation for the `phpCommand` setting
- Use of a safer execution method like `execFile` instead of `exec`
- Proper escaping and sanitization of user input
- Sandboxing or restricting the execution environment

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a repository controlled by the attacker in VSCode
- The repository must contain a malicious `.vscode/settings.json` with a crafted `LaravelExtraIntellisense.phpCommand` value

### Source Code Analysis
In `helpers.ts`, the `runPhp` function constructs and executes a command string:

1. The function takes a `code` parameter that contains PHP code to be executed
2. It performs minimal escaping: `code = code.replace(/\"/g, "\\\"");`
3. It retrieves the `phpCommand` configuration: `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand')`
4. It replaces `{code}` in the template with the PHP code: `command = commandTemplate.replace("{code}", code);`
5. Finally, it executes the command: `cp.exec(command, ...)`

An attacker can craft a `phpCommand` like:
```
"LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & calc.exe"
```

When the extension runs, it would execute both the PHP code and launch the calculator application. More dangerous commands could be used in a real attack.

### Security Test Case

1. Create a malicious repository with the following `.vscode/settings.json` file:
```json
{
    "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo 'PWNED' > /tmp/pwned.txt"
}
```

2. Add some basic Laravel project structure to make the extension activate
   - Create `artisan` file in the root
   - Create minimal `vendor/autoload.php` and `bootstrap/app.php` files

3. Invite the victim to open the repository in VSCode with the Laravel Extra Intellisense extension installed

4. When the victim opens the repository, the extension will attempt to analyze the Laravel project, executing the command injection
   - The file `/tmp/pwned.txt` will be created with the text 'PWNED'
   - In a real attack, the payload could download and execute malware, exfiltrate data, etc.

5. Verify: Check for the existence of `/tmp/pwned.txt` file

## 2. PHP Code Injection in Laravel Application Execution

### Description
The extension executes PHP code to interact with the Laravel application for retrieving autocomplete data. The `runLaravel` method in `helpers.ts` takes PHP code as input and includes it directly in a larger PHP script without adequate sanitization. An attacker can create a malicious extension provider file that, when parsed by the extension, could inject PHP code that would be executed when the extension retrieves autocomplete items.

### Impact
An attacker can achieve PHP code execution within the context of the PHP process, potentially allowing file system access, database access (if configured), and other malicious activities depending on the Laravel application's permissions.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The code replaces newlines with spaces: `code = code.replace(/(?:\r\n|\r|\n)/g, ' ');`, but this is insufficient to prevent code injection.

### Missing Mitigations
- Proper validation and sanitization of PHP code segments
- Use of a sandboxed environment for executing PHP code
- Implementation of a safer interface for retrieving data from Laravel

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a repository controlled by the attacker in VSCode
- The repository must be structured to trigger code that calls `runLaravel` with attacker-controlled input

### Source Code Analysis
In `helpers.ts`, the `runLaravel` function:

1. Takes a `code` parameter containing PHP code to be executed
2. Replaces newlines: `code = code.replace(/(?:\r\n|\r|\n)/g, ' ');`
3. Constructs a larger PHP script that includes the Laravel bootstrap code
4. Directly inserts the `code` parameter into this script
5. Calls `runPhp` to execute the resulting script

For example, in various provider classes, the extension calls `runLaravel` with dynamically constructed PHP code. An attacker could craft a repository to trick the extension into executing:

```javascript
Helpers.runLaravel("some_function(); file_put_contents('/tmp/hack.php', '<?php system($_GET[\"cmd\"]); ?>');", "description");
```

This would create a PHP web shell when the extension runs.

### Security Test Case

1. Create a malicious repository with a crafted Laravel component that would cause the extension to execute injected PHP code

2. Create a file that the extension would parse (e.g., a fake translation file) containing code that breaks out of the expected syntax:

```php
<?php
// Malicious translation file
return [
    'welcome' => 'Welcome to our site';
    file_put_contents('/tmp/hacked.txt', 'Code injection successful');
    '
];
```

3. Set up the repository structure to ensure the extension parses this file when gathering autocompletion data

4. Invite the victim to open the repository in VSCode with the Laravel Extra Intellisense extension installed

5. When the extension attempts to parse the translations, the injected code will execute

6. Verify: Check for the existence of `/tmp/hacked.txt` file
