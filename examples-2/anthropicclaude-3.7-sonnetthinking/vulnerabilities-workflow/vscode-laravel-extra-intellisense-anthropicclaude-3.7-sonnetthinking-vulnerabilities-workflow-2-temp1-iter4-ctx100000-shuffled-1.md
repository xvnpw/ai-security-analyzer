# Vulnerabilities

## 1. Command Injection Vulnerability in phpCommand Configuration

### Description
The Laravel Extra Intellisense extension allows users to configure a custom PHP command through the `LaravelExtraIntellisense.phpCommand` setting. This command is used to execute PHP code to extract data from the user's Laravel application. The extension performs a direct string replacement of `{code}` in the command template with PHP code without proper sanitization or validation of the command template itself. This allows a malicious actor to craft a phpCommand that includes additional OS commands which will be executed whenever the extension runs PHP code.

### Impact
An attacker could execute arbitrary system commands with the privileges of the VS Code user. This could lead to data theft, system compromise, or ransomware deployment. Since the extension periodically runs these commands automatically to update autocomplete data, the malicious commands would be repeatedly executed without requiring user action.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The extension includes a security note in the documentation that warns users about the extension periodically running their Laravel application. However, this note doesn't explicitly warn about the command injection risk through the `LaravelExtraIntellisense.phpCommand` setting.

### Missing Mitigations
1. Input validation for the `LaravelExtraIntellisense.phpCommand` setting to prevent command chaining characters
2. Use of safer execution methods than direct command execution
3. Clear security warning about the risks of modifying the phpCommand setting

### Preconditions
1. The user must have the VS Code extension installed
2. The `LaravelExtraIntellisense.phpCommand` setting must be set to a value containing command injection payloads
3. The extension must be enabled and running

### Source Code Analysis
The vulnerability exists in the `runPhp` method in `helpers.ts`:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Some escaping for Unix platforms
    if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
        code = code.replace(/\$/g, "\\$");
        code = code.replace(/\\\\'/g, '\\\\\\\\\'');
        code = code.replace(/\\\\"/g, '\\\\\\\\\"');
    }
    // Get the user-defined PHP command template
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";

    // Simply replace {code} with the PHP code to execute
    let command = commandTemplate.replace("{code}", code);

    // Execute the command directly using child_process.exec
    let out = new Promise<string>(function (resolve, error) {
        cp.exec(command,
            { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
            function (err, stdout, stderr) {
                // Process result...
            }
        );
    });
    return out;
}
```

The issue is that while the code parameter is escaped, there is no validation or sanitization of the `commandTemplate` itself. If a user (or an attacker who can modify the user's settings) sets the phpCommand to something like `php -r "{code}" && malicious-command`, the malicious command will be executed whenever the extension runs PHP code.

This method is called by various provider classes in the extension that periodically run PHP code to gather information about the Laravel application, such as in `ConfigProvider.ts`, `RouteProvider.ts`, etc.

### Security Test Case
1. Install the Laravel Extra Intellisense extension in VS Code
2. Open the VS Code settings (Ctrl+,)
3. Search for "LaravelExtraIntellisense.phpCommand"
4. Change the value to: `php -r "{code}" && echo "Vulnerability demonstrated" > /tmp/vulnerable.txt`
5. Open a Laravel project in VS Code
6. The extension will automatically start gathering data for autocompletion
7. Check if the file `/tmp/vulnerable.txt` was created, containing the text "Vulnerability demonstrated"
8. If the file exists, the vulnerability is confirmed
9. On Windows, you could use: `php -r "{code}" & echo Vulnerability demonstrated > %TEMP%\vulnerable.txt`
