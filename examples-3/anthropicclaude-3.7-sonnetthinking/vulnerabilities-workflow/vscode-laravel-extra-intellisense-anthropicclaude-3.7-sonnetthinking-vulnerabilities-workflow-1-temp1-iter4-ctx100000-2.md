# Vulnerabilities

## 1. Command Injection via LaravelExtraIntellisense.phpCommand Setting

### Description
The extension allows users to configure the PHP command template using the `LaravelExtraIntellisense.phpCommand` setting. This setting is intended to enable compatibility with Docker or other setups, but it introduces a critical command injection vulnerability. When a user opens a project with this extension enabled, the extension will read and use the `phpCommand` setting from the project's `.vscode/settings.json` file without any validation. If an attacker crafts a malicious repository with a manipulated setting, the extension will execute arbitrary commands on the victim's system.

The vulnerability exists in the `runPhp` method in `helpers.ts` which uses Node.js's `child_process.exec` to run commands constructed from user-controlled configuration:

```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);
// ...
cp.exec(command, ...);
```

### Impact
An attacker can execute arbitrary code with the privileges of the VS Code process on the victim's machine. This could lead to complete system compromise, including:
- Data theft
- Installation of malware
- Persistence on the system
- Lateral movement in the network

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
There are no effective mitigations currently implemented. The README file mentions a security note, but it doesn't explicitly warn about this specific vulnerability. The extension reads the phpCommand setting from user configuration without any validation or restriction.

### Missing Mitigations
1. Whitelist approach for allowed command patterns
2. Sandbox execution of external commands
3. Clear warning in the security note section about the risks of opening unknown projects
4. Prompt for confirmation before executing commands with custom phpCommand settings
5. Validate the phpCommand setting to ensure it only contains specific allowed patterns

### Preconditions
1. The victim must have the Laravel Extra Intellisense VS Code extension installed
2. The victim must open a malicious Laravel project in VS Code
3. The malicious project must contain a `.vscode/settings.json` file with a manipulated `LaravelExtraIntellisense.phpCommand` setting

### Source Code Analysis
The vulnerability is present in the `runPhp` method in `helpers.ts`:

1. First, the extension reads the user configuration for the PHP command template:
```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
```

2. Then it replaces the `{code}` placeholder with the PHP code to run:
```typescript
let command = commandTemplate.replace("{code}", code);
```

3. Finally, it executes the command using child_process.exec:
```typescript
cp.exec(command, { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined }, function (err, stdout, stderr) {...}
```

The extension runs periodically to get Laravel data (routes, views, configs, etc.), which means this command execution happens automatically without user interaction once the project is opened.

### Security Test Case
1. Create a malicious Laravel project structure with a basic Laravel installation
2. Add a `.vscode/settings.json` file with the following content:
```json
{
  "LaravelExtraIntellisense.phpCommand": "cmd.exe /c calc.exe && php -r \"{code}\""
}
```
3. For Linux targets, use:
```json
{
  "LaravelExtraIntellisense.phpCommand": "bash -c \"touch /tmp/pwned && php -r \\\"{code}\\\"\""
}
```
4. Host this malicious project on a public Git repository
5. Send the repository URL to the victim
6. When the victim clones and opens the project in VS Code with the Laravel Extra Intellisense extension enabled, the calculator application will launch (Windows) or a file will be created (Linux), demonstrating command execution
7. The attacker could replace the payload with more malicious commands to exfiltrate data or establish persistence

## 2. Path Traversal via basePath and basePathForCode Settings

### Description
The extension allows configuration of `basePath` and `basePathForCode` settings which are used when building file paths for inclusion in PHP code. These settings can be manipulated in a malicious repository's `.vscode/settings.json` file to cause the extension to include files from outside the intended project directory.

In the `projectPath` method of `helpers.ts`, the extension processes these settings and uses them to construct file paths:

```typescript
let basePath = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePath');
if (forCode === false && basePath && basePath.length > 0) {
    if (basePath.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
        basePath = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePath);
    }
    basePath = basePath.replace(/[\/\\]$/, "");
    return basePath + path;
}
```

### Impact
An attacker can force the extension to include arbitrary PHP files from the victim's file system when executing PHP code. This could lead to:
- Information disclosure (the content of sensitive PHP files could be parsed and exfiltrated)
- Execution of malicious code if the included PHP files contain code that would be harmful when executed
- Potential bypass of security restrictions in the victim's environment

### Vulnerability Rank
High

### Currently Implemented Mitigations
The code does resolve relative paths that start with `.`, but there's no validation to prevent setting absolute paths that point outside the project directory.

### Missing Mitigations
1. Validation to ensure the path doesn't traverse outside the project directory
2. Restrict basePath and basePathForCode settings to relative paths only
3. Implement a sandbox or container for executing PHP code
4. Prompt for confirmation when basePath points outside of the project directory

### Preconditions
1. The victim must have the Laravel Extra Intellisense VS Code extension installed
2. The victim must open a malicious Laravel project in VS Code
3. The malicious project must contain a `.vscode/settings.json` file with manipulated `LaravelExtraIntellisense.basePath` or `LaravelExtraIntellisense.basePathForCode` settings

### Source Code Analysis
In `helpers.ts`, the `projectPath` method uses the configured `basePath` or `basePathForCode` setting to construct the full path:

```typescript
static projectPath(path:string, forCode: boolean = false) : string {
    if (path[0] !== '/') {
        path = '/' + path;
    }

    let basePath = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePath');
    if (forCode === false && basePath && basePath.length > 0) {
        if (basePath.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
            basePath = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePath);
        }
        basePath = basePath.replace(/[\/\\]$/, "");
        return basePath + path;
    }

    let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
    if (forCode && basePathForCode && basePathForCode.length > 0) {
        if (basePathForCode.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
            basePathForCode = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePathForCode);
        }
        basePathForCode = basePathForCode.replace(/[\/\\]$/, "");
        return basePathForCode + path;
    }
    // ...
}
```

This method is then used in `runLaravel` to include PHP files:

```typescript
"require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
"$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';"
```

If an attacker sets `basePathForCode` to a sensitive directory on the victim's machine, the extension will attempt to include files from that directory.

### Security Test Case
1. Create a malicious Laravel project structure with a basic Laravel installation
2. Add a `.vscode/settings.json` file with the following content (for Windows):
```json
{
  "LaravelExtraIntellisense.basePathForCode": "C:/",
  "LaravelExtraIntellisense.phpCommand": "cmd.exe /c echo File content: && type C:\\Windows\\System32\\drivers\\etc\\hosts && php -r \"{code}\""
}
```
3. For Linux targets, use:
```json
{
  "LaravelExtraIntellisense.basePathForCode": "/",
  "LaravelExtraIntellisense.phpCommand": "bash -c \"echo File content: && cat /etc/passwd && php -r \\\"{code}\\\"\""
}
```
4. Host this malicious project on a public Git repository
5. Send the repository URL to the victim
6. When the victim clones and opens the project in VS Code with the Laravel Extra Intellisense extension enabled, the extension will attempt to include files from the root directory
7. The attacker's modified command will also display sensitive file content, demonstrating the ability to access files outside the project directory
