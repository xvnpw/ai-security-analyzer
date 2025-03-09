## Vulnerability List for Laravel Extra Intellisense Extension

### 1. Command Injection via `phpCommand` setting

- Description:
    1. A threat actor compromises a Laravel repository.
    2. The victim opens the compromised repository in VSCode and activates the Laravel Extra Intellisense extension.
    3. The threat actor crafts a malicious `.vscode/settings.json` file within the repository.
    4. This settings file overrides the user's `LaravelExtraIntellisense.phpCommand` setting to inject malicious commands. For example:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"malicious_command\"); {code}'"
       }
       ```
    5. When the extension attempts to run any Laravel command (e.g., to fetch routes, views, configs), it uses the compromised `phpCommand`.
    6. The injected `system("malicious_command")` is executed on the victim's machine before the intended PHP code `{code}` runs.

- Impact:
    - Remote Code Execution (RCE). The threat actor can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to data exfiltration, installation of malware, or further system compromise.

- Vulnerability Rank: critical

- Currently implemented mitigations:
    - None. The extension directly uses the `phpCommand` setting to execute PHP code without any sanitization or validation.

- Missing mitigations:
    - Input validation and sanitization for the `phpCommand` setting.
    - Restricting the characters allowed in the `phpCommand` setting.
    - Displaying a warning to the user when the `phpCommand` setting is modified within the workspace, especially if it deviates from a known safe pattern.
    - Potentially removing the ability to configure `phpCommand` via workspace settings and only allow it via user settings to limit repository-level attacks.

- Preconditions:
    - The victim must open a malicious Laravel repository in VSCode.
    - The victim must have the Laravel Extra Intellisense extension installed and activated.
    - The malicious repository must contain a `.vscode/settings.json` file that overrides `LaravelExtraIntellisense.phpCommand`.

- Source code analysis:
    1. **`src/helpers.ts:runPhp`**: This function constructs the command to execute PHP code by replacing `{code}` in the `phpCommand` setting with the actual PHP code.
       ```typescript
       static async runPhp(code: string, description: string|null = null) : Promise<string> {
           code = code.replace(/\"/g, "\\\""); // Basic escaping, insufficient for command injection
           if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
               code = code.replace(/\$/g, "\\$");
               code = code.replace(/\\\\'/g, '\\\\\\\\\'');
               code = code.replace(/\\\\"/g, '\\\\\\\\\"');
           }
           let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
           let command = commandTemplate.replace("{code}", code); // Vulnerable line: direct string replacement
           // ... execution using cp.exec(command, ...)
       }
       ```
    2. The `phpCommand` setting is retrieved from VSCode configuration without any validation.
       ```typescript
       let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
       ```
    3. The `code` argument is escaped using basic string replacement, but this is insufficient to prevent command injection if the `phpCommand` itself is malicious.

- Security test case:
    1. Create a new Laravel project.
    2. Inside the project root, create a `.vscode` folder and a `settings.json` file within it.
    3. In `settings.json`, add the following configuration:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r 'system(\"touch /tmp/vscode-laravel-extra-intellisense-pwned\"); {code}'"
       }
       ```
    4. Open the Laravel project in VSCode with the Laravel Extra Intellisense extension activated.
    5. Open any PHP or Blade file in the project to trigger the extension's autocomplete features. This will cause the extension to execute a Laravel command.
    6. Check if the file `/tmp/vscode-laravel-extra-intellisense-pwned` exists on the system. If it does, the command injection vulnerability is confirmed.

### 2. Code Injection via Malicious Model Files and `basePathForCode`, `modelsPaths` settings

- Description:
    1. A threat actor compromises a Laravel repository.
    2. The victim opens the compromised repository in VSCode with the Laravel Extra Intellisense extension activated.
    3. The threat actor crafts a malicious PHP file containing arbitrary code within a directory that will be scanned for models.
    4. The threat actor crafts a malicious `.vscode/settings.json` file within the repository.
    5. This settings file overrides the user's `LaravelExtraIntellisense.basePathForCode` and `LaravelExtraIntellisense.modelsPaths` settings. For example, assuming the malicious file `malicious.php` is placed in the project root:
       ```json
       {
           "LaravelExtraIntellisense.basePathForCode": ".",
           "LaravelExtraIntellisense.modelsPaths": ["."]
       }
       ```
    6. When the extension initializes or refreshes model information, it uses `include_once` to load PHP files from the configured `modelsPaths`.
    7. Due to the malicious settings, the extension includes and executes the attacker-controlled `malicious.php` file.

- Impact:
    - Remote Code Execution (RCE). The threat actor can inject and execute arbitrary PHP code within the context of the extension's PHP execution environment. This allows for actions similar to command injection, but with direct PHP code execution capabilities.

- Vulnerability Rank: high

- Currently implemented mitigations:
    - None. The extension directly uses the `basePathForCode` and `modelsPaths` settings to include PHP files without any sanitization or validation of the file content or path.

- Missing mitigations:
    - Input validation and sanitization for `basePathForCode` and `modelsPaths` settings.
    - Restricting `modelsPaths` to only include specific, trusted directories (e.g., only within the `app` directory).
    - Implementing checks to ensure that included files are actual Laravel models and not arbitrary PHP code (though this might be complex).
    - Displaying a warning to the user if `basePathForCode` or `modelsPaths` are modified within the workspace and deviate from default or expected values.

- Preconditions:
    - The victim must open a malicious Laravel repository in VSCode.
    - The victim must have the Laravel Extra Intellisense extension installed and activated.
    - The malicious repository must contain a `.vscode/settings.json` file that overrides `LaravelExtraIntellisense.basePathForCode` and `LaravelExtraIntellisense.modelsPaths`.
    - The malicious repository must contain a malicious PHP file in a location included in `modelsPaths`.

- Source code analysis:
    1. **`src/EloquentProvider.ts:loadModels`**: This function iterates through `modelsPaths` and uses `include_once` to load PHP files.
       ```typescript
       Helpers.runLaravel(
           "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" +
           "   if (is_dir(base_path($modelPath))) {" +
           "      foreach (scandir(base_path($modelPath)) as $sourceFile) {" +
           "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
           "             include_once base_path(\"$modelPath/$sourceFile\");" + // Vulnerable line: includes files based on settings
           "         }" +
           "      }" +
           "   }" +
           "}"
           // ... rest of the PHP code to extract model information
       );
       ```
    2. `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models'])` directly retrieves the `modelsPaths` setting, which can be controlled by workspace settings.
    3. `base_path()` in the executed PHP code resolves based on the `basePathForCode` setting, also controllable by workspace settings.

- Security test case:
    1. Create a new Laravel project.
    2. Inside the project root, create a `.vscode` folder and a `settings.json` file within it.
    3. In `settings.json`, add the following configuration:
       ```json
       {
           "LaravelExtraIntellisense.basePathForCode": ".",
           "LaravelExtraIntellisense.modelsPaths": ["."]
       }
       ```
    4. In the project root, create a file named `malicious.php` with the following content:
       ```php
       <?php
       file_put_contents('/tmp/vscode-laravel-extra-intellisense-code-injection.txt', 'pwned');
       ```
    5. Open the Laravel project in VSCode with the Laravel Extra Intellisense extension activated.
    6. Open any PHP or Blade file and trigger Eloquent autocompletion (e.g., type `$model->` where `$model` is an Eloquent model). This will trigger the `loadModels` function.
    7. Check if the file `/tmp/vscode-laravel-extra-intellisense-code-injection.txt` exists on the system and contains 'pwned'. If it does, the code injection vulnerability is confirmed.
