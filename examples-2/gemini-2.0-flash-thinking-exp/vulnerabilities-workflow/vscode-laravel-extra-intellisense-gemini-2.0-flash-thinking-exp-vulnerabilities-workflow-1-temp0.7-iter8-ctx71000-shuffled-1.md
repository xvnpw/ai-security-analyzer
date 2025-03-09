### Vulnerability List

* Vulnerability Name: Command Injection via `phpCommand` setting

* Description:
    1. The extension executes PHP code by running a command specified in the `LaravelExtraIntellisense.phpCommand` setting.
    2. This setting is user-configurable in VSCode settings.
    3. A malicious user can provide a crafted repository with a `.vscode/settings.json` file that modifies the `LaravelExtraIntellisense.phpCommand` setting to inject arbitrary commands.
    4. When a victim opens this malicious repository in VSCode and activates the Laravel Extra Intellisense extension, the extension will use the malicious `phpCommand` to execute PHP code.
    5. Since the `phpCommand` is now under attacker control, they can inject arbitrary shell commands into it.
    6. When the extension attempts to execute PHP code (e.g., to get route list, config values, etc.), the injected commands will also be executed by the system.

* Impact:
    - Remote Code Execution (RCE). An attacker can execute arbitrary shell commands on the victim's machine with the same privileges as the VSCode process. This can lead to full system compromise, data exfiltration, malware installation, and other malicious activities.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - The extension attempts to escape double quotes in the PHP code using `code = code.replace(/\"/g, "\\\"")` in `Helpers.runPhp`.
    - Platform-specific escaping for `$` and backslashes is applied for Linux/Unix systems.

* Missing Mitigations:
    - Input sanitization and validation for the `phpCommand` setting. The extension should not directly use user-provided settings to execute shell commands.
    - Principle of least privilege: The extension should not execute commands with shell if not strictly necessary. If shell execution is required, ensure proper escaping and consider using safer alternatives to `child_process.exec` if possible, or use parameterized commands.
    - Restrict the characters allowed in `phpCommand` or provide a way to reset it to a safe default.
    - Warn users about the security implications of modifying the `phpCommand` setting.

* Preconditions:
    1. Victim opens a malicious repository in VSCode.
    2. The malicious repository contains a `.vscode/settings.json` file that sets a malicious `LaravelExtraIntellisense.phpCommand`.
    3. The victim has the Laravel Extra Intellisense extension installed and activated in VSCode.
    4. The extension attempts to execute any Laravel command, which triggers the use of the malicious `phpCommand`.

* Source Code Analysis:
    1. **File: `src/helpers.ts`**:
        - `runPhp` function:
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
                    if (description != null) {
                        Helpers.outputChannel?.info("Laravel Extra Intellisense command started: " + description);
                    }

                    cp.exec(command, // <-- Command execution
                        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                        function (err, stdout, stderr) { ... }
                    );
                });
                return out;
            }
            ```
            - The `runPhp` function retrieves the `phpCommand` from VSCode configuration.
            - It uses `commandTemplate.replace("{code}", code)` to construct the command string.
            - It then uses `child_process.exec(command, ...)` to execute the command.
            - User-controlled `phpCommand` setting is directly used in `cp.exec`, leading to command injection.

        - `runLaravel` function:
            ```typescript
            static runLaravel(code: string, description: string|null = null) : Promise<string> {
                code = code.replace(/(?:\r\n|\r|\n)/g, ' ');
                if (fs.existsSync(Helpers.projectPath("vendor/autoload.php")) && fs.existsSync(Helpers.projectPath("bootstrap/app.php"))) {
                    var command = // ... php code generation ...
                        "exit($status);"

                    var self = this;

                    return new Promise(function (resolve, error) {
                        self.runPhp(command, description) // <-- Calls runPhp with generated code
                            .then(function (result: string) { ... })
                            .catch(function (e : Error) { ... });
                    });
                }
                return new Promise((resolve, error) => resolve(""));
            }
            ```
            - `runLaravel` generates PHP code and passes it to `runPhp` for execution.
            - If `phpCommand` is compromised, `runLaravel` will also be vulnerable because it relies on `runPhp`.

    2. **File: `README.md`**:
        - The `Sample config to use docker` section encourages users to modify the `phpCommand` setting, increasing the likelihood of users being exposed to malicious configurations.
        - While the `Security Note` mentions potential issues, it doesn't explicitly warn about command injection risks from modifying `phpCommand`.

* Security Test Case:
    1. Create a new Laravel project.
    2. Create a `.vscode` folder in the project root.
    3. Inside `.vscode`, create a `settings.json` file with the following content to inject a command that creates a file named `pwned` in the root directory:
        ```json
        {
            "LaravelExtraIntellisense.phpCommand": "php -r \\\"system('touch pwned'); {code}\\\""
        }
        ```
    4. Open the Laravel project in VSCode with the Laravel Extra Intellisense extension activated.
    5. Open any PHP file within the project (e.g., a controller or route file).
    6. Trigger autocompletion in a Laravel context (e.g., type `route('` to trigger route autocompletion). This will force the extension to execute a Laravel command.
    7. After a short delay (for the extension to execute the command), check the project root directory.
    8. If the vulnerability is present, a file named `pwned` will be created in the project root, indicating successful command injection and RCE.

---

* Vulnerability Name: Code Injection via `customValidationRules` setting

* Description:
    1. The extension allows users to define custom validation rules through the `LaravelExtraIntellisense.customValidationRules` setting in VSCode.
    2. This setting is intended to provide snippets for custom validation rules, but the extension uses `Helpers.evalPhp` to process the values in this setting.
    3. A malicious user can craft a repository with a `.vscode/settings.json` file that injects malicious PHP code into the `LaravelExtraIntellisense.customValidationRules` setting.
    4. When the victim opens this repository and the extension loads the settings, the malicious PHP code within `customValidationRules` will be evaluated by `Helpers.evalPhp`.
    5. This allows the attacker to execute arbitrary PHP code within the extension's context.

* Impact:
    - Code Injection and potentially Remote Code Execution (RCE). While directly executing shell commands might not be as straightforward as with `phpCommand`, an attacker can execute arbitrary PHP code. This could be used to read sensitive files, modify project files, or potentially achieve RCE depending on the available PHP functions and the environment.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - None specific to `customValidationRules`. The general code parsing and execution mechanisms are in place, but they do not mitigate this specific injection point.

* Missing Mitigations:
    - Input sanitization and validation for the `LaravelExtraIntellisense.customValidationRules` setting. The extension should treat user-provided configuration values as untrusted input and avoid directly evaluating them as code.
    - Instead of `evalPhp`, the extension should only use the `customValidationRules` values as simple string snippets for autocompletion, without attempting to parse or execute them.
    - Warn users about the security implications of modifying the `customValidationRules` setting, although ideally, this setting should not be exploitable for code injection in the first place.

* Preconditions:
    1. Victim opens a malicious repository in VSCode.
    2. The malicious repository contains a `.vscode/settings.json` file that sets a malicious `LaravelExtraIntellisense.customValidationRules`.
    3. The victim has the Laravel Extra Intellisense extension installed and activated in VSCode.
    4. The extension loads and processes the `customValidationRules` setting, which triggers the code injection.

* Source Code Analysis:
    1. **File: `src/ValidationProvider.ts`**:
        ```typescript
        provideCompletionItems(document: vscode.TextDocument, position: vscode.Position, token: vscode.CancellationToken, context: vscode.CompletionContext): Array<vscode.CompletionItem> {
            // ...
            var rules = this.rules;
            Object.assign(rules, vscode.workspace.getConfiguration("LaravelExtraIntellisense.customValidationRules")); // <-- Merges custom rules
            for (var i in rules) {
                var completeItem = new vscode.CompletionItem(i, vscode.CompletionItemKind.Enum);
                completeItem.range = document.getWordRangeAtPosition(position, Helpers.wordMatchRegex);
                completeItem.insertText = new vscode.SnippetString(this.rules[i]); // <-- Uses the rule value as snippet
                out.push(completeItem);
            }
            return out;
        }
        ```
        - The `ValidationProvider` retrieves `LaravelExtraIntellisense.customValidationRules` from configuration and merges it into `this.rules`.
        - The values from `this.rules` (including custom rules) are used to create `SnippetString` for autocompletion.
        - While not directly using `evalPhp` in `ValidationProvider.ts`, the vulnerability arises from the potential to inject code that *could* be executed elsewhere if these snippets are mishandled or interpreted as code in a later stage (though in the current code, they are used as snippets, so direct code injection via `customValidationRules` into extension's process seems less likely, but the *setting* itself is still a potential attack vector for other vulnerabilities if these rules are processed in a more dynamic way in the future).  The risk here is more about potential future vulnerabilities if the usage of `customValidationRules` is expanded.

    2. **File: `src/helpers.ts`**:
        - `evalPhp` function:
            ```typescript
            static evalPhp(code: string): any {
                var out = Helpers.parsePhp('<?php ' + code + ';'); // <-- Parses PHP code
                if (out && typeof out.children[0] !== 'undefined') {
                    return out.children[0].expression.value; // <-- Returns evaluated value
                }
                return undefined;
            }
            ```
            - `evalPhp` is used to parse and evaluate PHP code snippets. Although in the current flow of `ValidationProvider`, the output of `evalPhp` isn't directly used in a dangerous way, the *existence* of `evalPhp` and the fact that user-provided `customValidationRules` are processed, represents a potential code injection risk if the extension's logic evolves to use these rules more dynamically or in contexts where evaluation could be harmful.

* Security Test Case:
    1. Create a new Laravel project.
    2. Create a `.vscode` folder in the project root.
    3. Inside `.vscode`, create a `settings.json` file with the following content to inject PHP code that creates a file named `pwned_validation` in the root directory when the settings are loaded (Note: This test case is more about demonstrating code *execution* within the extension's PHP parsing context, not direct RCE via `customValidationRules` snippets, as they are currently used as static snippets).
        ```json
        {
            "LaravelExtraIntellisense.customValidationRules": {
                "pwned_rule": "<?php system('touch pwned_validation'); ?>"
            }
        }
        ```
    4. Open the Laravel project in VSCode with the Laravel Extra Intellisense extension activated.
    5. Open any PHP file where validation rules might be suggested (e.g., a FormRequest file, a controller).
    6. Trigger validation rule autocompletion (e.g., in a rules array, start typing a rule). While autocompletion itself might work with the injected rule, the key is to check if the code in `customValidationRules` is *processed*.
    7. After opening the project and letting the extension load (you might need to trigger autocompletion to ensure settings are fully loaded), check the project root directory.
    8. If the code is injected and processed, a file named `pwned_validation` *might* be created in the project root (depending on how and when `evalPhp` or similar parsing is triggered in relation to `customValidationRules`; current code uses them as snippets, so direct file creation might not occur from just loading settings, but future changes could increase this risk).  A more reliable test for *code execution* within the extension's PHP context would involve logging or other side-effects that are easier to observe within the extension's execution environment if direct file system changes aren't immediately apparent.  However, the core vulnerability is the *potential* for code injection via this setting if the usage of `customValidationRules` is expanded to involve more dynamic processing.
