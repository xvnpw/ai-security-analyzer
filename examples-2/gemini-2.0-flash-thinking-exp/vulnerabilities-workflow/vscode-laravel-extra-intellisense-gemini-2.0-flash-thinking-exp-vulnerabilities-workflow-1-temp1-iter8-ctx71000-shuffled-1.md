## Vulnerability List:

### 1. Command Injection in Translation Provider

* Vulnerability Name: Command Injection in Translation Provider
* Description: The Laravel Extra Intellisense extension is vulnerable to command injection. This vulnerability can be triggered by a malicious actor who provides a crafted Laravel project repository to a victim. By creating a translation file with a specially crafted filename within the `lang` directory of the malicious repository, an attacker can inject arbitrary PHP code that gets executed on the victim's machine when the extension attempts to load translations. The vulnerability occurs because the extension uses filenames from the filesystem directly within generated PHP code without proper sanitization.
* Impact: Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to complete system compromise, data theft, or further malicious activities.
* Vulnerability Rank: High
* Currently Implemented Mitigations: None. The extension does not sanitize filenames used in generated PHP code.
* Missing Mitigations:
    - Sanitize filenames obtained from the filesystem before incorporating them into PHP code strings. Specifically, when constructing the PHP code in `TranslationProvider.ts`, filenames should be escaped or validated to prevent code injection.
    - Consider using more secure methods to obtain translation data, avoiding dynamic code execution based on filesystem content.
* Preconditions:
    - The victim must have the "Laravel Extra Intellisense" extension installed in VSCode.
    - The victim must open a workspace in VSCode that contains a malicious Laravel project repository provided by the attacker.
    - The malicious repository must contain a crafted translation file with a malicious filename in the `lang` directory.
* Source Code Analysis:

    1. **File:** `src/TranslationProvider.ts`
    2. **Function:** `loadTranslations()`
    3. This function is responsible for loading translations to provide autocompletion. It fetches translation keys by executing PHP code using `Helpers.runLaravel`.
    4. Inside `loadTranslations`, the `nestedTranslationGroups` function and similar logic in `loadTranslations` discover translation file paths.
    5. In the `nestedTranslationGroups` function and the loop after `tranlationNamespaces[''] = langPath;`, filenames are processed without sanitization:
       ```typescript
       if (fs.lstatSync(path + '/' + file).isFile()) {
           out.push(relativePath + '/' + file.replace(/\.php/, ''));
       }
       ```
       and
       ```typescript
       fs.readdirSync(langPath).forEach(function (langDir) { ...
           fs.readdirSync(path).forEach(function (file) {
               if (fs.lstatSync(path + '/' + file).isFile()) {
                   translationGroups.push(i + file.replace(/\.php/, ''));
               }
           });
       });
       ```
       The `file.replace(/\.php/, '')` removes the extension, but the filename itself is used directly.
    6. These discovered translation group names (`translationGroups`) are then used to construct a PHP code string:
       ```typescript
       Helpers.runLaravel("echo json_encode([" + translationGroups.map((transGroup: string) => "'" + transGroup + "' => __('" + transGroup + "')").join(",") + "]);", "Translations inside namespaces")
       ```
    7. The `transGroup` variable, which is derived from the filename, is directly embedded within the `'__('${transGroup}')'` part of the PHP code string.
    8. If a malicious filename like `test'); system('calc'); //.php` exists, `transGroup` will become `test'); system('calc'); //`, and the generated PHP code will be:
       ```php
       echo json_encode(["test'); system('calc'); //" => __('test'); system('calc'); //')]);
       ```
    9. When this PHP code is executed by `Helpers.runLaravel` and `Helpers.runPhp`, the `system('calc')` command will be executed, achieving command injection.

* Security Test Case:

    1. **Setup Malicious Repository:**
        - Create a new directory for a malicious Laravel project, e.g., `malicious-laravel-project`.
        - Inside `malicious-laravel-project`, create a basic Laravel project structure (you can use `laravel new .` if you have Laravel CLI installed, or just create necessary directories like `lang`, `config`, `bootstrap`, `vendor`, `public`, etc. and a basic `artisan` file and `composer.json`, `composer.lock`). Only essential files are needed for the extension to activate and trigger the vulnerability.
        - Navigate to the `lang/en/` directory (create if it doesn't exist).
        - Create a new PHP file named `test'); system('calc'); //.php` (or `test'); system('open /Applications/Calculator.app'); //.php` on macOS, or `test'); system('start calc.exe'); //.php` on Windows). The crucial part is the filename.
        - The content of this file can be empty or contain any valid PHP array, e.g., `<?php return [];`.
    2. **Victim Setup:**
        - Ensure the "Laravel Extra Intellisense" extension is installed and enabled in VSCode.
        - Open VSCode and open the `malicious-laravel-project` directory as a workspace.
    3. **Trigger Vulnerability:**
        - Wait for the extension to activate and load translations (this usually happens automatically shortly after opening the workspace or when you open a PHP/Blade file). File watchers might trigger the loading immediately or a timer based reload in the extension may trigger it shortly after.
    4. **Verify Command Execution:**
        - Observe if the calculator application (`calc`, `Calculator.app`) is launched on the victim's machine. This indicates successful command injection and remote code execution.
    5. **Cleanup:**
        - Remove the `malicious-laravel-project` directory and the malicious translation file.
