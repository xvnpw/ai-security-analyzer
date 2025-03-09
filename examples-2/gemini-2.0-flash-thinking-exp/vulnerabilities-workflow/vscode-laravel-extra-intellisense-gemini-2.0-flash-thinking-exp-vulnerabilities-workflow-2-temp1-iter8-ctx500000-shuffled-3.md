* Vulnerability name: Arbitrary Code Execution via Malicious Model Files in EloquentProvider

* Description:
    1. A developer opens a malicious Laravel project in VSCode with the "Laravel Extra Intellisense" extension enabled.
    2. The malicious project contains a PHP file with malicious code placed in a directory that the extension considers a model directory (e.g., `app/Models` or directories configured in `LaravelExtraIntellisense.modelsPaths`).
    3. The `EloquentProvider` in the extension, during its initialization or refresh cycle, attempts to load model information to provide autocompletion features.
    4. The `loadModels` function in `EloquentProvider.ts` iterates through directories specified in `LaravelExtraIntellisense.modelsPaths` and includes PHP files found within these directories using `include_once`.
    5. Due to `include_once`, the malicious PHP code in the crafted model file gets executed within the extension's PHP execution environment.
    6. The attacker, by controlling the content of the included PHP file, achieves arbitrary command execution on the developer's machine with the privileges of the VSCode process.

* Impact:
    * Critical. An attacker can achieve arbitrary code execution on the developer's machine simply by crafting a malicious Laravel project that the developer opens in VSCode with the extension enabled. This can lead to complete compromise of the developer's workstation, including data theft, installation of malware, and further access to internal networks and systems that the developer has access to.

* Vulnerability rank: Critical

* Currently implemented mitigations:
    * None. The extension directly includes PHP files from directories defined by the user configuration `LaravelExtraIntellisense.modelsPaths` without any sanitization or security checks. The "Security Note" in the README.md warns about potential issues but does not prevent the vulnerability.

* Missing mitigations:
    * Input validation and sanitization for `LaravelExtraIntellisense.modelsPaths`: The extension should validate that the configured model paths are within the workspace and prevent absolute paths or paths outside the project directory to restrict file access.
    * Code review and security audit of included files:  Ideally, the extension should not execute arbitrary code from project files. If code execution is necessary, it should be strictly controlled and limited to specific, safe operations. In this case, instead of including model files, the extension could use PHP reflection or parsing techniques to extract model information without executing the entire file content.
    * Sandboxing or isolation of PHP execution:  If PHP code execution is unavoidable, it should be sandboxed or isolated from the main VSCode process to minimize the impact of potential vulnerabilities. However, for a VSCode extension, this might be complex to implement.
    * User awareness and security warnings:  While not a technical mitigation, improving the security warning in the README and displaying a prominent warning when the extension is activated in a workspace for the first time could raise user awareness about the risks.

* Preconditions:
    * The developer must have the "Laravel Extra Intellisense" extension installed and enabled in VSCode.
    * The developer must open a malicious Laravel project in VSCode.
    * The malicious Laravel project must contain a PHP file with malicious code in a directory that is considered a model path by the extension (either default `app/Models` or a path configured in `LaravelExtraIntellisense.modelsPaths`).

* Source code analysis:
    1. Open `src\EloquentProvider.ts`.
    2. Examine the `loadModels` function.
    3. Observe the loop that iterates through `vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models'])`. This retrieves the configured model paths from user settings, which can be manipulated by an attacker via project workspace settings.
    4. Inside the loop, for each path, the code uses `scandir` to read the directory content.
    5. For each file found with the `.php` extension, `include_once base_path(\"$modelPath/$sourceFile\")` is used to include the file.
    6. `base_path()` resolves to `Helpers.projectPath()`, which, if not configured with `basePathForCode`, defaults to the workspace root.
    7. `include_once` will execute the PHP code within the included file.

    ```typescript
    loadModels() {
        var self = this;
        try {
            Helpers.runLaravel(
                "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join('\', \'') + "'] as $modelPath) {" + // [POINT 1] User controlled modelsPaths
                "   if (is_dir(base_path($modelPath))) {" +
                "      foreach (scandir(base_path($modelPath)) as $sourceFile) {" + // [POINT 2] Directory scanning
                "         if (substr($sourceFile, -4) == '.php' && is_file(base_path(\"$modelPath/$sourceFile\"))) {" +
                "             include_once base_path(\"$modelPath/$sourceFile\");" + // [POINT 3] Code execution via include_once
                "         }" +
                "      }" +
                "   }" +
                "} ... ",
                "Eloquent Attributes and Relations"
            ).then(function (result) { ... });
        } catch (exception) { ... }
    }
    ```

    **Visualization of Attack Flow:**

    ```mermaid
    graph LR
        A[Developer Opens Malicious Laravel Project in VSCode] --> B(Extension Activation);
        B --> C[EloquentProvider.loadModels()];
        C --> D{Iterate modelsPaths from config};
        D --> E{Scan Directory (e.g., app/Models)};
        E --> F{Finds MaliciousModel.php};
        F --> G[include_once(MaliciousModel.php)];
        G --> H[Malicious PHP Code Execution];
        H --> I[Arbitrary Command Execution on Developer's Machine];
    ```

* Security test case:
    1. Create a new directory named `malicious-laravel-project`.
    2. Inside `malicious-laravel-project`, create a `.vscode` directory.
    3. Inside `.vscode`, create a `settings.json` file with the following content to ensure the extension is enabled:
    ```json
    {
        "laravel-extra-intellisense.phpCommand": "php -r \"{code}\""
    }
    ```
    4. Inside `malicious-laravel-project`, create the directory structure `app/Models`.
    5. Inside `app/Models`, create a file named `MaliciousModel.php` with the following malicious PHP code. This code will create a file named `pwned.txt` in the workspace root to demonstrate code execution:
    ```php
    <?php

    namespace App\Models;

    use Illuminate\Database\Eloquent\Model;

    class MaliciousModel extends Model
    {
        public static function boot()
        {
            parent::boot();
            file_put_contents(dirname(__DIR__, 2) . '/pwned.txt', 'PWNED!');
        }
    }
    ```
    6. Open VSCode and open the `malicious-laravel-project` folder.
    7. Wait for the "Laravel Extra Intellisense" extension to activate and initialize (this may take a few seconds).
    8. Verify that a file named `pwned.txt` has been created in the root directory of the `malicious-laravel-project`. The content of the file should be "PWNED!".
    9. If `pwned.txt` is created with the correct content, it confirms that the malicious PHP code in `MaliciousModel.php` has been executed by the extension, and arbitrary code execution is possible.
