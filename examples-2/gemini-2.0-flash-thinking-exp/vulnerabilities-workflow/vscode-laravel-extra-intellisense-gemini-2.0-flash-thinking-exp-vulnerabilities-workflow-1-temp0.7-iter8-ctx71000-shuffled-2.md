* Vulnerability Name: Command Injection via `phpCommand` Setting
* Description:
    An attacker can inject arbitrary shell commands by manipulating the `LaravelExtraIntellisense.phpCommand` setting in VSCode configuration. This setting, intended for customizing the PHP command executed by the extension, is directly passed to `child_process.exec` without proper sanitization. By providing a malicious repository with a crafted `.vscode/settings.json` file, an attacker can overwrite this setting and execute arbitrary commands on the victim's machine when the extension is activated in the context of this repository.
    Steps to trigger:
    1. The attacker creates a malicious Laravel repository.
    2. The attacker adds a `.vscode` directory to the repository.
    3. Inside `.vscode`, the attacker creates a `settings.json` file.
    4. In `settings.json`, the attacker sets the `LaravelExtraIntellisense.phpCommand` configuration to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"calc\");'"`
    5. The attacker shares or tricks the victim into opening this malicious repository in VSCode with the "Laravel Extra Intellisense" extension installed and activated.
    6. Once the repository is opened and the extension initializes or any autocompletion feature is triggered, the malicious command from `settings.json` will be executed by the extension.
* Impact:
    Remote Code Execution (RCE). Successful exploitation allows the attacker to execute arbitrary shell commands on the victim's machine with the same privileges as the VSCode process. This can lead to full system compromise, data theft, installation of malware, and other malicious activities.
* Vulnerability Rank: critical
* Currently Implemented Mitigations:
    None. While the README.md contains a "Security Note" advising users to be cautious and temporarily disable the extension if they suspect issues, this is not a code-level mitigation and relies on user awareness, which is insufficient to prevent exploitation.
* Missing Mitigations:
    - Input sanitization and validation for the `LaravelExtraIntellisense.phpCommand` setting to prevent injection of arbitrary shell commands.
    - Restrict allowed characters or use a safer method for executing PHP code that does not involve shell command execution, or use `child_process.spawn` with arguments array instead of `child_process.exec` with string command.
    - Ideally, the extension should avoid allowing users to directly configure the command execution in a way that introduces such a high risk of command injection. If command customization is needed, provide a more constrained and secure way to configure it.
* Preconditions:
    - The victim has the "Laravel Extra Intellisense" extension installed and activated in VSCode.
    - The victim opens a malicious Laravel repository in VSCode that contains a crafted `.vscode/settings.json` file.
    - Workspace settings are applied in VSCode (default behavior).
* Source Code Analysis:
    1. File: `src/helpers.ts`
    2. Function: `runPhp(code: string, description: string|null = null)`
    3. The function retrieves the `phpCommand` setting from VSCode configuration:
       ```typescript
       let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
       ```
    4. It replaces the `{code}` placeholder in the `commandTemplate` with the provided `$code`:
       ```typescript
       let command = commandTemplate.replace("{code}", code);
       ```
    5. The resulting `command` string is then directly executed using `child_process.exec`:
       ```typescript
       cp.exec(command, /* ... */);
       ```
    6. There is no sanitization or validation of the `commandTemplate` retrieved from user configuration before it is passed to `cp.exec`. This allows an attacker to inject arbitrary shell commands via the `LaravelExtraIntellisense.phpCommand` setting.

* Security Test Case:
    1. Create a new directory named `malicious-repo`.
    2. Inside `malicious-repo`, create a subdirectory named `.vscode`.
    3. Inside `.vscode`, create a file named `settings.json` with the following content:
       ```json
       {
           "LaravelExtraIntellisense.phpCommand": "php -r '{code}; system(\"calc\");'"
       }
       ```
    4. Open VSCode and open the `malicious-repo` directory as a workspace.
    5. Create any PHP file (e.g., `test.php`) in the `malicious-repo` directory.
    6. Open `test.php` and type `route(` or `config(` to trigger autocompletion.
    7. Observe that the calculator application is launched on your system, demonstrating successful command injection. This confirms that the malicious command set in `settings.json` was executed by the extension.
