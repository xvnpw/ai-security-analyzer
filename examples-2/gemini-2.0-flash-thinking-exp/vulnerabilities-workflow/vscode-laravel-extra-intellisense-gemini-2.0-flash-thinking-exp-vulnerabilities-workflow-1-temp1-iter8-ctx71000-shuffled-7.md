### Vulnerability List:

*   **Vulnerability Name:**  Command Injection via `phpCommand` Configuration

*   **Description:**
    The `Laravel Extra Intellisense` extension allows users to configure the PHP command used to run Laravel code through the `LaravelExtraIntellisense.phpCommand` setting. This setting is directly passed to `child_process.exec` in the `runPhp` function without sufficient sanitization. A malicious user who can influence the VSCode workspace settings (e.g., by providing a malicious repository) can inject arbitrary shell commands into the `phpCommand`. When the extension executes PHP code using `Helpers.runLaravel` or `Helpers.runPhp`, the injected commands will be executed by the system.

    Steps to trigger the vulnerability:
    1.  A threat actor creates a malicious Laravel repository.
    2.  The threat actor includes a `.vscode/settings.json` file in the repository.
    3.  In the `settings.json`, the threat actor sets the `LaravelExtraIntellisense.phpCommand` to a malicious command, for example: `"LaravelExtraIntellisense.phpCommand": "bash -c '{code} && touch /tmp/pwned'"`.
    4.  A victim clones or opens the malicious repository in VSCode with the `Laravel Extra Intellisense` extension installed.
    5.  The extension attempts to run Laravel code (e.g., to fetch routes, views, or configs), which triggers the `runPhp` function using the malicious `phpCommand` from the workspace settings.
    6.  The injected command (`touch /tmp/pwned` in the example) is executed on the victim's system.

*   **Impact:**
    Remote Code Execution (RCE). An attacker can execute arbitrary shell commands on the victim's machine with the privileges of the VSCode process. This can lead to complete compromise of the victim's system, including data theft, malware installation, and further lateral movement within the victim's network.

*   **Vulnerability Rank:** critical

*   **Currently Implemented Mitigations:**
    None. The code directly uses the user-provided `phpCommand` setting without any sanitization or validation. The `Security Note` in `README.md` warns about potential issues if sensitive code is in service providers, but it does not address the command injection vulnerability from a manipulated `phpCommand` setting.

*   **Missing Mitigations:**
    1.  **Input Sanitization/Validation:** Sanitize or validate the `phpCommand` setting to prevent command injection.  Ideally, restrict the command to a fixed path to the PHP executable and only allow passing the generated PHP code as an argument, without shell interpretation of the command template.
    2.  **Principle of Least Privilege:**  While not directly a mitigation for this vulnerability, running the PHP commands with the least necessary privileges would limit the impact of a successful command injection. However, this is likely not feasible in the context of a VSCode extension.
    3.  **User Awareness:** Improve the security note in the README to explicitly warn users about the risks of using custom `phpCommand` settings from untrusted repositories. However, this is not a sufficient mitigation.

*   **Preconditions:**
    1.  The victim must have the `Laravel Extra Intellisense` extension installed in VSCode.
    2.  The victim must open a malicious Laravel repository in VSCode that contains a crafted `.vscode/settings.json` file with a malicious `LaravelExtraIntellisense.phpCommand`.
    3.  The extension must be triggered to execute a PHP command (this happens automatically when the extension is active in a Laravel project).

*   **Source Code Analysis:**

    1.  **`src/helpers.ts:runPhp(code: string, description: string|null = null)`:**
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
        The `runPhp` function retrieves the `phpCommand` from the workspace configuration and uses `String.replace()` to insert the generated PHP code into the command template.  Crucially, `cp.exec(command, ...)` then directly executes this constructed command string. The `code = code.replace(/\"/g, "\\\"")` part attempts to escape double quotes in the PHP code itself but does nothing to sanitize the `commandTemplate` which comes directly from user configuration. There is no sanitization of the `commandTemplate` itself before being passed to `cp.exec`.

    2.  **`README.md`:**
        The `README.md` provides configuration examples, including Docker setups, which demonstrate how users are expected to customize the `phpCommand`. This reinforces that users are intended to modify this setting, increasing the likelihood of malicious exploitation.

        ```markdown
        #### Sample config to use docker
        This is a simple configuration to use via [Laradock](https://github.com/laradock/laradock).

        ```json
        "LaravelExtraIntellisense.phpCommand": "docker exec -w /var/www/your-project -u laradock laradock_workspace_1 php -r \"{code}\"",
        "LaravelExtraIntellisense.basePathForCode": "/var/www/your-project"
        ```

*   **Security Test Case:**

    1.  **Setup:**
        *   Victim machine with VSCode and `Laravel Extra Intellisense` extension installed.
        *   Attacker machine to create a malicious repository.
    2.  **Attacker Actions:**
        *   Create a new Laravel project (can be a minimal project, `laravel new malicious-repo`).
        *   Navigate to the project directory: `cd malicious-repo`.
        *   Create a `.vscode` directory: `mkdir .vscode`.
        *   Create a `settings.json` file inside `.vscode` with the following content:
            ```json
            {
                "LaravelExtraIntellisense.phpCommand": "bash -c '{code} && touch /tmp/pwned-laravel-extension'"
            }
            ```
        *   Initialize a Git repository: `git init`.
        *   Add and commit the files: `git add . && git commit -m "Malicious settings"`.
        *   Host the repository on a public platform like GitHub or GitLab.
    3.  **Victim Actions:**
        *   Clone the malicious repository: `git clone <attacker-repo-url> victim-repo`.
        *   Open the `victim-repo` folder in VSCode.
        *   Wait for the `Laravel Extra Intellisense` extension to initialize and attempt to fetch data (this might happen automatically, or by opening a PHP or Blade file that triggers autocompletion).
    4.  **Verification:**
        *   On the victim's machine, check if the file `/tmp/pwned-laravel-extension` exists.
        *   If the file exists, the command injection vulnerability is confirmed. The `touch` command, injected via the malicious `phpCommand` setting, has been successfully executed.

This test case demonstrates that a threat actor can achieve command execution on a victim's machine simply by providing a malicious repository that leverages the `LaravelExtraIntellisense.phpCommand` configuration setting.
