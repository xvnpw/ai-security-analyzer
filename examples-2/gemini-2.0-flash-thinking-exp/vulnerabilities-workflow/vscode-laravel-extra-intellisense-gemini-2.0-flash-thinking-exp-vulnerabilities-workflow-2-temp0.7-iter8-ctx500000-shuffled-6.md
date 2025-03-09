- Vulnerability Name: Arbitrary PHP code execution via `phpCommand` setting
- Description:
  1. An attacker crafts a malicious Laravel project.
  2. Within this project, the attacker creates a `.vscode/settings.json` file in the `.vscode` directory.
  3. In this `settings.json` file, the attacker overrides the `LaravelExtraIntellisense.phpCommand` setting. They set it to a malicious PHP command that executes arbitrary code. For example, they could set it to `php -r "system('whoami');"`.
  4. The attacker distributes or shares this malicious Laravel project, for example by hosting it on a public repository or sending it to a developer.
  5. A developer with the "Laravel Extra Intellisense" extension installed opens this malicious Laravel project in VSCode.
  6. When VSCode opens the project, the "Laravel Extra Intellisense" extension activates.
  7. The extension, in its normal operation, executes PHP code using the command specified in `LaravelExtraIntellisense.phpCommand` to gather autocompletion data from the Laravel project.
  8. Because the attacker has modified the `LaravelExtraIntellisense.phpCommand` setting, the malicious PHP code provided by the attacker (e.g., `system('whoami');`) is executed on the developer's machine when the extension runs.
- Impact:
  Successful exploitation allows arbitrary PHP code execution on the developer's machine upon opening the malicious project in VSCode. This can lead to:
  - Information Disclosure: Attackers can read sensitive data, including files and environment variables accessible to the VSCode process.
  - Local Privilege Escalation: If VSCode is run with elevated privileges, the attacker might inherit or leverage these privileges.
  - Lateral Movement: Compromised developer machines can be used as a pivot point to attack other systems within the developer's network.
  - Malware Installation: Attackers can install malware, backdoors, or other malicious software on the developer's system.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
  - The extension's `README.md` includes a "Security Note" advising users to be cautious due to the extension's automatic execution of the Laravel application. It suggests temporarily disabling the extension when working with sensitive code in service providers. This is a documentation-level warning but not a technical mitigation within the extension itself.
- Missing Mitigations:
  - Input validation and sanitization: The extension should validate and sanitize the `LaravelExtraIntellisense.phpCommand` setting to prevent the execution of arbitrary commands. It should ideally restrict the command to only the intended `php -r "{code}"` structure and disallow any modifications.
  - User Warning: VSCode should display a warning to the user when a workspace setting like `LaravelExtraIntellisense.phpCommand` is changed from its default, especially when it involves executing code.
  - Sandboxing or Isolation: The extension could employ sandboxing or isolation techniques to limit the impact of executed PHP code, even if malicious.
  - Alternative Data Gathering Mechanism: Explore safer methods for collecting autocompletion data that do not involve executing arbitrary PHP code provided or influenced by the opened project's settings.
- Preconditions:
  - The developer has the "Laravel Extra Intellisense" extension installed in VSCode.
  - The developer opens a Laravel project that contains a malicious `.vscode/settings.json` file crafted by the attacker.
  - The opened folder must be recognized as a Laravel project, typically by the presence of an `artisan` file, to trigger the extension's features.
- Source Code Analysis:
  1. File: `src/helpers.ts`
  2. Function: `runPhp(code: string, description: string|null = null)`
  3. Line:
     ```typescript
     let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
     ```
     - This line retrieves the value of the `LaravelExtraIntellisense.phpCommand` configuration setting from VSCode. If no setting is found, it defaults to `php -r "{code}"`.
  4. Line:
     ```typescript
     let command = commandTemplate.replace("{code}", code);
     ```
     - This line constructs the final PHP command to be executed by replacing the `{code}` placeholder in the `commandTemplate` with the actual PHP code (`code` argument passed to `runPhp`).
  5. Line:
     ```typescript
     cp.exec(command, ...
     ```
     - This line uses `child_process.exec` to execute the `command` constructed in the previous step.
     - **Vulnerability Point:** The `commandTemplate` is directly sourced from user-configurable settings without any validation. This allows an attacker to inject arbitrary commands by modifying the `LaravelExtraIntellisense.phpCommand` setting, which is then directly executed by `cp.exec`.

- Security Test Case:
  1. Create a new directory named `test-laravel-project`.
  2. Inside `test-laravel-project`, create a subdirectory named `.vscode`.
  3. Within `.vscode`, create a file named `settings.json`.
  4. Add the following JSON content to `settings.json` to override the `phpCommand` setting and execute the `whoami` command:
     ```json
     {
         "LaravelExtraIntellisense.phpCommand": "php -r \\"system('whoami');\\""
     }
     ```
  5. In the root of `test-laravel-project`, create an empty file named `artisan`. This simulates a minimal Laravel project structure, enough to activate the extension.
  6. Open VSCode and then open the `test-laravel-project` folder.
  7. After opening the project, navigate to the "Output" panel in VSCode (View -> Output) and select "Laravel Extra Intellisense" from the dropdown menu in the Output panel.
  8. Observe the output in the "Laravel Extra Intellisense" output channel. You should see the result of the `whoami` command being executed, indicating successful arbitrary command execution. The output will display the username under which VSCode is running.
