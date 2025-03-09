## Vulnerability List

### 1. Command Injection via `phpCommand` Configuration and Backticks in Generated Code

*   **Vulnerability Name:** Command Injection via `phpCommand` and Backticks
*   **Description:**
    1.  The VSCode Laravel Extra Intellisense extension executes PHP code to gather information about the Laravel project, such as routes, views, and configurations.
    2.  The extension uses the user-configurable setting `LaravelExtraIntellisense.phpCommand` to determine how to execute PHP code. The default value is `php -r "{code}"`.
    3.  The extension attempts to sanitize the `{code}` placeholder by escaping double quotes using `code = code.replace(/\"/g, "\\\"")`. However, this is insufficient to prevent command injection if the user modifies `phpCommand` to use single quotes and if the generated `{code}` contains backticks or `$(...)` for command substitution in the shell.
    4.  An attacker can craft a malicious Laravel repository that encourages or tricks a victim into setting a vulnerable `phpCommand` (e.g., `php -r '$c="{code}"; system($c);'`). This could be done via a README instruction or a setup guide within the malicious repository.
    5.  When the extension executes PHP code (e.g., to fetch routes), it inserts the generated PHP code into the `{code}` placeholder of the user-defined `phpCommand`.
    6.  If the generated PHP code inadvertently or intentionally contains backticks or `$(...)`, and the user's `phpCommand` uses single quotes to wrap the `{code}` part, these backticks/`$(...)` will be interpreted by the shell during command execution, leading to command injection.
    7.  An attacker could potentially gain Remote Code Execution (RCE) on the victim's machine by injecting arbitrary shell commands.

*   **Impact:** Remote Code Execution (RCE). An attacker can execute arbitrary shell commands on the machine where VSCode is running with the extension activated and the malicious repository opened. This could lead to complete compromise of the victim's development environment and potentially their system if VSCode has broader permissions.
*   **Vulnerability Rank:** Critical
*   **Currently Implemented Mitigations:**
    *   The extension escapes double quotes in the generated PHP code using `code = code.replace(/\"/g, "\\\"")` in `src/helpers.ts` within the `runPhp` function.
    ```typescript
    static async runPhp(code: string, description: string|null = null) : Promise<string> {
        code = code.replace(/\"/g, "\\\"");
        // ...
        let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
        let command = commandTemplate.replace("{code}", code);
        // ...
        cp.exec(command, ...);
    }
    ```
    *   The README.md contains a "Security Note" warning users that the extension runs their Laravel application and to be cautious with sensitive code. However, it does not specifically warn about the risks of modifying `phpCommand` or the command injection vulnerability.
*   **Missing Mitigations:**
    *   Input sanitization for the `phpCommand` setting itself. The extension should validate or sanitize the `phpCommand` setting to prevent users from introducing obviously unsafe patterns like using `system()` or `exec()` directly in the command template.
    *   More robust escaping of the `{code}` placeholder in `runPhp`. Instead of just escaping double quotes, the extension should use a secure method to pass the PHP code to the `php -r` command, potentially avoiding shell interpretation altogether if possible, or using more comprehensive escaping for shell safety.
    *   Clearer security warnings in the README and within the extension settings description about the risks of modifying `phpCommand` and the potential for command injection. Suggest secure configurations and warn against using shell-executing functions within `phpCommand`.

*   **Preconditions:**
    1.  Victim has the "Laravel Extra Intellisense" extension installed in VSCode.
    2.  Victim opens a malicious Laravel repository in VSCode and activates the extension for this workspace.
    3.  Victim is tricked into setting a vulnerable `phpCommand` configuration. A simple vulnerable configuration is `php -r '$c="{code}"; system($c);'`. This could be presented as a "performance optimization" or "alternative docker setup" in a malicious README.md.

*   **Source Code Analysis:**
    1.  **`src/helpers.ts` - `runPhp` function:**
        *   The `runPhp` function in `src/helpers.ts` is responsible for executing PHP code.
        *   It retrieves the `phpCommand` from the extension settings:
            ```typescript
            let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
            ```
        *   It replaces the `{code}` placeholder in the template with the provided `code` argument:
            ```typescript
            let command = commandTemplate.replace("{code}", code);
            ```
        *   It attempts to escape double quotes in the `code` using:
            ```typescript
            code = code.replace(/\"/g, "\\\"");
            ```
        *   Finally, it executes the constructed command using `child_process.exec`:
            ```typescript
            cp.exec(command, ...);
            ```
        *   **Vulnerability Point:** The single double-quote escaping is insufficient to prevent command injection, especially when users can customize the `phpCommand` template. If a user sets a vulnerable template and the injected `code` contains shell-sensitive characters like backticks, command injection occurs.

    *Visualization:*

    ```mermaid
    graph LR
        A[User Configures phpCommand (e.g., php -r '$c="{code}"; system($c);')] --> B(Extension calls runPhp with code);
        B --> C{runPhp sanitizes code (only escapes double quotes)};
        C --> D{commandTemplate.replace("{code}", code)};
        D --> E[Resulting Command: php -r '$c="`malicious command`"; system($c);'];
        E --> F(cp.exec(command));
        F --> G{Shell executes command};
        G --> H{Command Injection Vulnerability Triggered};
    ```

*   **Security Test Case:**
    1.  **Setup Malicious Repository:** Create a simple Laravel project in a folder named `malicious-repo`. Add a `README.md` file to this repository instructing the user to set the `LaravelExtraIntellisense.phpCommand` to `php -r '$c="{code}"; system($c);'` for "better performance" or some other deceptive reason.
    2.  **Victim Setup:**
        *   Install the "Laravel Extra Intellisense" extension in VSCode.
        *   Clone the `malicious-repo` to a local directory.
        *   Open the `malicious-repo` folder in VSCode.
        *   **Manually configure `phpCommand`:**  In VSCode settings (Workspace Settings for `malicious-repo`), set `LaravelExtraIntellisense.phpCommand` to  `php -r '$c="{code}"; system($c);'`.
    3.  **Trigger Extension Activity:** Open any PHP file in the `malicious-repo` project (e.g., a controller or route file) to trigger the extension's autocompletion features. This will cause the extension to execute PHP code using `runLaravel` and `runPhp`.
    4.  **Observe Command Injection:** Observe the output of the extension (in the "Laravel Extra Intellisense" output channel or in any unexpected system behavior).
        *   **Expected Outcome:**  If the command injection is successful, commands injected via backticks in the generated `{code}` will be executed. For example, if the extension attempts to fetch routes, and the generated code somehow contains backticks (even if inadvertently, or if the attacker can influence the generated code indirectly), and the `phpCommand` is set to the vulnerable template, you should see the output of the injected command (like `whoami`, `id`, etc.) in the output channel or system behavior that indicates command execution.

        *Example Malicious Code Snippet (Illustrative - the actual code generation in the extension might not directly produce this, but demonstrates the vulnerability principle):*  Imagine the extension, under certain conditions in a malicious project, generates PHP code that contains something like `` `echo system('whoami');` ``.  When this is inserted into the vulnerable `phpCommand`, it becomes `php -r '$c="`echo system('whoami');`"; system($c);'`, and `whoami` will be executed by the shell.

5.  **Cleanup:** Reset the `LaravelExtraIntellisense.phpCommand` setting to its default value in VSCode to mitigate the immediate risk.
