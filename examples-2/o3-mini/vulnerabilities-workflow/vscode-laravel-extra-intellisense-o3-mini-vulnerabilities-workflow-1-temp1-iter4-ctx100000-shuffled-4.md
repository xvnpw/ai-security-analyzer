# Vulnerabilities List

---

## 1. Workspace Configuration Command Injection via phpCommand Setting

**Description:**
The extension obtains the PHP command string from a workspace configuration value ("LaravelExtraIntellisense.phpCommand"). This value is used without additional sanitization to construct a shell command that the extension later passes to Node’s `cp.exec`. An attacker who supplies a malicious repository (for example, via a manipulated `.vscode/settings.json` file in the repository) can override the default command template. For instance, the attacker could set the `phpCommand` configuration to a string that appends an extra shell command (e.g. `php -r "{code}; system('malicious_command');"`) so that when the extension attempts to run a generated piece of PHP code, the extra command runs as well.

**Triggering Steps:**
1. The attacker prepares a repository that looks like a valid Laravel project but includes a malicious workspace configuration file (e.g. a manipulated `.vscode/settings.json` file).
2. In that settings file, the attacker sets the “LaravelExtraIntellisense.phpCommand” (and optionally related settings like `basePathForCode`) to a value that, for example, appends an arbitrary shell command after the injected PHP code.
3. The victim opens the repository in VSCode, which loads the workspace settings and activates the extension.
4. Later, when the extension attempts to execute a PHP snippet (e.g. to fetch routes, views, translations, etc.), it uses the malicious `phpCommand` string from configuration.
5. The extension replaces the `{code}` placeholder with the intended PHP code and then calls `cp.exec` to run the full command, thereby triggering the appended malicious command.

**Impact:**
Successful exploitation allows an attacker to run arbitrary shell commands on the victim’s machine with the privileges of the VSCode process. This constitutes a critical Remote Code Execution (RCE) vulnerability that may lead to full system compromise (e.g. exfiltration of data, installation of malware, lateral movement, etc.).

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The code performs a rudimentary replacement (escaping of quote characters within the provided PHP code) in `Helpers.runPhp`.
- However, this escaping focuses only on the injected PHP snippet and does not sanitize the entire command template obtained from configuration.
- There is no check or validation on the “phpCommand” setting to ensure it does not include extra shell syntax.

**Missing Mitigations:**
- The extension should treat workspace (or user) configuration values as untrusted and either validate or whitelist acceptable values for sensitive settings like “phpCommand.”
- It could, for example, restrict the command template to a fixed pattern (only allowing "{code}" to be substituted) or outright ignore workspace overrides that deviate from a safe default.
- Additional sanitization of the final command string (such as proper shell-escaping for injected parameters) would reduce the risk.

**Preconditions:**
- The victim opens a repository that includes malicious workspace configuration (e.g. a `.vscode/settings.json` file) where “LaravelExtraIntellisense.phpCommand” is overridden with a payload.
- The extension is activated and proceeds to execute PHP code via the configured command.

**Source Code Analysis:**
1. In **helpers.ts → runPhp()**, the code retrieves the command template as follows:
   ```ts
   let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
   ```
2. No validation is performed on the fetched string. The command template is assumed to be safe.
3. The extension then substitutes the placeholder `{code}` with the PHP code (after performing only minimal escaping on quotes and some shell-sensitive characters).
4. Finally, it calls:
   ```ts
   cp.exec(command, { cwd: … }, (err, stdout, stderr) => { … });
   ```
   As a result, if the configuration value includes additional shell commands (for example after “{code}”), those extra commands will be executed as part of the overall shell invocation.

**Security Test Case:**
1. **Setup:**
   - Create a test repository that mimics a Laravel project and includes a `.vscode/settings.json` (or instruct a test workspace to set these values) with a malicious override. For example:
     ```json
     {
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('echo INJECTED;')\""
     }
     ```
2. **Execution:**
   - Open the test repository in VSCode.
   - Trigger an action in the extension that forces it to run PHP code (for example, refresh the route autocomplete or request the Blade directives).
3. **Observation:**
   - Monitor the output channel or check the system output to verify that the injected command (`system('echo INJECTED;')`) was executed (for example, by spotting “INJECTED” in the output log or observing the effect of a harmless command you specified).
4. **Verification:**
   - Confirm that the extra command executed as part of the PHP command, thus demonstrating that the unsanitized configuration value allowed command injection.

---

*This vulnerability is valid, not already mitigated, and has a rank of at least high. It falls under the categories of Remote Code Execution, Command Injection, and Code Injection and is triggered by a malicious repository supplying altered workspace configuration.*
