### Vulnerability Name: Command Injection via configurable `phpCommand`
#### Description:
The extension allows users to configure the `phpCommand` setting, which defines how PHP code is executed. An attacker can manipulate this setting to include arbitrary commands. When the extension runs PHP code via `Helpers.runPhp`, the provided command template is directly interpolated with user-supplied code without validation, enabling command injection. For example, setting `phpCommand` to `bash -c "{code} && <malicious-command>"` would execute the malicious command alongside the intended PHP code.

#### Step-by-Step Trigger:
1. An attacker provides a malicious configuration (e.g., via a malicious VSCode settings file) where `phpCommand` is set to include arbitrary shell commands.
2. The extension executes PHP code (e.g., during route or validation rule resolution) using the tainted `phpCommand`.
3. The injected shell commands execute with the privileges of the VSCode process, leading to RCE.

#### Impact:
An attacker can execute arbitrary system commands, potentially leading to full compromise of the host system. This includes file deletion, data theft, or installing malicious software.

#### Vulnerability Rank:
Critical

#### Currently Implemented Mitigations:
- The documentation warns users to configure the extension carefully (as noted in the README's security note).
- Docker usage examples are provided with explicit paths, but these are user-configurable and not validated.

#### Missing Mitigations:
- No input validation or sanitization is performed on the `phpCommand` setting.
- No default secure command template is enforced (e.g., restricting execution to a sandboxed environment).
- No mechanism to block potentially dangerous commands or validate the command structure.

#### Preconditions:
- The user must have configured `phpCommand` with malicious values from a compromised repository or settings file.
- The extension must be active and trigger a code execution event (e.g., autocompleting routes/models).

#### Source Code Analysis:
In `Helpers.ts`, the `runPhp` function constructs the command by replacing `{code}` in the user-configured `phpCommand` template:
```typescript
command = commandTemplate.replace("{code}", code);
```
The `phpCommand` value is sourced directly from user settings via:
```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
```
No validation ensures that `commandTemplate` does not include malicious payloads. When `runPhp` executes commands via `child_process.exec`, it blindly trusts the template, allowing arbitrary command injection.

#### Security Test Case:
**Setup**:
1. Configure the extension with a malicious `phpCommand`:
   ```json
   "LaravelExtraIntellisense.phpCommand": "bash -c \"{code}; echo 'Malicious command executed' > /tmp/exploit.txt\"",
   ```
2. Create a test PHP project with a file `test.php` containing arbitrary code (e.g., `echo "test";`).

**Trigger**:
- Open the project in VSCode and trigger an event that runs PHP code (e.g., modify a route or validation rule to force `Helpers.runPhp` execution).

**Expectation**:
- A file `exploit.txt` is created in `/tmp/` with the message "Malicious command executed", demonstrating command injection.
- The attacker's arbitrary command (e.g., file deletion or data exfiltration) executes.

This vulnerability is critical because it allows full system compromise through a simple misconfiguration. The attacker can leverage user trust in repositories or settings files to inject malicious commands, enabling remote code execution.
