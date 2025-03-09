- Vulnerability name: VSCode Extension Settings Injection leading to Command Injection in Deno Test Task
- Description:
    1. Attacker creates a malicious repository with a `.vscode/settings.json` file.
    2. In `.vscode/settings.json`, attacker injects malicious commands into `deno.codeLens.testArgs` or `deno.testing.args`.
    3. Victim clones and opens the malicious repository in VSCode with the vscode-deno extension.
    4. Victim runs a Deno test using code lens or test explorer.
    5. VSCode applies settings from `.vscode/settings.json`, including malicious arguments.
    6. The `deno test` command is executed with injected arguments, leading to command injection.
- Impact: Remote Code Execution (RCE). Attacker can execute arbitrary commands on the victim's machine.
- Vulnerability rank: high
- Currently implemented mitigations: None. The extension directly uses the settings values without sanitization.
- Missing mitigations:
    - Sanitize and validate `deno.codeLens.testArgs` and `deno.testing.args` settings to prevent command injection.
    - Consider whitelisting allowed arguments or disallowing arguments that can introduce new commands (e.g., arguments starting with `-`, `--`, `;`, `&`, etc.).
- Preconditions:
    1. VSCode with vscode-deno extension installed and enabled.
    2. Victim opens a malicious repository containing crafted `.vscode/settings.json`.
    3. Victim runs a Deno test using code lens or test explorer in the malicious repository.
- Source code analysis:
    - File: `client\src\commands.ts`, function `test()`
    - The `testArgs` are retrieved from `vscode.workspace.getConfiguration(EXTENSION_NS).get<string[]>("codeLens.testArgs")` without sanitization.
    - These `testArgs` are directly included in the `args` array for `ProcessExecution`, leading to potential command injection.
- Security test case:
    1. Create a directory `vscode_deno_test_vuln`.
    2. Create `.vscode/settings.json` with:
       ```json
       {
           "deno.codeLens.testArgs": ["; echo PWNED ;"]
       }
       ```
    3. Create `test.ts` with:
       ```typescript
       import { assertEquals } from "https://deno.land/std@0.218.2/assert/mod.ts";
       Deno.test("test example", () => { assertEquals(1, 1); });
       ```
    4. Open `vscode_deno_test_vuln` in VSCode with vscode-deno extension enabled.
    5. Open `test.ts`, click "▶ Run Test" code lens.
    6. Check "Tasks - Deno" output panel. If "PWNED" is printed, command injection is successful.
