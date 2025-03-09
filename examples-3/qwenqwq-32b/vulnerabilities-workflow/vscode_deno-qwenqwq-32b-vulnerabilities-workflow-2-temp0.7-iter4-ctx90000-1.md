- **Vulnerability Name**: Arbitrary Code Execution via Malicious Deno Tests with Default `--allow-all` Permissions
  **Description**: The extension's default configuration for test execution via the Test Code Lens feature includes the `--allow-all` flag. An attacker can craft a malicious Deno test file (e.g., `tests/malicious_test.ts`) containing harmful system commands (e.g., `Deno.run("sh", { stdin: "rm -rf /" })`). When a user triggers the test via the "Run Test" Code Lens, the test executes with full Deno permissions, allowing unauthorized system access.
  **Impact**: Full system access, leading to data destruction, theft, or compromise.
  **Vulnerability Rank**: Critical
  **Currently Implemented Mitigations**: None. The default `deno.codeLens.testArgs` is `["--allow-all"]`.
  **Missing Mitigations**:
    - Default settings should restrict permissions (e.g., `--allow-none`).
    - Require explicit user approval for `--allow-all`.
  **Preconditions**:
    - User has the extension installed with default settings.
    - Malicious test file exists in the workspace.
    - User clicks the Test Code Lens.
  **Source Code Analysis**:
    In `client/src/commands.ts`, the `test` function directly uses `--allow-all` from the configuration:
    ```typescript
    const testArgs: string[] = config.get("codeLens.testArgs") ?? ["--allow-all"];
    // Malicious args are included directly from settings
    ```
    The test execution process runs these arguments without validation.
  **Security Test Case**:
  1. Create `tests/malicious.ts` with `Deno.run("sh", { args: ["echo Compromise > /tmp/exploit"] });`.
  2. Ensure `deno.codeLens.testArgs` is default (`["--allow-all"]`).
  3. Open the file in VSCode and click "Run Test".
  4. Verify `/tmp/exploit` is created.

- **Vulnerability Name**: Test Execution with Unrestricted User-Supplied Arguments
  **Description**: The test execution process in `client/src/commands.ts` directly includes user-supplied settings (e.g., `deno.env`, import maps, or `deno.unstable`) without validation. An attacker could manipulate these to execute malicious code (e.g., injecting shell commands via environment variables).
  **Impact**: Arbitrary code execution via injected commands (e.g., environment variables, malicious import maps).
  **Vulnerability Rank**: High
  **Currently Implemented Mitigations**: None.
  **Missing Mitigations**:
    - Sanitize user-supplied arguments (e.g., environment variables, import maps).
    - Restrict dangerous command-line arguments.
  **Preconditions**:
    - User has malicious settings configured (e.g., `deno.env` with shell commands).
    - The test execution includes these dangerous settings.
  **Source Code Analysis**:
    In `client/src/commands.ts`, unvalidated user-supplied values are used directly:
    ```typescript
    const env = config.get<Record<string, string>>("env"); // Unvalidated
    // Directly used in process execution without sanitization
    ```
  **Security Test Case**:
  1. Set `deno.env` to `{"CMD": "echo Compromise > /tmp/compromise"}`.
  2. Create a test file using `Deno.env.get("CMD")`.
  3. Run the test via Test Code Lens.
  4. Verify `/tmp/compromise` is created.
```

### Excluded Vulnerabilities:
1. **Unvalidated Task Execution from Config Files**: Not part of the specified attack vector (Test Code Lens).
2. **Unrestricted Environment Variables in Testing**: Redundant with the second vulnerability.
3. **Default "deno.testing.args" with `--allow-all`**: Same root cause as the first vulnerability but via Testing Explorer, which is outside the specified attack vector.
