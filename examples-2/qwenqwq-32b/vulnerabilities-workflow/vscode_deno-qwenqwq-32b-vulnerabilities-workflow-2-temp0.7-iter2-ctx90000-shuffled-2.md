- vulnerability name: Command Injection via Test Arguments Configuration
  description: Attackers can manipulate `deno.testing.args` or `deno.codeLens.testArgs` settings to inject malicious command-line arguments. These arguments are directly passed to the Deno CLI during test execution without validation. For example, setting `deno.codeLens.testArgs` to `["--allow-run", "&&", "rm", "-rf", "/"]` would execute arbitrary commands when running tests via code lenses.
  impact: Allows execution of arbitrary commands with user permissions, potentially leading to full system compromise.
  vulnerability rank: Critical
  currently implemented mitigations: None. No validation occurs for arguments in these settings.
  missing mitigations: Input validation/sanitization for command-line arguments in test configurations. Should restrict dangerous flags (e.g., `--allow-run`) or at least warn users of risks when enabling them via configuration.
  preconditions: Attacker must configure the workspace's settings (e.g., via a malicious `deno.json` or workspace settings file).
  source code analysis:
  1. In `client/src/testing.ts`, the `test` function retrieves `testArgs` from configuration (`config.get<string[]>("codeLens.testArgs")`) and appends them to the command line arguments for Deno test execution.
  2. The `buildDenoTask` function in `client/src/tasks.ts` constructs the task command by directly appending user-provided arguments to the CLI without validation.
  security test case:
  1. Create a workspace with a `deno.json` containing:
    ```json
    {
      "codeLens": {
        "testArgs": ["--allow-run", "&&", "echo", "ATTACK_SUCCEEDED", ">", "/tmp/exploit.txt"]
      }
    }
    ```
  2. Add a simple test file (e.g., `test.ts` with `Deno.test("dummy", () => {});`).
  3. Use the code lens to run the test. The malicious argument `--allow-run && echo...` will execute, creating `/tmp/exploit.txt`.
  4. Verify the file exists, indicating successful command injection.
