# Valid Vulnerabilities

## 1. **Vulnerability Name:** Default Test Permissions Allow Arbitrary Code Execution
**Description:**
The extension's default configuration for running tests via VSCode's Test Explorer uses the `--allow-all` flag, which grants full system permissions to test scripts. An attacker can create a malicious test file (e.g., `Deno.test(() => Deno.run("rm -rf /"))`), and when a user runs the test through the Test Explorer, the extension executes it with unrestricted permissions, enabling arbitrary code execution.

**Step-by-Step Trigger:**
1. Attacker creates a malicious Deno test file in a project.
2. The test file includes Deno API calls like `Deno.readSymlink` or `Deno.run` with harmful commands.
3. User triggers the test via the Test Explorer or `deno test` command.
4. The extension runs the test with `--allow-all`, bypassing Deno's permission prompts.

**Impact:**
Arbitrary code execution in the user's environment with full system permissions. Attackers can delete files, access network resources, or install malware.

**Vulnerability Rank:** Critical
**Currently Implemented Mitigations:** None. The default `deno.testing.args` explicitly sets `--allow-all`.
**Missing Mitigations:**
- Remove `--allow-all` from default test arguments.
- Require explicit permission selection via Deno's prompt system when running tests.
- Provide a workspace setting to restrict permissions for tests by default.

**Preconditions:**
The VSCode extension is installed, and the workspace uses the default configuration.

**Source Code Analysis:**
In `client/src/constants.ts`, the default `deno.testing.args` is hardcoded to `["--allow-all"]`:
```typescript
// From client/src/commands.ts
const testArgs: string[] = [...config.get<string[]>("codeLens.testArgs") ?? []];
// In default scenarios, this starts with ["--allow-all"]
```
The test execution code in `client/src/commands.ts` constructs the Deno CLI command with these args without user prompt:
```typescript
args = ["test", ...testArgs, "--filter", nameRegex, filePath];
```
The `deno.testing.args` setting is configured here by default:
```typescript
// From client/src/commands.ts
testArgs: string[] = [...config.get("codeLens.testArgs") ?? []];
```

**Security Test Case:**
1. Create a test file with `Deno.run({ cmd: ["sh", "-c", "echo 'Exploit executed' > /tmp/exploit.txt"] })`.
2. Configure the workspace to use default `deno.testing.args`.
3. Run the test via Test Explorer. Observe that the `exploit.txt` file is created without any permission prompts, proving unrestricted execution.

---

## 2. **Vulnerability Name:** Insecure Debug Configuration with Default `--allow-all`
**Description:**
The debug configuration provider in `debug_config_provider.ts` defaults to `--allow-all` in debug command-line arguments, allowing attackers to escalate privileges during debugging sessions.

**Step-by-Step Trigger:**
1. Attacker crafts a debug configuration file (e.g., `.vscode/launch.json`) with malicious arguments.
2. When the user starts a debug session, the extension executes the Deno code with `--allow-all`, granting full system permissions.

**Impact:**
Elevated code execution during debugging sessions, enabling unauthorized file access, network operations, or command injection.

**Vulnerability Rank:** High
**Currently Implemented Mitigations:** None. The debug configuration hardcodes `--allow-all`.
**Missing Mitigations:**
- Remove `--allow-all` from default debug arguments.
- Provide a workspace setting to enforce restricted permissions during debugging.

**Preconditions:**
The VSCode extension is installed, and the workspace uses the default debug configuration.

**Source Code Analysis:**
```typescript
// client/src/debug_config_provider.ts
runtimeArgs: ["run", ...this.#getAdditionalRuntimeArgs(), ...this.#getInspectArg(), "--allow-all"]
```
The debug configuration explicitly includes `--allow-all`, bypassing Deno's permission prompts.

**Security Test Case:**
1. Create a debug configuration file (`.vscode/launch.json`) with a script that writes to `/tmp/debug_exploit.txt` using `Deno.writeTextFile`.
2. Start a debug session. Observe that the file is created without permission prompts, confirming unrestricted access.
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "deno",
      "request": "launch",
      "name": "Debug",
      "program": "./test.ts",
      "args": ["--allow-write"]
    }
  ]
}
```
```typescript
// test.ts
Deno.writeTextFile("/tmp/debug_exploit.txt", "Exploit via debug");
```
3. Verify the file exists after debugging.
