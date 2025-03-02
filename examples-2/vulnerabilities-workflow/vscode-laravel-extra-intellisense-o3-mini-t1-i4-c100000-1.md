# Vulnerabilities List

Below is the updated list of vulnerabilities that meet the criteria. These vulnerabilities are of high severity, fall under the classes of Remote Code Execution (RCE), Command Injection, or Code Injection, and are not already mitigated. Each vulnerability can be triggered when a threat actor supplies a malicious repository (for example, via a committed `.vscode/settings.json`) that manipulates configuration values injected into PHP commands.

---

## Vulnerability Name: PHP Code Injection via Unvalidated `modelsPaths` Configuration

**Description:**
The extension’s Eloquent provider builds a PHP code snippet by retrieving the user‑configured array of model search paths (from the `LaravelExtraIntellisense.modelsPaths` setting) and concatenating them directly into a dynamically generated PHP script. In particular, the code:
```php
Helpers.runLaravel(
    "foreach (['" + vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models']).join("', '") + "'] as $modelPath) { … }" +
    " … echo json_encode($output);",
    "Eloquent Attributes and Relations"
)
```
simply joins the values inside single quotes without proper escaping or validation. An attacker who controls the workspace settings could supply a malicious string that—when injected into the PHP code—closes the literal and appends arbitrary PHP code (for example, a call to `system('malicious command')`).

**Impact:**
Arbitrary PHP code execution within the context of the victim’s Laravel project. An attacker can run any PHP code on the target system, potentially leading to full system compromise.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
– There is no escaping, input validation, or sanitization applied to the `modelsPaths` configuration value before it is concatenated into the PHP command.

**Missing Mitigations:**
– Proper escaping of any user‑supplied values when constructing PHP code strings.
– Input validation or whitelisting for acceptable directory names.

**Preconditions:**
– The malicious repository must provide a workspace settings file (or otherwise inject configuration) that assigns a manipulated value for `LaravelExtraIntellisense.modelsPaths`.
– The victim then opens the repository in VSCode with the extension active so that the injection code is executed during the auto‑refresh of model data.

**Source Code Analysis:**
1. In `EloquentProvider.loadModels`, the code obtains the models paths with:
   ```js
   vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<Array<string>>('modelsPaths', ['app', 'app/Models'])
   ```
2. The returned array is then joined with:
   ```js
   "['" + array.join("', '") + "']"
   ```
   and embedded directly into a PHP `foreach` loop without sanitization.
3. Since the string literal in PHP is not escaped, an attacker’s injected closing quote and appended PHP code will be executed when the command is run by `Helpers.runLaravel()`.

**Security Test Case:**
1. In a test Laravel project, create a `.vscode/settings.json` file with a modified configuration:
   ```json
   {
     "LaravelExtraIntellisense.modelsPaths": [
       "app', system('echo vulnerable'); //",
       "app/Models"
     ]
   }
   ```
2. Open the project in VSCode with the Laravel Extra Intellisense extension enabled.
3. Trigger an action that causes the extension to load model information (for example, open a PHP file where model attribute autocompletion is invoked).
4. Examine the PHP output (or logs) to see if the injected command (`system('echo vulnerable')`) is executed, indicating that arbitrary PHP code is running.

---

## Vulnerability Name: PHP Code Injection via Unvalidated `basePathForCode` Configuration

**Description:**
The helper function that builds file paths for use in PHP commands reads the user‑supplied `LaravelExtraIntellisense.basePathForCode` configuration and concatenates it with a given relative path. The code in `Helpers.projectPath` does minimal processing (only removing a trailing slash) and then returns:
```js
basePathForCode + path
```
This value is later embedded (inside single quotes) into PHP commands such as:
```php
require_once '" + Helpers.projectPath("vendor/autoload.php", true) + "';
```
Without proper sanitization or escaping, an attacker can supply a `basePathForCode` value that includes a single quote and additional PHP code. For instance, setting it to:
```
/var/www/html'; system('echo vulnerable'); //
```
will break out of the intended literal and execute the injected command.

**Impact:**
Arbitrary PHP code execution in the context of the Laravel project. This can lead to complete compromise of the victim’s system.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
– Only a basic removal of trailing slashes is applied. No sanitization or escaping has been carried out.

**Missing Mitigations:**
– Proper sanitization and escaping of configuration values used in constructing PHP command strings.
– Validation to ensure that `basePathForCode` contains only a safe, expected directory path.

**Preconditions:**
– The attacker can influence the workspace configuration (for instance, via a committed `.vscode/settings.json`) to set a malicious value for `basePathForCode`.
– The user opens the manipulated repository so that the extension uses the unsafe configuration during command execution.

**Source Code Analysis:**
1. The function `Helpers.projectPath(path: string, forCode: boolean = false)` retrieves the setting via:
   ```js
   let basePathForCode = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('basePathForCode');
   ```
2. It then verifies if the value is nonempty (and, if relative, converts it to an absolute path) but does no further sanitization:
   ```js
   return basePathForCode + path;
   ```
3. When this unsanitized value is concatenated into PHP string literals (e.g., in `require_once`), any injected single quote may break the intended string context, allowing arbitrary PHP code injection.

**Security Test Case:**
1. In a test repository, add a `.vscode/settings.json` file with the following configuration:
   ```json
   {
     "LaravelExtraIntellisense.basePathForCode": "/var/www/html'; system('echo vulnerable'); //"
   }
   ```
2. Open the repository in VSCode with the extension enabled.
3. Trigger a request that causes the extension to run Laravel code (for example, by opening a file that requires autocompletion that uses `runLaravel()`).
4. Monitor the output or logs for evidence (such as the word “vulnerable”) that the injected PHP code has executed.

---

## Vulnerability Name: Command Injection via Misconfigured `phpCommand` Template

**Description:**
The extension uses a configurable template string (the `LaravelExtraIntellisense.phpCommand` setting) to build the command that executes PHP code via the Node.js `cp.exec` function. The default template is:
```
php -r "{code}"
```
However, since the command is obtained directly from the user‑supplied configuration without validation, an attacker can supply a malicious template that appends extra shell commands. For example, by setting:
```
docker exec -w /var/www/your-project -u laradock laradock_workspace_1 php -r "{code}"; echo vulnerable
```
the attacker’s appended command (`echo vulnerable`) will be executed every time the extension calls `runPhp()`.

**Impact:**
This vulnerability results in arbitrary command execution on the target system, which might allow an attacker to run any shell command with the privileges of the user running the code.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
– The extension performs only simple replacements (e.g., replacing `{code}` with the generated PHP code) without any validation or sanitization of the overall command template.

**Missing Mitigations:**
– Validation and sanitization of the `phpCommand` configuration value to ensure it adheres strictly to an expected safe pattern.
– Possibly, using a safer method of building and executing commands that avoids direct substitution into a shell command string.

**Preconditions:**
– The attacker must be able to supply a malicious `.vscode/settings.json` to change the extension’s `phpCommand` setting.
– The victim must open this repository in VSCode with the extension active, causing the malicious command template to be used.

**Source Code Analysis:**
1. In `Helpers.runPhp`, the template is retrieved as follows:
   ```js
   let commandTemplate = vscode.workspace.getConfiguration("LaravelExtraIntellisense").get<string>('phpCommand') ?? "php -r \"{code}\"";
   ```
2. The PHP code (built by the extension) is substituted in for `{code}`:
   ```js
   let command = commandTemplate.replace("{code}", code);
   ```
3. The final `command` is passed to `cp.exec`, meaning any extra commands injected via configuration will be executed by the shell.

**Security Test Case:**
1. In a controlled environment, create a `.vscode/settings.json` file in your Laravel project with the following entry:
   ```json
   {
     "LaravelExtraIntellisense.phpCommand": "php -r \"{code}\"; echo vulnerable"
   }
   ```
2. Open the project in VSCode with the extension installed.
3. Trigger an action that causes the extension to run PHP code (for example, requesting autocompletion that involves a call to `runPhp()`).
4. Check the output channel or terminal for the text “vulnerable” to confirm that the extra shell command was executed.

---
