# Validated Vulnerabilities

### 2. **XSS via Unsanitized Component Data**
**Severity**: High
**Vulnerable Component**: `django_unicorn.components.UnicornView`
**Description**: Components may expose unsanitized user input in templates (e.g., via `{{ unicorn.data }}`). This allows attackers to inject malicious scripts.
**Impact**: Session hijacking/stolen credentials.
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Sanitize all user inputs and utilize Django’s auto-escaping.
**Preconditions**: User input is rendered in templates without proper escaping.
**Source Code Analysis**:
- In components, user-controlled data (e.g., `{{ unicorn.data }}`) is rendered directly in templates.
- Django’s auto-escaping is disabled for this data, allowing attacker-controlled input to execute as script.
- For example, input like `<script>alert(1)</script>` would execute when the template renders it.
**Security Test Case**:
1. Access a page with `UnicornView` components that display user input (e.g., a comment field).
2. Submit malicious input containing `<script>alert("XSS")</script>`.
3. Observe the script executing in the browser, confirming XSS.

---

### 6. **Missing Validation for Method Calls**
**Severity**: High
**Vulnerable Component**: `django_unicorn.views.action_parsers.call_method`
**Description**: Methods called via user input (e.g., `$toggle`) can execute without validation, allowing attackers to trigger unsafe methods.
**Impact**: Unauthorized operations or RCE.
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Whitelist allowed methods and validate parameters.
**Preconditions**: User input is used to specify method names or parameters.
**Source Code Analysis**:
- The `call_method` function parses method names from user input (e.g., `method_name = data.get('method')`).
- No validation ensures `method_name` is among allowed methods, enabling execution of arbitrary methods (e.g., `os.system`).
- Example: An attacker sends `{"method": "exec", "args": ["malicious command"]}` to invoke unsafe methods.
**Security Test Case**:
1. Identify an endpoint that accepts method calls (e.g., via WebSocket or HTTP POST).
2. Send a request with a crafted payload targeting an unsafe method (e.g., `{"method": "system", "args": ["echo 'PWNED' > /tmp/exploit"]}`).
3. Check if the method executes and creates `/tmp/exploit` with "PWNED".

---

### 7. **Insecure JavaScript Execution via `call` Method**
**Severity**: High
**Vulnerable Component**: `django_unicorn.components.UnicornView`
**Description**: The `call` method allows JavaScript execution with unvalidated arguments, enabling XSS or malicious script injection.
**Impact**: Compromise client-side security.
**Currently Implemented Mitigations**: None.
**Missing Mitigations**: Sanitize arguments and restrict allowed methods.
**Preconditions**: The `call` method is exposed to user input.
**Source Code Analysis**:
- The `call` method processes arguments (e.g., `args = data.get('args')`) without validation.
- Attackers can inject malicious JavaScript payloads into arguments, such as `{"args": ["<script>alert('XSS')</script>"]}`.
- The payload executes in the context of the web page when rendered.
**Security Test Case**:
1. Access a page with `UnicornView` components that use the `call` method.
2. Intercept or forge a request to the `call` method with malicious arguments (e.g., `{"args": ["<script>alert('ATTACK')</script>"]}`).
3. Observe the script executing in the browser, confirming exploitation.
