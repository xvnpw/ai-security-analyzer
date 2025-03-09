## Vulnerability List for django-unicorn Project

### Vulnerability 1: Potential Command Injection via `eval_value` in `call_method_parser.py`

- Description:
    1. An attacker can craft a malicious `call_method_name` that includes Python code within arguments of a method call.
    2. The `parse_call_method_name` function in `django_unicorn\call_method_parser.py` uses `ast.parse` and `eval_value` to parse the method name and arguments.
    3. The `eval_value` function uses `ast.literal_eval` to evaluate arguments, but falls back to `_cast_value` if `ast.literal_eval` fails due to `SyntaxError`.
    4. If `_cast_value` fails to properly sanitize input, and the input string bypasses `ast.literal_eval` but is still executable Python code, it could be executed.
    5. This could allow an attacker to inject and execute arbitrary Python code on the server when a component action is triggered.

- Impact:
    - Critical. Successful command injection allows the attacker to execute arbitrary Python code on the server. This could lead to complete server compromise, data exfiltration, or denial of service.

- Vulnerability Rank: critical

- Currently implemented mitigations:
    - The project uses `ast.literal_eval` which is designed to safely evaluate literal expressions in strings, which mitigates against direct execution of arbitrary code in many cases.
    - Type casting and validation might be implemented in components themselves, but the framework does not enforce it at this level.

- Missing mitigations:
    - Input sanitization within `_cast_value` to prevent execution of arbitrary code.
    - Strict input validation to ensure arguments passed to component methods are of expected types and formats.
    - Consider moving away from `ast.literal_eval` entirely for user-provided arguments or implement a more robust and secure parsing mechanism.

- Preconditions:
    - The application must be running `django-unicorn`.
    - An attacker needs to be able to trigger a component action and control the arguments passed to that action.

- Source code analysis:
    1. **File:** `django_unicorn\call_method_parser.py`
    2. **Function:** `eval_value(value)`
    ```python
    @lru_cache(maxsize=128, typed=True)
    def eval_value(value):
        """
        Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.

        Also returns an appropriate object for strings that look like they represent datetime,
        date, time, duration, or UUID.
        """

        try:
            value = ast.literal_eval(value) # potential safe eval
        except SyntaxError:
            value = _cast_value(value) # potential unsafe handling if _cast_value is bypassed

        return value
    ```
    3. **Function:** `parse_call_method_name(call_method_name)`
    ```python
    @lru_cache(maxsize=128, typed=True)
    def parse_call_method_name(
        call_method_name: str,
    ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
        ...
        tree = ast.parse(method_name, "eval")
        statement = tree.body[0].value #type: ignore

        if tree.body and isinstance(statement, ast.Call):
            call = tree.body[0].value # type: ignore
            method_name = call.func.id
            args = [eval_value(arg) for arg in call.args] # arguments are evaluated here
            kwargs = {kw.arg: eval_value(kw.value) for kw.keywords}
        ...
    ```
    4. **Vulnerability:** If a carefully crafted string can bypass `ast.literal_eval` (raising `SyntaxError`) but still contain malicious Python code that `_cast_value` does not sanitize, this code could be executed. While `ast.literal_eval` is intended to be safe, vulnerabilities can arise from complex interactions or if the fallback `_cast_value` is not secure enough.

- Security test case:
    1. Create a Django Unicorn component with a method that accepts an argument.
        ```python
        # components/command_injection.py
        from django_unicorn.components import UnicornView

        class CommandInjectionView(UnicornView):
            def execute_command(self, command):
                import os
                os.system(command) # Insecure: for demonstration only. Do not use os.system in production

        ```
        ```html
        <!-- templates/unicorn/command_injection.html -->
        <button unicorn:click="execute_command('ls -l')">Execute Command</button>
        ```
    2. Include this component in a Django template and render it.
    3. In the browser's developer tools, inspect the network requests when the button is clicked.
    4. Modify the request payload (specifically the `callMethodName` parameter) to inject a malicious command. For example, change the payload to:
        ```json
        {"callMethodName": "execute_command('__import__(\\'os\\').system(\\'touch /tmp/pwned\\')')", ...}
        ```
    5. Send the modified request to the server.
    6. **Expected outcome (Vulnerable):** If the vulnerability exists, the command `touch /tmp/pwned` will be executed on the server. Check for the file `/tmp/pwned` on the server to confirm command execution.
    7. **Expected outcome (Mitigated):** If the vulnerability is mitigated, the command will not be executed, and no file `/tmp/pwned` will be created. The server might return an error if input validation is in place.
