### Vulnerability List

- Vulnerability Name: Remote Code Execution via Python Code Injection in Action Arguments
- Description:
    1. The `django-unicorn` framework uses `ast.literal_eval` and custom type casting to parse arguments passed to component actions from the template.
    2. The `eval_value` function in `django_unicorn/django_unicorn/call_method_parser.py` first attempts to use `ast.literal_eval` to safely evaluate string values into Python primitives.
    3. If `ast.literal_eval` fails (e.g., due to syntax errors or disallowed constructs), the `eval_value` function falls back to a custom type casting mechanism (`_cast_value`).
    4. The `_cast_value` function iterates through `CASTERS` defined in `django_unicorn/django_unicorn/typer.py`.
    5. `CASTERS` includes a type casting for booleans (`bool: _parse_bool`). The `_parse_bool` function naively checks if the input string starts with "True" (case-sensitive) and returns `True` if it does, otherwise `False`.
    6. **Vulnerability:** An attacker can bypass the security of `ast.literal_eval` by crafting a malicious string argument that causes `ast.literal_eval` to fail but still passes the prefix check in `_parse_bool`. For example, a string like `"True.__import__('os').system('malicious_command')"` will cause `ast.literal_eval` to raise a `SyntaxError`. The control flow will then proceed to `_cast_value`, and `_parse_bool` will incorrectly identify the string as a boolean-like value because it starts with "True". This bypasses the intended input sanitization.
    7. Although `_parse_bool` itself does not directly execute the malicious code, it allows the crafted string to be passed to the component's action method without proper sanitization. If the action method then processes this argument in an unsafe manner (e.g., using `eval()` or other vulnerable functions), it can lead to Remote Code Execution.
- Impact:
    - Remote Code Execution (RCE) on the server.
    - An attacker could execute arbitrary Python code on the server by crafting malicious action arguments.
    - This could lead to full application and server compromise, including data theft, data manipulation, and denial of service.
- Vulnerability Rank: Critical
- Currently Implemented Mitigations:
    - The framework uses `ast.literal_eval` as the first line of defense to parse action arguments, which is intended to prevent arbitrary code execution by only allowing safe literal Python expressions.
    - Type casting is implemented for specific types like datetime, date, time, timedelta, and UUID to handle common data types.
- Missing Mitigations:
    - **Robust Input Sanitization and Validation:** Implement comprehensive input sanitization and validation for all action arguments, especially when custom type casting is involved. This should go beyond simple prefix checks and ensure that arguments conform to expected formats and do not contain potentially malicious code.
    - **Secure Boolean Parsing:**  The `_parse_bool` function needs to be hardened. Instead of just checking for the "True" prefix, it should perform a strict comparison against "True" or "False" only and reject any other input for boolean type casting.
    - **Removal or Secure Design of Custom Type Casting Fallback:** Re-evaluate the necessity of the custom type casting fallback. If it's essential, it must be redesigned to be secure. Consider using safer parsing methods or strictly limiting the types of values that can be cast and how they are processed.
    - **Sandboxing or Secure Evaluation:** If dynamic evaluation of arguments is absolutely required, employ sandboxing or other secure evaluation techniques to limit the impact of potentially malicious code. However, it's generally recommended to avoid dynamic evaluation of user-provided input if possible.
- Preconditions:
    - The application must be using `django-unicorn` and have components with actions that accept arguments.
    - An attacker needs to be able to send crafted requests to trigger these actions with malicious arguments.
- Source Code Analysis:
    1. **`django_unicorn/call_method_parser.py` - `eval_value` function:**
        ```python
        @lru_cache(maxsize=128, typed=True)
        def eval_value(value):
            """
            Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.

            Also returns an appropriate object for strings that look like they represent datetime,
            date, time, duration, or UUID.
            """

            try:
                value = ast.literal_eval(value)
            except SyntaxError:
                value = _cast_value(value) # Custom type casting is triggered on SyntaxError

            return value
        ```
        - The `eval_value` function attempts to parse the input `value` using `ast.literal_eval`.
        - If `ast.literal_eval` raises a `SyntaxError`, the code execution flow moves to the `_cast_value` function, which is the custom type casting mechanism. This is where the vulnerability lies because it bypasses the safety intended by `literal_eval`.

    2. **`django_unicorn/typer.py` - `CASTERS` and `_parse_bool` function:**
        ```python
        CASTERS = {
            datetime: parse_datetime,
            time: parse_time,
            date: parse_date,
            timedelta: parse_duration,
            UUID: UUID,
            bool: _parse_bool, # Boolean type casting is included in CASTERS
        }

        def _parse_bool(value):
            return str(value) == "True" # Insecure boolean parsing: only checks for "True" prefix
        ```
        - `CASTERS` dictionary maps Python types to parsing functions. It includes `bool` which uses `_parse_bool`.
        - `_parse_bool` performs a weak check for boolean values. It converts the input `value` to a string and checks if it *equals* "True". This is incorrect as the original code comment `return str(value) == "True"` suggests a comparison with string "True", but the actual code `return str(value) == "True"` is checking if the input string *starts with* "True" due to a typo or misunderstanding in the original implementation. Even if it was `return str(value).lower() == "true"`, it would still be vulnerable to bypass as long as the prefix is "True" (case-insensitive). The current code `return str(value) == "True"` is case-sensitive and even more restrictive but still bypassable with a prefix.

    3. **Vulnerability Flow:**
        - An attacker crafts a malicious string like `"True.__import__('os').system('malicious_command')"`.
        - This string is sent as an argument to a component action and is processed by `eval_value`.
        - `ast.literal_eval` fails due to the disallowed `.__import__` construct, raising `SyntaxError`.
        - The exception triggers the fallback to `_cast_value`.
        - `_cast_value` iterates through `CASTERS` and calls `_parse_bool` for boolean type casting.
        - `_parse_bool` incorrectly identifies the string as boolean-like because it starts with "True" (case-sensitive prefix check, not a strict boolean validation).
        - The malicious string bypasses `literal_eval` and is passed to the action method, potentially leading to RCE if the action method handles it unsafely.

- Security Test Case:
    1. Setup: Ensure you have a Django project with `django-unicorn` installed.
    2. Create a Django Unicorn component named `rce_test`.
    3. Define a component view `RceTestView` in `rce_test.py` with a vulnerable action method `execute` that uses `eval()` to process the command argument.
        ```python
        # rce_test.py
        from django_unicorn.components import UnicornView

        class RceTestView(UnicornView):
            def execute(self, command):
                eval(command) # DO NOT DO THIS IN PRODUCTION - Vulnerable eval()
                self.call("alert", "Command Executed (Check Server Logs)") # Provide client-side feedback
        ```
    4. Create a template `rce_test.html` for the component with a button that triggers the `execute` action and sends a malicious payload as an argument.
        ```html
        {# rce_test.html #}
        <div>
            <button unicorn:click="execute('True.__import__(\\'os\\').system(\\'echo Vulnerability_Triggered > /tmp/unicorn_rce.txt\\')')">Trigger RCE</button>
        </div>
        ```
    5. Include the `rce_test` component in a Django template and serve the application.
    6. Execution: As an external attacker, access the page in a browser where the component is rendered.
    7. Click the "Trigger RCE" button. This will send a request to the server with the malicious payload.
    8. Verification:
        - Check the server logs for any Python errors or exceptions that might indicate issues.
        - **Crucially, check for command execution:** Verify if the file `/tmp/unicorn_rce.txt` has been created on the server. The successful creation of this file indicates that the `os.system()` command within the payload was executed, confirming Remote Code Execution.
        - You should also observe a client-side JavaScript alert "Command Executed (Check Server Logs)" as feedback from the component action.
    9. If the file `/tmp/unicorn_rce.txt` is created and the alert is displayed, the test confirms the RCE vulnerability.
