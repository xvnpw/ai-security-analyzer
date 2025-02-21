### Vulnerability List

- Vulnerability Name: Unsafe arbitrary Python code execution via crafted action arguments

- Description:
    1. An attacker can craft a malicious `call_method_name` payload in the AJAX request to the `/unicorn/message` endpoint.
    2. The `parse_call_method_name` function in `django_unicorn/call_method_parser.py` uses `ast.parse` and `eval_value` with `ast.literal_eval` to parse arguments for component methods.
    3. Although `ast.literal_eval` is intended to be safe for evaluating literal expressions, the `eval_value` function also includes `_cast_value` which iterates through `CASTERS`.
    4. If a type hint in a component method action uses a custom class without proper sanitization, or if there's a vulnerability in one of the default `CASTERS`, it could lead to unsafe deserialization and potentially arbitrary code execution.
    5. By manipulating the arguments passed to a component method through `unicorn:click` or similar attributes, an attacker might be able to inject and execute arbitrary Python code on the server.

- Impact:
    - Critical: Successful exploitation allows for arbitrary Python code execution on the server hosting the Django application. This could lead to complete server compromise, data breach, and other severe security incidents.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - The project uses `ast.literal_eval` which is intended to safely evaluate literal Python expressions, as a primary parsing mechanism for action arguments.
    - Type casting is applied using `CASTERS` to coerce arguments to expected types.

- Missing Mitigations:
    - Lack of robust input validation and sanitization for arguments passed to component methods, especially when custom classes or complex types are used as type hints.
    - Insufficient restrictions on the types of objects that can be deserialized or instantiated through action arguments.
    - No sandboxing or isolation for the execution of component methods to limit the impact of potential code injection.

- Preconditions:
    - The application must be using `django-unicorn` and have publicly accessible components with methods that accept arguments, especially those with complex type hints or custom classes.
    - The attacker needs to be able to send AJAX requests to the `/unicorn/message` endpoint, which is the default behavior for `django-unicorn` applications.

- Source Code Analysis:
    1. **`django_unicorn/call_method_parser.py` - `parse_call_method_name` function:**
        ```python
        tree = ast.parse(method_name, "eval")
        statement = tree.body[0].value #type: ignore

        if tree.body and isinstance(statement, ast.Call):
            call = tree.body[0].value # type: ignore
            method_name = call.func.id
            args = [eval_value(arg) for arg in call.args] # [!] Potential vulnerability: eval_value is called on arguments
            kwargs = {kw.arg: eval_value(kw.value) for kw.value in call.keywords} # [!] Potential vulnerability: eval_value is called on keyword arguments
        ```
        This code snippet shows that arguments and keyword arguments are passed to `eval_value` for processing. The `ast.parse(method_name, "eval")` parses the method name string as a Python expression in 'eval' mode. If the `method_name` string is maliciously crafted, it can lead to the execution of unintended code during the parsing stage.

    2. **`django_unicorn/call_method_parser.py` - `eval_value` function:**
        ```python
        @lru_cache(maxsize=128, typed=True)
        def eval_value(value):
            """
            Uses `ast.literal_eval` to parse strings into an appropriate Python primitive.

            Also returns an appropriate object for strings that look like they represent datetime,
            date, time, duration, or UUID.
            """

            try:
                value = ast.literal_eval(value) # [!] Safe literal evaluation, but _cast_value follows
            except SyntaxError:
                value = _cast_value(value) # [!] _cast_value introduces more complex casting

            return value
        ```
        `eval_value` first uses `ast.literal_eval` which is generally safe for evaluating literal Python expressions, preventing the execution of arbitrary code in most cases. However, in case of a `SyntaxError` during `ast.literal_eval`, the code falls back to `_cast_value`. This fallback mechanism is intended to handle non-literal values, but it expands the scope of evaluation beyond safe literals.

    3. **`django_unicorn/call_method_parser.py` - `_cast_value` function:**
        ```python
        def _cast_value(value):
            """
            Try to cast a value based on a list of casters.
            """

            for caster in CASTERS.values(): # [!] Iterates through CASTERS
                try:
                    casted_value = caster(value) # [!] Calls each caster function

                    if casted_value:
                        value = casted_value
                        break
                except ValueError:
                    pass

            return value
        ```
        `_cast_value` iterates through the `CASTERS` dictionary and attempts to cast the input `value` using each caster function. The `CASTERS` dictionary, defined in `django_unicorn/typer.py`, determines which casting functions are used. If a malicious user can introduce a crafted string that bypasses `ast.literal_eval` (resulting in a `SyntaxError`) and is then processed by a vulnerable or improperly sanitized caster function in `CASTERS`, it could lead to arbitrary code execution. Even seemingly safe casters, if they have unexpected behavior or vulnerabilities, could be exploited. Furthermore, if custom casters are added in user projects without sufficient security considerations, they could easily become attack vectors.

    4. **`django_unicorn/typer.py` - `CASTERS` dictionary:**
        ```python
        CASTERS = {
            datetime: parse_datetime,
            time: parse_time,
            date: parse_date,
            timedelta: parse_duration,
            UUID: UUID,
            bool: _parse_bool,
        }
        ```
        The default `CASTERS` dictionary includes casting functions for standard Python types and Django utilities. While these default casters might be considered relatively safe, potential vulnerabilities could still exist within their implementation or in how they handle specific inputs. Moreover, the extensibility of `CASTERS` poses a risk. If developers are allowed or encouraged to add custom casting functions (e.g., for custom data types in their application), and if these custom casters are not carefully vetted for security, they could introduce significant vulnerabilities, including arbitrary code execution if a caster is designed or inadvertently allows for unsafe operations when processing attacker-controlled strings.

    **Visualization:**

    ```mermaid
    graph LR
        A[AJAX Request to /unicorn/message] --> B(parse_call_method_name);
        B --> C{ast.parse};
        C -- Success --> D{eval_value (arguments)};
        C -- SyntaxError --> E{_cast_value (arguments)};
        D --> F[Method Call];
        E --> F;
        F --> G[Component Action];
    ```

- Security Test Case:
    1. **Identify a component with an action method that takes arguments.** For example, consider a component with a method like `receive_string(self, input_string: str)`.
    2. **Craft a malicious payload for `call_method_name` argument in the AJAX request.** The goal is to bypass `ast.literal_eval` and trigger `_cast_value` to execute arbitrary code. Try to construct a payload that results in a `SyntaxError` in `ast.literal_eval` but is still processed by `_cast_value`. For instance, if a method expects a string argument, try to pass a string that, when processed by a hypothetical malicious custom caster or an exploited default caster, would execute code. For example, assuming a vulnerable caster exists that processes a string like `'os.system("reboot")'` try crafting `call_method_name` as `receive_string('os.system("reboot")')`.
    3. **Send an AJAX POST request to `/unicorn/message`** with the crafted payload. Include necessary data like `component_name`, `component_id`, and the malicious `call_method_name`. For example:

        ```json
        {
          "component_name": "test-component",
          "component_id": "test-id",
          "call_method_name": "receive_string('__import__(\\'os\\').system(\\'touch /tmp/unicorn_pwned\\')')",
          "data": {},
          "checksum": "...",
          "epoch": 1678886400,
          "action_queue": []
        }
        ```
    4. **Monitor the server logs and application behavior.** Check if the injected code was executed. In this example, check if the file `/tmp/unicorn_pwned` was created on the server.
    5. **Verify successful code execution.** If the server-side action results in the execution of the injected code (e.g., file creation, shell command execution, reverse shell), the vulnerability is confirmed. Check for the creation of `/tmp/unicorn_pwned` to confirm the exploit.
