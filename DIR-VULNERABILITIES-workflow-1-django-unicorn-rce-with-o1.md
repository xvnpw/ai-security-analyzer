Here is the combined list of vulnerabilities, formatted as markdown:

### Combined Vulnerability List

This list combines vulnerabilities from the provided lists, removing any duplicates and formatting each vulnerability with detailed descriptions, impact assessments, mitigation strategies, source code analysis, and security test cases.

#### Vulnerability 1: Remote Code Execution via Python Code Injection in Action Arguments

- **Description:**
    1. The `django-unicorn` framework uses `ast.literal_eval` and custom type casting to parse arguments passed to component actions from the template.
    2. The `eval_value` function in `django_unicorn/django_unicorn/call_method_parser.py` first attempts to use `ast.literal_eval` to safely evaluate string values into Python primitives.
    3. If `ast.literal_eval` fails (e.g., due to syntax errors or disallowed constructs), the `eval_value` function falls back to a custom type casting mechanism (`_cast_value`).
    4. The `_cast_value` function iterates through `CASTERS` defined in `django_unicorn/django_unicorn/typer.py`.
    5. `CASTERS` includes a type casting for booleans (`bool: _parse_bool`). The `_parse_bool` function naively checks if the input string starts with "True" (case-sensitive) and returns `True` if it does, otherwise `False`.
    6. **Vulnerability:** An attacker can bypass the security of `ast.literal_eval` by crafting a malicious string argument that causes `ast.literal_eval` to fail but still passes the prefix check in `_parse_bool`. For example, a string like `"True.__import__('os').system('malicious_command')"` will cause `ast.literal_eval` to raise a `SyntaxError`. The control flow will then proceed to `_cast_value`, and `_parse_bool` will incorrectly identify the string as a boolean-like value because it starts with "True". This bypasses the intended input sanitization.
    7. Although `_parse_bool` itself does not directly execute the malicious code, it allows the crafted string to be passed to the component's action method without proper sanitization. If the action method then processes this argument in an unsafe manner (e.g., using `eval()` or other vulnerable functions), it can lead to Remote Code Execution.
- **Impact:**
    - Remote Code Execution (RCE) on the server.
    - An attacker could execute arbitrary Python code on the server by crafting malicious action arguments.
    - This could lead to full application and server compromise, including data theft, data manipulation, and denial of service.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - The framework uses `ast.literal_eval` as the first line of defense to parse action arguments, which is intended to prevent arbitrary code execution by only allowing safe literal Python expressions.
    - Type casting is implemented for specific types like datetime, date, time, timedelta, and UUID to handle common data types.
- **Missing Mitigations:**
    - **Robust Input Sanitization and Validation:** Implement comprehensive input sanitization and validation for all action arguments, especially when custom type casting is involved. This should go beyond simple prefix checks and ensure that arguments conform to expected formats and do not contain potentially malicious code.
    - **Secure Boolean Parsing:**  The `_parse_bool` function needs to be hardened. Instead of just checking for the "True" prefix, it should perform a strict comparison against "True" or "False" only and reject any other input for boolean type casting.
    - **Removal or Secure Design of Custom Type Casting Fallback:** Re-evaluate the necessity of the custom type casting fallback. If it's essential, it must be redesigned to be secure. Consider using safer parsing methods or strictly limiting the types of values that can be cast and how they are processed.
    - **Sandboxing or Secure Evaluation:** If dynamic evaluation of arguments is absolutely required, employ sandboxing or other secure evaluation techniques to limit the impact of potentially malicious code. However, it's generally recommended to avoid dynamic evaluation of user-provided input if possible.
- **Preconditions:**
    - The application must be using `django-unicorn` and have components with actions that accept arguments.
    - An attacker needs to be able to send crafted requests to trigger these actions with malicious arguments.
- **Source Code Analysis:**
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

- **Security Test Case:**
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

#### Vulnerability 2: Insecure Deserialization Leading to Remote Code Execution

- **Description:**
    1. The application uses Python’s `pickle` to store and retrieve full component objects in the Django cache (`cache_full_tree` and `restore_from_cache`).
    2. A component receives a short 8-character string (from `shortuuid.uuid()[:8]`) as its unique ID.
    3. An attacker can guess or brute-force this component ID due to the limited space of an 8-character short UUID.
    4. By injecting a malicious `pickle` payload at the key `unicorn:component:<guessed-id>` in the Django cache (for instance, in a misconfigured or publicly accessible Redis/Memcache server), the attacker can coerce the application to call `pickle.loads` on untrusted data during `restore_from_cache`.
    5. This untrusted deserialization allows the attacker to execute arbitrary Python code once the legitimate user triggers that same component ID.
- **Impact:**
    - Complete Remote Code Execution (RCE). An attacker can run arbitrary commands or Python code with the permissions of the Django application process.
- **Vulnerability Rank:** Critical
- **Currently Implemented Mitigations:**
    - None. Though the code tries to cache only valid component objects, there is no signature check or secure alternative to `pickle.loads`.
- **Missing Mitigations:**
    1. Use a cryptographically strong, non-conflicting component ID or require secure random tokens that cannot be easily guessed.
    2. Store a secure HMAC or signature in the cache to verify data integrity before unpickling.
    3. Replace `pickle` with a safe serialization method (e.g., JSON without objects, or a specialized safe library).
    4. Restrict or authenticate access to the cache so that untrusted users cannot write arbitrary data to these keys.
- **Preconditions:**
    - Attacker can brute-force or guess the short 8-character component ID.
    - Attacker can place a malicious payload in the Django cache at the corresponding `unicorn:component:<component-id>` key.
- **Source Code Analysis:**
    1. `django_unicorn\cacher.py` defines `cache_full_tree()` and `restore_from_cache()`.
    2. `restore_from_cache()` calls `pickle.loads(cached_data)` directly. No verification or cryptographic check is done.
    3. `component_id` is generated in `unicorn\templatetags\unicorn.py` or in `UnicornView.as_view`, where `shortuuid.uuid()[:8]` is used, creating a small keyspace.
    4. The combination of short ID + unguarded unpickling can lead to RCE.
- **Security Test Case:**
    1. Deploy a Redis/Memcache server that is accessible to the attacker or intercept the application’s cache store.
    2. Pick an 8-character random string that is likely to appear as a component ID (e.g., “abcxyz12”).
    3. Generate a malicious pickle payload locally (e.g., using `pickle` plus a custom `__reduce__` method).
    4. Insert that serialized pickle under the key `unicorn:component:abcxyz12` (or whichever ID the attacker wants to target) into the cache.
    5. In a browser or script, load the page that references the same component ID (for example, by forcing or reusing a guessed link, or by forging the component’s ID in a request).
    6. Observe that the Django process unpickles the attacker’s data, allowing arbitrary code execution.

#### Vulnerability 3: Class Pollution via Unrestricted Property Setting

- **Description:**
    1. The component’s code allows external user input to update Python object attributes through methods like `_set_property()`.
    2. The logic in `_set_property()` calls `setattr(self, name, value)` directly without verifying that the attribute is truly safe to set.
    3. A malicious user can craft calls that set special or internal attributes (e.g. `__class__`, `parent`, `_someprivate`, or similar) because no strict check is enforced.
    4. This can lead to “class pollution,” letting an attacker manipulate the Python object’s structure or force the component into unexpected states.
    5. In extreme scenarios, it can escalate to code execution if the attacker manages to reassign critical class-level references or break out of normal attribute usage.
- **Impact:**
    - High severity. Attackers may overwrite internal references, bypass certain validations, or disrupt logic by rewriting component fields. While it may require additional environment details to push it to code execution, the foundation for hijacking the Python class is present.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The code has `_is_public(name)` checks, but those primarily prevent display of attributes in the template context, not setting them from user-supplied data.
    - No direct block exists in `_set_property` to reject private or magic attribute names.
- **Missing Mitigations:**
    1. Enforce an allowlist for which properties can be updated (only recognized public fields).
    2. Reject or ignore property names starting with `_` or containing `__` to prevent Python internals from being overwritten.
    3. Validate that the attribute matches known fields so that no unapproved mutation can occur.
- **Preconditions:**
    - Attacker can author or tamper with requests that set or update component field names, either via crafted JavaScript calls or template parameters.
    - The application exposes these components publicly with no attribute-level checks.
- **Source Code Analysis:**
    1. `unicorn_view.py`, especially the `_set_property()` method, sets arbitrary attributes:
       ```python
       setattr(self, name, value)
       ```
    2. `_is_public()` only excludes private attributes from being *serialized*, but does not prevent a malicious user from naming or updating them.
    3. This can be exploited to manipulate internal fields, e.g., `__class__` or reference to `parent`, possibly chaining with other logic for deeper compromise.
- **Security Test Case:**
    1. Set up or intercept a request that updates a field in the component (e.g., JSON or form data which is ultimately used by `_set_property`).
    2. Inject an attribute name like `__class__` or `_secret_field` or `parent.force_render`.
    3. Confirm that the server’s `_set_property()` method processes and stores the new attribute or overwrites a critical internal attribute with no error.
    4. Observe unexpected changes in the object’s behavior (e.g., hooking new references, toggling internal flags, or corrupting the parent relationship).

#### Vulnerability 4: Class Pollution via Custom Type Instantiation

- **Description:**
    1. An attacker can trigger a component action that accepts a custom class as an argument with a type hint.
    2. The attacker crafts a malicious request, providing a JSON payload for the custom class argument that is designed to exploit the class's constructor.
    3. Django-unicorn's `cast_value` function in `typer.py` attempts to instantiate the custom class using the provided JSON data as keyword arguments to the constructor: `value = _type_hint(**value)`.
    4. If the custom class constructor (`__init__` method) is vulnerable to class pollution, for example by directly setting attributes based on the input without sanitization, the attacker can pollute the class or its instances.
- **Impact:**
    - High
    - Class Pollution. An attacker may be able to modify the attributes of the custom class, potentially affecting other parts of the application that use this class. In some scenarios, depending on the custom class implementation, this could potentially lead to Remote Code Execution if class pollution can be leveraged to modify critical application behavior.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - None. The code attempts to instantiate custom classes directly from user-provided data without sanitization in `django_unicorn\typer.py` in the `cast_value` function.
- **Missing Mitigations:**
    - Input validation and sanitization for custom class constructor arguments.
    - Restrict instantiation of arbitrary custom classes based on user input.
    - Documentation warning to developers about the security risks of using custom classes as action arguments, especially regarding constructor security.
- **Preconditions:**
    - The application must use a Unicorn component with an action method that accepts a custom class as an argument with a type hint.
    - The custom class constructor must be vulnerable to class pollution if provided with malicious input.
- **Source Code Analysis:**
    1. File: `django_unicorn\typer.py`
    2. Function: `cast_value(type_hint, value)`
    3. Code snippet:
       ```python
       if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
           value = _type_hint(**value)
           break
       else:
           value = _type_hint(value)
           break
       ```
    4. Visualization:
       ```
       [External Request] --> [Unicorn Component Action] --> cast_value(type_hint, value)
                                                                  |
                                                                  V
                                                        [Custom Class Instantiation] _type_hint(**value) or _type_hint(value)
                                                                  |
                                                                  V
                                                         [Class Pollution if constructor is vulnerable]
       ```
    5. Step-by-step explanation:
        - When a Unicorn component action is triggered with arguments, the `cast_value` function is called to convert the string representation of arguments to their Python types based on type hints.
        - If the type hint is a custom class (including Pydantic models and dataclasses), `cast_value` attempts to instantiate this class.
        - For Pydantic models and dataclasses, it uses keyword arguments (`**value`). For other custom classes, it uses positional arguments (if applicable).
        - The `value` dictionary here comes directly from the deserialized JSON payload from the client request.
        - If a custom class constructor is not carefully implemented and directly sets attributes from the input dictionary without validation or sanitization, a malicious user can craft a JSON payload to include unexpected keys. These keys might correspond to class attributes or methods, leading to class pollution when the class is instantiated.
- **Security Test Case:**
    1. Create a Django application with a Unicorn component.
    2. Define a custom class `PollutedClass` with a vulnerable constructor in `components/polluted_component.py`:
       ```python
       class PollutedClass:
           def __init__(self, value, polluted_attribute=None):
               self.value = value
               if polluted_attribute:
                   PollutedClass.polluted_attribute = polluted_attribute  # Class pollution vulnerability

           polluted_attribute = "original_value" # Class attribute to pollute

       from django_unicorn.components import UnicornView

       class PollutedView(UnicornView):
           def take_polluted_class(self, obj: PollutedClass):
               print(f"PollutedClass.polluted_attribute before: {PollutedClass.polluted_attribute}")
               print(f"obj.value: {obj.value}")
               print(f"PollutedClass.polluted_attribute after: {PollutedClass.polluted_attribute}")
               self.call("js_alert", PollutedClass.polluted_attribute) # Call JS alert to show polluted value

           def render(self): # Dummy render method to avoid errors
               return super().render()
       ```
    3. Create a template `unicorn/polluted-component.html`:
       ```html
       <div>
           <button unicorn:click="take_polluted_class({'value': 'test', 'polluted_attribute': 'malicious_value'})">Trigger Pollution</button>
       </div>
       ```
    4. Create a view and include the component in a template.
    5. Run the Django application.
    6. Open the page with the Unicorn component in a browser.
    7. Open browser developer tools to observe JavaScript alerts and console output.
    8. Click the "Trigger Pollution" button.
    9. Observe in the browser's console and the JavaScript alert that `PollutedClass.polluted_attribute` has been changed to `'malicious_value'`, demonstrating class pollution.
