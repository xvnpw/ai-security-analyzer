### Vulnerability List

*   **Vulnerability Name:** Insecure Deserialization and Server-Side Template Injection via Action Arguments and Property Updates

    *   **Description:**
        1.  A threat actor can craft malicious input from the client-side to be processed by the server in two main ways: by manipulating the arguments passed to a component's methods (actions) and by manipulating the data used to update component properties.
        2.  The `django-unicorn` framework uses `ast.literal_eval` and custom `eval_value` function in `django_unicorn\call_method_parser.py` to deserialize arguments passed from the client to the server when an action is triggered. It also uses `ast.literal_eval` and `set_property_from_data` in `django_unicorn\views\utils.py` to deserialize data for property updates.
        3.  While `ast.literal_eval` is generally considered safe for evaluating literal Python expressions, the custom `eval_value` function, especially combined with `cast_value` in `django_unicorn\typer.py`, and the logic within `set_property_from_data` introduce potential vulnerabilities by attempting to cast values to various types, including custom objects, dataclasses, pydantic models and Django models based on type hints, and by using custom casters defined in `CASTERS`.
        4.  If a component method accepts arguments with type hints or if component properties are type-hinted as custom classes, dataclasses, pydantic models or Django models, and if the deserialization process is not properly secured, an attacker could potentially inject malicious payloads as arguments or property values.
        5.  This could lead to server-side template injection if the injected data is directly rendered in the template without proper sanitization, or insecure deserialization if the injected data can manipulate the application's state or behavior in unintended ways, potentially leading to remote code execution.
        6.  Specifically, if type coercion is not strictly controlled in `cast_value` function and `set_property_from_data`, an attacker might be able to pass strings that, after type coercion, are interpreted in a way that leads to unintended code execution or data access.
        7.  Test files like `test_call_method_parser.py`, `test_call_method_name.py`, `test_type_hints.py` and `test_set_property_from_data.py` confirm that the framework's argument parsing and type coercion mechanism is designed to handle various data types, including custom classes, dataclasses, and models, based on type hints, reinforcing the attack surface in both action arguments and property updates.

    *   **Impact:**
        *   **High:** Successful exploitation could lead to Server-Side Template Injection (SSTI), allowing an attacker to execute arbitrary code on the server, read sensitive data, or modify application data. Insecure deserialization vulnerabilities can also lead to Remote Code Execution (RCE) or data corruption depending on the application logic and how deserialized objects are used.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        *   The framework uses Django's CSRF protection to prevent cross-site request forgery attacks, which mitigates some aspects of unauthorized action triggering and property updates.
        *   HTML encoding is applied to responses to prevent XSS, as mentioned in `docs\source\changelog.md` for version 0.36.0. This might mitigate the impact of SSTI if the vulnerability is purely about injecting into the HTML context, however, SSTI can occur in other contexts like JavaScript or CSS.

    *   **Missing Mitigations:**
        *   Input validation and sanitization are missing for action arguments and component property updates, especially for arguments or properties that are type-hinted as custom classes, dataclasses, pydantic models or Django models.
        *   There's no explicit control over which classes, dataclasses, pydantic models or models can be instantiated or accessed through action arguments or property updates, creating a potential for abuse.
        *   Lack of server-side sanitization of data before rendering in templates increases the risk of SSTI.
        *   No restrictions on instantiation of arbitrary classes through type hinting in action arguments or component properties.

    *   **Preconditions:**
        *   The application must use components with methods that accept arguments with type hints, particularly custom classes, dataclasses, pydantic models or Django models, OR the application must have component properties type-hinted as custom classes, dataclasses, pydantic models or Django models and allow client-side updates of these properties (e.g., using `wire:model`).
        *   The application must render user-controlled data in templates without proper output encoding in all contexts (HTML, JavaScript, CSS, URL).

    *   **Source Code Analysis:**
        1.  **File: `django_unicorn\call_method_parser.py`**
            *   The `eval_value` function is the entry point for argument parsing in action calls. It's called by `parse_kwarg` and `parse_call_method_name`.
            *   `eval_value` first uses `ast.literal_eval` to parse the string value. This is intended for safe literal evaluation.
            *   Then, `_cast_value` (from `django_unicorn\typer.py`) is called to perform type coercion based on `CASTERS` and type hints.
            *   `CASTERS` are defined as `CASTERS = [UUID, bool, datetime, time, date, timedelta]`. These are relatively safe built-in types.
            *   The vulnerability lies in the type hinting and the `cast_value` function in `django_unicorn\typer.py` which allows instantiation of arbitrary classes based on type hints.

            ```python
            # File: django_unicorn\call_method_parser.py
            def eval_value(value: str) -> Any:
                try:
                    value = ast.literal_eval(value)
                except (ValueError, SyntaxError):
                    pass

                return _cast_value(value)
            ```

        2.  **File: `django_unicorn\typer.py`**
            *   The `cast_value` function is responsible for type coercion based on type hints, and is used both for action arguments and property updates.
            *   It iterates through `type_hints` provided for the argument or property.
            *   For each `_type_hint` in `type_hints`, it checks if it's in `CASTERS` or a list/union of casters and applies casting if found.
            *   If `_type_hint` is not in `CASTERS`, the code attempts to instantiate the type hint class directly:
                ```python
                if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
                    value = _type_hint(**value) # Potential insecure deserialization for pydantic/dataclasses
                    break

                value = _type_hint(value) # Potential insecure deserialization for custom classes
                break
                ```
            *   If `_type_hint` is a pydantic model or dataclass, it attempts to instantiate it with keyword arguments from `value` (which is client-provided data). This can lead to insecure deserialization if the class constructor performs unsafe operations based on the input.
            *   If `_type_hint` is any other class (including Django models), it attempts to instantiate it directly with `value` as the first argument. This is extremely dangerous as it allows instantiation of arbitrary classes controlled by the attacker, given a suitable type hint is used in the component method definition or property.

            ```python
            # File: django_unicorn\typer.py
            def cast_value(type_hint, value):
                ...
                for _type_hint in type_hints:
                    ...
                    else:
                        if issubclass(_type_hint, Model):
                            continue # Model creation is skipped here, but handled elsewhere.

                        if _check_pydantic(_type_hint) or is_dataclass(_type_hint):
                            value = _type_hint(**value) # Potential insecure deserialization for pydantic/dataclasses
                            break

                        value = _type_hint(value) # Potential insecure deserialization for custom classes
                        break
                return value
            ```
        3.  **File: `django_unicorn\views\utils.py`**
            *   The `set_property_from_data` function is used to update component properties based on data from the client, for example, when using `wire:model`.
            *   It retrieves the property from the component and its type hint.
            *   It calls `cast_value` to coerce the client-provided data to the hinted type.
            *   The coerced value is then set as the component property:
                ```python
                setattr(component, name, cast_value(type_hint, value))
                ```
            *   This flow shows that component properties are also vulnerable to insecure deserialization through type coercion, similar to action arguments.

            ```python
            # File: django_unicorn\views\utils.py
            def set_property_from_data(component: UnicornView, name: str, value: Any):
                ...
                if type_hint := component.__get_type_hints__().get(name):
                    setattr(component, name, cast_value(type_hint, value))
                else:
                    setattr(component, name, value)

            ```

        4.  **File: `django_unicorn\views\action_parsers\call_method.py`**
            *   The `_call_method_name` function retrieves the method from the component and its type hints.
            *   It then iterates through the arguments of the method and calls `cast_value` to coerce the arguments to the hinted types.
            *   The coerced arguments are then used to call the component method:
                ```python
                return func(*parsed_args, **parsed_kwargs)
                ```
            *   This flow demonstrates how client-provided data is deserialized and used to call methods on the server-side component, highlighting the insecure deserialization vulnerability for action calls.

        5.  **File: `django_unicorn\tests\views\action_parsers\call_method\test_call_method_name.py`, `django_unicorn\tests\views\message\test_type_hints.py` and `django_unicorn\tests\views\utils\test_set_property_from_data.py`**
            *   These test files contain test cases that implicitly validate the described code flows and the use of type hints for argument and property parsing, including tests for custom classes, dataclasses, and models, further highlighting the potential attack surface for both action arguments and property updates. Specifically, `test_set_property_from_data.py` tests the `set_property_from_data` function and demonstrates how different types of properties are handled, including models and lists, and how data from client can update these properties.

    *   **Security Test Case:**
        1.  **Action Argument Vulnerability Test:** (Same as before, verifying action argument vulnerability)
            1.  Create a Django Unicorn component named `vuln_test` in `example/unicorn/components/vuln_test.py`.
            2.  Define a custom class `MaliciousClass` in `example/unicorn/components/vuln_test.py` with `__init__` that executes system commands or performs other malicious actions (for testing purposes, a simple print statement is sufficient to confirm execution).
            3.  In `VulnTestView` component, define a method `trigger_vuln(self, malicious_arg: MaliciousClass)` that takes an argument type-hinted as `MaliciousClass`. This method doesn't need to do anything other than accept the argument.
            4.  Create a template `example/unicorn/components/vuln_test.html` with a button that triggers the `trigger_vuln` action.
            5.  Include the `vuln_test` component in a test page template in `example/www/templates/vuln_test_page.html` and create a corresponding view in `example/www/views.py` and URL in `example/www/urls.py` to render this page.
            6.  Access the test page in a browser.
            7.  Open browser's developer tools, go to the Network tab, and find the AJAX request when clicking the button.
            8.  Intercept or modify the AJAX request payload for the `trigger_vuln` action.
            9.  Craft a JSON payload for the `malicious_arg` that will be deserialized as `MaliciousClass`. A simple string value is enough to trigger the vulnerability because `cast_value` will try to instantiate `MaliciousClass` with the given string. For example, `{"actionQueue": [{"type": "callMethod", "payload": {"name": "trigger_vuln", "args": ["test"]}}]}`.
            10. Send the modified request.
            11. Observe the server-side logs or behavior to confirm that the `MaliciousClass.__init__` code was executed, proving insecure deserialization and potential for RCE.
            12. For SSTI, create a component method that takes a string argument and renders it in the template without sanitization. Send a malicious string like `{{ settings.SECRET_KEY }}` as argument and observe if `SECRET_KEY` is rendered in the HTML.

        2.  **Property Update Vulnerability Test:** (New test case, verifying property update vulnerability)
            1.  Create a Django Unicorn component named `vuln_prop_test` in `example/unicorn/components/vuln_prop_test.py`.
            2.  Define a custom class `MaliciousPropClass` in `example/unicorn/components/vuln_prop_test.py` with `__init__` that executes system commands or performs other malicious actions (for testing purposes, a simple print statement is sufficient to confirm execution).
            3.  In `VulnPropTestView` component, define a property `malicious_prop: MaliciousPropClass = None` type-hinted as `MaliciousPropClass`.
            4.  In the template `example/unicorn/components/vuln_prop_test.html`, include an input field bound to the `malicious_prop` using `wire:model="malicious_prop"`.
            5.  Include the `vuln_prop_test` component in a test page template in `example/www/templates/vuln_prop_test_page.html` and create a corresponding view in `example/www/views.py` and URL in `example/www/urls.py` to render this page.
            6.  Access the test page in a browser.
            7.  Open browser's developer tools and go to the Network tab.
            8.  In the input field, type any string. This will trigger a property update request.
            9.  Observe the server-side logs or behavior to confirm that `MaliciousPropClass.__init__` code was executed when the property was updated, proving insecure deserialization and potential for RCE through property updates.
