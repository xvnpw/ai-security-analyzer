### Vulnerability List

*   **Vulnerability Name:** Insecure Deserialization/Code Injection in Action Arguments

    *   **Description:**
        1.  An attacker can craft a malicious action call within the Django template, injecting arbitrary Python code or manipulating application state through specially crafted arguments.
        2.  The `django-unicorn` framework uses `ast.parse` and `ast.literal_eval` in `django_unicorn\call_method_parser.py` to parse arguments passed to component methods from the frontend.
        3.  While `ast.literal_eval` is generally considered safer than `eval`, vulnerabilities can arise if the context in which it operates is not strictly controlled, or if parsing logic is flawed.
        4.  An attacker could potentially bypass intended argument parsing and inject malicious payloads that are then executed by the server when the component action is processed.
        5.  This could lead to arbitrary code execution on the server, data manipulation, or other severe security impacts.

    *   **Impact:**
        *   **Critical**. Successful exploitation can lead to Remote Code Execution (RCE) on the server hosting the Django application.
        *   Full compromise of the application and potentially the underlying server.
        *   Data breach, data manipulation, and denial of service.

    *   **Vulnerability Rank:** Critical

    *   **Currently Implemented Mitigations:**
        *   The framework uses `ast.literal_eval` which is designed to safely evaluate literal expressions in strings.
        *   Input values are type-hinted and casted in `django_unicorn\typer.py` to limit the possible types of arguments passed to methods. (Not included in the provided files, but mentioned in previous analysis)
        *   Checksum validation for component data to prevent tampering during transit (`django_unicorn\views\objects.py` - `ComponentRequest.validate_checksum`).

    *   **Missing Mitigations:**
        *   Lack of input sanitization or validation beyond type casting for action arguments.
        *   Insufficient restriction on the context in which `ast.literal_eval` operates, potentially allowing access to unintended functionalities.
        *   No specific checks to prevent injection of potentially harmful code snippets through action arguments.

    *   **Preconditions:**
        *   The application uses `django-unicorn` framework.
        *   The application exposes components with methods callable from the frontend via actions.
        *   An attacker has knowledge of the component structure and callable methods, which is generally the case as components are defined in templates.

    *   **Source Code Analysis:**
        1.  **File:** `django_unicorn\call_method_parser.py` (from previous analysis)
        2.  **Function:** `parse_call_method_name(call_method_name: str)` and `eval_value(value)` (from previous analysis)
        3.  The analysis from previous steps remains valid. The code still uses `ast.literal_eval` which is the core of this vulnerability. Tests in `django_unicorn\tests\call_method_parser\test_parse_args.py` and `django_unicorn\tests\call_method_parser\test_parse_call_method_name.py` confirm the parsing logic, but do not include security-focused test cases to validate against code injection.
        4.  **File:** `django_unicorn\views\action_parsers\call_method.py`
        5.  **Function:** `handle(component_request: ComponentRequest, component: UnicornView, payload: Dict)`
        6.  This function is responsible for handling the `callMethod` action. It calls `parse_call_method_name` to parse the method name and arguments from the payload.
        7.  The parsed arguments are then passed to the method call using `_call_method_name`.
        8.  **Function:** `_call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any])`
        9.  This function retrieves the method from the component using `getattr(component, method_name)` and then calls it with parsed arguments and keyword arguments as shown in `django_unicorn\tests\views\action_parsers\call_method\test_call_method_name.py`.
        10. **Vulnerability Point:** The vulnerability lies in the parsing of `call_method_name` using `ast.literal_eval` and `ast.parse` without sufficient input validation, allowing potential code injection through crafted arguments. While type casting is present, it might not be enough to prevent all forms of malicious input, especially if complex data structures or specific object states can be manipulated.
        11. **Additional Context from New Files:** The file `django_unicorn\tests\views\utils\test_set_property_from_data.py` demonstrates how data is set to component properties, which highlights the importance of secure data handling throughout the framework. However, this specific test file doesn't directly relate to the parsing of action arguments, which is the focus of this vulnerability. The `pyproject.toml` file provides general project context but doesn't directly impact this vulnerability analysis.
        12. **Visualization:**

            ```
            Frontend (Browser) --> crafted action call string --> Backend (django_unicorn\views.py - message view)
                                                                    --> django_unicorn\views\action_parsers\call_method.py - handle()
                                                                        --> django_unicorn\call_method_parser.py - parse_call_method_name()
                                                                            --> ast.parse(method_name, "eval")
                                                                            --> eval_value(arg)
                                                                                --> ast.literal_eval(value)  <-- POTENTIAL VULNERABILITY
                                                                        --> django_unicorn\views\action_parsers\call_method.py - _call_method_name()
                                                                            --> getattr(component, method_name)
                                                                            --> func(*parsed_args, **parsed_kwargs)
                                                                    --> ... component method execution ...
            ```

    *   **Security Test Case:**
        1.  **Precondition:** Same as before. Assume a simple component with a method that takes a string argument and is callable from the template (e.g., `TestComponentView` and `test_component.html` from previous analysis).
        2.  **Test Steps:** Same as before. Craft a malicious `call_method_name` within the request `data` payload. Attempt to inject Python code as an argument to `set_message`. For example, try to pass an argument like: `[].__class__.__base__.__subclasses__()[123].__init__.__globals__['system']('touch /tmp/unicorn_pwned')` or similar payloads that could demonstrate code execution.
        3.  **Expected Result:** Same as before. If vulnerable, the injected code will be executed on the server. Check for server-side effects like file creation (`/tmp/unicorn_pwned`). Even if direct RCE is prevented, look for unexpected behavior, errors, or data leakage.

*   **Vulnerability Name:** Cross-Site Scripting (XSS) via Template Injection

    *   **Description:**
        1.  The `django-unicorn` framework dynamically updates parts of the DOM by sending HTML over AJAX and merging it into the existing page using morphing libraries.
        2.  If user-provided data or data retrieved from a database without proper sanitization is included in the component's template and re-rendered, it could lead to Cross-Site Scripting (XSS) vulnerabilities.
        3.  An attacker could inject malicious JavaScript code into the data, which would then be rendered and executed in the context of other users' browsers when the component updates.
        4.  This vulnerability is heightened because `django-unicorn` is designed to progressively enhance Django templates, implying developers might directly render variables without explicit output encoding, assuming Django's template engine handles it by default, which might not be sufficient in dynamic updates.

    *   **Impact:**
        *   **High**. Successful XSS exploitation can allow an attacker to execute arbitrary JavaScript code in the victim's browser.
        *   Session hijacking, cookie theft, defacement of the website, redirection to malicious sites, and further attacks against users.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        *   The changelog mentions a security fix for CVE-2021-42053 to prevent XSS attacks in version 0.36.0, suggesting awareness and attempts to mitigate XSS.
        *   The documentation for `views.md` mentions a `safe` Meta option and the use of `safe` template filter, indicating a mechanism to control HTML encoding.
        *   HTML encoding of responses is mentioned as a default behavior after version 0.36.0.
        *   `sanitize_html` function in `django_unicorn\utils.py` escapes HTML/XML special characters.
        *   `UnicornTemplateResponse._desoupify` in `django_unicorn\components\unicorn_template_response.py` uses `BeautifulSoup` to handle HTML encoding during component rendering, as tested in `django_unicorn\tests\components\test_unicorn_template_response.py`.
        *   `test_html_entities_encoded` in `django_unicorn\tests\views\test_process_component_request.py` shows that HTML entities are encoded by default when syncing input.

    *   **Missing Mitigations:**
        *   While HTML encoding and `sanitize_html` exist, it's crucial to verify if `sanitize_html` is consistently applied to user-provided or database-retrieved data rendered in templates, especially during dynamic updates and partial updates.
        *   Lack of automated checks or guidelines to ensure developers always use safe output methods for dynamic content in Unicorn components.
        *   Potential bypasses in morphing libraries or scenarios where encoding is not correctly applied during DOM updates, especially when using `safe` filter incorrectly or relying solely on default template auto-escaping.

    *   **Preconditions:**
        *   The application uses `django-unicorn` framework.
        *   Components render user-provided data or data from a database directly into the template that gets updated dynamically.
        *   Insufficient output encoding or sanitization of the data before rendering.

    *   **Source Code Analysis:**
        1.  **File:** `django_unicorn\components\unicorn_template_response.py`
        2.  **Function:** `render()`
        3.  This function renders the component template and prepares the response.
        4.  It uses `BeautifulSoup` to parse the rendered HTML and add `unicorn:` attributes.
        5.  **Crucially, it calls `sanitize_html(init)` before setting it as the string content for the `<script>` tag in `init_script` section.** This mitigates XSS in the component initialization data.
        6.  **Function:** `_desoupify(soup)`
        7.  This static method is used to convert the `BeautifulSoup` object back to HTML string. It uses `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`.  This part relies on `BeautifulSoup`'s default encoding, which should be HTML encoding. Tests like `test_desoupify` in `django_unicorn\tests\components\test_unicorn_template_response.py` confirm basic encoding but may not cover all XSS bypasses, especially in dynamic contexts.
        8.  **File:** `django_unicorn\views\test_process_component_request.py` and `django_unicorn\components\unicorn_view.py`
        9.  `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` in `django_unicorn\tests\views\test_process_component_request.py` and `FakeComponentSafe` in `django_unicorn\tests\views\test_process_component_request.py` demonstrate the usage of `safe` Meta option.
        10. **Missing explicit sanitization before template rendering**: While `sanitize_html` is used for the init script, there is no explicit call to sanitize user-provided data *before* it's rendered into the template within the `UnicornView.render()` or `UnicornTemplateResponse.render()` methods. Django's template engine does auto-escaping, but in dynamic contexts, especially with JavaScript morphing, relying solely on default template auto-escaping might be insufficient.
        11. **Vulnerability Point:**  If developers are not explicitly sanitizing user input before passing it to the template context within their component logic, and are relying only on Django's template auto-escaping, there might still be XSS vulnerabilities, especially if they are using `safe` filter incorrectly or if the morphing process introduces bypasses. The `safe` Meta option and filter, while documented, require developer awareness and correct usage, and might be misused leading to XSS.
        12. **Additional Context from New Files:** The file `django_unicorn\tests\views\utils\test_set_property_from_data.py` is not directly related to template rendering or XSS. It focuses on how component properties are updated with data from the frontend. The `pyproject.toml` file lists dependencies like `beautifulsoup4` and `htmlmin`, which are relevant to HTML processing and minification, but these are already considered in the existing mitigation analysis. This file does not introduce new information that changes the XSS vulnerability assessment.

    *   **Security Test Case:**
        1.  **Precondition:** Same as before. Assume a component that renders a user-controlled string in its template (e.g., `XssComponentView` and `xss_component.html` from previous analysis).
        2.  **Test Steps:** Same as before. In the input field, enter a typical XSS payload, such as `<img src=x onerror=alert('XSS')>`. Trigger a component update and observe if the JavaScript code is executed.
        3.  **Expected Result:** Same as before. If vulnerable, the JavaScript payload will execute, indicating an XSS vulnerability. If mitigated, the payload will be rendered as plain text. **Need to specifically test if `<img src=x onerror=alert('XSS')>` payload is properly encoded and does not execute Javascript. Also test scenarios with `safe` filter and `safe` Meta option to ensure they are used correctly and do not introduce bypasses.** Test also with different XSS vectors, including event handlers and script tags.

*   **Vulnerability Name:** Information Disclosure via Verbose Model Serialization

    *   **Description:**
        1.  When using Django Models directly within `django-unicorn` components and binding them to templates (e.g., `unicorn:model="book.title"`), the framework serializes the model and sends the data to the frontend as part of the component's state.
        2.  By default, this serialization process might include more model data than intended for public exposure, potentially revealing sensitive or internal information about the application's data structure and backend.
        3.  An attacker viewing the page source or intercepting network requests could access this serialized model data and gain unintended insights into the application.

    *   **Impact:**
        *   **Medium**. Information disclosure vulnerability.
        *   Exposure of potentially sensitive data like internal IDs, database structure details, or non-public model attributes.
        *   Could aid in further attacks by revealing application internals.

    *   **Vulnerability Rank:** Medium

    *   **Currently Implemented Mitigations:**
        *   Documentation in `django-models.md` warns about the risk of exposing the entire model and suggests using `Meta.exclude` or `Meta.javascript_exclude` to limit the data serialized. (Not included in provided files, but from previous analysis)
        *   The `javascript_exclude` Meta option in `views.md` provides a way to prevent specific attributes from being serialized to JavaScript. (Not included in provided files, but from previous analysis)
        *   `Meta.exclude` in `django_unicorn\components\unicorn_view.py` - `UnicornView._is_public()`: This allows excluding fields from serialization, but it's opt-in and requires developer awareness.
        *   Tests in `django_unicorn\tests\components\test_component.py` like `test_get_frontend_context_variables_javascript_exclude` and `test_meta_javascript_exclude_nested_with_tuple` confirm the functionality of `javascript_exclude`.
        *   Tests in `django_unicorn\tests\serializer\test_dumps.py` and `django_unicorn\tests\benchmarks\serializer\test_dumps.py` demonstrate the default verbose serialization and the effect of `exclude_field_attributes` (used internally by `javascript_exclude`).

    *   **Missing Mitigations:**
        *   Default behavior serializes the entire model, requiring developers to explicitly opt-out of exposing sensitive data, which is prone to developer oversight.
        *   Lack of automated checks or warnings to alert developers when they are potentially exposing excessive model data to the frontend.
        *   No built-in mechanism to easily define a "public" view of a model for serialization, forcing developers to manually manage excluded fields.

    *   **Preconditions:**
        *   The application uses `django-unicorn` framework.
        *   Components utilize Django Models and bind them to templates using `unicorn:model`.
        *   Developers are not explicitly using `Meta.exclude` or `Meta.javascript_exclude` to restrict serialized model data.

    *   **Source Code Analysis:**
        1.  **File:** `django_unicorn\serializer.py` (from previous analysis)
        2.  **Function:** `_get_model_dict(model: Model)` and `dumps(data: Dict, ...)` (from previous analysis)
        3.  The analysis from previous steps remains valid. Default serialization is verbose as confirmed by tests in `django_unicorn\tests\serializer\test_dumps.py` and `django_unicorn\tests\benchmarks\serializer\test_dumps.py`.
        4.  **File:** `django_unicorn\components\unicorn_view.py`
        5.  **Function:** `get_frontend_context_variables()`
        6.  This function serializes the component's data to JSON. It calls `serializer.dumps` to perform the serialization.
        7.  It correctly processes `Meta.javascript_exclude` to exclude fields, as tested in `django_unicorn\tests\components\test_component.py`.
        8.  **Function:** `_is_public(self, name: str)`
        9.  This function checks if an attribute should be considered public and included in the frontend context. It respects `Meta.exclude`.
        10. **Vulnerability Point:** While `javascript_exclude` and `exclude` Meta options provide mitigation, the default behavior is still to serialize the entire model. If developers are unaware of these options or forget to use them, sensitive model data can be exposed. The risk is mitigated if developers are careful and use `javascript_exclude` or `exclude`. Tests in `django_unicorn\tests\serializer\test_exclude_field_attributes.py` and `django_unicorn\tests\serializer\test_model_value.py` further detail the serialization and exclusion mechanisms.
        11. **Additional Context from New Files:** The file `django_unicorn\tests\views\utils\test_set_property_from_data.py` directly relates to how model data can be set as component properties. This reinforces the potential for information disclosure if models are not handled carefully. The tests in this file focus on data type conversion and property setting, but do not specifically address security aspects of model serialization. The `pyproject.toml` file provides general project context but does not directly impact this vulnerability analysis.

    *   **Security Test Case:**
        1.  **Precondition:** Same as before. Assume a component that renders a Django Model in its template without using `javascript_exclude` (e.g., `SecretComponentView` and `secret_component.html` from previous analysis).
        2.  **Test Steps:** Same as before. Access the page, view source, and examine the serialized JSON data for the `secret_model`.
        3.  **Expected Result:** Same as before. If vulnerable, the serialized JSON will include both `public_field` and `secret_field` values. If mitigated (by using `javascript_exclude` correctly), only `public_field` should be present or neither if properly excluded. **Test with different model field types, including sensitive data, to confirm the extent of information exposure.**
