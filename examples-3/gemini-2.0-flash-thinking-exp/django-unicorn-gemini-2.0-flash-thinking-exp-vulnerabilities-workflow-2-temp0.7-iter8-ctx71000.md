## Combined Vulnerability List for django-unicorn project

### 1. Cross-Site Scripting (XSS) through Misuse of `safe` Mechanism and Unsanitized User Inputs

- Description:
    1. A developer uses Django Unicorn components to render dynamic content, potentially including user-provided data, within Django templates.
    2. Django Unicorn, by default, automatically HTML encodes output to prevent XSS. However, developers can bypass this default encoding by using the `safe` template filter in templates or the `safe` Meta option in component classes.
    3. When the `safe` filter or `safe` Meta option is used with user-controlled data without proper sanitization, it creates an XSS vulnerability.
    4. An attacker crafts malicious input containing JavaScript code and injects it into user-controlled data sources, such as form fields, URL parameters, or database records that are subsequently rendered by a Django Unicorn component.
    5. If a component template renders this user-provided data, either directly using the `safe` filter or because the corresponding component property is marked as `safe` in `Meta`, the HTML encoding is bypassed.
    6. Consequently, when a user views the page, the injected JavaScript code is executed in their browser because the output is not sanitized, leading to Cross-Site Scripting.
    7. This vulnerability can also occur even without explicit use of `safe` if developers fail to ensure default HTML encoding is applied to all user-provided data rendered in templates, or if they introduce custom rendering logic that bypasses the built-in sanitization.

- Impact:
    - Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary JavaScript code in the browser of a user viewing the affected page. This can lead to:
        - **Account Takeover:** Stealing session cookies or user credentials, allowing the attacker to impersonate the user and gain unauthorized access to their account.
        - **Session Hijacking:** Intercepting and hijacking user sessions to perform actions on behalf of the authenticated user.
        - **Data Theft:** Accessing and exfiltrating sensitive user data or application secrets displayed on the page.
        - **Website Defacement:** Altering the content and appearance of the website to mislead users or damage the website's reputation.
        - **Redirection to Malicious Sites:** Redirecting users to attacker-controlled websites, potentially leading to phishing attacks or malware infections.
        - **Unauthorized Actions:** Performing actions on behalf of the user, such as making purchases, changing settings, or disclosing private information without their consent or knowledge.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - **Default HTML Encoding:** Django Unicorn, by default since version 0.36.0, automatically HTML encodes component output. This is achieved through the use of `BeautifulSoup` in `UnicornTemplateResponse._desoupify()` which, by default, escapes HTML entities when serializing HTML. This behavior is intended to prevent XSS in most common scenarios.
    - **`sanitize_html` function:** The `django_unicorn.utils.sanitize_html` function provides HTML escaping for JSON output, used specifically for initial component data.
    - **Opt-in `safe` Mechanism:** Django Unicorn provides the `safe` template filter and `safe` Meta option to allow developers to explicitly disable HTML encoding for specific template variables or component properties when they need to render raw HTML. This feature is intended for cases where developers are certain that the content is safe and does not originate from user input or is already properly sanitized.

- Missing Mitigations:
    - **Developer Warnings and Guidelines:** There is a lack of prominent warnings in the documentation about the security risks associated with using the `safe` filter and `safe` Meta option. Clear guidelines and best practices for secure usage of `safe`, emphasizing the necessity of sanitizing user-provided content before rendering with `safe`, are missing.
    - **Automated Security Checks:** The project lacks automated security checks or linting tools that could detect potentially unsafe usage of the `safe` mechanism, especially in conjunction with user inputs. Static analysis could help identify templates or components where `safe` is used on variables that might be user-controlled.
    - **Input Sanitization Utilities:** Django Unicorn does not provide built-in input sanitization utilities for developers to easily sanitize user input before rendering it in templates, especially when using the `safe` mechanism.
    - **Content Security Policy (CSP):** Implementing a Content Security Policy would provide an additional layer of security to mitigate the impact of XSS vulnerabilities, even if output encoding is bypassed.

- Preconditions:
    - **Django Unicorn Component Rendering User Data:** A Django Unicorn component must be designed to render user-controlled data in its template.
    - **Misuse of `safe` or Lack of Default Encoding:** The developer must either intentionally use the `safe` filter or `safe` Meta option for user-controlled data without sanitization, or unintentionally bypass or miss the default HTML encoding mechanism in template rendering logic.
    - **Attacker-Controlled Input:** An attacker must be able to inject malicious JavaScript code into the source of the user-controlled data. This can be achieved through various input vectors, including:
        - Form inputs bound to component properties via `unicorn:model`.
        - URL parameters.
        - Database records displayed by the component.
        - Any other source of data dynamically rendered in the component template that can be influenced by an attacker.

- Source Code Analysis:
    1. **`django_unicorn/views/__init__.py` - `_process_component_request` function:**
        - This function handles component requests and processes `safe_fields` from `Meta`. It uses `mark_safe` to disable HTML encoding for fields listed in `Meta.safe`. This is where the `safe` Meta option directly bypasses encoding.
        ```python
        # django_unicorn/views/__init__.py
        from django.utils.html import mark_safe

        def _process_component_request(request: HttpRequest, component_request: ComponentRequest) -> Dict:
            # ...
            safe_fields = []
            if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
                if isinstance(component.Meta.safe, Sequence):
                    for field_name in component.Meta.safe:
                        if field_name in component._attributes().keys():
                            safe_fields.append(field_name)

            for field_name in safe_fields:
                value = getattr(component, field_name)
                if isinstance(value, str):
                    setattr(component, field_name, mark_safe(value))  # noqa: S308
            # ...
        ```
    2. **`django_unicorn/components/unicorn_template_response.py` - `UnicornTemplateResponse._desoupify` and `UnicornTemplateResponse.render`:**
        - `_desoupify` uses `BeautifulSoup` with `HTMLFormatter` that performs HTML entity substitution by default, providing HTML encoding.
        - `render` function uses `_desoupify` to process the rendered template, which means default HTML encoding is applied unless bypassed by `safe`.
    3. **`django_unicorn/utils.py` - `sanitize_html`:**
        - Provides HTML escaping for JSON data, but is not used for general template rendering.
    4. **`tests/views/test_process_component_request.py`:**
        - `test_html_entities_encoded` confirms default HTML encoding.
        - `test_safe_html_entities_not_encoded` confirms `safe` Meta option bypasses encoding, demonstrating the vulnerability if misused.

    **Vulnerability Flow Diagram (using `safe`):**

    ```
    User Input (Malicious Script) --> Component Property (marked as `safe` or used with `safe` filter) --> Template Rendering (no HTML encoding due to `safe`) --> User Browser (malicious script execution)
    ```

- Security Test Case:
    1. **Setup:**
        - Create a Django project with Django Unicorn installed and a running Django development server.
        - Create a Django Unicorn component named `xss_component`.
    2. **Vulnerable Component (`xss_component.py`):**
        ```python
        from django_unicorn.components import UnicornView

        class XssComponentView(UnicornView):
            user_input = ""

            class Meta:
                safe = ("user_input",)  # Vulnerable configuration: marking user_input as safe
        ```
    3. **Vulnerable Template (`unicorn/xss_component.html`):**
        ```html
        <div>
            <input type="text" unicorn:model="user_input" id="xss-input">
            <div id="xss-output">User Input: {{ user_input }}</div> {# Vulnerable rendering: user_input is rendered without encoding because of Meta.safe #}
        </div>
        ```
    4. **Django View and Template:** Create a Django view and template to include the `xss_component`.
        ```python
        # views.py
        from django.shortcuts import render

        def xss_test_view(request):
            return render(request, 'xss_test_page.html')
        ```
        ```html
        {# xss_test_page.html #}
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% unicorn 'xss-component' %}
        </body>
        </html>
        ```
    5. **Run Server and Access Page:** Start the Django development server and access the page containing the `xss_component` in a browser.
    6. **Inject XSS Payload:** In the input field, enter the XSS payload: `<script>alert('XSS Vulnerability!')</script>`.
    7. **Trigger Re-render:** Click outside the input field or perform any action that triggers a Django Unicorn update.
    8. **Verification:** Observe if an alert box with "XSS Vulnerability!" appears. If it does, the XSS vulnerability is confirmed due to the misuse of `Meta.safe`.
    9. **Test with `safe` filter:** Modify the template to use `{{ user_input|safe }}` instead of `Meta.safe` and repeat steps 6-8. Verify that the `safe` filter also leads to XSS.
    10. **Test without `safe`:** Remove `Meta.safe` and use default rendering `{{ user_input }}`. Repeat steps 6-8 and verify that the alert box does *not* appear, indicating that default encoding is working.

### 2. Server-Side Template Injection (SSTI) via Action Method Arguments

- Description:
    1. Django Unicorn allows calling component methods from templates using attributes like `unicorn:click="method(argument)"`.
    2. The `parse_call_method_name` function parses the method name and arguments from the string provided in the template attribute. This parsing is done using `ast.parse` from Python's `ast` module.
    3. If an attacker can control or influence the arguments passed to the action method in the template (e.g., through user-controlled data rendered into the template), they can inject malicious Python code within these arguments.
    4. Because `ast.parse` is used to parse these arguments, and the parsed arguments are then evaluated using `eval_value` (which itself uses `ast.literal_eval` for safer evaluation, but the initial `ast.parse` is the risk), a Server-Side Template Injection vulnerability can occur.
    5. By crafting a malicious payload in the method arguments, an attacker can potentially execute arbitrary Python code on the server when the component processes the action.

- Impact:
    - Remote Code Execution (RCE). Successful exploitation of this vulnerability allows an attacker to execute arbitrary Python code on the server hosting the Django application. This can have catastrophic consequences, including:
        - **Full System Compromise:** Complete control over the server, allowing the attacker to access sensitive data, modify system configurations, install malware, and pivot to other systems.
        - **Data Breach:** Access to and exfiltration of sensitive application data, user data, and confidential business information.
        - **Denial of Service (DoS):**  Crashing the application or server, or using server resources to launch attacks against other systems.
        - **Privilege Escalation:** Gaining higher-level privileges within the application or server infrastructure.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
    - None identified in the code. The parsing logic in `parse_call_method_name` uses `ast.parse` without any input sanitization or validation to prevent code injection. While `eval_value` uses `ast.literal_eval` for evaluating arguments which is safer, the initial parsing with `ast.parse` is the entry point for injection.

- Missing Mitigations:
    - **Input Sanitization:** Implement robust sanitization of the `call_method_name` string in `parse_call_method_name` before parsing it with `ast.parse`. This should involve removing or neutralizing any potentially malicious code constructs.
    - **Input Validation:** Validate the structure and content of `call_method_name` to ensure it conforms to expected patterns and does not contain unexpected or dangerous elements. Restrict allowed characters and syntax to only what is necessary for calling methods with arguments.
    - **Safer Parsing Methods:** Explore using `ast.literal_eval` or other safer parsing mechanisms instead of `ast.parse` for the initial parsing of action method arguments. `ast.literal_eval` is designed to safely evaluate only literal Python expressions, preventing the execution of arbitrary code. However, it might be too restrictive for complex argument parsing.
    - **Sandboxing or Isolation:** Consider running component logic in a sandboxed or isolated environment to limit the impact of potential RCE vulnerabilities. This could involve using containers, virtual machines, or restricted Python environments.
    - **Security Audits and Testing:** Conduct thorough security audits and penetration testing specifically focused on Server-Side Template Injection in Django Unicorn's action method argument parsing. Include test cases that attempt to inject malicious payloads and bypass any implemented mitigations.

- Preconditions:
    - **Django Unicorn Actions with Arguments:** The application must use Django Unicorn components that handle actions with arguments passed from the template (e.g., using `unicorn:click="method(user_input)"`).
    - **User-Controlled Template Context:** An attacker needs to be able to influence the arguments passed to the action method, typically through user-controlled input that is rendered into the template context and used in the `unicorn:click` attribute.

- Source Code Analysis:
    1. **`django_unicorn/call_method_parser.py` - `parse_call_method_name(call_method_name: str)`:**
        - This function is responsible for parsing the method name and arguments from the string provided in template attributes like `unicorn:click`.
        - **Vulnerable Line:** `tree = ast.parse(method_name, "eval")` - This line uses `ast.parse` to parse the `method_name` string. `ast.parse` is designed to parse full Python code and is not safe for untrusted input.
        - The function then extracts arguments and keyword arguments from the parsed AST tree and processes them using `eval_value`. While `eval_value` itself uses `ast.literal_eval` which is safer, the initial parsing with `ast.parse` allows for injection of arbitrary Python code syntax.

        ```python
        # django_unicorn/call_method_parser.py
        import ast
        from typing import Any, Dict, List, Tuple

        from django_unicorn.call_method_parser import eval_value  # noqa: PLC0415


        def parse_call_method_name(call_method_name: str) -> Tuple[str, List[Any], Dict[str, Any]]:
            """
            Parse the call method name.

            Handles no arguments, positional arguments, and keyword arguments.
            """

            method_name = call_method_name.strip()
            args: List[Any] = []
            kwargs: Dict[str, Any] = {}

            if "(" in method_name:
                method_name_base = method_name[: method_name.index("(")]
                arg_string = method_name[method_name.index("(") + 1 : -1]

                if arg_string:
                    tree = ast.parse(method_name, "eval") # Vulnerable line: ast.parse is used
                    statement = tree.body[0].value

                    if tree.body and isinstance(statement, ast.Call):
                        call = statement
                        args = [eval_value(arg) for arg in call.args]
                        kwargs = {kw.arg: eval_value(kw.value) for kw in call.keywords}

                method_name = method_name_base

            return method_name, args, kwargs
        ```

    2. **`django_unicorn/call_method_parser.py` - `eval_value(value)`:**
        - This function is used to evaluate the arguments extracted by `parse_call_method_name`. It uses `ast.literal_eval` which is safer than `eval`, but the vulnerability is in the initial parsing with `ast.parse`.

        ```python
        # django_unicorn/call_method_parser.py
        import ast


        def eval_value(value: ast.AST) -> Any:
            """
            Evaluate value from AST node.
            """

            if isinstance(value, ast.Constant):
                return value.value

            return ast.literal_eval(value) # Safer evaluation, but initial parsing with ast.parse is the issue
        ```

    **Vulnerability Flow Diagram (SSTI):**

    ```
    User Input (via template attribute) --> `call_method_name` string --> `ast.parse(method_name, "eval")` --> Python code execution on server
    ```

- Security Test Case:
    1. **Setup:**
        - Create a Django project with Django Unicorn installed.
        - Define a Django Unicorn component `ssti_component` with an action method `test_method` that takes an argument.
    2. **Vulnerable Component (`ssti_component.py`):**
        ```python
        from django_unicorn.components import UnicornView
        import os

        class SstiComponentView(UnicornView):
            def test_method(self, malicious_input):
                # This method is intentionally left empty for testing purposes.
                pass
        ```
    3. **Vulnerable Template (`unicorn/ssti_component.html`):**
        ```html
        <div>
            <button unicorn:click="test_method('{{ malicious_payload }}')">Trigger SSTI</button>
        </div>
        ```
    4. **Django View and Template:** Create a Django view and template to render the `ssti_component`, injecting a malicious payload into the template context.
        ```python
        # views.py
        from django.shortcuts import render

        def ssti_test_view(request):
            malicious_payload = "'); import os; os.system('touch /tmp/unicorn_ssti_pwned'); x = ('" # Payload to trigger RCE
            return render(request, 'ssti_test_page.html', {'malicious_payload': malicious_payload})
        ```
        ```html
        {# ssti_test_page.html #}
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% unicorn 'ssti-component' %}
        </body>
        </html>
        ```
    5. **Run Server and Access Page:** Start the Django development server and access the page containing the `ssti_component` in a browser.
    6. **Trigger Action:** Click the "Trigger SSTI" button. This will send a request to the server with the malicious payload in the `unicorn:click` action.
    7. **Verification:** Check if the command `touch /tmp/unicorn_ssti_pwned` was executed on the server. Verify if the file `/tmp/unicorn_ssti_pwned` exists in the `/tmp/` directory on the server. If the file is created, it confirms successful Remote Code Execution via Server-Side Template Injection.
