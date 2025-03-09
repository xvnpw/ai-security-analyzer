- Vulnerability Name: Cross-Site Scripting (XSS) through `safe` template filter and `safe` Meta option
- Description:
    1. A developer uses the `safe` template filter in a django-unicorn component template or the `safe` Meta option in the component's view to bypass default HTML escaping.
    2. User-provided data is passed to the component and rendered in the template with the `safe` filter or `safe` Meta option.
    3. A threat actor crafts a malicious payload (e.g., `<script>alert("XSS")</script>`).
    4. The threat actor injects this payload as user-provided data (e.g., through a form input, URL parameter, etc.).
    5. The component re-renders with the malicious payload due to a user action or polling, or initial page load if the data is already present.
    6. Because the `safe` filter or `safe` Meta option is used, the payload is rendered without HTML escaping.
    7. When a user views the page, the malicious script executes in their browser, potentially leading to account takeover, data theft, or other malicious actions.
- Impact:
    - Account Takeover: Attackers can potentially steal session cookies or credentials, leading to account hijacking.
    - Data Theft: Sensitive user data can be exfiltrated by executing JavaScript code that sends data to attacker-controlled servers.
    - Website Defacement: The website's appearance and content can be altered, damaging the website's reputation.
    - Malicious Redirection: Users can be redirected to malicious websites.
    - Execution of Arbitrary JavaScript: Any action achievable through JavaScript can be performed in the user's browser.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - By default, django-unicorn HTML encodes updated field values to prevent XSS attacks. This is mentioned in `docs\source\changelog.md` for version `0.36.0` and in `docs\source\views.md` regarding the `safe` Meta option.
    - HTML encoding is the default behavior, mitigating XSS in most cases where developers don't explicitly use `safe`.
- Missing Mitigations:
    - No explicit warning or documentation within the project files (e.g., in `README.md`, `docs\source\templates.md`, `docs\source\views.md`) that clearly advises against using `safe` with user-provided data without proper sanitization. While the documentation for `safe` Meta option in `docs\source\views.md` mentions "explicitly opt-in to allow a field to be returned without being encoded", it doesn't explicitly warn about the security implications of bypassing HTML encoding when handling user inputs, especially concerning user-provided data.
    - Lack of automated checks (e.g., linters, security scans) to detect potential misuse of `safe` filter/Meta option with user-provided data.
- Preconditions:
    - The developer must use the `safe` template filter or the `safe` Meta option.
    - User-provided data must be dynamically rendered in the template using the `safe` filter or `safe` Meta option.
    - There must be a way for an attacker to inject malicious JavaScript code as user-provided data.
- Source Code Analysis:
    - **`docs\source\views.md`**: This file documents the `safe` Meta option: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." This indicates that HTML encoding is default and `safe` is an opt-in to disable it, but lacks explicit security warning, especially about user-provided data.
    - **`docs\source\templates.md`**: Mentions Django templates are used, and Django templates auto-escape by default, but `safe` filter can bypass it.
    - **`django_unicorn\serializer.py`**: This file handles serialization. Reviewing the code, it does not show any explicit HTML sanitization function that is applied by default during serialization for general template rendering. The changelog for version `0.36.0` suggests that HTML encoding is applied during rendering, not during serialization itself. The `safe` Meta option would likely control whether this encoding is applied during the template rendering phase.
    - **`django_unicorn\views.md`**: Describes how to use `safe` Meta option. Example code:
      ```python
      # safe_example.py
      from django_unicorn.components import UnicornView

      class SafeExampleView(UnicornView):
          something_safe = ""

          class Meta:
              safe = ("something_safe", )
      ```
      and template example:
      ```html
      <!-- safe-example.html -->
      <div>
        <input unicorn:model="something_safe" />
        {{ something_safe }}
      </div>
      ```
      This example demonstrates how to use `safe`, but does not highlight the security risk associated with user-provided data.
    - **`django_unicorn\components\unicorn_template_response.py`**: This file is responsible for rendering the component.
        - The `render` method in `UnicornTemplateResponse` class is where the component is rendered.
        - It uses `BeautifulSoup` to parse the HTML content, adds unicorn attributes, and then serializes it back.
        - The `sanitize_html` function from `django_unicorn.utils` is used to escape HTML characters specifically when creating the `init_script` json data.
        - However, `sanitize_html` as defined in `django_unicorn\utils.py` is used for escaping characters for JSON output, not for general HTML sanitization in the component template rendering context to prevent XSS.
        - The core template rendering itself (using Django templates and BeautifulSoup) does not include explicit HTML sanitization by django-unicorn for user inputs, relying on Django's default auto-escaping, which is explicitly bypassed when `safe` is used.
    - **`django_unicorn\utils.py`**:
        - Contains `sanitize_html` function which uses `html.translate(_json_script_escapes)` and `mark_safe`.
        - This function is designed to escape HTML/XML special characters for JSON output, as indicated in the function docstring: "Escape all the HTML/XML special characters with their unicode escapes, so value is safe to be output in JSON."
        - It is not intended for general HTML sanitization of user input within templates to prevent XSS attacks.
    - **`tests\views\test_process_component_request.py`**:
        - Includes `FakeComponentSafe` component which uses `safe` Meta option.
        - `test_safe_html_entities_not_encoded` test in the same file explicitly demonstrates that when using `FakeComponentSafe` and providing HTML content like `<b>test1</b>` as input, the output in `response["dom"]` is `<b>test1</b>` (not encoded), confirming the bypass of HTML encoding when `safe` is enabled. This test serves as a practical example of the XSS vulnerability when `safe` is misused with user inputs.

- Security Test Case:
    1. Create a django-unicorn component named `xss_safe_component` in a Django application.
    2. Define a component view `XssSafeView` with a `text` field and use `safe` Meta option:
       ```python
       # components/xss_safe_component.py
       from django_unicorn.components import UnicornView

       class XssSafeView(UnicornView):
           text = ""

           class Meta:
               safe = ("text", )
       ```
    3. Create a template for the component `unicorn/xss-safe-component.html`:
       ```html
       {# templates/unicorn/xss-safe-component.html #}
       <div>
           <input type="text" unicorn:model.defer="text">
           <div id="xss-output">{{ text }}</div>
       </div>
       ```
    4. Create a Django view to render a page with the `xss_safe_component`:
       ```python
       # views.py
       from django.shortcuts import render

       def xss_test_page(request):
           return render(request, 'xss_test_page.html', {})
       ```
    5. Create a template `xss_test_page.html` to include the component:
       ```html
       {# templates/xss_test_page.html #}
       {% load unicorn %}
       <html>
       <head><title>XSS Test</title>{% unicorn_scripts %}</head>
       <body>
           {% csrf_token %}
           {% unicorn 'xss-safe-component' %}
       </body>
       </html>
       ```
    6. Set up URL routing to access `xss_test_page`.
    7. Access the `xss_test_page` in a browser.
    8. In the input field of the `xss-safe-component`, enter a JavaScript payload: `<img src=x onerror="alert('XSS')">`.
    9. Click outside the input field (to trigger `defer` modifier if used) or perform an action that updates the component.
    10. Observe that an alert box with "XSS" is displayed, indicating successful XSS vulnerability.
    11. Verify that if the `safe` Meta option is removed from `XssSafeView`, the XSS is mitigated (the payload is rendered as plain text).

    This test case demonstrates that using `safe` Meta option without sanitizing user input leads to XSS vulnerability, proving the vulnerability is valid.
