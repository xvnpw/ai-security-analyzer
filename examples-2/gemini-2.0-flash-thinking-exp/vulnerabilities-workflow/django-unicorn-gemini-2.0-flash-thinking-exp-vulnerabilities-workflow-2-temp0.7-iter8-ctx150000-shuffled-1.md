- Vulnerability Name: Cross-Site Scripting (XSS) via `safe` Meta attribute

- Description:
    1. A developer uses the `safe` attribute in the `Meta` class of a Django Unicorn component to disable HTML escaping for a specific component field.
    2. User-provided data is bound to this field using `unicorn:model` in the component's template.
    3. A malicious user inputs JavaScript code into the input field.
    4. When the component updates, the Django Unicorn backend renders the component and includes the user-provided, unescaped JavaScript code in the HTML response because of the `safe` attribute.
    5. The frontend JavaScript merges the updated HTML into the DOM.
    6. The malicious JavaScript code is executed in the user's browser, leading to XSS.

- Impact:
    Successful XSS attacks can allow threat actors to:
    - Steal session cookies, potentially gaining unauthorized access to user accounts.
    - Redirect users to malicious websites.
    - Deface the web page.
    - Perform actions on behalf of the user, such as making unauthorized transactions or accessing sensitive data.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - By default, Django Unicorn HTML-encodes all component data to prevent XSS. This is the standard behavior unless explicitly overridden.
    - Documentation warns against using `safe` with user-provided data and explains its purpose is for explicitly trusted content. (`docs\source\views.md`)

- Missing Mitigations:
    - No explicit warnings or checks in the code to prevent developers from using `safe` attribute with user-provided data.
    - It relies solely on developer awareness and correct usage based on documentation.

- Preconditions:
    1. A Django Unicorn component is created.
    2. The component's `Meta` class incorrectly uses the `safe` attribute for a field that is bound to user input.
    3. An attacker can provide malicious JavaScript code as input to the component through the UI.

- Source Code Analysis:
    1. **`django_unicorn\components\unicorn_view.py`**: The `Meta` class and `safe` attribute are defined and processed in the `UnicornView`.
    2. **`django_unicorn\serializer.py`**: The `dumps` function serializes component data to JSON. It doesn't inherently sanitize HTML; it relies on the default Django template escaping unless `safe` is used.
    3. **`django_unicorn\components\unicorn_template_response.py`**: The `UnicornTemplateResponse.render()` method renders the component and includes the serialized data in the HTML. If `safe` is used, the data is passed without encoding.

    ```python
    # Example of Safe usage in docs\source\views.md:

    # safe_example.py
    from django_unicorn.components import UnicornView

    class SafeExampleView(UnicornView):
        something_safe = ""

        class Meta:
            safe = ("something_safe", )
    ```
    In this example, `something_safe` will NOT be HTML encoded when rendered because it's listed in `Meta.safe`. If `something_safe` is directly bound to user input and rendered in the template without further escaping, it becomes vulnerable to XSS.

- Security Test Case:
    1. Create a Django Unicorn component named `xss_safe_test` in a Django app, e.g., `unicorn_xss_test`.
    2. In the component's Python view (`unicorn_xss_test/components/xss_safe_test.py`), define a field `user_input` and add `safe = ("user_input",)` to the `Meta` class:

    ```python
    # unicorn_xss_test/components/xss_safe_test.py
    from django_unicorn.components import UnicornView

    class XssSafeTestView(UnicornView):
        user_input = ""

        class Meta:
            safe = ("user_input", )
    ```

    3. Create a template for the component (`unicorn_xss_test/templates/unicorn/xss_safe_test.html`) that renders the `user_input` field:

    ```html
    {# unicorn_xss_test/templates/unicorn/xss_safe_test.html #}
    <div>
        <input type="text" unicorn:model="user_input">
        <div id="output">
            {{ user_input }}
        </div>
    </div>
    ```

    4. Create a Django template (e.g., `xss_test.html`) to include the `xss_safe_test` component:

    ```html
    {# templates/xss_test.html #}
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-safe-test' %}
    </body>
    </html>
    ```

    5. Create a Django view and URL to render the `xss_test.html` template.
    6. Access the URL in a web browser.
    7. In the input field, enter the following XSS payload: `<img src=x onerror="alert('XSS Vulnerability')">`.
    8. After typing or submitting the input (depending on model modifier), an alert box with "XSS Vulnerability" will appear, demonstrating the XSS vulnerability.

This test case proves that when `safe` is enabled and user input is rendered, XSS is possible.
