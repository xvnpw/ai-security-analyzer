- Vulnerability Name: Cross-Site Scripting (XSS) due to unsafe template rendering with `safe` meta option

- Description:
    1. A Django Unicorn component uses the `safe` meta option to mark a property as safe for HTML rendering.
    2. A threat actor can control the value of this property, potentially injecting malicious JavaScript code.
    3. When the component renders, the template uses the `safe` filter or the `safe` meta option to output this property without proper sanitization.
    4. The injected JavaScript code gets executed in the user's browser when the component is rendered or updated via AJAX.

- Impact:
    Successful exploitation allows a threat actor to execute arbitrary JavaScript code in the context of a user's browser. This can lead to:
    * Account takeover through session hijacking or credential theft.
    * Defacement of the web application.
    * Redirection of users to malicious websites.
    * Data theft or manipulation.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    The project documentation in `views.md` mentions that by default, `unicorn` HTML encodes updated field values to prevent XSS attacks. It also documents the `safe` meta option and `safe` template filter, explicitly stating that they should be used with caution. However, there is no automatic sanitization or escaping implemented when `safe` is explicitly used, leaving the developer responsible for ensuring the content is safe.

- Missing Mitigations:
    * Automatic sanitization of properties marked as `safe`. While complete automatic sanitization might be complex and have performance implications, Django Unicorn could provide built-in functions or guidance for developers to sanitize their data before marking it as `safe`.
    * Clear warnings in the documentation about the severe security implications of using the `safe` option without proper sanitization and guidance on how to sanitize user-provided content.
    * Security test cases within the project to detect and prevent regressions of XSS vulnerabilities related to the `safe` option.

- Preconditions:
    * A Django Unicorn component must use the `safe` meta option or the `safe` template filter.
    * An attacker must be able to control the data that is rendered in the template using the `safe` option/filter. This could be through URL parameters, form inputs, or other user-controlled inputs that are bound to the component's properties.

- Source Code Analysis:
    1. **`views.md`**: The documentation explains the `safe` meta option and its purpose, highlighting the developer's responsibility:

    ```markdown
    By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple.
    ```

    2. **`SafeExampleView` and `safe-example.html` in `docs\source\views.md`**: Example code demonstrates how to use the `safe` meta option. It shows that the `something_safe` variable will not be encoded, implying that any HTML or JavaScript code within it will be rendered as is.

    ```python
    # safe_example.py
    from django_unicorn.components import UnicornView

    class SafeExampleView(UnicornView):
        something_safe = ""

        class Meta:
            safe = ("something_safe", )
    ```

    ```html
    <!-- safe-example.html -->
    <div>
      <input unicorn:model="something_safe" />
      {{ something_safe }}
    </div>
    ```

    3. **`UnicornTemplateResponse.render` in `django_unicorn\components\unicorn_template_response.py`**: This code renders the component template. There is no code to automatically sanitize variables marked as `safe`. The framework relies on the developer to ensure that properties marked as safe are indeed safe.

    ```python
    class UnicornTemplateResponse(TemplateResponse):
        # ...
        def render(self):
            # ...
            # Mark safe attributes as such before rendering
            for field_name in safe_fields: # safe_fields are populated based on Meta.safe option
                value = getattr(self.component, field_name)
                if isinstance(value, str):
                    setattr(self.component, field_name, mark_safe(value))  # noqa: S308
            # ...
    ```

    In summary, the code correctly identifies and marks variables as `safe` based on the `Meta` option, but it does not perform any sanitization. This design decision leaves the application vulnerable to XSS if developers use `safe` incorrectly with user-controlled data.

- Security Test Case:

    1. Create a Django Unicorn component named `XssComponent` with a property `unsafe_content` and mark it as `safe` in the Meta class.

    ```python
    # components/xss_component.py
    from django_unicorn.components import UnicornView

    class XssComponentView(UnicornView):
        unsafe_content = ""

        class Meta:
            safe = ("unsafe_content", )
    ```

    2. Create a template `unicorn/xss-component.html` to render the `XssComponent` and display the `unsafe_content` in the template.

    ```html
    {# unicorn/xss-component.html #}
    <div>
        <input unicorn:model="unsafe_content" type="text" id="xss-input" />
        <div id="xss-output">
            {{ unsafe_content }}
        </div>
    </div>
    ```

    3. Create a Django view and template to include the `XssComponent`.

    ```python
    # views.py
    from django.shortcuts import render
    from django.views.generic import TemplateView

    class XssTestView(TemplateView):
        template_name = 'xss_test.html'

    ```

    ```html
    {# templates/xss_test.html #}
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-component' %}
    </body>
    </html>
    ```

    4. Run the Django development server.

    5. Open the page in a browser that renders `xss_test.html`.

    6. In the input field, enter the following JavaScript payload: `<img src='x' onerror='alert("XSS Vulnerability")'>` and trigger an update (e.g., by clicking outside the input field if `lazy` is not used, or by triggering an action if using `defer`).

    7. Observe that an alert box with "XSS Vulnerability" is displayed, demonstrating the execution of injected JavaScript code.

    8. Alternatively, enter `<script>alert("XSS Vulnerability");</script>` in the input field and observe the alert box.

    This test case proves that the `safe` option, when used with user-controlled input without sanitization, leads to a Cross-Site Scripting vulnerability.
