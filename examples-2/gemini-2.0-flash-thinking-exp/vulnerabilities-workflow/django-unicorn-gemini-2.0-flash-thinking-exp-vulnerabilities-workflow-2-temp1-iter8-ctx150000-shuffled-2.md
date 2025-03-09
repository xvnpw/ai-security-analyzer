- Vulnerability name: Unsafe HTML rendering with `safe` Meta attribute

- Description:
    - When a component defines a `Meta.safe` attribute, the fields listed in it are marked as safe using Django's `mark_safe`.
    - This prevents Django from escaping HTML content in templates for these specific fields.
    - If user-provided data is assigned to these `safe` fields without proper sanitization, it can lead to Cross-Site Scripting (XSS) vulnerabilities.
    - Step-by-step trigger:
        1. Create a Django Unicorn component and define `Meta: safe = ("unsafe_content",)` in the component class.
        2. In the component's Python code, assign user-provided data directly to the `unsafe_content` property without sanitizing it.
        3. In the component's template, render the `unsafe_content` property using `{{ unsafe_content }}`.
        4. An attacker provides malicious JavaScript code as user input (e.g., through a form field that updates `unsafe_content`).
        5. When the component is rendered, the malicious script will be executed in the user's browser because the content is marked as safe and not escaped.

- Impact:
    - Cross-Site Scripting (XSS).
    - An attacker can execute arbitrary JavaScript code in the user's browser.
    - Potential consequences include account hijacking, data theft, or other malicious actions.

- Vulnerability rank: High

- Currently implemented mitigations:
    - By default, Django templates escape HTML content, mitigating XSS risks for most cases.
    - Django Unicorn does not automatically mark any fields as safe; developers must explicitly use `Meta.safe`.

- Missing mitigations:
    - Documentation should strongly emphasize the security implications of using `Meta.safe`.
    - Advise developers to sanitize user input before assigning it to `safe` fields to prevent XSS.
    - Consider adding a development-time warning or runtime check when `Meta.safe` is used, prompting developers to review code for XSS risks.
    - Explore providing safer utilities or best practices for handling user input and `Meta.safe` to guide developers towards secure implementation.

- Preconditions:
    - A Django Unicorn component must explicitly define `Meta.safe` and include a property in the `safe` tuple.
    - User input must be dynamically assigned to a component property listed in `Meta.safe` without sanitization.
    - The `safe` property must be rendered in the component's template using template tags.

- Source code analysis:
    - File: `django_unicorn\views\__init__.py`
    - Function: `_process_component_request`
    - Vulnerable code snippet:
    ```python
        # Get set of attributes that should be marked as `safe`
        safe_fields = []
        if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
            if isinstance(component.Meta.safe, Sequence):
                for field_name in component.Meta.safe:
                    if field_name in component._attributes().keys():
                        safe_fields.append(field_name)

        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(component, field_name)
            if isinstance(value, str):
                setattr(component, field_name, mark_safe(value))  # noqa: S308
    ```
    - The code iterates through `safe_fields` defined in the component's `Meta` class.
    - It uses `mark_safe` to mark these fields as safe, which bypasses Django's HTML escaping mechanism during template rendering.
    - This behaviour is confirmed by the test case in `django_unicorn\tests\views\test_process_component_request.py`:
    ```python
    def test_safe_html_entities_not_encoded(client):
        # ...
        assert "<b>test1</b>" in response["dom"]
    ```

- Security test case:
    1. Create a component `xss_component` in `example/unicorn/components/xss_component.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XSSComponentView(UnicornView):
        unsafe_content = ""

        class Meta:
            safe = ("unsafe_content",)
    ```
    2. Create a template for the component `xss-component.html` in `example/unicorn/templates/unicorn/`:
    ```html
    <div>
        {{ unsafe_content }}
    </div>
    ```
    3. Create a view `xss_test_view` in `example/www/views.py` to render the component:
    ```python
    from django.shortcuts import render
    from example.unicorn.components.xss_component import XSSComponentView

    def xss_test_view(request):
        return render(request, 'www/xss_test.html', {"component_name": "unicorn/xss-component", "component_id": "xss_test"})
    ```
    4. Create a template `xss_test.html` in `example/www/templates/www/`:
    ```html
    {% extends "www/base.html" %}
    {% load unicorn %}

    {% block content %}
        {% unicorn 'xss-component' component_id='xss_test' %}
    {% endblock %}
    ```
    5. Add a path to `urls.py` in `example/www/urls.py`:
    ```python
    path("xss-test", views.xss_test_view, name="xss-test"),
    ```
    6. Access `/xss-test` in a browser.
    7. Send a POST request to `/message/unicorn.components.xss_component` with the following JSON payload using browser's developer tools:
    ```json
    {
      "id": "xss_test",
      "name": "unicorn.components.xss_component.XSSComponentView",
      "data": {
        "unsafe_content": "<script>alert('XSS Vulnerability')</script>"
      },
      "checksum": "TfxFqcQL",
      "actionQueue": [
        {
          "type": "syncInput",
          "payload": {
            "name": "unsafe_content",
            "value": "<script>alert('XSS Vulnerability')</script>"
          }
        }
      ],
      "epoch": 1678886400
    }
    ```
    (Note: Replace `"TfxFqcQL"` with an actual checksum. If the initial data is empty, it could be calculated for `{}`. Interacting with the page first might be necessary to obtain a valid checksum.)
    8. Observe an alert box with "XSS Vulnerability" displayed in the browser, confirming the vulnerability.
