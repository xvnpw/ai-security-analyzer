- Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML rendering when using the `safe` attribute
- Description:
    1. An attacker can inject malicious JavaScript code into user-provided data.
    2. When a Django Unicorn component renders a template that includes this unsanitized user data through a property marked as `safe` in the component's `Meta` class, the malicious script is executed in the user's browser.
    3. This occurs because the `safe` attribute explicitly tells django-unicorn to bypass the default HTML encoding for the specified component property.
    4. If a developer uses `safe` without properly sanitizing user input, it will render raw HTML, including any injected malicious scripts.
    5. For example, if a component has a `message` property and `Meta.safe = ("message",)`, and the template renders `{{ message }}`, and the `message` property is updated with user input containing `<script>alert('XSS')</script>`, the alert will be executed.
- Impact:
    - An attacker can execute arbitrary JavaScript code in the context of the user's browser.
    - This can lead to stealing user session cookies, performing actions on behalf of the user, defacing the website, or redirecting the user to malicious websites.
    - If an administrator account is compromised, it could lead to full control of the web application.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - By default, django-unicorn automatically HTML-encodes data rendered in templates, as indicated in `docs\source\changelog.md` (version 0.36.0) and verified by the test `test_html_entities_encoded` in `django_unicorn\tests\views\test_process_component_request.py`.
    - The `sanitize_html` function in `django_unicorn\utils.py` is used to escape HTML special characters for JSON output, which is applied to initial component data in `django_unicorn\components\unicorn_template_response.py`.
    - The documentation (`docs\source\views.md`) and source code in `django_unicorn\views\__init__.py` highlight the `safe` Meta attribute as a way to opt-out of HTML encoding for specific fields, making encoding the default and safer behavior.
- Missing Mitigations:
    - Developers are responsible for sanitizing user input when using the `safe` attribute. There is no built-in mechanism within django-unicorn to enforce sanitization when `safe` is used.
    - Documentation should be improved to strongly emphasize the security implications of using the `safe` attribute and provide clear guidance on how to properly sanitize user input in these cases.
    - Content Security Policy (CSP) is not mentioned as a mitigation strategy in the provided documentation, and could be recommended as a defense-in-depth measure.
- Preconditions:
    - The application must be using django-unicorn to render dynamic components.
    - User input must be incorporated into a component's property and rendered in the template.
    - The component's `Meta` class must declare the property as `safe`, e.g., `Meta.safe = ("unsafe_property",)`.
    - The developer must not sanitize the user input before assigning it to the `safe` property.
- Source Code Analysis:
    - In `django_unicorn\views\__init__.py`, the `_process_component_request` function handles marking fields as safe based on the `Meta.safe` attribute:
        ```python
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
        - This code retrieves `safe_fields` from `component.Meta.safe`.
        - It iterates through these fields and uses `mark_safe` from `django.utils.safestring` to mark the corresponding component attributes as safe.
        - `mark_safe` tells Django's template engine not to escape the HTML content of these variables when rendering the template.
        - This mechanism is intended for developers to render trusted HTML, but it creates an XSS vulnerability if used with unsanitized user input.
    - The test `test_safe_html_entities_not_encoded` in `django_unicorn\tests\views\test_process_component_request.py` demonstrates this behavior by showing that HTML entities are not encoded when using a `safe` field.
        ```python
        def test_safe_html_entities_not_encoded(client):
            data = {"hello": "test"}
            action_queue = [
                {
                    "payload": {"name": "hello", "value": "<b>test1</b>"},
                    "type": "syncInput",
                }
            ]
            response = post_and_get_response(
                client,
                url="/message/tests.views.test_process_component_request.FakeComponentSafe",
                data=data,
                action_queue=action_queue,
            )

            assert not response["errors"]
            assert response["data"].get("hello") == "<b>test1</b>"
            assert "<b>test1</b>" in response["dom"]
        ```
        - This test confirms that when a component (`FakeComponentSafe`) is configured with `Meta.safe = ("hello",)`, and the `hello` property is updated with HTML content (`<b>test1</b>`), the HTML is rendered as-is in the DOM, without encoding.

- Security Test Case:
    1. Create a Django Unicorn component named `SafeAttributeXSSComponent` in `components/safe_xss_component.py`:
        ```python
        from django_unicorn.components import UnicornView

        class SafeAttributeXSSComponent(UnicornView):
            template_name = "unicorn/safe-xss.html"
            user_input = ""

            class Meta:
                safe = ("user_input",)
        ```
    2. Create a template `unicorn/safe-xss.html` for the component in `templates/unicorn/safe-xss.html`:
        ```html
        <div>
            <input type="text" unicorn:model="user_input" id="user-input">
            <div id="output">
                {{ user_input }}
            </div>
        </div>
        ```
    3. Create a Django view to render the `SafeAttributeXSSComponent` in `views.py`:
        ```python
        from django.shortcuts import render
        from .components.safe_xss_component import SafeAttributeXSSComponent

        def safe_attribute_xss_view(request):
            return render(request, 'safe_xss_template.html', {"component_name": "safe-xss-component"})
        ```
    4. Create a template `safe_xss_template.html` to include the component in `templates/safe_xss_template.html`:
        ```html
        {% load unicorn %}
        <!DOCTYPE html>
        <html>
        <head>
            <title>Safe Attribute XSS Test</title>
            {% unicorn_scripts %}
        </head>
        <body>
            {% unicorn "safe-xss-component" %}
        </body>
        </html>
        ```
    5. Add a URL path to `urls.py` to access the view:
        ```python
        from django.urls import path
        from . import views

        urlpatterns = [
            path('safe-xss/', views.safe_attribute_xss_view, name='safe_xss_view'),
            # ... other urls ...
        ]
        ```
    6. Run the Django development server.
    7. As an attacker, navigate to the `safe-xss/` URL in a web browser.
    8. In the input field (id `user-input`), enter the following XSS payload: `<img src="x" onerror="alert('XSS_safe_attribute')">`.
    9. Observe if the JavaScript alert `alert('XSS_safe_attribute')` is executed in the browser when you type or after you blur the input field.
    10. If the alert is executed, it confirms the XSS vulnerability due to the `safe` attribute. The user-provided input was rendered without HTML encoding, leading to script execution.
    11. If the alert is not executed and the raw HTML is rendered as text (e.g., `&lt;img src="x" onerror="alert('XSS_safe_attribute')">`), re-examine the component code, template, and view to ensure they are correctly set up according to the test case. If it still doesn't execute, it might indicate a different behavior than expected, which would also be a finding to investigate. However, based on the code analysis and documentation, the alert should execute when using the `safe` attribute with unsanitized input.
