### Reflected Cross-Site Scripting (XSS) via `safe` Meta Class

* Description:
    1. A developer uses the `safe` Meta class in a Django Unicorn component to bypass HTML encoding for a specific component field.
    2. An attacker crafts a malicious URL or input that injects JavaScript code into this component field.
    3. When the component is rendered, the injected JavaScript code is executed in the victim's browser because HTML encoding is bypassed for the marked field.

* Impact:
    * Critical
    * An attacker can execute arbitrary JavaScript code in the victim's browser. This can lead to session hijacking, account takeover, defacement of the website, or redirection to malicious sites.

* Vulnerability Rank:
    * Critical

* Currently implemented mitigations:
    * By default, Django Unicorn HTML-encodes all component field values to prevent XSS.
    * Developers must explicitly use the `safe` Meta class to disable HTML encoding for specific fields.

* Missing mitigations:
    * There are no missing mitigations in the project to prevent developers from using `safe` Meta class. The `safe` Meta class is intended to be used when developers explicitly want to render unescaped HTML. However, there is no warning or guidance in the documentation about the security implications of using `safe` Meta class and when it is appropriate to use it safely.

* Preconditions:
    * A Django Unicorn component exists that uses the `safe` Meta class to mark at least one field as safe.
    * An attacker can influence the value of this safe field, either through URL parameters, form inputs, or other means.

* Source code analysis:
    1. File: `django-unicorn\docs\source\views.md`
    ```markdown
    ### safe

    By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple.

    ```html
    <!-- safe-example.html -->
    <div>
    <input unicorn:model="something_safe" />
    {{ something_safe }}
    </div>
    ```

    ```python
    # safe_example.py
    from django_unicorn.components import UnicornView

    class SafeExampleView(UnicornView):
        something_safe = ""

        class Meta:
            safe = ("something_safe", )
    ```
    ```
    This documentation explains the `safe` Meta class and how to use it. It highlights that by default, Unicorn prevents XSS by HTML encoding, and `safe` is used to opt-out of this protection. It does not explicitly warn about the security risks associated with using `safe` Meta class and potential XSS vulnerabilities if used incorrectly.

    2. File: `django-unicorn\django_unicorn\components\unicorn_template_response.py`
    ```python
    class UnicornTemplateResponse(TemplateResponse):
        ...
        def render(self):
            ...
            # Mark safe attributes as such before rendering
            for field_name in safe_fields:
                value = getattr(component, field_name)
                if isinstance(value, str):
                    setattr(component, field_name, mark_safe(value))  # noqa: S308
            ...
    ```
    This code snippet from `UnicornTemplateResponse.render` shows how fields marked in the `safe` Meta class are explicitly marked as safe using `mark_safe`. This bypasses Django's automatic HTML escaping, making the field vulnerable to XSS if the value is not properly sanitized before being assigned to the component field.

* Security test case:
    1. Create a Django Unicorn component that uses the `safe` Meta class.
    ```python
    # safe_xss.py
    from django_unicorn.components import UnicornView

    class SafeXssView(UnicornView):
        safe_content = ""

        class Meta:
            safe = ("safe_content", )
    ```
    2. Create a template for the component that renders the `safe_content` field.
    ```html
    <!-- safe-xss.html -->
    <div>
        {{ safe_content }}
    </div>
    ```
    3. Create a Django view to render a template that includes the `SafeXssView` component.
    ```python
    # views.py
    from django.shortcuts import render
    from .unicorn.components.safe_xss import SafeXssView # assuming components are in 'unicorn' app

    def safe_xss_test_view(request):
        return render(request, 'safe_xss_test.html', {"component_name": "safe-xss"})
    ```
    4. Create a Django template `safe_xss_test.html` to include the component.
    ```html
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>Safe XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% unicorn 'safe-xss' safe_content=xss_payload %}
    </body>
    </html>
    ```
    5. Create a URL path to access the view.
    ```python
    # urls.py
    from django.urls import path
    from . import views

    urlpatterns = [
        path('safe-xss-test/', views.safe_xss_test_view, name='safe_xss_test'),
    ]
    ```
    6. Access the `safe-xss-test` URL with a malicious payload as a URL parameter `xss_payload`.
    For example: `http://127.0.0.1:8000/safe-xss-test/?xss_payload=<script>alert("XSS Vulnerability");</script>`
    7. Observe that an alert box with "XSS Vulnerability" is displayed when the page loads, indicating that the JavaScript code in `xss_payload` was executed.

* Missing mitigations:
    * The project itself correctly implements HTML encoding by default and provides `safe` Meta class for explicit opt-out, which is not a mitigation but a feature. The missing mitigation is guidance or warning in documentation about the risk of using `safe` Meta class and how to use it safely.
    * The documentation should be updated to include a strong warning about the security implications of using the `safe` Meta class. It should emphasize that using `safe` to render user-provided content without proper sanitization will lead to XSS vulnerabilities.
    * Best practices and examples of safe usage of `safe` Meta class should be provided, such as when rendering content from trusted sources or after properly sanitizing user input on the backend before assigning it to a `safe` field.
