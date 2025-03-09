- **Vulnerability Name:** Potential XSS vulnerability through unsafe rendering of Django Model fields

- **Description:**
    1. A developer uses Django Models to store data, potentially including user-provided content, within a Django application utilizing django-unicorn components.
    2. Within a django-unicorn component's HTML template, the developer directly embeds fields from Django Model instances. This is typically done using Django template syntax such as `{{ model_instance.field_name }}` or through django-unicorn's features like `unicorn:model` (though `unicorn:model` usage was not explicitly found in provided files, the concept is relevant).
    3. If a Django Model field is populated with user-supplied data that hasn't undergone proper sanitization before database storage, and this field is subsequently rendered in the template without employing Django's `escape` filter or by incorrectly using the `safe` filter or `Meta.safe`, an XSS vulnerability can arise.
    4. A malicious actor injects JavaScript code into the database field. This could be achieved via application forms, APIs, or directly if there's a vulnerability in data handling prior to database storage.
    5. When the django-unicorn component is rendered, the template engine processes `{{ model_instance.field_name }}`. Due to the lack of proper escaping, the malicious JavaScript code, now sourced from the database field, will be directly embedded into the HTML output.
    6. The browser of a user viewing the rendered page executes this unsanitized JavaScript code, leading to Cross-Site Scripting.

- **Impact:**
    - Successful Cross-Site Scripting (XSS) exploitation allows an attacker to execute arbitrary JavaScript code within a victim's web browser.
    - The consequences range from benign actions like defacing the website to severe security breaches, including session hijacking, theft of cookies (potentially granting unauthorized account access), redirection to external malicious sites, data theft, and other actions performed under the security context of the user and the vulnerable domain.

- **Vulnerability Rank:** Medium

- **Currently Implemented Mitigations:**
    - **Default HTML Encoding:** django-unicorn, starting from version 0.36.0, implements default HTML encoding for server responses. This is a significant security measure as it automatically escapes HTML entities in rendered content, preventing most basic XSS attempts.  The `test_html_entities_encoded` test in `tests\views\test_process_component_request.py` confirms this behavior by asserting that HTML entities are encoded in the DOM.
    - **`Meta.safe` for Explicit HTML Rendering:**  To allow developers to intentionally render raw HTML, django-unicorn provides the `Meta.safe` attribute within component classes. By listing attribute names in `Meta.safe = ("attribute_name",)`, developers can bypass the default HTML encoding for specific component attributes. The `test_safe_html_entities_not_encoded` in `tests\views\test_process_component_request.py` verifies that `Meta.safe` disables encoding.
    - **Documentation Warning (Django Models):** The `docs\source\django-models.md` documentation contains a warning regarding the potential exposure of model data in HTML source code when using default model serialization in components. It advises caution against displaying private properties and suggests customizing serialization or using `Meta.exclude` to control data exposure.

- **Missing Mitigations:**
    - **Automatic Input Sanitization:** django-unicorn lacks built-in, automatic sanitization of user inputs before rendering them in templates. It relies on Django's template engine's default escaping and expects developers to manually apply sanitization when necessary, especially when bypassing default encoding using `Meta.safe`.
    - **Enhanced Documentation for `Meta.safe`:** While a documentation warning exists, it could be more prominent and explicitly detail the XSS risks associated with `Meta.safe`. Best practices and clearer guidelines are needed, strongly emphasizing the developer's responsibility for sanitization when using `Meta.safe`. Examples in documentation should showcase both secure and insecure usage patterns of `Meta.safe`, and recommend using Django's `escape` filter or dedicated sanitization libraries whenever raw HTML rendering is intentionally required.

- **Preconditions:**
    1. The Django application stores user-provided data in Django Model fields without sufficient sanitization before saving to the database.
    2. A django-unicorn component is designed to display data from these Django Model fields within its template.
    3. The component template renders the potentially vulnerable model field using `{{ model_instance.field_name }}` or similar methods, without applying Django's `escape` filter.
    4. The developer either incorrectly uses the `safe` template filter or explicitly enables `Meta.safe` for the model field attribute in the component, intending to render raw HTML without realizing the XSS risk in this specific context of unsanitized user data.

- **Source Code Analysis:**
    - `changelog.md` indicates a past security fix (CVE-2021-42053) addressing XSS by implementing default HTML encoding.
    - `django_unicorn\components\unicorn_template_response.py` (not provided, assumed to handle rendering logic) likely enforces the default HTML encoding.
    - Tests in `tests\views\test_process_component_request.py` (`test_html_entities_encoded`, `test_safe_html_entities_not_encoded`) validate the default encoding and the `Meta.safe` bypass. `test_html_entities_encoded` confirms default encoding by asserting that `<` and `>` are converted to `&lt;` and `&gt;` in the DOM. `test_safe_html_entities_not_encoded` shows that `Meta.safe` renders raw HTML (`<b>` instead of `&lt;b&gt;`).
    - `django_unicorn\views\action_parsers\utils.py` contains the `set_property_value` function. This function is crucial as it demonstrates how user-provided data from requests can be used to update component properties.  Specifically, the function processes incoming requests, extracts property names and values, and sets these values on the component instance. This mechanism can be exploited if the property being set is later rendered in a template without proper sanitization. The function doesn't include any sanitization logic, relying on the Django template engine for output escaping, which can be bypassed by developers using `Meta.safe`.
    - `django_unicorn\serializer.py`, `django_unicorn\views\objects.py`, `django_unicorn\views\utils.py`, `django_unicorn\typer.py`: These files deal with data serialization, request processing and type handling, and confirm that user-provided data from requests can be bound to component properties and subsequently rendered, but they don't introduce new mitigations or vulnerabilities related to XSS beyond the template rendering context.
    - `docs\source\django-models.md` provides a basic warning, but could be more explicit in guiding developers on secure usage of `Meta.safe` and emphasizing the developer's responsibility for sanitization when bypassing default encoding.

- **Security Test Case:**
    1. **Setup:** Create a Django project with django-unicorn integration. Define a simple Django app and register it in `INSTALLED_APPS`.
    2. **Model Definition:** Create a Django Model named `VulnerableModel` in `models.py` of your app with a `TextField` named `content` to store user-provided content:
    ```python
    # your_app/models.py
    from django.db import models

    class VulnerableModel(models.Model):
        content = models.TextField()
    ```
    3. **Component Creation:** Create a django-unicorn component named `xss-test` in `components.py` of your app:
    ```python
    # your_app/components.py
    from django_unicorn.components import UnicornView
    from .models import VulnerableModel

    class XssTestView(UnicornView):
        model_instance = None

        def mount(self):
            self.model_instance = VulnerableModel.objects.create(content="") # Create instance initially

        class Meta:
            # Uncomment `safe = ("model_instance",)` to test vulnerability with Meta.safe
            # safe = ("model_instance",)
            pass
    ```
    4. **Template for Component:** Create a template `unicorn/xss-test.html` for the component:
    ```html
    <!-- your_app/templates/unicorn/xss-test.html -->
    <div>
        Content: {{ model_instance.content }}
    </div>
    ```
    5. **View and Template to Render Component:** Create a Django view in `views.py` and a template to render the component:
    ```python
    # your_app/views.py
    from django.shortcuts import render
    from .components import XssTestView # Import component to ensure it's loaded

    def xss_test_view(request):
        return render(request, 'xss_test.html')
    ```
    ```html
    <!-- your_app/templates/xss_test.html -->
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-test' %}
    </body>
    </html>
    ```
    6. **URL Configuration:** Add URL patterns in `urls.py` to access the view:
    ```python
    # your_app/urls.py
    from django.urls import path
    from .views import xss_test_view

    urlpatterns = [
        path('xss-test/', xss_test_view, name='xss_test_view'),
    ]
    ```
    7. **Initial Test - Default Encoding (Not Vulnerable):**
        - Access `/xss-test/` in a browser. No alert should appear. View source, verify `{{ model_instance.content }}` renders as text, encoding HTML entities.
    8. **Database Injection:** Using Django admin panel (or custom form/script if preferred), access the `VulnerableModel` instance and edit the `content` field to: `<img src='x' onerror='alert("XSS Vulnerability")'>`. Save the changes.
    9. **Component Rendering (Default Encoding):** Refresh `/xss-test/` in the browser.
    10. **Verification (Default Encoding - Not Vulnerable):** Confirm that an alert box with "XSS Vulnerability" does **not** appear. Inspect the HTML source; the injected payload should be HTML-encoded (e.g., `&lt;img src='x' onerror='alert("XSS Vulnerability")'&gt;`), displayed as text, proving default encoding is active.
    11. **Vulnerability Test - Bypass Encoding with `Meta.safe`:**
        - In `your_app/components.py`, uncomment the line `safe = ("model_instance",)` within the `Meta` class of `XssTestView`.
    2. **Component Rendering (With `Meta.safe`):** Refresh `/xss-test/` in the browser.
    13. **Verification (Vulnerable with `Meta.safe`):** If an alert box with "XSS Vulnerability" pops up, it confirms that using `Meta.safe` without sanitization leads to XSS. Inspect the HTML source; the payload should be rendered as raw HTML (`<img src='x' onerror='alert("XSS Vulnerability")'>`).
    14. **Mitigation Test - Using `escape` filter:**
        - In `your_app/components.py`, comment out `safe = ("model_instance",)` in `Meta`.
        - Modify the template `unicorn/xss-test.html` to use Django's `escape` filter:
        ```html
        <div>
            Description: {{ model_instance.content|escape }}
        </div>
        ```
    15. **Component Rendering (With `escape` filter):** Refresh `/xss-test/` in the browser.
    16. **Verification (With `escape` filter - Mitigated):** Verify that the alert box does not appear. Check the HTML source; the payload should again be HTML-encoded (`&lt;img src='x' onerror='alert("XSS Vulnerability")'&gt;`), demonstrating that the `escape` filter mitigates the XSS risk.

    **Expected Results:**
    - **Default Encoding:** No alert box, HTML encoded.
    - **With `Meta.safe`:** Alert box appears, HTML is raw (vulnerable).
    - **With `escape` filter:** No alert box, HTML encoded (mitigated).

This test case validates the XSS vulnerability arising from rendering unsanitized Django Model fields in django-unicorn components when default HTML encoding is bypassed (e.g., using `Meta.safe`) and highlights the effectiveness of Django's `escape` filter in mitigating this risk. It emphasizes the critical responsibility of developers to sanitize user inputs, especially when intentionally rendering raw HTML within django-unicorn templates.
