### Vulnerability List for django-unicorn project

* Vulnerability Name: Potential Cross-Site Scripting (XSS) via misuse of `safe` Meta attribute

* Description:
    1. A developer uses the `safe` attribute in the `Meta` class of a Unicorn component to mark a component field as safe from HTML encoding.
    2. The developer intends to render HTML content from a trusted source, but mistakenly marks a field that can be influenced by user input as `safe`.
    3. An attacker injects malicious JavaScript code into the user-controlled data.
    4. When the component re-renders, the malicious JavaScript code is rendered into the DOM without proper sanitization because the field is marked as `safe`.
    5. The attacker's JavaScript code executes in the victim's browser, potentially leading to account takeover, data theft, or other malicious actions.

* Impact:
    - High: Cross-site scripting can lead to a wide range of attacks, including session hijacking, defacement, redirection to malicious sites, or information disclosure. In the context of a Django application, this could compromise user accounts and sensitive data.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    - By default, django-unicorn HTML encodes updated field values to prevent XSS attacks.
    - The documentation advises against putting sensitive data into public properties and highlights the `javascript_exclude` Meta attribute.
    - The `sanitize_html` function in `django_unicorn.utils` is used to escape HTML.
    - The project fixed CVE-2021-42053 by HTML encoding responses.

* Missing Mitigations:
    - **Enhanced Code-level Warning in DEBUG Mode:** Implement a more robust check within the `UnicornView._render` method or during component initialization. This check should specifically identify fields marked as `safe` that are also:
        - Bound using `unicorn:model` in the template.
        - Modified within any component method that is directly callable from the frontend via actions (e.g., methods decorated for action handling or implicitly callable methods).
        When such a condition is detected in `DEBUG` mode, raise a `SuspiciousOperation` exception or log a very explicit warning using the `logging` module with a 'WARNING' level. This warning should clearly state the potential XSS risk due to the unsafe use of the `safe` attribute with user-controlled data, and guide developers to review their component's `Meta` settings and template usage.
    - **Template and Component Code Linting/Static Analysis Tooling:** Develop a dedicated linting rule or extend existing Django template linters (if feasible) or create a standalone static analysis tool. This tool should:
        - Parse Unicorn component templates to identify `safe` fields used in conjunction with `unicorn:model` or within event handlers.
        - Analyze the Python code of Unicorn components to trace data flow and identify if `safe` fields are updated by methods that handle user input from the frontend.
        - Generate warnings or errors during development or CI pipelines to proactively flag potential XSS vulnerabilities arising from `safe` misuse.
    - **Comprehensive Documentation with Security-Focused Examples and Best Practices:**  Significantly expand the documentation section on the `safe` attribute to include:
        - **Prominent Security Warning:** Start with a clear and strong warning about the dangers of misusing the `safe` attribute, especially with user-controlled data, emphasizing the potential for XSS vulnerabilities.
        - **Detailed Vulnerable Code Examples:** Provide concrete, easy-to-understand code examples that demonstrate how developers can unintentionally create XSS vulnerabilities by incorrectly using `safe`. Show examples with `unicorn:model` and methods handling user input.
        - **Secure Alternatives and Best Practices:** Offer clear and actionable guidance on secure alternatives to using `safe` on user-controlled fields. Recommend patterns like:
            - Using a dedicated sanitization function (like `django.utils.html.escape` or a more advanced HTML sanitizer like Bleach) within the template itself, directly where the user-controlled data is rendered, instead of marking the field as `safe`.
            - Sanitizing user input within the component's Python code before rendering it, even if the field is marked as `safe` (although generally, avoid using `safe` for user inputs altogether).
            - Clearly document when and when not to use the `safe` attribute, focusing on scenarios where the data source is absolutely trusted and not influenced by user input.
        - **Security Checklist:** Include a security checklist for developers to review when using the `safe` attribute, reminding them to verify the data source and consider sanitization.

* Preconditions:
    - A developer must create a Unicorn component and mistakenly use the `safe` Meta attribute on a field that is directly or indirectly influenced by user input.
    - An attacker must be able to inject malicious JavaScript code into this user-controlled data source (e.g., through a form, API endpoint, or other means outside of django-unicorn itself).

* Source Code Analysis:
    1. **`django_unicorn/components/unicorn_view.py`**: The `_render` method in `UnicornView` is responsible for rendering the component. Within this method, the component's attributes are prepared for template rendering. The code iterates through `safe_fields` (determined by the `Meta.safe` attribute) and marks the corresponding attributes as safe using `mark_safe(value)`. This bypasses the default HTML escaping.
    ```python
    # django_unicorn/views/__init__.py excerpt from _process_component_request method:
    [...]
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
    [...]
    ```
    2. **`django_unicorn/utils.py`**: The `sanitize_html` function is available for escaping HTML, and it is used in other parts of the project (e.g., for CVE-2021-42053 fix). However, the usage of `safe` attribute in `Meta` explicitly circumvents this sanitization, relying entirely on the developer's correct usage.
    3. **`django_unicorn/views.py`**: The `message` view processes actions and calls `_render`. It does not include any checks or warnings related to the `safe` attribute or potential XSS risks arising from its misuse.
    4. **`docs/source/views.md` documentation**: While the documentation describes the `safe` Meta attribute, it does not sufficiently emphasize the security implications of using it on user-controlled data. The documentation could be improved by including a strong warning against this practice and providing concrete examples of vulnerable code and secure alternatives.

    **Visualization:**

    ```
    User Input --> Component Field (marked as 'safe' in Meta) --> Template Rendering (no sanitization) --> DOM --> XSS
    ```

    The vulnerability is triggered when the developer creates a component that:
    - Defines a field intended to hold user-provided data.
    - Incorrectly marks this field as `safe` in the `Meta` class.
    - Renders this field in the component's template without any further sanitization.
    When an attacker can control the input to this field, they can inject malicious scripts that will execute in the user's browser when the component is rendered.

* Security Test Case:
    1. Create a Django project with django-unicorn installed.
    2. Create a Unicorn component named `unsafe_component` in `myapp/components/unsafe_component.py` with the following content:
    ```python
    from django_unicorn.components import UnicornView

    class UnsafeComponentView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data", )
    ```
    3. Create a template for the component in `myapp/templates/unicorn/unsafe_component.html` with the following content:
    ```html
    <div>
        <input type="text" unicorn:model="unsafe_data">
        <div id="output">Output: {{ unsafe_data }}</div>
    </div>
    ```
    4. Create a Django view and template to include the `unsafe_component`. For example, in `myapp/views.py`:
    ```python
    from django.shortcuts import render
    from myapp.components.unsafe_component import UnsafeComponentView

    def unsafe_view(request):
        return render(request, 'myapp/unsafe_template.html', {'component_name': 'unsafe-component'})
    ```
    and in `myapp/templates/myapp/unsafe_template.html`:
    ```html
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>Unsafe Component Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        <h1>Unsafe Component Test</h1>
        {% unicorn "unsafe-component" %}
    </body>
    </html>
    ```
    5. Configure URLs in `myapp/urls.py`:
    ```python
    from django.urls import path
    from myapp import views

    urlpatterns = [
        path('unsafe/', views.unsafe_view, name='unsafe_view'),
    ]
    ```
    and include `myapp.urls` in the main `urls.py`.
    6. Access the page at `/unsafe/` in a browser.
    7. In the input field, enter the following payload: `<img src=x onerror=alert('XSS')>`
    8. Observe that an alert box with 'XSS' is displayed, demonstrating that the JavaScript code was executed because the `unsafe_data` field was marked as `safe` and the input was rendered without sanitization.

* Missing Mitigations:
    - **Enhanced Code-level Warning in DEBUG Mode:** Implement a more robust runtime warning in development environments to flag potential misuse of the `safe` attribute with user-controlled data.
    - **Template and Component Code Linting/Static Analysis Tooling:** Develop static analysis tools to detect potential XSS vulnerabilities caused by incorrect usage of the `safe` attribute.
    - **Comprehensive Documentation with Security-Focused Examples and Best Practices:** Improve documentation to strongly warn against misuse of `safe` and provide secure alternatives with detailed code examples.
