## Vulnerabilities Report

The following vulnerability has been identified in the project.

### Cross-Site Scripting (XSS) due to unsafe usage of `safe` meta attribute or `|safe` template filter

- **Description:**
    1. Django Unicorn, by default, HTML-encodes component data to prevent XSS attacks. This is a built-in mitigation to ensure that dynamic content is rendered safely.
    2. However, developers can explicitly bypass this HTML encoding for specific component properties or template variables by using the `safe` meta attribute in `UnicornView` or the `|safe` template filter in Django templates.
    3. This opt-out mechanism is intended for cases where developers need to render HTML content intentionally, but it introduces a security risk if used improperly with user-controlled data.
    4. If a developer uses the `safe` meta attribute or `|safe` filter on a component property or template variable that is directly or indirectly derived from unsanitized user input, it can lead to Cross-Site Scripting (XSS) vulnerabilities.
    5. An attacker can craft malicious input containing JavaScript code and inject it into the application through various input vectors such as URL parameters, form fields, or database records if the component is rendering data from the database.
    6. When a user interacts with the application in a way that triggers the rendering of the vulnerable component with the attacker's malicious input, the injected JavaScript code will be executed in the user's browser.
    7. This occurs because Django Unicorn will render the content marked as `safe` without HTML encoding, allowing the malicious script to run within the user's session.

- **Impact:**
    - High
    - Successful exploitation of this XSS vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to severe security consequences, including:
        - **Account Takeover:** Stealing user session cookies, leading to account hijacking and unauthorized access.
        - **Data Theft:** Exfiltrating sensitive information displayed on the page or accessible within the user's session.
        - **Website Defacement:** Modifying the content of the web page viewed by the user, damaging website integrity.
        - **Redirection to Malicious Sites:** Redirecting users to phishing websites or sites hosting malware, increasing the risk of further attacks.
        - **Execution of Arbitrary JavaScript:** Gaining full control over the user's browser within the context of the vulnerable web page, enabling a wide range of malicious actions.
        - In the context of applications with administrative users, successful XSS attacks targeting administrators could lead to the compromise of the entire application and its data.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Default HTML Encoding:** Django Unicorn, by default, HTML-encodes all updated field values and responses to prevent XSS attacks. This is a crucial baseline mitigation.
    - **Opt-in for Unsafe Rendering:** Developers must explicitly opt-in to disable HTML encoding by using the `Meta.safe` attribute in the component class or the `|safe` filter in templates. This design intends to force developers to consciously bypass the default protection.
    - **Documentation Awareness:** The documentation mentions the `Meta.safe` option and implicitly warns against putting sensitive data into public properties. It also suggests using `Meta.exclude` and `Meta.javascript_exclude` to control data exposure, which can indirectly reduce the attack surface.
    - **Server-side Sanitization (Partial):** The server-side code includes a `sanitize_html` function in `django_unicorn/utils.py`. This function is used to sanitize component data before sending it to the frontend in some contexts. However, this sanitization is explicitly bypassed for properties marked as `safe`.
    - **HTML Encoding in Template Rendering:**  Django's template engine, used by Django Unicorn, also defaults to auto-escaping HTML content unless the `|safe` filter is used or autoescape is turned off.

- **Missing Mitigations:**
    - **Lack of Sanitization for `safe` Properties:** No explicit server-side sanitization or validation is automatically applied to user inputs that are bound to component properties marked as `safe` or rendered with `|safe` filter.
    - **Insufficient Documentation Warning:** While the documentation mentions `safe`, it could be strengthened with more explicit and prominent warnings about the severe security risks associated with its improper use, especially when handling user-provided data.
    - **No Automated Detection or Warnings:** There is no built-in mechanism within Django Unicorn to automatically detect potentially unsafe usage of `safe` with user-controlled data or to warn developers about such scenarios during development or runtime.
    - **Reliance on Developer Responsibility:** The library heavily relies on developers to fully understand the security implications of using `safe` and to implement proper sanitization and validation of user inputs themselves, which can be error-prone.

- **Preconditions:**
    - A Django Unicorn component must render a property or template variable that is marked as `safe` (using `Meta.safe` or `|safe` filter).
    - The value of this `safe` property or variable must be derived, directly or indirectly, from user-controlled input, such as URL parameters, form data, database records populated by user input, or external APIs providing user-influenced data.
    - An attacker must be able to inject malicious JavaScript code into this user-controlled data source.

- **Source Code Analysis:**
    1. **`django_unicorn/serializer.py`:** The `dumps` function, responsible for serializing data to JSON for frontend communication, by default performs HTML encoding. This is a core part of Django Unicorn's default XSS mitigation strategy.
    2. **`django_unicorn/views/__init__.py`:**
        - The `_process_component_request` function, within the `message` view, handles component actions and rendering.
        - This function retrieves the list of 'safe' fields defined in `component.Meta.safe`.
        - For each field name listed in `Meta.safe` that corresponds to a component attribute, the code uses `mark_safe` from `django.utils.safestring`.
        ```python
        # django_unicorn/views/__init__.py
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
        - `mark_safe` explicitly marks the string as safe from further HTML escaping by Django's template engine. This effectively bypasses the default HTML encoding for these specified properties.
        - Notably, this `mark_safe` operation happens *after* any potential sanitization steps within `_process_component_request`, meaning that for `safe` fields, the sanitization is intentionally overridden.
    3. **`django_unicorn/components/unicorn_view.py`:** The `UnicornView` class and its nested `Meta` class define the `safe` attribute. This is where developers declare which component properties should be treated as 'safe' and rendered without HTML encoding.
    4. **`django_unicorn/templatetags/unicorn.py`:** The `unicorn` template tag is used to render components in Django templates. It does not perform any additional HTML encoding or sanitization itself, relying on Django's template engine and the `mark_safe` status of variables.
    5. **`django_unicorn/views/action_parsers/sync_input.py`:** The `sync_input.handle` function is responsible for updating component properties based on user input received from the frontend via WebSocket actions. This is a critical point where user-provided data is directly bound to component properties. If these properties are subsequently rendered in templates using `Meta.safe` or `|safe` without sanitization, XSS vulnerabilities arise.
    6. **`django_unicorn\components\unicorn_template_response.py` and `django_unicorn\utils.py`:** While `sanitize_html` and HTML encoding mechanisms exist in the library (demonstrated by `_desoupify` and default behavior), the `Meta.safe` feature directly circumvents these protections when used.

- **Security Test Case:**
    1. Create a Django project with Django Unicorn installed and set up.
    2. Define a Django Unicorn component (`xss_component.py`) with a property `unsafe_data` and mark it as safe using `Meta.safe`. This property will be used to render user-controlled input.
        ```python
        # components/xss_component.py
        from django_unicorn.components import UnicornView

        class XSSView(UnicornView):
            unsafe_data = ""

            class Meta:
                safe = ("unsafe_data",)

            def mount(self):
                self.unsafe_data = self.component_kwargs.get("user_input", "")
        ```
    3. Create a template for the component (`unicorn/xss_component.html`) to render the `unsafe_data` property.
        ```html
        {# templates/unicorn/xss_component.html #}
        <div>
            <p>Unsafe Input: {{ unsafe_data }}</p>
        </div>
        ```
    4. Create a Django view (`views.py`) and a Django template (`xss_test.html`) to include the vulnerable component. The view should pass user input from the URL query parameters to the component as a kwarg.
        ```python
        # views.py
        from django.shortcuts import render
        def xss_test_view(request):
            user_input = request.GET.get('input', '')
            return render(request, 'xss_test.html', {'user_input': user_input})
        ```
        ```html
        {# templates/xss_test.html #}
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
            <title>XSS Test</title>
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-view' user_input=user_input %}
        </body>
        </html>
        ```
    5. Configure URL routing (`urls.py`) to access the test view.
        ```python
        # urls.py
        from django.urls import path
        from . import views
        from django.conf.urls import include

        urlpatterns = [
            path('xss_test/', views.xss_test_view, name='xss_test'),
            path("unicorn/", include("django_unicorn.urls")),
        ]
        ```
    6. Run the Django development server.
    7. Access the following URL in a web browser, injecting a JavaScript `alert` as user input: `http://127.0.0.1:8000/xss_test/?input=<script>alert("XSS Vulnerability");</script>`
    8. **Expected Outcome:** An alert box with the message "XSS Vulnerability" should appear in the browser. This confirms that the injected JavaScript code was executed because the `unsafe_data` property, marked as `safe`, rendered the user-provided input without HTML encoding, leading to a successful XSS attack.

This test case demonstrates that by intentionally using `Meta.safe` and passing unsanitized user input to the marked property, a reflected Cross-Site Scripting vulnerability can be easily exploited. Developers must exercise extreme caution when using `safe` and ensure proper sanitization of all user-provided data before rendering it in templates, especially when bypassing default HTML encoding.
