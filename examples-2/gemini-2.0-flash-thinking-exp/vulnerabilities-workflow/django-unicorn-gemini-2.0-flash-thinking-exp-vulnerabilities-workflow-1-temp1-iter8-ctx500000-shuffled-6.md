### Vulnerability List for django-unicorn project

* Vulnerability Name: Cross-Site Scripting (XSS) via `safe` Meta Option

* Description:
    1. An attacker crafts a malicious string containing Javascript code.
    2. A developer uses a Django Unicorn component and marks a property as `safe` in the `Meta` class.
    3. The component renders a template that includes this `safe` property without further sanitization.
    4. An attacker can inject and execute arbitrary Javascript code in the victim's browser by setting the component property to the malicious string via user-controlled input in the application's frontend.

* Impact:
    - Critical. Successful exploitation allows an attacker to execute arbitrary Javascript code in the context of the user's browser. This can lead to account takeover, data theft, redirection to malicious sites, and other malicious actions.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - By default, Django Unicorn HTML encodes updated field values to prevent XSS attacks. This encoding is implemented in the `views.py` when rendering the component response.
    - Developers have to explicitly opt-in to disable HTML encoding for specific properties using the `safe` tuple in the `Meta` class of a component view.

* Missing Mitigations:
    - There is no explicit security warning in the documentation about using the `safe` option and the inherent risk of XSS if used with unsanitized user input.
    - No automatic sanitization is performed on `safe` properties before rendering in the template. The responsibility for sanitizing data marked as `safe` is entirely left to the developer.

* Preconditions:
    - A Django Unicorn component must have a property marked as `safe` in its `Meta` class.
    - The application must allow user-controlled input (e.g., via form fields, URL parameters, or other input mechanisms) to be dynamically bound to this `safe` property in the component, typically using `unicorn:model` in the template.
    - The application must be deployed and publicly accessible to external attackers.

* Source Code Analysis:
    1. The `rendered` function within `UnicornView` in `django-unicorn/django_unicorn/views/__init__.py` is responsible for rendering the component and processing the `safe` meta option.
    2. It retrieves the list of fields marked as `safe` from the component's `Meta` class (`safe_fields`).
    3. For each `field_name` in `safe_fields`, it fetches the corresponding property value from the component instance using `getattr(component, field_name)`.
    4. It checks if the retrieved value is a string using `isinstance(value, str)`.
    5. If the value is a string, it's marked as safe for HTML output using Django's `mark_safe(value)` function: `setattr(component, field_name, mark_safe(value))`. The `# noqa: S308` indicates that a bandit security check is being explicitly ignored here, likely because `mark_safe` is intended to be used when the developer *knows* the content is safe, but in this context, it blindly trusts the developer's `safe` declaration in `Meta`.
    ```python
    # django-unicorn/django_unicorn/views/__init__.py
    # ...
    # Mark safe attributes as such before rendering
    for field_name in safe_fields:
        value = getattr(component, field_name)
        if isinstance(value, str):
            setattr(component, field_name, mark_safe(value))  # noqa: S308
    # ...
    ```
    6. When Django renders the template and encounters `{{ property_name }}` where `property_name` corresponds to a `safe` field, it outputs the value directly without any HTML escaping because `mark_safe` tells Django that the string is already safe to render as HTML.
    7. If user input is directly bound to a `safe` property without any sanitization being performed by the developer *before* setting the component property, and an attacker provides malicious Javascript code as input, this code will be rendered directly into the HTML output and executed by the user's browser, leading to XSS.

* Security Test Case:
    1. **Setup:** Ensure you have a Django project with Django Unicorn installed. Create a Django app, and within it, create a `components` directory.
    2. **Create Component:** Create a component file `xss_safe.py` in the `components` directory with the following code:
    ```python
    # xss_safe.py
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        text = ""

        class Meta:
            safe = ("text",)
    ```
    3. **Create Template:** Create a template file `xss_safe.html` in the `components/templates/unicorn` directory (or the appropriate template path configured for your project) with the following content:
    ```html
    <!-- xss_safe.html -->
    <div>
        <input type="text" unicorn:model="text" id="xss-input">
        <div id="output">Output: {{ text }}</div>
    </div>
    ```
    4. **Create Django View and Template:** Create a Django view in `views.py` in your app and a corresponding template to render the `XssSafeView` component.  For example, in `views.py`:
    ```python
    # views.py
    from django.shortcuts import render
    from .components.xss_safe import XssSafeView # adjust import path if needed

    def xss_test_view(request):
        return render(request, 'xss_test.html', {"component_name": "xss-safe"}) # component name matches component class name, lowercased and hyphenated
    ```
    And in `templates/xss_test.html`:
    ```html
    <!-- xss_test.html -->
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test</title>
    </head>
    <body>
        <h1>XSS Vulnerability Test</h1>
        {% unicorn "xss-safe" %}
        <script src="{% unicorn_scripts %}"></script>
    </body>
    </html>
    ```
    5. **Configure URL:** Add a URL pattern in your `urls.py` to map a URL to `xss_test_view`.
    6. **Run Development Server:** Start your Django development server.
    7. **Open Browser:** Navigate to the URL you configured for `xss_test_view` in your web browser.
    8. **Inject XSS Payload:** In the input field with `id="xss-input"`, enter the following Javascript payload: `<script>alert("XSS Vulnerability");</script>`.
    9. **Trigger Update:** Click outside the input field to trigger the `blur` event which, by default in Unicorn, sends an update to the server, or you can use the `lazy` modifier and change the event to `change` if you prefer to trigger on input change.
    10. **Observe:** Observe if an alert box with the message "XSS Vulnerability" appears in your browser. If the alert box appears, the XSS vulnerability is confirmed.

* Missing Mitigations:
    - **Documentation Enhancement:**  Crucially, the documentation needs to be updated with a prominent security warning detailing the risks of using the `safe` option, especially when handling user-provided data. It should explicitly advise developers to sanitize any user input before assigning it to a `safe` property in a Unicorn component. Example code snippets demonstrating safe handling and potential sanitization methods should be provided.
    - **Consider Sanitization Helper/Guidance:** While automatic sanitization might be too restrictive and break legitimate use cases for `safe`, Django Unicorn could consider providing utility functions or clear guidelines in the documentation on how developers can easily sanitize data before marking it as `safe`. This could include recommending specific Django or Python sanitization libraries or demonstrating common sanitization patterns.
    - **Static Analysis Tooling/Checks (Optional):**  For more advanced mitigation, consider if static analysis tools could be configured to detect potential misuse of the `safe` option, particularly when combined with data binding from user input. This would require more sophisticated analysis but could provide an extra layer of security for developers.
