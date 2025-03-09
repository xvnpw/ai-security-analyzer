* Vulnerability Name: Cross-Site Scripting (XSS) in Component Properties Rendering

* Description:
    1. An attacker can inject malicious JavaScript code into a component property value, for example through URL parameters, form inputs, or other data sources that are used to initialize component properties.
    2. When the Django template renders the component and displays this property value without proper sanitization, the malicious JavaScript code gets embedded into the HTML output.
    3. When a user's browser renders the page, the injected JavaScript code executes, potentially leading to XSS.

* Impact:
    - Execution of arbitrary JavaScript code in the victim's browser.
    - Cookie theft and session hijacking.
    - Defacement of the web page.
    - Redirection to malicious websites.
    - Sensitive data disclosure.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - HTML encoding of updated field values: As mentioned in `docs/source/changelog.md` for version 0.36.0, responses are HTML encoded to prevent XSS attacks. This is a global mitigation.
    - `safe` Meta attribute and template filter: Developers can mark specific component properties or template variables as `safe` to bypass HTML encoding, but this requires explicit opt-in. See `docs/source/views.md` and `docs/source/changelog.md`.

* Missing Mitigations:
    - Automatic sanitization of all component properties rendered in templates by default. While HTML encoding is implemented, it might not be consistently applied in all scenarios, or developers might inadvertently use `safe` incorrectly.
    - Context-aware output encoding: Depending on the rendering context (HTML elements, attributes, JavaScript), different encoding schemes might be needed for robust XSS prevention. Currently, it's not clear if django-unicorn` applies context-aware encoding.

* Preconditions:
    - A django-unicorn component is used in a Django template to render user-controlled data as component properties.
    - The component template renders the property value without explicitly using Django's `escape` filter or other sanitization mechanisms, and the property is not excluded from HTML encoding via `safe` Meta attribute.
    - An attacker can control the input source for the component property.

* Source Code Analysis:
    1. **`django_unicorn/views/utils.py` -> `set_property_from_data` function**: This function is responsible for setting component properties based on data received from the frontend. It handles different data types and nested properties. While it performs type casting, it does not include explicit sanitization of the property values before setting them on the component.
    2. **`django_unicorn/components/unicorn_view.py` -> `get_frontend_context_variables` function**: This function serializes component properties to JSON for frontend use. It respects `javascript_exclude` Meta attribute but doesn't automatically sanitize the values before serialization.
    3. **Template rendering**: Django templates, by default, escape HTML content to prevent basic XSS. However, if `safe` filter or attribute is used, or if the context is JavaScript code or HTML attributes, standard Django escaping might be insufficient or bypassed.
    4. **`docs/source/views.md` -> Meta -> safe**: The documentation explains the `safe` Meta attribute and the `safe` template filter, indicating that developers have the option to bypass HTML encoding for specific properties. This also implies that by default, some form of encoding is applied, but it may not be sufficient in all cases.
    5. **`docs/source/changelog.md` -> v0.36.0**: This changelog entry explicitly mentions a security fix for CVE-2021-42053 to prevent XSS attacks by HTML encoding responses. This confirms that XSS is a recognized vulnerability and mitigation has been implemented. However, the opt-in nature of `safe` and potential inconsistencies in encoding application could still leave room for vulnerabilities.

* Security Test Case:
    1. Create a django-unicorn component named `xss_test`.
    2. Add a property `user_input` to `XssTestView` component:
    ```python
    # xss_test.py
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        user_input = ""
    ```
    3. Create a template `xss_test.html` that renders the `user_input` property without any sanitization:
    ```html
    <!-- xss_test.html -->
    <div>
        <p>User Input: {{ user_input }}</p>
    </div>
    ```
    4. Create a Django view and template to include the `xss_test` component.
    5. Access the page with a URL that sets the `user_input` property via a GET parameter (or use a form to POST data that sets this property). For example, if component property is initialized from `component_kwargs`, pass the malicious payload as kwarg:
    ```html
    <!-- template_with_xss.html -->
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-test' user_input=xss_payload %}
    </body>
    </html>
    ```
    ```python
    # views.py
    from django.shortcuts import render

    def template_with_xss(request):
        xss_payload = '<img src=x onerror=alert("XSS")>'
        context = {'xss_payload': xss_payload}
        return render(request, 'template_with_xss.html', context)
    ```
    6. Load the `template_with_xss` page in a browser.
    7. Observe if the JavaScript alert `alert("XSS")` is executed. If the alert box pops up, it confirms the XSS vulnerability because the injected JavaScript code from `xss_payload` was executed by the browser.
