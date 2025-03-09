* Vulnerability name: Cross-Site Scripting (XSS) via unsafe template rendering

* Description:
    1. An attacker can inject malicious JavaScript code into component properties. This can be achieved through various mechanisms, including:
        - Model binding (`unicorn:model`): User input from form fields or other interactive elements can be directly bound to component properties.
        - Action arguments: Arguments passed to component actions, which are often triggered by user interactions, can also be attacker-controlled.
    2. If a developer then renders these component properties in a template using the `safe` filter or the `safe` attribute in the component's `Meta` class, the injected JavaScript code will be rendered without proper sanitization. The `safe` filter and `Meta.safe` attribute are intended for developers to explicitly mark content as safe HTML, bypassing Django's automatic HTML escaping.
    3. When a user views the rendered component, the injected JavaScript code will be executed in their browser. This can allow the attacker to perform a wide range of malicious actions, such as stealing session cookies, redirecting the user to a malicious website, defacing the website, or even performing actions on behalf of the user.

* Impact:
    Critical. Successful exploitation allows an attacker to execute arbitrary JavaScript code in the context of a user's session when they interact with the vulnerable component. This can lead to complete account takeover, exposure of sensitive data, manipulation of user data, and other severe security breaches. The impact is critical because XSS vulnerabilities are often easily exploitable and can have widespread consequences.

* Vulnerability rank: Critical

* Currently implemented mitigations:
    - **Default HTML Encoding:** django-unicorn, starting from version 0.36.0, automatically HTML-encodes responses by default. This is a global mitigation that significantly reduces the risk of XSS in most cases. This behavior is confirmed by the analysis of `changelog.md` in previous steps.
    - **Explicit `safe` usage:** Developers are forced to explicitly use the `safe` filter in templates or define `Meta.safe` in components when they intentionally need to render unescaped HTML. This design decision pushes the responsibility for ensuring the safety of dynamically rendered content onto the developer.
    - **`sanitize_html` for JSON data:** The `sanitize_html` function in `django_unicorn.utils` is used to escape HTML characters in JSON data that is embedded within `<script>` tags and sent to the frontend for the component's initial state. This mitigates XSS risks specifically within the component's initial data payload.

* Missing mitigations:
    - **Lack of Security Guidance:** The documentation (as analyzed in previous steps and `docs/source/conf.py`) does not adequately emphasize the security risks associated with using the `safe` filter or `Meta.safe`. Developers may not fully understand the implications of bypassing HTML escaping, potentially leading to unintentional XSS vulnerabilities when using these features.
    - **Absence of Usage Warnings:** django-unicorn does not provide any warnings or alerts during component rendering to highlight when the `safe` filter or `Meta.safe` is being used. Such warnings could encourage developers to carefully review the source of the data being rendered unsafely and ensure it is properly sanitized or originates from a trusted source.
    - **No Built-in Sanitization for `safe`:** While django-unicorn provides `sanitize_html` for JSON data, it lacks a built-in, recommended sanitization mechanism specifically designed for use with the `safe` filter in templates or `Meta.safe`. Developers are left to implement their own sanitization, which can be error-prone if not done correctly.

* Preconditions:
    1. **`safe` filter or `Meta.safe` usage:** A developer must explicitly use the `safe` filter in a Django template or declare a component property as `safe` in the `Meta` class. This is a necessary condition for bypassing django-unicorn's default HTML encoding and introducing the risk of XSS.
    2. **Attacker-controlled data:** An attacker must have control over the data that is eventually rendered using the `safe` filter or `Meta.safe`. This can be achieved through:
        - **`unicorn:model` binding:** If a component property rendered with `safe` is bound to user input using `unicorn:model`, any malicious input provided by the user will be rendered unsafely.
        - **Action arguments:** If a component action accepts arguments that are then rendered unsafely, and these arguments can be manipulated by the attacker (e.g., through URL parameters or form data), XSS is possible.

* Source code analysis:
    1. **`views.md`**: (Analyzed in previous steps) This documentation file introduces and explains the `safe` Meta attribute and the `safe` template filter, highlighting their intended usage for developers.
    2. **`serializer.py`**: (Analyzed in previous steps) The `dumps` function in `django_unicorn\django_unicorn\serializer.py` handles the serialization of data sent to the frontend. While it doesn't perform HTML encoding for template rendering directly, it is relevant as it shows how data is passed from the backend to the frontend.
    3. **`templates.md`**: (Analyzed in previous steps) This documentation file explains "`unicorn:model` updates are triggered by listening to `input` events". This is crucial as it directly links user input to component property updates, which can then be rendered using `safe`.
    4. **`changelog.md`**: (Analyzed in previous steps) Version 0.36.0 documents the security fix and the change to default HTML encoding of responses, emphasizing the importance of this mitigation and implicitly highlighting the risk of XSS when `safe` is used.
    5. **`components/unicorn_template_response.py`**: The `UnicornTemplateResponse` class in `django_unicorn\django_unicorn\components\unicorn_template_response.py` is responsible for rendering component templates. It uses Django's template engine, which by default escapes HTML unless the `safe` filter is applied. `django-unicorn` does not add any extra sanitization layer during template rendering itself beyond Django's default behavior and the explicit use of `safe`. The `sanitize_html` function is used only for the JSON data embedded in `<script>` tags for initial component state, not for the template rendering with `safe`.
    6. **`templatetags/unicorn.py`**: The `unicorn` template tag in `django_unicorn\django_unicorn\templatetags\unicorn.py` orchestrates the component rendering process. It utilizes `UnicornView.create` to instantiate the component and then calls `self.view.render(...)`. The core template rendering is handled by Django, and django-unicorn relies on Django's template engine for HTML escaping (unless `safe` is used).
    7. **`tests/test_utils.py`**:  The `test_sanitize_html` test confirms that the `sanitize_html` function properly escapes `<script>` tags. This reinforces that `sanitize_html` is a specific mitigation for XSS within the JSON data, but not a general solution for unsafely rendered template content when `safe` is used.
    8. **`test_set_property_from_data.py`**: This test file demonstrates how component properties are updated based on data received from the frontend. It shows that various data types, including strings and potentially malicious payloads, can be set as component properties. This is relevant as these properties could then be rendered unsafely using `safe`.

    **Visualization:**
    ```
    User Input (via unicorn:model or action args) --> Component Property --> Template Rendering (with or without 'safe') --> HTML Response --> User Browser
    ```
    If "safe" is used in the Template Rendering step and User Input contains malicious JavaScript, XSS occurs.

* Security test case:
    1. Create a django-unicorn component with a property designed to hold potentially unsafe data, for example, `unsafe_data`.
    2. In the component's template, render the `unsafe_data` property using the `safe` filter: `{{ unsafe_data|safe }}`. This intentionally bypasses HTML escaping for this specific property.
    3. Create a Django view that uses this component and sets the `unsafe_data` property to a string containing malicious JavaScript code. A simple example payload is: `<img src=x onerror=alert("XSS_VULN_SAFE_FILTER")>`. You can set this property directly in the view when instantiating the component, or allow it to be dynamically updated via a `unicorn:model` binding in a more complex scenario.
    4. Serve the Django view and access the page containing the unicorn component in a web browser.
    5. Observe that the JavaScript code injected into `unsafe_data` is executed by the browser. In this test case, an alert box with the message "XSS_VULN_SAFE_FILTER" should appear, confirming the XSS vulnerability when the `safe` filter is used with attacker-controlled data.

    **Detailed steps:**
    1. Create a new Django app named `vulntest`.
    2. In `vulntest/components/xss_test.py`, define a simple unicorn component:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        unsafe_data = ""
    ```
    3. Create the component template at `vulntest/templates/unicorn/xss-test.html`:
    ```html
    <div>
        <p>Unsafe Data: {{ unsafe_data|safe }}</p>
    </div>
    ```
    4. In `vulntest/views.py`, create a Django view to render the component and pass in the malicious payload:
    ```python
    from django.shortcuts import render
    from vulntest.components.xss_test import XssTestView

    def xss_test_view(request):
        component = XssTestView()
        component.unsafe_data = '<img src=x onerror=alert("XSS_VULN_SAFE_FILTER")>'
        return render(request, 'xss_test.html', {'component': component})
    ```
    5. Create a Django template `vulntest/templates/xss_test.html` to include the unicorn component and necessary scripts:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn component %}
    </body>
    </html>
    ```
    6. Configure `urls.py` in your `vulntest` app to map the URL path `/xss-test/` to the `xss_test_view` view function.
    7. Start the Django development server using `python manage.py runserver`.
    8. Open a web browser and navigate to `http://127.0.0.1:8000/xss-test/` (or the appropriate address if your server is configured differently).
    9. Observe that an alert dialog box appears with the message "XSS_VULN_SAFE_FILTER". This confirms that the JavaScript code injected as `unsafe_data` was executed, demonstrating the XSS vulnerability when the `safe` filter is used with potentially malicious user input.

This vulnerability remains a critical security issue. While django-unicorn provides default HTML encoding as a general mitigation, the explicit use of the `safe` filter or `Meta.safe` still creates a significant XSS risk if developers are not extremely cautious about the data they render unsafely. Improved documentation, warnings, and potentially built-in sanitization options for `safe` usage are crucial missing mitigations. The analysis of the new files reinforces the understanding of data flow and property setting, further highlighting the attack surface related to user-controlled data and unsafe rendering with `safe`.
