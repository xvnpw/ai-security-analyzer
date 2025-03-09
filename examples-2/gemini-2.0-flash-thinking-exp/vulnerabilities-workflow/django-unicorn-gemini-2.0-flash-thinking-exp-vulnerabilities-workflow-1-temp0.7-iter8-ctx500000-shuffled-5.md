### Vulnerability List for django-unicorn Project

* Vulnerability Name: Cross-Site Scripting (XSS) via Unsafe HTML Attributes

* Description:
    1. An attacker can inject malicious JavaScript code through component's properties if the `safe` meta attribute is enabled or if the output is not properly sanitized.
    2. Assume a component has a property that renders user-controlled data as HTML attributes, and the `safe` attribute is mistakenly used for this property in the component's Meta class.
    3. An attacker provides a malicious string containing JavaScript code (e.g., `<img src=x onerror=alert('XSS')>`) as input to this property through a `unicorn:model` or as an argument to a `unicorn:call` method.
    4. When the component re-renders, the malicious JavaScript is embedded directly into the HTML attribute without proper sanitization because of `safe` attribute.
    5. The victim's browser executes the injected JavaScript when rendering the component, leading to XSS.

* Impact:
    - Critical
    - Execution of arbitrary JavaScript code in the victim's browser.
    - Session hijacking, cookie theft, redirection to malicious sites, defacement, or other malicious actions depending on the attacker's payload.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    - By default, django-unicorn HTML encodes updated field values to prevent XSS attacks (described in `views.md`).
    - The documentation warns against putting sensitive data into public properties and mentions the `javascript_exclude` Meta option to prevent data from being exposed to JavaScript.
    - The documentation describes the `safe` Meta option to explicitly allow a field to be returned without encoding (described in `views.md`).

    - Mitigation location: Default behavior of django-unicorn templates, documentation in `views.md`.

* Missing Mitigations:
    - While encoding is the default, the `safe` attribute can disable it, and if developers mistakenly use `safe` attribute for user-controlled HTML attributes, it can lead to XSS.
    - There's no clear mechanism to enforce secure defaults and prevent developers from accidentally introducing XSS when using `safe`.
    - Missing clear guidelines and security warnings in documentation about the risks of using `safe` and when it is appropriate (and when it is not).

* Preconditions:
    - Developer must explicitly use `safe` Meta attribute for a component property that renders user-controlled data into HTML attributes.
    - An attacker must be able to control the data that is bound to this property (e.g., through `unicorn:model` or `unicorn:call` arguments).

* Source Code Analysis:
    - Based on documentation (`views.md#safe`), django-unicorn by default HTML encodes output to prevent XSS.
    - The `safe` Meta attribute (`views.md#safe`) is explicitly designed to bypass this encoding.
    - If a developer configures `safe = ("something_safe", )` in Meta and uses `{{ something_safe }}` in template within an HTML attribute (e.g., `<div data-attribute="{{ something_safe }}">`), and `something_safe` is user-controlled, then XSS is possible.
    - Example from `views.md`:
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
    - If `something_safe` contains malicious JavaScript, it will be rendered without encoding because of `safe` attribute, leading to XSS if used within HTML attribute context.

* Security Test Case:
    1. Create a django-unicorn component named `xss_safe_component` with a property `unsafe_data` and `safe = ("unsafe_data", )` in `Meta`.
    2. In the component's template, render `unsafe_data` in an HTML attribute, e.g., `<div data-user-input="{{ unsafe_data }}">`.
    3. Create a view that renders this component.
    4. As an attacker, send a request to the view rendering `xss_safe_component` with a malicious payload for `unsafe_data` via `unicorn:model`, e.g., `<input type="text" unicorn:model="unsafe_data" value="<img src=x onerror=alert('XSS')>">`.
    5. Submit the form to trigger a component update.
    6. Observe that the rendered HTML in the response contains the injected JavaScript directly in the `data-user-input` attribute: `<div unicorn:id="..." unicorn:name="..." unicorn:checksum="..." unicorn:data="..." data-user-input="<img src=x onerror=alert('XSS')>" unicorn:calls="...">`.
    7. Render the response in a browser.
    8. Verify that the JavaScript `alert('XSS')` is executed, demonstrating the XSS vulnerability.

    Security Test Case Steps:
    1. Create component `xss_safe_component` in `unicorn/components/xss_safe_component.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssSafeComponentView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data", )
    ```
    2. Create template `unicorn/templates/unicorn/xss_safe_component.html`:
    ```html
    <div>
        <div id="xss-test" data-user-input="{{ unsafe_data }}"></div>
        <input type="text" unicorn:model="unsafe_data">
    </div>
    ```
    3. Create view in `www/views.py`:
    ```python
    from django.shortcuts import render
    from django_unicorn.components import UnicornView

    def xss_safe_view(request):
        return render(request, 'www/xss_safe.html')
    ```
    4. Create template `www/xss_safe.html`:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-safe-component' %}
    </body>
    </html>
    ```
    5. Add URL to `project/urls.py`:
    ```python
    path("xss-safe", views.xss_safe_view, name="xss_safe"),
    ```
    6. Run the Django development server.
    7. Open browser and navigate to `/xss-safe`.
    8. In the input field, enter `<img src=x onerror=alert('XSS')>`.
    9. Click outside the input field to trigger `lazy` or submit the form.
    10. Observe that an alert box with 'XSS' is displayed, confirming the vulnerability.

* Missing Mitigations:
    - Improve documentation to strongly discourage using `safe` for user-controlled data, especially in HTML attribute contexts.
    - Consider providing alternative, safer ways to handle cases where developers might be tempted to use `safe`, such as specific sanitization helpers or template filters that can be used selectively.
    - Maybe add a warning in the `Meta` class or during component initialization if `safe` is used without explicit developer acknowledgement of the risks.
    - Security documentation section specifically for XSS prevention and safe practices in django-unicorn components.
