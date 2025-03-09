## Vulnerability List for django-unicorn

### 1. Unsafe HTML rendering in `safe` context could lead to Cross-Site Scripting (XSS)

* Description:
    1. A Django Unicorn component uses `Meta.safe` to mark a property as safe for HTML rendering.
    2. The component directly assigns user-controlled input to this `safe` property without proper sanitization.
    3. An attacker crafts malicious HTML or JavaScript code and inputs it through a user interface element bound to the `safe` property (e.g., using `unicorn:model`).
    4. When the component updates, Django Unicorn renders the attacker-controlled, unsanitized HTML directly into the DOM because it is marked as `safe`.
    5. The malicious script executes in the victim's browser, potentially leading to session hijacking, cookie theft, or other malicious actions.

* Impact:
    * High: Cross-Site Scripting (XSS). An attacker can execute arbitrary JavaScript code in the context of the user's session. This can lead to account takeover, data theft, or defacement of the application.

* Vulnerability Rank: high

* Currently implemented mitigations:
    * Django Unicorn by default HTML-encodes updated field values to prevent XSS attacks. This is the primary mitigation.
    * Developers have to explicitly opt-in to disable HTML encoding by using `Meta.safe`.

* Missing mitigations:
    * Django Unicorn does not provide built-in sanitization or validation for properties marked as `safe`. It relies on the developer to ensure that any data marked as safe is properly sanitized before being assigned to the property.
    * There is no warning or guidance in the documentation about the critical security implications of using `Meta.safe` without proper sanitization. The documentation only states "You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." and "Never put sensitive data into a public property because that information will publicly available in the HTML source code, unless explicitly prevented with [`javascript_exclude`](views.md#javascript_exclude)." without explicitly mentioning XSS risk related to `safe`.

* Preconditions:
    * A Django Unicorn component must:
        * Define a property and mark it as `safe` in `Meta.safe`.
        * Bind a user input element (e.g., `<input unicorn:model="...">`) to this `safe` property.
        * Not sanitize user input before assigning it to the `safe` property in the component's Python code.

* Source code analysis:
    1. **`views.md` documentation**: Describes the `Meta.safe` option and mentions that "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." This indicates that the default behavior is safe, but using `safe` requires careful handling of data.
    2. **`django_unicorn/components/UnicornView` class**: Review the code that handles property updates and rendering, specifically how `safe` properties are processed. (Code not provided in PROJECT FILES, needs further investigation in actual source code).
    3. **`django_unicorn/templatetags/unicorn.py`**: Examine the template tag rendering logic to see how properties marked as `safe` are handled during template rendering and DOM updates. (Code not provided in PROJECT FILES, needs further investigation in actual source code).
    4. **`django_unicorn/views/__init__.py`**: In `_process_component_request` function, lines:
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
       This code snippet retrieves field names marked as `safe` in the component's `Meta` class. For each of these fields, if the value is a string, it's marked as safe using `mark_safe(value)`. This means that during template rendering, Django will not escape the HTML content of these fields, potentially leading to XSS if the content is user-provided and not sanitized.

* Security test case:
    1. Create a Django Unicorn component named `xss_component`.
    2. In `xss_component.py`, define a property `unsafe_content` and mark it as `safe` in the `Meta` class. Leave the component-side sanitization out.
    ```python
    # xss_component.py
    from django_unicorn.components import UnicornView

    class XssComponentView(UnicornView):
        unsafe_content = ""

        class Meta:
            safe = ("unsafe_content", )
    ```
    3. In `xss_component.html`, create an input field bound to `unsafe_content` and render `unsafe_content` in the template.
    ```html
    {# xss_component.html #}
    <div>
        <input type="text" unicorn:model="unsafe_content">
        <div id="content-area">
            {{ unsafe_content }}
        </div>
    </div>
    ```
    4. Create a Django template that includes the `xss_component`.
    ```html
    {# test_xss.html #}
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-component' %}
    </body>
    </html>
    ```
    5. Create a Django view to render `test_xss.html` and add URL mapping.
    6. Access the page in a browser.
    7. In the input field, enter the following XSS payload: `<img src=x onerror="alert('XSS')">`.
    8. Observe if an alert box appears when you type or blur the input field. If the alert box appears, the vulnerability is confirmed.
    9. Inspect the HTML source of the rendered component in the browser's developer tools. Check if the XSS payload is rendered without HTML encoding inside the `content-area` div.

* Missing mitigations:
    * Implement a warning or error when `Meta.safe` is used without explicit sanitization.
    * Provide clear documentation and best practices for using `Meta.safe` securely, emphasizing the risk of XSS and the need for sanitization.
    * Consider adding built-in sanitization options or guidelines within Django Unicorn for developers who need to render user-provided HTML content safely.
