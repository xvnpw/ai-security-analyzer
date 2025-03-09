## Vulnerabilities List

### Cross-Site Scripting (XSS) Vulnerability due to Improper Use of `safe` Meta Option

- **Description:**
    - Django Unicorn components, by default, HTML-encode updated field values to prevent XSS attacks. However, developers can use the `Meta.safe` option within a Django Unicorn component to explicitly bypass this HTML encoding for specific component attributes.
    - This `safe` option is intended for cases where developers need to render pre-sanitized HTML and are certain about the safety of the content. However, if a developer mistakenly uses `Meta.safe` for an attribute that is directly or indirectly populated with user-controlled data, and fails to implement proper sanitization, it can lead to Cross-Site Scripting (XSS) vulnerabilities.
    - An attacker can inject malicious HTML or JavaScript code through user input fields that are bound to a `safe` attribute using `unicorn:model` or by manipulating data passed to component methods.
    - When the component re-renders with the attacker's payload, the malicious script will be executed in the victim's browser because Django Unicorn will not HTML-encode the attribute value due to the `safe` Meta option. This bypasses the default XSS protection, and the injected script is rendered directly into the HTML output.
    - This vulnerability arises because Django Unicorn's design places the responsibility for sanitization entirely on the component developer when the `safe` option is enabled. The framework provides the mechanism to bypass encoding but does not automatically sanitize data marked as `safe`.

- **Impact:**
    - Cross-Site Scripting (XSS) vulnerability (High Severity).
    - An attacker can execute arbitrary JavaScript code in the victim's browser within the security context of the web application.
    - Successful exploitation can lead to severe consequences:
        - **Account Hijacking:** Stealing user session cookies or credentials to impersonate the user and gain unauthorized access to their accounts.
        - **Data Theft:** Accessing sensitive information, including personal data, application secrets, or any data visible to the user.
        - **Website Defacement:** Modifying the content of the web page seen by the user, damaging the website's reputation and user trust.
        - **Malicious Redirection:** Redirecting users to external malicious websites, potentially for phishing attacks or malware distribution.
        - **Unauthorized Actions:** Performing actions on behalf of the user without their consent, such as making purchases, changing settings, or disclosing private information.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
    - **Default HTML Encoding:** Django Unicorn's primary mitigation against XSS is its default behavior of HTML-encoding updated field values. This encoding is automatically applied during the component rendering process, ensuring that HTML entities are escaped, thus preventing basic XSS attacks. This default encoding is confirmed by test cases like `test_html_entities_encoded` in `tests\views\test_process_component_request.py`.
    - **Documentation and Warnings:** The documentation (`docs\source\views.md`) explicitly describes the `safe` Meta option and warns about its security implications. It states that developers must explicitly opt-in to bypass HTML encoding using `Meta.safe` and highlights that this should be done only when necessary and with caution. The documentation acts as a warning to developers about the risks associated with disabling default HTML encoding.
    - **Test Cases Demonstrating `safe` Behavior:** Test cases like `test_safe_html_entities_not_encoded` in `tests\views\test_process_component_request.py` explicitly demonstrate that the `safe` Meta option indeed disables HTML encoding, further emphasizing the developer's responsibility when using this feature.

- **Missing Mitigations:**
    - **No Automatic Sanitization for `safe` Attributes:**  Django Unicorn does not provide any built-in mechanism to automatically sanitize data even when the `Meta.safe` option is used. The framework relies entirely on the developer to perform input sanitization when bypassing default encoding.
    - **Lack of Static Code Analysis/Linting:** There is no static code analysis tool or linter integrated within Django Unicorn or recommended for use with Django Unicorn projects that can automatically detect potentially unsafe usage of `Meta.safe`. Such tools could flag instances where `Meta.safe` is used on attributes that are directly or indirectly influenced by user input without explicit sanitization.
    - **More Prominent and Explicit Documentation Guidance:** While the documentation mentions `Meta.safe`, it could be enhanced with more prominent warnings, best practices, and clear examples illustrating both safe and unsafe usage scenarios. The documentation should strongly emphasize the developer's responsibility to sanitize user input when using `Meta.safe` and recommend specific sanitization methods or libraries.
    - **Runtime Warnings in Development Mode:** In development mode, Django Unicorn could potentially issue runtime warnings if it detects components where `Meta.safe` is used for properties that are bound to user input (e.g., using `unicorn:model`) without explicit sanitization code being apparent in the component's logic.

- **Preconditions:**
    - A Django Unicorn component must be implemented.
    - The component's view class must have a `Meta` class that includes the `safe` option, listing at least one attribute in the `safe` tuple.
    - An attribute marked as `safe` must be directly or indirectly populated with user-controlled data. This is typically achieved through:
        - Binding an input field in the template to the `safe` attribute using `unicorn:model`.
        - Passing user-controlled data as arguments to component action methods that then update the `safe` attribute.
    - The template must render the `safe` attribute value directly without any further output filtering or sanitization.

- **Source Code Analysis:**
    - **`docs\source\views.md`:**  This documentation file is crucial as it describes the `safe` Meta option and its security implications. It clearly states that `safe` bypasses default HTML encoding and places sanitization responsibility on the developer.
    - **`tests\views\test_process_component_request.py`:** This file contains test cases specifically designed to verify HTML encoding behavior and the effect of the `safe` option. The tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` are key to understanding how `safe` operates and its impact on XSS prevention.
    - **`django_unicorn\views\__init__.py`:**  The function `_process_component_request` within this file is responsible for processing component requests, updating component properties based on user input, and preparing the component for rendering.  The relevant code snippet shows how `safe` attributes are handled:
    ```python
    # django_unicorn\views\__init__.py
    def _process_component_request(request: HttpRequest, component_request: ComponentRequest) -> Dict:
        # ...
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

        # Pass the current request so that it can be used inside the component template
        rendered_component = component.render(request=request)
        # ...
    ```
    This code iterates through the `safe_fields` defined in the component's `Meta` class and applies `mark_safe` to the corresponding attribute values using `django.utils.safestring.mark_safe`. `mark_safe` explicitly marks a string as safe for HTML rendering, preventing Django's template engine from escaping it. This is the mechanism that bypasses default XSS protection for `safe` attributes.
    - **`django_unicorn\components\unicorn_view.py`:** The `serialize_value` method in `UnicornView` class also plays a role in marking attributes as safe during serialization for template rendering.
    ```python
    # django_unicorn/components/unicorn_view.py
    def serialize_value(self, name: str, value: Any) -> Any:
        # ...
        if getattr(meta, "safe", None) and name in meta.safe:
            return mark_safe(value)
        # ...
    ```
    This code confirms that attributes listed in `Meta.safe` are marked as safe at the component level, influencing how they are rendered in templates.

- **Security Test Case:**
    1. **Create a Vulnerable Component:** Define a Django Unicorn component, e.g., `UnsafeComponentView`, with a `message` attribute and enable `Meta.safe` for it:
        ```python
        # example/unicorn/components/unsafe_component.py
        from django_unicorn.components import UnicornView

        class UnsafeComponentView(UnicornView):
            message = ""

            class Meta:
                safe = ("message", )
        ```
    2. **Create a Template:** Create a template for the component, `unsafe_component.html`, to render the `message` attribute within an input field and a display area:
        ```html
        {# example/unicorn/components/unsafe_component.html #}
        <div>
            <input unicorn:model="message" id="xss-input"/>
            <div id="message-output">{{ message }}</div>
        </div>
        ```
    3. **Create a Django View and URL:** Set up a Django view and URL to render a page that includes this `UnsafeComponent`.
    4. **Access the Page:** Navigate to the page in a browser where the `UnsafeComponent` is rendered.
    5. **Inject XSS Payload:** In the input field of the component (identified by `id="xss-input"`), enter the following malicious JavaScript payload: `<img src='x' onerror='alert("XSS Vulnerability!")'>`.
    6. **Trigger Component Update:** Click outside the input field, or trigger any action that causes the component to update and re-render (depending on the `unicorn:model` modifier used, if any).
    7. **Observe XSS Execution:** An alert box with "XSS Vulnerability!" should appear in the browser. This confirms that the injected JavaScript code was executed due to the improper use of `Meta.safe`.
    8. **Inspect HTML Output:** Examine the HTML source of the rendered component (specifically the `message-output` div). You should observe that the injected payload `<img src='x' onerror='alert("XSS Vulnerability!")'>` is rendered directly as HTML without encoding, confirming that the `safe` option bypassed HTML escaping and led to the XSS vulnerability.
