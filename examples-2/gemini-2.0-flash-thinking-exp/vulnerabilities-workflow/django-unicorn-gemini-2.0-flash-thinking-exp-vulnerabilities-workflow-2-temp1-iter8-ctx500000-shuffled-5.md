- ### Vulnerability 1: Cross-Site Scripting (XSS) due to unsafe usage of `safe` mark

    - Description:
        1. A developer uses `unicorn:model` to bind a user-controlled input field to a component property.
        2. The developer intends to render this property as raw HTML in the template, and thus adds the property name to the `Meta.safe` tuple in the component view or uses the `|safe` template filter.
        3. An attacker injects malicious JavaScript code into the user-controlled input field.
        4. When the component re-renders, the malicious JavaScript code is rendered directly into the HTML without proper sanitization because the developer has marked it as `safe`.
        5. The attacker's JavaScript code is then executed in the user's browser, leading to XSS.

    - Impact:
        - Critical. An attacker can execute arbitrary JavaScript code in the context of the user's session. This can lead to account takeover, data theft, malware distribution, and other malicious activities.

    - Vulnerability Rank: critical

    - Currently Implemented Mitigations:
        - By default, django-unicorn HTML-encodes all component properties to prevent XSS. This is a global mitigation.
        - Developers need to explicitly use `Meta.safe` or `|safe` filter to disable HTML encoding for specific properties or template variables, indicating a conscious decision to render raw HTML.

    - Missing Mitigations:
        - No further mitigations are implemented beyond the default HTML encoding and the explicit opt-in for raw HTML rendering.
        - It would be beneficial to have documentation that strongly warns against using `Meta.safe` or `|safe` with user-controlled input without proper sanitization of the input beforehand.
        -  Ideally, the library could provide utilities or guidance on how to sanitize user input if raw HTML rendering is absolutely necessary.

    - Preconditions:
        1. A Django Unicorn component with a property bound to a user-controlled input field using `unicorn:model`.
        2. The developer has marked this property as `safe` either in `Meta.safe` or using the `|safe` template filter.
        3. An attacker has the ability to input arbitrary text into the user-controlled input field.

    - Source Code Analysis:
        - In `django_unicorn\components\unicorn_template_response.py`, the `UnicornTemplateResponse.render` method is responsible for rendering the component and handling XSS mitigation.
        - The documentation in `docs\source\views.md` and `docs\source\templates.md` clearly states that HTML encoding is the default behavior and that `Meta.safe` and `|safe` are used to bypass this encoding.
        - The code itself does not perform any sanitization when `safe` is used; it directly renders the property value.
        - Example from `docs\source\views.md`:
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
            - In this example, if `something_safe` is populated with user input and marked as safe, any malicious script in the user input will be rendered and executed.

    - Security Test Case:
        1. Create a Django Unicorn component with a property `xss_input` and bind it to a text input using `unicorn:model`.
        2. Mark `xss_input` as safe using `Meta.safe = ("xss_input",)`.
        3. Create a template that renders `xss_input` within the component.
        4. Access the page with the component in a browser.
        5. In the input field, enter the following payload: `<script>alert("XSS Vulnerability")</script>`.
        6. Interact with the component in a way that triggers a re-render (e.g., type another character in the input field, or click a button that updates the component).
        7. Observe that an alert box with "XSS Vulnerability" appears, confirming the execution of the injected JavaScript code.
