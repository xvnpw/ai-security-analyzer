- Vulnerability Name: Cross-Site Scripting (XSS) via `Meta.safe` attribute
- Description:
    1. A developer uses the `Meta.safe` attribute within a Django Unicorn component to mark a property as safe from HTML encoding.
    2. User-controlled input is bound to this property using `unicorn:model`.
    3. An attacker injects malicious JavaScript code as input.
    4. Due to the `Meta.safe` attribute, the injected JavaScript is not HTML-encoded when the component is re-rendered.
    5. The browser executes the attacker's JavaScript code, leading to XSS.
- Impact:
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, defacement, or any other action the attacker can script in JavaScript, performed in the context of the victim user's session.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - By default, Django Unicorn HTML-encodes updated field values to prevent XSS. This is a general mitigation.
    - Documentation warns against putting sensitive data into public properties.
    - Documentation explains the purpose and usage of `Meta.safe` and `safe` template filter, implicitly warning against misuse by highlighting the responsibility of developers when using it.
- Missing Mitigations:
    - No explicit warnings or checks in the code to prevent developers from using `Meta.safe` with user-controlled input without proper sanitization.
    - No built-in sanitization functions are enforced when using `Meta.safe`.
- Preconditions:
    - A Django Unicorn component uses `Meta.safe` to mark a property as safe.
    - User input is bound to this property using `unicorn:model`.
    - The developer using `Meta.safe` fails to properly sanitize user input before marking it as safe.
- Source Code Analysis:
    1. In `django_unicorn/components/unicorn_template_response.py`, the `UnicornTemplateResponse.render` method is responsible for rendering the component and handling data serialization.
    2. Inside `UnicornTemplateResponse.render`, the line `root_element["unicorn:data"] = frontend_context_variables` serializes component data to be included in the HTML.
    3. The `frontend_context_variables` are prepared in the `UnicornView.get_frontend_context_variables` method in `django_unicorn/components/unicorn_view.py`.
    4. In `UnicornView.get_frontend_context_variables`, the code iterates through `safe_fields` which are defined in `Meta.safe`.
    5. For fields listed in `Meta.safe`, the code sets the value as `mark_safe(value)` if the value is a string, effectively bypassing HTML encoding for these specific properties during template rendering.
    6. If a developer marks a property that directly reflects user input (e.g., from `unicorn:model`) as `safe` without sanitizing it, any malicious JavaScript injected by a user will be rendered directly into the HTML output without encoding, leading to XSS.

    ```python
    # File: django_unicorn/components/unicorn_view.py

    def get_frontend_context_variables(self) -> str:
        ...
        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(self, field_name)
            if isinstance(value, str):
                setattr(self, field_name, mark_safe(value))  # noqa: S308
        ...
    ```

    Visualization:

    ```
    User Input (Malicious JS) --> unicorn:model --> Component Property (marked as Meta.safe) --> get_frontend_context_variables --> mark_safe() --> UnicornTemplateResponse.render --> HTML Output (Unsanitized JS) --> Browser executes JS (XSS)
    ```
- Security Test Case:
    1. Create a Django Unicorn component named `xss_safe_component` within a Django app.
    2. In `components/xss_safe_component.py`, define the component view with a `text` property and mark it as `safe` in `Meta`.

    ```python
    # File: components/xss_safe_component.py
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        text = ""

        class Meta:
            safe = ("text", )
    ```
    3. In `templates/unicorn/xss_safe_component.html`, create a template with an input bound to the `text` property and display the `text` property in the template.

    ```html
    <!-- File: templates/unicorn/xss_safe_component.html -->
    <div>
        <input type="text" unicorn:model="text">
        <div id="output">Output: {{ text }}</div>
    </div>
    ```
    4. Create a Django template, e.g., `xss_safe_test.html`, to include the `xss_safe_component`.

    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        <h1>XSS via Meta.safe Vulnerability Test</h1>
        {% unicorn 'xss-safe' %}
    </body>
    </html>
    ```
    5. Create a Django view and URL path to render `xss_safe_test.html`.
    6. Access the `xss_safe_test` URL in a browser.
    7. In the input field, enter the following JavaScript payload: `<img src=x onerror=alert('XSS Vulnerability')>`
    8. Observe that after typing the input and triggering an update (e.g., by clicking outside the input field), an alert box with "XSS Vulnerability" appears.
    9. This confirms that the JavaScript code injected through the input field was executed because `Meta.safe` prevented HTML encoding.
