- Vulnerability Name: Cross-Site Scripting (XSS) in Component Property Rendering
  - Description:
    1. An attacker can inject malicious JavaScript code into a component property.
    2. The application renders this property in a Django template without proper sanitization.
    3. When a user views the page, the malicious script executes in their browser, potentially leading to session hijacking, cookie theft, or other malicious actions.
  - Impact:
    - Cross-Site Scripting (XSS) allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, defacement of the website, or redirection to malicious sites.
    - In the context of Django Unicorn, this vulnerability can be triggered by injecting malicious scripts into component properties that are dynamically rendered in templates.
  - Vulnerability Rank: High
  - Currently Implemented Mitigations:
    - Django's automatic escaping is likely in use for general template rendering, but it might be insufficient for reactive updates where content is dynamically injected.
    - The documentation mentions "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks." in `views.md#safe`. This suggests that encoding is applied by default, but there might be bypasses or unsafe configurations. The `safe` Meta attribute explicitly disables this encoding for specified fields.
  - Missing Mitigations:
    - Explicit Content Security Policy (CSP) headers to restrict the sources from which the browser is permitted to load resources.
    - Ensure that all dynamically rendered content, especially user-provided data, is consistently and properly sanitized before being injected into the DOM, even with default HTML encoding enabled.
    - Consider using a strict templating engine that automatically escapes all variables by default, requiring explicit "safe" filters for unescaped output, and auditing usage of `|safe` filter and `safe` Meta attribute.
  - Preconditions:
    - The application must be using Django Unicorn to render dynamic components.
    - An attacker needs to find an injection point where component properties are rendered without sufficient sanitization. This could be through URL parameters, form inputs, or any other user-controlled data that can influence component properties.
  - Source Code Analysis:
    1. **`django_unicorn/components/unicorn_template_response.py`**: This file is responsible for rendering the component and updating the DOM. The `UnicornTemplateResponse.render()` method uses `BeautifulSoup` to parse and modify the template. It serializes component data into JSON and embeds it in the HTML. It also handles morphing the DOM.
    2. **`UnicornTemplateResponse.render()` method**: It calls `sanitize_html(init)` for the initial JSON data. Let's examine `sanitize_html` function.
    3. **`django_unicorn/utils.py`**: `sanitize_html` uses `html.escape` which should provide basic HTML entity encoding.
    4. **`views.md#safe`**: Documentation mentions `Meta.safe` attribute to disable HTML encoding. This is a potential area of concern if developers are encouraged or default to using `safe` without understanding the implications.
    5. **`views.Meta.safe`**: If `safe` is used, the output will *not* be encoded. This is a clear path for XSS if used improperly.
    6. **`templates.md`**:  Describes `unicorn:model` and rendering with `{{ }}`. If a component property bound to `unicorn:model` is marked as `safe` or if there's a bypass in the default encoding, XSS is possible.

    **Visualization:**

    ```
    User Input --> unicorn:model --> Component Property --> Template Rendering ({{ }}) --> DOM (Potential XSS if not sanitized)
    ```

    **Code Snippet from `views.md#safe`**:
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
    In `SafeExampleView`, `something_safe` will *not* be encoded, as explicitly intended by the developer using `Meta.safe`. This is a documented feature that, if misused, becomes a vulnerability.

  - Security Test Case:
    1. **Vulnerability Component**: Create a new Django Unicorn component named `xss_test`.
    2. **Vulnerability View (`xss_test.py`):**
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        malicious_code = ""

        class Meta:
            safe = ("malicious_code", ) # Simulate developer explicitly marking field as safe

        def mount(self):
            self.malicious_code = "<img src='x' onerror='alert(\"XSS Vulnerability\")'>"
    ```
    3. **Vulnerability Template (`xss_test.html`):**
    ```html
    <div>
        {{ malicious_code }}
    </div>
    ```
    4. **Test Template**: Include the `xss_test` component in a test Django template, e.g., `xss_test_template.html`:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% unicorn 'xss_test' %}
    </body>
    </html>
    ```
    5. **Access the Test Template**: Create a Django view to render `xss_test_template.html` and access it via a browser.
    6. **Verify XSS**: Observe if an alert box with "XSS Vulnerability" appears when the page loads. If the alert box appears, it confirms that the malicious JavaScript code injected into the `malicious_code` property was executed, demonstrating the XSS vulnerability when `safe` is used.

    This test case demonstrates that when `Meta.safe` is used, XSS is possible if malicious content is rendered. This confirms the vulnerability when explicit mitigations are bypassed by developers. The risk is present whenever `Meta.safe` is used and the developer does not manually sanitize the input.
