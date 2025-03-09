### Vulnerability List

- Vulnerability Name: Cross-Site Scripting (XSS) Vulnerability due to Opt-in rather than Default Sanitization in Component Rendering
- Description:
    1. An attacker can inject malicious JavaScript code into a component's property, for example through URL parameters, form inputs, or other data sources that a component processes.
    2. The attacker crafts a request to trigger a component update where the malicious JavaScript is part of the updated property.
    3. Django-unicorn re-renders the component, including the attacker-controlled property value into the HTML template.
    4. **If the component template renders this property value without using the `safe` filter or declaring `Meta.safe = False` for the component or property, and if the developer assumes default sanitization but it is not in place for all contexts, then the application becomes vulnerable.**  Specifically, while django-unicorn defaults to HTML-encoding all component data, developers might incorrectly assume that rendering data without the `safe` filter or `Meta.safe` is inherently safe in all situations. If they misunderstand the opt-in nature of disabling HTML encoding with `safe`, they might inadvertently introduce XSS vulnerabilities.
    5. When the re-rendered HTML is merged into the DOM on the client-side, the malicious JavaScript is executed in the user's browser if not properly handled by the developer in the template by ensuring data from untrusted sources is always treated as unsafe by default.
- Impact:
    - Execution of arbitrary JavaScript code in the victim's browser.
    - Account takeover if session cookies are stolen.
    - Stealing of sensitive information (cookies, session tokens, user data).
    - Defacement of the website or specific component.
    - Redirection to malicious websites, potentially for phishing or malware distribution.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - **Default HTML Encoding:** Django-unicorn version 0.36.0 and later versions implement default HTML encoding for component properties when rendered in templates. This is intended to prevent XSS by escaping HTML characters. This behavior is mentioned in the changelog of version 0.36.0 and documented in `views.md`.
    - **Opt-out mechanism using `safe`:** Django-unicorn provides mechanisms to bypass the default HTML encoding when developers explicitly need to render raw HTML. This can be achieved using the `safe` template filter in templates or by setting `Meta.safe = False` at the component or property level. This is documented in `views.md#safe`.
- Missing Mitigations:
    - **Lack of Clear and Prominent Security Guidance:** While mitigations are present, the documentation should more prominently emphasize the security implications of using the `safe` filter and `Meta.safe = False`. It should strongly advise developers to always treat user-provided data as unsafe by default and to only use `safe` when absolutely necessary and after careful consideration of the security context.
    - **No automatic Content Security Policy (CSP) integration:** Django-unicorn does not automatically set up or recommend Content Security Policy (CSP) headers. CSP can significantly reduce the impact of XSS vulnerabilities by controlling the resources the browser is allowed to load and execute. While CSP is a general web security measure and not specific to django-unicorn, its importance in mitigating XSS risks in dynamic web applications should be highlighted in the documentation and potentially offer guidance on how to implement it effectively within Django applications using django-unicorn.
- Preconditions:
    - The application must be using django-unicorn components and rendering user-controlled data within these components in templates without proper usage of `safe` filter or `Meta.safe`.
    - An attacker must be able to influence a component's property value through user-controlled input mechanisms that get processed by the component's backend logic and reflected in the template.
- Source Code Analysis:
    - **`django_unicorn/utils.py` and `django_unicorn/components/unicorn_template_response.py`:** The `sanitize_html` function in `utils.py` is used for JSON serialization within the component's initial JavaScript data (`init` script). This function escapes HTML characters for JSON safety, but it is not applied to the general HTML template rendering of component properties.
    - **`django_unicorn/views/__init__.py`:** The `_process_component_request` function in `views/__init__.py` is responsible for rendering components. It includes logic to mark "safe" attributes as safe using `mark_safe` based on `Meta.safe` declaration. This is the primary mechanism for developers to bypass default HTML encoding, and conversely, the default behavior is to HTML-encode properties not marked as safe.
    - **Template Rendering Process:** Django templates, by default, automatically HTML-escape variables when rendered using `{{ variable }}`. Django-unicorn leverages this default Django behavior for properties that are *not* marked as `safe`. However, developers must be aware that if they use template constructs like `{% if ... %}` or `{% with ... %}` and introduce user-controlled data within these blocks without proper escaping, they could still introduce XSS if not using `safe` filter correctly within these contexts or for properties.
    - **Action Handlers and Property Updates (`django_unicorn/views/action_parsers/*` and `django_unicorn/views/utils.py`):** The code responsible for handling actions (`sync_input`, `call_method`) and updating component properties does not include any explicit HTML sanitization at the point of updating the component's state. It relies on the default Django template escaping mechanism and the developer's use of `safe` (or lack thereof) in the templates to handle XSS prevention.
- Security Test Case:
    1. Create a django-unicorn component named `unsafe_render_test`.
    2. In `unsafe_render_test.py`, define a property `user_input` initialized with an empty string:
    ```python
    from django_unicorn.components import UnicornView

    class UnsafeRenderTestView(UnicornView):
        user_input = ""

        def set_input(self, input_value):
            self.user_input = input_value
    ```
    3. Create a template `unicorn/unsafe-render-test.html` for the component that renders the `user_input` property directly without any `safe` filter or `Meta.safe` declaration:
    ```html
    <div>
        <input type="text" unicorn:model="user_input" />
        <div id="output">
            {{ user_input }}
        </div>
        <button unicorn:click="set_input('Set via Button')">Set Input</button>
    </div>
    ```
    4. Create a Django view and template to render the `unsafe_render_test` component on a page.
    5. Access the page in a browser.
    6. In the input field, enter a JavaScript payload, for example: `<img src=x onerror=alert('XSS')>`.
    7. Click outside the input field or trigger an update (e.g., by typing or using the button which calls `set_input`).
    8. **Expected Result (Vulnerable):** An alert box with 'XSS' will be displayed, indicating that the JavaScript payload was executed. Inspecting the HTML source of the `output` div should show the unescaped `<img>` tag.
    9. **Mitigation Test:**
        - **Template Filter Mitigation:** Modify the template `unicorn/unsafe-render-test.html` to use the `safe` filter: `{{ user_input|safe }}`. Repeat steps 5-8. **Expected Result (Mitigated with `safe` incorrectly used):** The alert box will be displayed, demonstrating that `safe` filter bypasses encoding and makes it vulnerable.
        - **No `safe` and Default Encoding (Correct Mitigation):** Remove the `safe` filter from the template, leaving it as `{{ user_input }}`. Repeat steps 5-8. **Expected Result (Mitigated):** The alert box will *not* be displayed. Inspecting the HTML source of the `output` div should show the HTML-encoded version of the payload (e.g., `&lt;img src=x onerror=alert('XSS')&gt;`), confirming that default HTML encoding is active and prevents the XSS.

This test case demonstrates that while default HTML encoding is in place, developers need to understand when and how to use the `safe` filter and `Meta.safe` correctly to avoid introducing XSS vulnerabilities, and that incorrect usage of `safe` will indeed lead to XSS.
