- Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML rendering of component attributes
- Description:
    - An attacker can inject malicious JavaScript code into a component's attribute, which, when rendered in the template, will be executed in the user's browser.
    - Step-by-step trigger:
        1. Identify a component that renders an attribute value directly in its template without proper HTML escaping. For example, an attribute named `name` is rendered as `{{ name }}` in a template.
        2. Find a way to control or influence the value of this attribute, either through URL parameters, form inputs that are bound to the component's model, or other means of user-provided data injection.
        3. Inject a malicious string containing JavaScript code as the value of the attribute. For example, set `name` to `<img src=x onerror=alert('XSS')>`.
        4. Trigger a component update or initial render that causes the template to be rendered with the malicious attribute value.
        5. When the template is rendered in the user's browser, the injected JavaScript code will be executed.
- Impact:
    - Execution of malicious JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, defacement, or other malicious actions performed on behalf of the user.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Based on changelog v0.36.0, HTML encoding was introduced to prevent XSS attacks. It is mentioned that "responses will be HTML encoded going forward". Changelog v0.36.1 also mentions "More complete handling to prevent XSS attacks". This suggests that the project is aware of and has attempted to mitigate XSS vulnerabilities by HTML encoding responses. The documentation for views mentions `Meta.safe` to explicitly opt-in to previous behavior.
    - The `sanitize_html` function in `django_unicorn.utils.py` escapes HTML characters to prevent XSS when used. This function is used in `UnicornTemplateResponse.render` to sanitize the `init` data which is embedded in a `<script>` tag.
    - Tests in `test_views\test_process_component_request.py` (`test_html_entities_encoded`) confirm that by default, HTML entities in component attributes are encoded when rendered in templates. This prevents execution of injected HTML/JavaScript code.
    - The `Meta.safe` option can be used to disable HTML encoding for specific component attributes. Tests in `test_views\test_process_component_request.py` (`test_safe_html_entities_not_encoded`) demonstrate that when `Meta.safe = ("hello",)` is set, the `hello` attribute is rendered without HTML encoding.
- Missing Mitigations:
    - While HTML encoding is implemented by default, and `sanitize_html` function exists, it is crucial to ensure its consistent and correct application across the entire project, specifically:
        - Verify that all component attributes rendered in templates are HTML encoded by default using Django's template engine auto-escaping, unless explicitly marked as safe using `Meta.safe`.
        - Confirm that HTML encoding is applied consistently in backend responses that update the frontend, beyond just the initial `init` data.
        - Audit the usage of `Meta.safe` to ensure it is used judiciously and only for attributes containing trusted and already-safe HTML content.  Overuse of `Meta.safe` can re-introduce XSS vulnerabilities.
        - Investigate if there are any template contexts or constructs within Django Unicorn components templates where Django's default auto-escaping might be bypassed or ineffective (e.g., usage of `safe` filter within templates, custom template tags, or raw template tags) and ensure these are handled securely.
- Preconditions:
    - The application must be rendering component attributes directly in templates using Django template syntax (e.g., `{{ attribute_name }}`).
    - An attacker must be able to influence the value of these attributes, directly or indirectly, through user-controlled input.
- Source Code Analysis:
    - The file `django_unicorn\utils.py` contains `sanitize_html` function which uses `html.translate(_json_script_escapes)` and `mark_safe`. This function is used to escape HTML characters for safe JSON output, especially within `<script>` tags.
    - `UnicornTemplateResponse.render()` method in `django_unicorn\components\unicorn_template_response.py` uses `sanitize_html(init)` when creating the `json_tag` script element to embed component initialization data:
      ```python
      json_tag = soup.new_tag("script")
      json_tag["type"] = "application/json"
      json_tag["id"] = json_element_id
      json_tag.string = sanitize_html(init)
      ```
      This confirms HTML-encoding of component initialization data in `<script>` tags.
    - Tests in `test_views\test_process_component_request.py` show that when setting component attributes through `syncInput` actions, the rendered HTML in `response["dom"]` is HTML-encoded by default (see `test_html_entities_encoded`). However, using `Meta.safe` bypasses this encoding (see `test_safe_html_entities_not_encoded`).
    - The project uses Django's template engine, which generally auto-escapes variables by default. Django Unicorn relies on this default behavior for template rendering, except when `Meta.safe` is used. Further review is needed to guarantee that auto-escaping is consistently applied in all template contexts within Django Unicorn and no bypasses exist, particularly around the use of `Meta.safe`.
- Security Test Case:
    - Step-by-step test:
        1. Create a simple Django Unicorn component with an attribute, e.g., `message = "Hello"`.
        2. Render this `message` attribute in the component's template using `{{ message }}`.
        3. In the component's view, create an action that allows updating the `message` attribute with user-provided data. For example, an action `set_message(self, new_message)` that sets `self.message = new_message`.
        4. In the template, add an input field bound to the `message` model using `unicorn:model="message"` and a button to trigger the `set_message` action.
        5. Access the page in a browser and use developer tools to inspect the HTML source code of the component. Verify that the initial value "Hello" is rendered as plain text and not HTML encoded in the source (this is initial server side render and might be already encoded by django template engine).
        6. In the input field, enter a malicious XSS payload, for example: `<img src=x onerror=alert('XSS-Test')>`.
        7. Click the button to trigger the `set_message` action, or trigger update by other means (e.g. blur if lazy modifier is used).
        8. After the component updates, inspect the rendered HTML in the browser again, and check if the malicious payload is rendered as plain text (HTML encoded) or if the JavaScript code is executed (XSS vulnerability).
        9. If the JavaScript `alert('XSS-Test')` box appears, then the XSS vulnerability is present. If the payload is rendered as text (e.g. `&lt;img src=x onerror=alert('XSS-Test')&gt;`), then HTML encoding is working as a mitigation.
        10. Additionally, test with `Meta.safe` enabled for the `message` attribute (in the component's `Meta` class, add `safe = ("message",)`) and repeat steps 6-9. When `Meta.safe` is used, the JavaScript code should be executed, demonstrating that `Meta.safe` bypasses HTML encoding and should only be used for trusted content. Verify this behavior to confirm understanding and secure usage of `Meta.safe`.
