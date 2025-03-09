### 1. Cross-Site Scripting (XSS) vulnerability due to unsafe dynamic template rendering

* Description:
    1. An attacker injects malicious JavaScript code into a component property or user input.
    2. The user input is bound to a component property using `unicorn:model` or set programmatically in the component's Python code.
    3. The component property, containing the malicious JavaScript code, is dynamically rendered in a Django template.
    4. Django-unicorn renders the template without proper sanitization of the component property by default.
    5. When a user views the page, the malicious JavaScript code is executed in their browser, potentially leading to session hijacking, cookie theft, or other malicious actions.

* Impact:
    * Critical. Successful XSS attacks can have severe consequences, including:
        - Account takeover: Attackers can steal user session cookies or credentials, gaining unauthorized access to user accounts.
        - Data theft: Attackers can steal sensitive data displayed on the page or accessible through the user's session.
        - Malware distribution: Attackers can redirect users to malicious websites or inject malware into the page.
        - Defacement: Attackers can modify the content of the web page, displaying misleading or harmful information.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    * According to changelog v0.36.0, responses are HTML encoded by default to prevent XSS attacks.
    * The documentation for `views.md` mentions a `safe` Meta attribute to explicitly allow unsafe rendering, implying default behavior is safe rendering (HTML encoded).
    * `django_unicorn.utils.sanitize_html` function is used to escape HTML characters for JSON output, specifically for `init` script in `UnicornTemplateResponse.render`.
    * Tests like `test_html_entities_encoded` in `test_process_component_request.py` confirm that by default, component properties are HTML encoded.
    * The `safe` Meta attribute in component allows developers to bypass HTML encoding for specific properties, as demonstrated by `test_safe_html_entities_not_encoded` in `test_process_component_request.py`.

* Missing mitigations:
    * While HTML encoding is the default behavior and `sanitize_html` function exists, it's crucial to confirm that this function or equivalent sanitization is consistently applied to *all* dynamic content rendered in templates by default, especially component properties directly rendered within HTML tags using template variables like `{{ user_input }}`.
    * The provided `sanitize_html` function in `django_unicorn/utils.py` is primarily used for escaping HTML in JSON script, not for general template variable rendering within HTML templates.
    * It is still unclear whether django-unicorn automatically sanitizes all data rendered in templates by default for direct template variable rendering or if developers need to be aware of the default safe behavior and the implications of using the `safe` attribute.
    * There is no clear and prominent documentation on best practices for developers to avoid XSS vulnerabilities when using django-unicorn in templates for direct variable rendering. Guidance is needed on when and how to use the `safe` attribute responsibly and when manual sanitization might be necessary for template variable rendering even with default HTML encoding enabled. Developers might mistakenly assume that all data is automatically and always safe, regardless of rendering context.

* Preconditions:
    1. A django-unicorn component is used in a Django template.
    2. The component template dynamically renders user-controlled data or component properties that can be influenced by users directly into HTML structure, e.g., using `{{ component_property }}`.
    3. The application is deployed and accessible to potential attackers.

* Source code analysis:
    * `django_unicorn/utils.py`: The `sanitize_html` function escapes HTML special characters for JSON output.
    ```python
    def sanitize_html(html: str) -> SafeText:
        """
        Escape all the HTML/XML special characters with their unicode escapes, so
        value is safe to be output in JSON.
        ...
        """
        html = html.translate(_json_script_escapes)
        return mark_safe(html)  # noqa: S308
    ```
    * `django_unicorn/components/unicorn_template_response.py`: In `UnicornTemplateResponse.render`, `sanitize_html` is used for `init` data within `<script>` tag.
    ```python
        json_tag.string = sanitize_html(init)
    ```
    * `test_views_test_process_component_request.py`: Tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` demonstrate the behavior of HTML encoding and the `safe` attribute.
    * However, no code in the provided files explicitly shows automatic HTML sanitization for template variables rendered directly into HTML structure like `{{ component_property }}` within component templates. The default behavior relies on Django's template engine auto-escaping, but it's crucial to verify if django-unicorn consistently leverages this for all dynamic content in component templates and if developers are sufficiently informed about this and the `safe` attribute implications for direct HTML rendering.
    * `test_set_property_from_data.py`: This test file demonstrates how component properties are set based on data received from the client. It shows that user-provided data can directly update component properties without explicit sanitization at this stage. This further emphasizes the importance of ensuring proper sanitization during template rendering of these properties.

* Security test case:
    1. Create a simple django-unicorn component with a property bound to user input and rendered in the template.
    2. Component Python code (`test_component.py`):
    ```python
    from django_unicorn.components import UnicornView

    class TestComponentView(UnicornView):
        user_input = ""

        class Meta:
            safe = ("user_input",) # Remove or comment this line to test default behaviour
    ```
    3. Component template (`test_component.html`):
    ```html
    <div>
        <input type="text" unicorn:model="user_input" id="user-input">
        <div id="output">{{ user_input }}</div>
    </div>
    ```
    4. Create a Django view and template to include this component.
    5. Access the page in a browser.
    6. In the input field (`user-input`), enter the following malicious JavaScript code: `<img src='x' onerror='alert("XSS Vulnerability!")'>`.
    7. Observe if the alert box "XSS Vulnerability!" is displayed when the component re-renders after input.
    8. If the alert box is displayed when `safe = ("user_input",)` is present in component's Meta class, it confirms the XSS vulnerability when `safe` is used.
    9. If the alert box is *not* displayed when `safe = ("user_input",)` is *removed or commented*, it indicates that default HTML encoding is active for template variable rendering.
    10. To further test default behavior, try other XSS payloads with `safe` attribute removed or commented out, including script tags, event handlers, and different injection vectors to assess the robustness of the default sanitization for template variable rendering.
    11. To test `safe` attribute behavior, add `safe = ("user_input",)` to the Meta class and repeat steps 6-9 to ensure that XSS is possible when `safe` is explicitly used, highlighting the developer's responsibility in using this attribute carefully.
