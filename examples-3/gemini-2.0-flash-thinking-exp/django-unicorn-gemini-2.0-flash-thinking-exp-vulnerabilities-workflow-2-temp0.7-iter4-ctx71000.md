## Combined Vulnerability Report

This report combines identified vulnerabilities related to Cross-Site Scripting (XSS) in Django Unicorn, focusing on the misuse of the `safe` attribute.

### Vulnerability 1: Cross-Site Scripting (XSS) vulnerability due to unsafe HTML rendering when using the `safe` attribute

- Description:
  - An attacker can inject malicious JavaScript code into user-provided data.
  - When a Django Unicorn component renders a template that includes this unsanitized user data through a property marked as `safe` in the component's `Meta` class, or using the `safe` template filter, the malicious script is executed in the user's browser.
  - This occurs because the `safe` attribute and `safe` template filter explicitly tells Django Unicorn and Django template engine to bypass the default HTML encoding for the specified component property or template variable.
  - If a developer uses `safe` without properly sanitizing user input, it will render raw HTML, including any injected malicious scripts.
  - For example, if a component has a `message` property and `Meta.safe = ("message",)`, and the template renders `{{ message }}`, and the `message` property is updated with user input containing `<script>alert('XSS')</script>`, the alert will be executed. Similarly, using `{{ user_input|safe }}` in a template will bypass auto-escaping.

- Impact:
  - An attacker can execute arbitrary JavaScript code in the context of the user's browser.
  - Successful XSS attacks can lead to:
    - **Account hijacking:** Attacker can steal session cookies and impersonate users, potentially gaining full control of user accounts, including administrator accounts, leading to complete compromise of the web application.
    - **Data theft:** Attacker can steal sensitive information displayed on the page or submitted by the user, including personal data, financial information, and application secrets.
    - **Website defacement:** Attacker can modify the content of the web page seen by the victim, damaging the website's reputation and user trust.
    - **Redirection to malicious sites:** Attacker can redirect users to phishing or malware distribution websites, increasing the risk of further attacks and malware infections.
    - **Execution of arbitrary JavaScript:** Attacker can perform any action that JavaScript can perform within the context of the victim's browser and the vulnerable web page, including making API requests on behalf of the user, keylogging, and more.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - **Default HTML Encoding:** Django Unicorn, leveraging Django templates, automatically HTML-encodes data rendered in templates by default. This is documented in `changelog.md` (version 0.36.0) and confirmed by tests like `test_html_entities_encoded` in `django_unicorn\tests\views\test_process_component_request.py`. This default behavior significantly mitigates XSS risks.
  - **`sanitize_html` function:** The `sanitize_html` function in `django_unicorn\utils.py` is used to escape HTML special characters for JSON output, specifically when embedding initial component data in `<script>` tags within `django_unicorn\components\unicorn_template_response.py`. This function helps prevent XSS in initial component data passed to JavaScript.
  - **Explicit Opt-in for Unsafe Rendering:** Django Unicorn forces developers to explicitly use the `safe` filter in templates or the `Meta.safe` attribute in component views to disable HTML escaping for specific variables. This design makes bypassing default protection a conscious decision, encouraging safer development practices by default.
  - **Test Coverage:** The project includes tests like `test_sanitize_html` in `django_unicorn\tests\test_utils.py` which verifies HTML sanitization and `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` in `django_unicorn\tests\views\test_process_component_request.py` which explicitly test HTML encoding and the `safe` attribute behavior, ensuring some level of verification for encoding and `safe` functionality.

- Missing Mitigations:
  - **Lack of Built-in Sanitization with `safe`:** When developers choose to use `safe`, there is no built-in mechanism within Django Unicorn to automatically enforce or guide input sanitization. Developers are entirely responsible for sanitizing user input before marking it as safe, which can be error-prone.
  - **Insufficient Documentation Emphasis on `safe` Misuse:** While the documentation mentions the `safe` attribute, it could be improved by adding a more prominent and explicit security warning about the significant dangers of using `safe` with unsanitized user input and the critical need for proper sanitization to prevent XSS vulnerabilities.
  - **No Automated Checks for `safe` Misuse:** There are no documented automated checks or linters within Django Unicorn itself to detect potentially unsafe usage of `safe`. This relies on developers' manual code reviews and security awareness to prevent vulnerabilities. Automated checks could help identify risky patterns.
  - **Absence of CSP Recommendation:** Content Security Policy (CSP) is not mentioned in the documentation as a recommended security measure. Recommending CSP as a defense-in-depth strategy could provide an additional layer of protection against XSS, especially if developers inadvertently misuse `safe` or miss output encoding in some contexts.
  - **Contextual Output Encoding Guidance:** While default HTML encoding is present, the documentation lacks specific guidance on contextual output encoding. It should emphasize the importance of considering the output context (HTML attributes, JavaScript, URLs) and using appropriate encoding methods beyond basic HTML encoding when `safe` is used or when manually bypassing auto-escaping.

- Preconditions:
  - The application must be using Django Unicorn to render dynamic components.
  - User input must be incorporated into a component's property and rendered in a template, or rendered directly in a template using `safe` filter.
  - The component's `Meta` class must declare the property as `safe` (e.g., `Meta.safe = ("unsafe_property",)`), or the template must use the `safe` filter (e.g., `{{ user_input|safe }}`).
  - The developer must fail to sanitize the user input before assigning it to the `safe` property or rendering it with the `safe` filter.
  - An attacker must be able to control user input that is rendered in the template through a `safe` context.

- Source Code Analysis:
  - **Default HTML Auto-Escaping:** Django's template engine, used by Django Unicorn, provides default HTML auto-escaping, which is the primary built-in mitigation against XSS.
  - **`django_unicorn\utils.py - sanitize_html`:**
    ```python
    def sanitize_html(html: str) -> SafeText:
        """
        Escape all the HTML/XML special characters with their unicode escapes, so
        value is safe to be output in JSON.

        This is the same internals as `django.utils.html.json_script` except it takes a string
        instead of an object to avoid calling DjangoJSONEncoder.
        """

        html = html.translate(_json_script_escapes)
        return mark_safe(html)  # noqa: S308
    ```
    - This function escapes HTML special characters for JSON output, used for initial component data. It uses `mark_safe` to mark the output as safe from further auto-escaping, intended for JSON context but not for general HTML output sanitization for XSS prevention.
  - **`django_unicorn\components\unicorn_template_response.py - UnicornTemplateResponse.render`:**
    ```python
    class UnicornTemplateResponse(TemplateResponse):
        # ...
        @timed
        def render(self):
            # ...
            if self.init_js:
                init = { ... }
                init = orjson.dumps(init).decode("utf-8")
                json_element_id = f"unicorn:data:{self.component.component_id}"
                json_tag = soup.new_tag("script")
                json_tag["type"] = "application/json"
                json_tag["id"] = json_element_id
                json_tag.string = sanitize_html(init) # Sanitize init data here
                # ...
    ```
    - `sanitize_html` is used to sanitize initial component data embedded in `<script>` tags, mitigating XSS in this specific context.
  - **`django_unicorn\views\__init__.py - _process_component_request`:**
    ```python
    def _process_component_request(request: HttpRequest, component_request: ComponentRequest) -> Dict:
        # ...
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
        # ...
        rendered_component = component.render(request=request)
        # ...
    ```
    - This code handles the `Meta.safe` attribute. It retrieves fields listed in `Meta.safe` and uses `mark_safe` on the corresponding component attributes *before* rendering. This bypasses Django's default auto-escaping for these specific fields, creating a potential XSS vulnerability if these fields contain unsanitized user input.
  - **`django_unicorn/tests/views/test_process_component_request.py - test_safe_html_entities_not_encoded`:**
    ```python
    def test_safe_html_entities_not_encoded(client):
        # ...
        response = post_and_get_response(
            client,
            url="/message/tests.views.test_process_component_request.FakeComponentSafe",
            # ...
        )
        # ...
        assert response["data"].get("hello") == "<b>test1</b>"
        assert "<b>test1</b>" in response["dom"]
    ```
    - This test explicitly demonstrates that when `Meta.safe` is used, HTML content is rendered without encoding, confirming the bypass of default HTML escaping and the potential for XSS.

- Security Test Case:
  - Step 1: Deploy a Django application with Django Unicorn installed and configured.
  - Step 2: Create a Django Unicorn component named `SafeAttributeXSSComponent` in `components/safe_xss_component.py`:
    ```python
    from django_unicorn.components import UnicornView

    class SafeAttributeXSSComponent(UnicornView):
        template_name = "unicorn/safe-xss.html"
        user_input = ""

        class Meta:
            safe = ("user_input",)
    ```
  - Step 3: Create a template `unicorn/safe-xss.html` for the component in `templates/unicorn/safe-xss.html`:
    ```html
    <div>
        <input type="text" unicorn:model="user_input" id="user-input">
        <div id="output">
            {{ user_input }}
        </div>
    </div>
    ```
  - Step 4: Create a Django view to render the `SafeAttributeXSSComponent` in `views.py`:
    ```python
    from django.shortcuts import render
    from .components.safe_xss_component import SafeAttributeXSSComponent

    def safe_attribute_xss_view(request):
        return render(request, 'safe_xss_template.html', {"component_name": "safe-xss-component"})
    ```
  - Step 5: Create a template `safe_xss_template.html` to include the component in `templates/safe_xss_template.html`:
    ```html
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>Safe Attribute XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% unicorn "safe-xss-component" %}
    </body>
    </html>
    ```
  - Step 6: Add a URL path to `urls.py` to access the view:
    ```python
    from django.urls import path
    from . import views

    urlpatterns = [
        path('safe-xss/', views.safe_attribute_xss_view, name='safe_xss_view'),
        # ... other urls ...
    ]
    ```
  - Step 7: Run the Django development server.
  - Step 8: As an attacker, navigate to the `/safe-xss/` URL in a web browser.
  - Step 9: In the input field (id `user-input`), enter the following XSS payload: `<img src="x" onerror="alert('XSS_safe_attribute')">`.
  - Step 10: Observe if the JavaScript alert `alert('XSS_safe_attribute')` is executed in the browser when you type or after you blur the input field, or interact with the component to trigger an update.
  - Step 11: If the alert is executed, it confirms the XSS vulnerability due to the `safe` attribute. The user-provided input was rendered without HTML encoding, leading to script execution.
  - Step 12: Modify the component `SafeAttributeXSSComponent` to **remove** `user_input` from the `safe` tuple in `Meta` class.
  - Step 13: Repeat steps 9 and 10.
  - Step 14: If no alert box appears and the malicious payload is rendered as text (e.g., `&lt;img src="x" onerror="alert('XSS-Test-Safe-Attribute')&gt;`), it confirms that default HTML encoding is in place and mitigates XSS when `safe` is not used.
