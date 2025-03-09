### Vulnerability 1: Cross-Site Scripting (XSS) through Unsanitized User Inputs in Templates

- Description:
  - An attacker can inject malicious JavaScript code into user-supplied data that is then rendered by a Django Unicorn component.
  - Step 1: An attacker crafts a malicious input containing JavaScript code, for example, `<img src=x onerror=alert('XSS')>`.
  - Step 2: This malicious input is submitted through a form or any other user interaction that updates a Django Unicorn component's data.
  - Step 3: If Django Unicorn does not properly sanitize this user input when re-rendering the component's template, the malicious JavaScript code will be executed in the victim's browser.
  - Step 4: The attacker's JavaScript code can then perform actions such as stealing cookies, redirecting the user to a malicious website, or performing actions on behalf of the user.

- Impact:
  - Successful XSS attacks can lead to:
    - Account hijacking: Attacker can steal session cookies and impersonate users.
    - Data theft: Attacker can steal sensitive information displayed on the page or submitted by the user.
    - Website defacement: Attacker can modify the content of the web page seen by the victim.
    - Redirection to malicious sites: Attacker can redirect users to phishing or malware distribution websites.
    - Execution of arbitrary JavaScript: Attacker can perform any action that JavaScript can perform within the context of the victim's browser and the vulnerable web page.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - Based on `changelog.md` from version 0.29.0, "Sanitize initial JSON to prevent XSS" and from version 0.36.0, "Security fix: for CVE-2021-42053 to prevent XSS attacks ... responses will be HTML encoded going forward".
  - From `docs\source\views.md`, "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple.".
  - From `django_unicorn\utils.py`, the `sanitize_html` function uses `html.translate(_json_script_escapes)` and `mark_safe` to escape HTML characters. This is used for initial component data.
  - From `django_unicorn\components\unicorn_template_response.py`, the `sanitize_html` function is used to sanitize the `init` data which is passed to `Unicorn.componentInit` in a `<script>` tag.
  - From `django_unicorn\views\__init__.py`, in `_process_component_request` function, it is mentioned that "Get set of attributes that should be marked as `safe`" and "Mark safe attributes as such before rendering" but this part only marks attributes as safe and does not sanitize, relying on the template engine's auto-escaping unless `safe` is used.
  - **Test coverage**: The project includes tests like `test_sanitize_html` in `django_unicorn\tests\test_utils.py` which verifies HTML sanitization and `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` in `django_unicorn\tests\views\test_process_component_request.py` which explicitly test HTML encoding and the `safe` attribute behavior.

- Missing Mitigations:
  - While HTML encoding is a good general mitigation, context-aware output encoding might be missing for specific scenarios, especially when using `safe` attribute.
  - It's unclear from the code if Django template auto-escaping is consistently applied to all user-provided data rendered by Unicorn components, especially in dynamic updates. However, tests like `test_html_entities_encoded` suggest default auto-escaping is active.
  - The usage of `mark_safe` in `sanitize_html` and potentially within templates when `safe` attribute is used, requires careful review to ensure it's only applied to truly safe content, and not user-controlled data that could be manipulated to bypass sanitization in certain contexts.
  - It's unclear if default HTML encoding is applied to attribute values as well, not just text content.

- Preconditions:
  - The application using Django Unicorn must render user-supplied data in Django templates dynamically through Django Unicorn components.
  - The user-supplied data must not be properly sanitized before being rendered in the template, or the `safe` attribute must be used incorrectly allowing execution of HTML.

- Source Code Analysis:
  - **`django_unicorn\utils.py`**: Contains `sanitize_html` function.
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
    This function is used to escape HTML special characters for JSON output, specifically for the `init` data. It uses `mark_safe` which means that the output is considered safe by Django's template engine and will not be auto-escaped further. Test `test_sanitize_html` in `django_unicorn\tests\test_utils.py` validates this function by asserting that `<script>` tags are properly escaped.

  - **`django_unicorn\components\unicorn_template_response.py`**: Renders the component template and includes initial Javascript.
    ```python
    class UnicornTemplateResponse(TemplateResponse):
        # ...
        @timed
        def render(self):
            # ...
            if self.init_js:
                init = {
                    "id": self.component.component_id,
                    "name": self.component.component_name,
                    "key": self.component.component_key,
                    "data": orjson.loads(frontend_context_variables),
                    "calls": self.component.calls,
                    "hash": content_hash,
                }
                init = orjson.dumps(init).decode("utf-8")
                json_element_id = f"unicorn:data:{self.component.component_id}"
                init_script = (
                    f"Unicorn.componentInit(JSON.parse(document.getElementById('{json_element_id}').textContent));"
                )

                json_tag = soup.new_tag("script")
                json_tag["type"] = "application/json"
                json_tag["id"] = json_element_id
                json_tag.string = sanitize_html(init) # Sanitize init data here
                # ...
    ```
    The `sanitize_html` function is used to sanitize the `init` data which is embedded in a `<script type="application/json">` tag. This mitigates XSS in the initial component data passed to Javascript. However, this is for the initial component load and not for dynamically updated data rendered in the HTML template itself.

  - **`django_unicorn\views\__init__.py`**: Handles the `message` view which processes user interactions.
    ```python
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
        # ...
        rendered_component = component.render(request=request)
        # ...
    ```
    This code section retrieves attributes listed in the `Meta.safe` tuple of a component. If an attribute is a string and is in the `safe_fields`, it's marked as safe using `mark_safe` **before** rendering the component. This means that these fields will **not** be auto-escaped by Django's template engine. If developers incorrectly add user-supplied data fields to `safe` tuple without proper sanitization, it will lead to XSS vulnerability. Tests in `django_unicorn\tests\views\test_process_component_request.py` such as `test_safe_html_entities_not_encoded` confirm that `safe` attribute bypasses HTML encoding.

  **Visualization of Data Flow:**
  ```mermaid
  graph LR
      A[User Input] --> B(Component Request - JSON Payload);
      B --> C(Django Unicorn Backend - views.message);
      C --> D{_process_component_request};
      D --> E{Component Instance Creation};
      D --> F{Data Binding};
      D --> G{Action Handling (syncInput, callMethod)};
      D --> H{Validation};
      D --> I{Safe Field Marking};
      I --> J{Component Rendering (component.render)};
      J --> K[HTML Response];
      K --> L[Browser];
      L -- Renders HTML --> M[DOM];
      M -- Executes JavaScript (if injected) --> N[XSS Impact];

      style D fill:#f9f,stroke:#333,stroke-width:2px
      style I fill:#f9f,stroke:#333,stroke-width:2px
      style J fill:#f9f,stroke:#333,stroke-width:2px
  ```

  **Source Code Analysis Summary:**
  - Django Unicorn uses `sanitize_html` to encode initial component data for JSON in `<script>` tags, which is good.
  - Django Unicorn provides a `safe` attribute in component's `Meta` class to bypass HTML auto-escaping for specific fields.
  - If developers use `safe` incorrectly by including user-supplied data fields in the `safe` tuple without additional context-aware sanitization, it can lead to XSS vulnerabilities. This is explicitly tested and confirmed by `test_safe_html_entities_not_encoded` in `django_unicorn\tests\views\test_process_component_request.py`.
  - The default behavior is to HTML-encode updated field values to prevent XSS, which is good, and validated by `test_html_entities_encoded` in `django_unicorn\tests\views\test_process_component_request.py`, but the `safe` attribute creates a potential bypass if misused.
  - There is no explicit context-aware escaping evident in the provided code for different HTML contexts (attributes, javascript etc.). Django's auto-escaping is relied upon, which is context-agnostic HTML escaping.

- Security Test Case:
  - Step 1: Deploy a Django application with Django Unicorn installed and configured.
  - Step 2: Create a Django Unicorn component that renders a user-supplied string variable in the template, and mark this variable as `safe` in the component's `Meta` class. For example, create a component `xss_test.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        user_input = ""

        class Meta:
            safe = ("user_input",)
    ```
  - Step 3: Create a template `unicorn/xss-test.html` for the component:
    ```html
    <div>
        <input type="text" unicorn:model="user_input">
        <div id="xss-output">
            {{ user_input }}
        </div>
    </div>
    ```
  - Step 4: Create a Django view to render this component in a page, and include `{% unicorn_scripts %}` and `{% load unicorn %}` in the template.
  - Step 5: Access the page in a browser and in the input field, enter the malicious payload: `<img src=x onerror=alert('XSS-Test-Safe-Attribute')>`
  - Step 6: Observe the behavior in the browser.
    - If an alert box with 'XSS-Test-Safe-Attribute' appears, it confirms the XSS vulnerability when `safe` attribute is used without proper sanitization. This is because `mark_safe` prevents Django's auto-escaping, and the malicious JavaScript is executed.
  - Step 7: Modify the component `XssTestView` to **remove** `user_input` from the `safe` tuple in `Meta` class.
  - Step 8: Repeat steps 5 and 6.
    - If no alert box appears and the malicious payload is rendered as text (e.g., `&lt;img src=x onerror=alert('XSS-Test-Safe-Attribute')&gt;`), it confirms that default HTML encoding is in place and mitigates XSS when `safe` is not used.
  - Step 9: Test different payloads to bypass HTML encoding if possible in default (non-safe) scenario, and different payloads specifically targeting `safe` scenario to confirm lack of sanitization when `safe` is used. For example, try event handlers, javascript URLs etc. within `safe` context.
