- Vulnerability Name: Inconsistent HTML Encoding leading to Cross-Site Scripting (XSS)
- Description:
    - Prior to version 0.36.0, django-unicorn responses were not consistently HTML encoded.
    - This could allow an attacker to inject malicious scripts into the template if user-provided input was not properly sanitized before being rendered by a Django Unicorn component.
    - An attacker could craft a request to a django-unicorn component that includes malicious JavaScript code in user-controlled input fields.
    - If this input is rendered without proper HTML encoding, the JavaScript code would be executed in the victim's browser, leading to XSS.
- Impact:
    - Cross-Site Scripting (XSS) vulnerability.
    - An attacker can execute arbitrary JavaScript code in the victim's browser when they interact with a vulnerable django-unicorn component.
    - This can lead to session hijacking, defacement, redirection to malicious sites, or other malicious actions performed on behalf of the victim.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - Starting from version 0.36.0, django-unicorn responses are HTML encoded by default. This is mentioned in the changelog for version 0.36.0: "responses will be HTML encoded going forward".
    - The component initialization data, which is embedded in the template as JSON within a `<script>` tag, is sanitized using the `sanitize_html` function in `django_unicorn\django_unicorn\utils.py`. This function escapes HTML/XML special characters using `html.translate(_json_script_escapes)` before marking the string as safe for HTML output with `mark_safe`. This is implemented in `django_unicorn\components\unicorn_template_response.py` within the `render` method when creating the `json_tag.string`.
- Missing Mitigations:
    - While HTML encoding is now default, there might be cases where developers intentionally use `safe` filter or `Meta.safe` option to bypass encoding. If `safe` is used improperly on user-controlled input, it can re-introduce XSS vulnerabilities.
    - It's unclear from the provided files if there are any mechanisms to warn or prevent developers from using `safe` on user-provided data.
    - Documentation should strongly emphasize the risks of using `safe` and recommend against using it with user-provided input unless absolutely necessary and input is strictly validated and sanitized on the server-side before rendering.
- Preconditions:
    - Vulnerable versions of django-unicorn prior to 0.36.0 are used.
    - Or, developers are using version 0.36.0 or later but are incorrectly using `safe` filter or `Meta.safe` option on user-provided input within django-unicorn components.
- Source Code Analysis:
    - In `django_unicorn\components\unicorn_template_response.py`, the `render` method processes the template response.
    - It serializes component data into JSON format (`frontend_context_variables`).
    - This JSON data is embedded into the rendered HTML using a `<script>` tag with `id` like `unicorn:data:{component_id}`.
    - Before embedding the JSON data into the `<script>` tag, the `sanitize_html` function from `django_unicorn\utils.py` is applied to the JSON string:
        ```python
        json_tag.string = sanitize_html(init)
        ```
    - `sanitize_html` function in `django_unicorn\utils.py`:
        ```python
        def sanitize_html(html: str) -> SafeText:
            html = html.translate(_json_script_escapes)
            return mark_safe(html)
        ```
        - `_json_script_escapes` from `django.utils.html` escapes HTML special characters like `<`, `>`, `&`, etc. to their unicode escape sequences.
        - `mark_safe` marks the escaped string as safe, preventing Django's template engine from further escaping it when rendering.
    - This `sanitize_html` function is applied to the component initialization JSON data, which mitigates XSS risk in this specific part of the library.
    - However, the library still allows developers to use the `safe` filter or `Meta.safe` option, which bypasses HTML encoding for template variables. If developers use these features with user-provided data without proper sanitization, XSS vulnerabilities can be re-introduced.
- Security Test Case:
    1.  **Setup a vulnerable django-unicorn application:** Use a version of django-unicorn prior to 0.36.0 or a version >= 0.36.0 where `Meta.safe` or `|safe` filter is used on a component field that is populated from user input.
    2.  **Create a component with a vulnerable field:** Create a django-unicorn component that renders a field which can be influenced by user input and is marked as `safe` or rendered with `|safe`. For example, a component that displays a `message` field and the template uses `{{ message|safe }}`.
    3.  **Inject malicious JavaScript:** As an attacker, send a request to the application that populates the vulnerable component's field with a malicious JavaScript payload, such as `<img src=x onerror=alert('XSS')>`. This could be through URL parameters, form input, or any other mechanism that updates the component's data.
    4.  **Observe XSS execution:** Access the page with the vulnerable component in a browser. If the application is vulnerable, an alert box with 'XSS' will be displayed, demonstrating successful execution of the injected JavaScript code.
    5.  **Verify mitigation in newer versions:** Repeat the test with django-unicorn version 0.36.0 or later, without using `Meta.safe` or `|safe`. The alert box should not appear, and the malicious script should be rendered as plain text due to HTML encoding, demonstrating that the default HTML encoding mitigates the XSS vulnerability in default cases. However, if `safe` is explicitly used, the vulnerability will still be present.
