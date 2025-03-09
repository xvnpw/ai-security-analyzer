- Vulnerability Name: Unsafe HTML rendering using `safe` Meta option
- Description:
    1. A developer uses the `safe` Meta option in a django-unicorn component's `Meta` class to prevent HTML encoding for a specific property.
    2. This property is used in the component's template to render user-controlled data, such as data bound using `unicorn:model` or passed as arguments to the component.
    3. The developer fails to sanitize this user-controlled data before rendering it in the template.
    4. An attacker can inject malicious Javascript code into the user-controlled data.
    5. When the component updates and re-renders (e.g., after a user interaction or model update), the injected Javascript code is rendered without HTML encoding and executed in the user's browser.
- Impact: Cross-Site Scripting (XSS). An attacker can execute arbitrary Javascript code in the context of the user's browser. This can lead to session hijacking, cookie theft, defacement of the web page, or redirection to malicious websites.
- Vulnerability Rank: High
- Currently Implemented Mitigations:
    - By default, django-unicorn automatically HTML-encodes all component properties before rendering them in the template. This behavior is described in `docs\source\views.md` and confirmed by the changelog entry for version 0.36.0 in `docs\source\changelog.md`, which mentions a security fix (CVE-2021-42053) to prevent XSS attacks by ensuring default HTML encoding.
- Missing Mitigations:
    - While default HTML encoding is a strong mitigation, the `safe` Meta option allows developers to explicitly disable this protection. The documentation (`docs\source\views.md`) explains the `safe` option but lacks sufficient security warnings about its use, especially when rendering user-controlled data. There are no explicit warnings against using `safe` without careful sanitization of user inputs in the documentation for the `safe` option in `docs\source\views.md`.
- Preconditions:
    1. The developer must explicitly use the `safe` Meta option in the component's Python view for a specific property.
    2. This property must be used to render user-controlled data in the component's HTML template.
    3. The developer must not sanitize or escape the user-controlled data before rendering it when the `safe` option is enabled.
- Source Code Analysis:
    - `docs\source\views.md`: As previously analyzed, this file documents the `safe` Meta option, explaining that it disables default HTML encoding.
    - `docs\source\changelog.md`: Confirms that HTML encoding is the default behavior as a security measure against XSS, and the `safe` option is provided to opt-out of this default encoding.
    - `django_unicorn\components\unicorn_view.py`: The `get_frontend_context_variables` method prepares data for the frontend. While default encoding is not explicitly visible here, it's implied to be handled during template rendering by Django's template engine, which is bypassed by the `safe` option. The code iterates through `safe_fields` and uses `mark_safe` in `django_unicorn\views\__init__.py` within the `_process_component_request` function, specifically in the lines:
        ```python
        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(component, field_name)
            if isinstance(value, str):
                setattr(component, field_name, mark_safe(value))  # noqa: S308
        ```
        This code marks the Python variable as safe, but the template rendering process, especially when `safe` is used, will directly render this "safe" content without further encoding, leading to potential XSS if the content is user-controlled and contains malicious script.
    - `django_unicorn\templatetags\unicorn.py`: The `unicorn` template tag is responsible for rendering the component. It does not include any explicit HTML sanitization logic for component properties. When the template engine renders the component's template, and if a property marked as `safe` is used, it will render the raw, unsanitized content.
    - `django_unicorn\django_unicorn\components\unicorn_template_response.py`: This file handles the overall template response but delegates the actual rendering to Django's template engine. It includes `sanitize_html` for the component initialization data within the `<script>` tag, but this is separate from the template rendering of component properties. The `_desoupify` method in `UnicornTemplateResponse` uses `BeautifulSoup` to process the rendered HTML, but this is for manipulating the HTML structure (adding attributes, scripts), not for sanitizing the content rendered from component properties within the templates.
- Security Test Case:
    1. Create a new django-unicorn component named `xss_test`.
    2. In `xss_test/components/xss_test.py`, define a component view like this:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        unsafe_data = ""

        class Meta:
            safe = ("unsafe_data",)
    ```
    3. In `xss_test/templates/unicorn/xss_test.html`, create the component template:
    ```html
    <div>
        <input type="text" unicorn:model="unsafe_data" id="input-field">
        <div id="output-area">{{ unsafe_data }}</div>
    </div>
    ```
    4. Create a Django template (e.g., `test_page.html`) to include the `xss_test` component:
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss-test' %}
    </body>
    </html>
    ```
    5. Set up a Django view to render `test_page.html` and include `django_unicorn` in `INSTALLED_APPS` and `urls.py` as described in the django-unicorn documentation.
    6. Access `test_page.html` in a web browser.
    7. In the input field (identified by `input-field`), enter the following malicious payload: `<img src=x onerror=alert('XSS Vulnerability')>`.
    8. Click outside the input field or trigger an update to the component (e.g., by adding a button with an action).
    9. Observe that an alert box with the message "XSS Vulnerability" pops up in the browser. This confirms that the Javascript code injected through the input field was executed because the `unsafe_data` was rendered without proper HTML encoding due to the `safe` Meta option, resulting in a Cross-Site Scripting vulnerability.
