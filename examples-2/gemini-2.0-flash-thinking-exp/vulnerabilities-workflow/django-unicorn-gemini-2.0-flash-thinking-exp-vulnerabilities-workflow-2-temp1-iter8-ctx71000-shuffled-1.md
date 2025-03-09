### Vulnerability List

- Vulnerability Name: Unsafe HTML Rendering with `safe` Meta Option

- Description:
    - A component developer can use the `Meta.safe` option within a Django Unicorn component to bypass HTML encoding for specific component attributes.
    - If user-provided data is assigned to an attribute marked as `safe` and rendered in a template without further sanitization, it can lead to Cross-Site Scripting (XSS).
    - An attacker can inject malicious HTML or JavaScript code through user input fields that are bound to a `safe` attribute.
    - When the component re-renders with the attacker's payload, the malicious script will be executed in the victim's browser.
    - The vulnerability arises because Django Unicorn's default behavior is to HTML-encode data for security, but the `safe` option explicitly disables this encoding for chosen attributes, placing the responsibility for sanitization entirely on the component developer.

- Impact:
    - Cross-Site Scripting (XSS) vulnerability.
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, defacement of the website, redirection to malicious sites, or theft of sensitive user data.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - By default, Django Unicorn HTML-encodes updated field values to prevent XSS attacks. This default encoding is handled in the component rendering process.
    - The documentation in `docs\source\views.md` clearly warns about the security implications of using the `safe` option: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
    - Test case `test_html_entities_encoded` in `tests\views\test_process_component_request.py` confirms that by default HTML entities are encoded.
    - Test case `test_safe_html_entities_not_encoded` in `tests\views\test_process_component_request.py` confirms that when `safe` meta option is used, HTML entities are NOT encoded.

- Missing Mitigations:
    - No additional mitigations are inherently missing within the project regarding the `safe` option, as the responsibility to use it securely is clearly placed on the developer, and this is documented.
    - However, further enhancements could include:
        - Static code analysis tools or linters that can detect usage of `Meta.safe` and flag potential unsanitized user input scenarios.
        - More prominent warnings or best practices in the documentation, emphasizing input sanitization even when using `safe` for legitimate use cases like rendering pre-sanitized HTML.

- Preconditions:
    - A Django Unicorn component must be implemented with `Meta.safe` option enabled for an attribute that is directly or indirectly populated with user-controlled data.
    - The template must render this `safe` attribute without additional output filtering or sanitization.
    - An attacker must be able to influence the data bound to the `safe` attribute, typically through form inputs or URL parameters.

- Source Code Analysis:
    - `docs\source\views.md`: This documentation file describes the `safe` Meta option and its security implications.
    - `tests\views\test_process_component_request.py`: Contains test cases specifically verifying HTML encoding behavior and the `safe` option.
    - `django_unicorn\views\utils.py`: The function `set_property_from_data` handles setting component properties from data received from the frontend, but it does not include HTML sanitization. This function is called within `django_unicorn\views\__init__.py` in `_process_component_request` to update component properties based on user input.
    - `django_unicorn\views\__init__.py`: The `_process_component_request` function is responsible for processing component requests, updating properties using `set_property_from_data`, and rendering the component. It includes logic to mark `safe` attributes as safe for template rendering using `django.utils.safestring.mark_safe`.
    ```python
    # django_unicorn\views\__init__.py
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

        # Pass the current request so that it can be used inside the component template
        rendered_component = component.render(request=request)
        # ...
    ```
    - The code explicitly uses `mark_safe` for attributes listed in `Meta.safe`, which bypasses Django's automatic HTML escaping during template rendering. This design relies on developers to sanitize input when using `safe`.

- Security Test Case:
    1. Create a Django Unicorn component named `SafeComponent` with a `message` attribute and enable `Meta.safe` for it.
        ```python
        # example/unicorn/components/safe_component.py
        from django_unicorn.components import UnicornView

        class SafeComponentView(UnicornView):
            message = ""

            class Meta:
                safe = ("message", )
        ```
    2. Create a template `safe_component.html` to render the component and display the `message` attribute:
        ```html
        {# example/unicorn/components/safe_component.html #}
        <div>
            <input unicorn:model="message" />
            <div id="message-output">{{ message }}</div>
        </div>
        ```
    3. Create a view and URL to render this component.
    4. On the frontend, navigate to the view rendering `SafeComponent`.
    5. Open browser developer tools and find the Unicorn component's ID (e.g., using `document.querySelector('[unicorn\\:id]').getAttribute('unicorn:id')`).
    6. Construct a POST request to the Unicorn message endpoint `/unicorn/message` with the following JSON payload, replacing `<component_id>` with the actual component ID:
        ```json
        {
          "id": "<component_id>",
          "name": "example.unicorn.components.safe_component.SafeComponentView",
          "data": {
            "message": "<img src='x' onerror='alert(\"XSS\")'>"
          },
          "checksum": "initial_checksum_value",
          "actionQueue": [
            {
              "type": "syncInput",
              "payload": {
                "id": "message",
                "name": "message",
                "value": "<img src='x' onerror='alert(\"XSS\")'>"
              }
            }
          ]
        }
        ```
    7. Send this request (e.g., using `fetch` in the browser console).
    8. Observe that an alert box with "XSS" is displayed in the browser, demonstrating successful XSS.
    9. Inspect the HTML output in the `dom` part of the JSON response. You should see the raw HTML injected without encoding in the `message-output` div: `<div id="message-output"><img src='x' onerror='alert("XSS")'></div>`.

---
- Vulnerability Name: Potential Cross-Site Scripting (XSS) Vulnerability Prior to Version 0.36.0 (CVE-2021-42053)

- Description:
    - Versions of Django Unicorn prior to 0.36.0 were potentially vulnerable to Cross-Site Scripting (XSS) attacks.
    - The exact nature of the vulnerability is not described in detail within the provided files, but the changelog for version 0.36.0 explicitly mentions a "Security fix: for CVE-2021-42053 to prevent XSS attacks (reported by [Jeffallan](https://github.com/Jeffallan))." and "More complete handling to prevent XSS attacks." in version 0.36.1.
    - It's likely that user-provided data rendered in templates was not consistently or adequately sanitized by default, allowing attackers to inject and execute malicious scripts.
    - Prior to version 0.36.0, the default behavior might have been to render data without HTML encoding, or the encoding might have been inconsistently applied, leaving room for XSS attacks.

- Impact:
    - Cross-Site Scripting (XSS) vulnerability.
    - In vulnerable versions, attackers could potentially execute arbitrary JavaScript code in users' browsers.
    - This could have led to similar impacts as described in the "Unsafe HTML Rendering with `safe` Meta Option" vulnerability, allowing for session hijacking, website defacement, malicious redirects, and data theft.

- Vulnerability Rank: High (for versions prior to 0.36.0), Low (for current versions if mitigated effectively)

- Currently Implemented Mitigations:
    - Version 0.36.0 and later versions include security fixes to prevent XSS attacks, as stated in `docs\source\changelog.md`:
        - "v0.36.0 - Security fix: for CVE-2021-42053 to prevent XSS attacks (reported by [Jeffallan](https://github.com/Jeffallan)). Breaking changes - responses will be HTML encoded going forward (to explicitly opt-in to previous behavior use [safe](views.md#safe))"
        - "v0.36.1 - More complete handling to prevent XSS attacks."
    - The breaking change in v0.36.0, "responses will be HTML encoded going forward," indicates that output encoding was strengthened and made default to prevent XSS. This change likely involved modifying the component rendering process in `django_unicorn\views\__init__.py` and `django_unicorn\components\unicorn_view.py` to ensure default HTML encoding.

- Missing Mitigations:
    - Based on the changelog, it seems the primary missing mitigation in prior versions was proper and consistent HTML encoding of dynamic content before rendering.
    - While the changelog indicates that output encoding was made default and strengthened, without analyzing the specific code changes between versions prior to and post 0.36.0, it's hard to pinpoint the exact previous weakness and the precise mitigation.
    - It's plausible that before 0.36.0, the default template rendering in `django_unicorn\components\unicorn_view.py` or the request processing in `django_unicorn\views\__init__.py` did not consistently apply HTML encoding.

- Preconditions:
    - Project must be running a version of Django Unicorn older than 0.36.0 to be vulnerable to the original CVE-2021-42053.
    - Similar to the general XSS attack vector in Django Unicorn, user-provided data must be dynamically rendered in a template without sufficient sanitization within the vulnerable versions.
    - An attacker must be able to control or influence the data that gets rendered in the template.

- Source Code Analysis:
    - `docs\source\changelog.md`: The changelog entries for versions 0.36.0 and 0.36.1 are the primary source of evidence for this past vulnerability and its mitigation.
    - `django_unicorn\views\__init__.py`: This file is central to request processing and component rendering. The mitigation for CVE-2021-42053 likely involved changes in the `_process_component_request` function to ensure default HTML encoding of component data before rendering.
    - `django_unicorn\components\unicorn_view.py`: This file contains the `render` function, which is responsible for rendering the component template. Changes to ensure default HTML encoding might have been implemented here, or in conjunction with changes in `views\__init__.py`.
    - *To pinpoint the exact code changes that addressed CVE-2021-42053, a code diff analysis between versions prior to and post 0.36.0 would be necessary.*

- Security Test Case:
    1. Set up a Django project with a version of Django Unicorn *prior to* 0.36.0 (if possible for testing; you might need to manually install an older version using `pip install django-unicorn==0.35.0` or similar).
    2. Create a simple Django Unicorn component, e.g., `VulnerableComponent`, with a `message` attribute and a template that renders it:
        ```python
        # example/unicorn/components/vulnerable_component.py (for version < 0.36.0)
        from django_unicorn.components import UnicornView

        class VulnerableComponentView(UnicornView):
            message = ""
        ```
        ```html
        {# example/unicorn/components/vulnerable_component.html (for version < 0.36.0) #}
        <div>
            <input unicorn:model="message" />
            <div id="message-output">{{ message }}</div>
        </div>
        ```
    3. Create a view and URL to render `VulnerableComponent`.
    4. On the frontend, navigate to the view and use browser developer tools to send a crafted AJAX request to the Unicorn endpoint. Use the same JSON payload structure as in the "Unsafe HTML Rendering" test case, but this time inject a basic XSS payload without relying on `safe` meta option. For instance:
        ```json
        {
          "id": "<component_id>",
          "name": "example.unicorn.components.vulnerable_component.VulnerableComponentView",
          "data": {
            "message": "<script>alert(\"Vulnerable Version XSS\");</script>"
          },
          "checksum": "initial_checksum_value",
          "actionQueue": [
            {
              "type": "syncInput",
              "payload": {
                "id": "message",
                "name": "message",
                "value": "<script>alert(\"Vulnerable Version XSS\");</script>"
              }
            }
          ]
        }
        ```
    5. Observe if the JavaScript payload executes (e.g., an alert box appears with "Vulnerable Version XSS"). If it does, it confirms the XSS vulnerability in the older version due to lack of default HTML encoding.
    6. Repeat the same test with version 0.36.0 or later. The XSS should be mitigated due to the implemented fixes. The JavaScript payload should not execute, and instead be rendered as plain text in the `message-output` div, demonstrating the mitigation.
