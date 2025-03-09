- Vulnerability name: Cross-Site Scripting (XSS) through unsafe field rendering
- Description:
    1. A Django Unicorn component renders a template that includes user-controlled data without proper output encoding.
    2. An attacker crafts malicious input containing Javascript code.
    3. The attacker injects this malicious input into the application, for example, through a form field bound to a Unicorn component's `unicorn:model`.
    4. When the component re-renders (e.g., after a model update or action), the malicious Javascript is rendered into the HTML response *without* HTML encoding if the field is marked as `safe` or if `safe` is misused.
    5. The victim's browser executes the malicious Javascript, potentially leading to session hijacking, data theft, or other malicious actions.
- Impact: Successful exploitation of this vulnerability allows an attacker to execute arbitrary Javascript code in the victim's browser. This can lead to account compromise, session hijacking, sensitive data disclosure, redirection to malicious websites, or defacement.
- Vulnerability rank: high
- Currently implemented mitigations:
    - Django Unicorn *defaults* to HTML encoding all component field values to prevent XSS.
    - Developers need to explicitly opt-in to disable HTML encoding for specific fields by adding them to the `safe` tuple in the `Meta` class of the component view.
- Missing mitigations:
    - No mechanism to automatically detect or warn developers about potential XSS vulnerabilities when using `safe`.
    - No clear guidance or security warning in the documentation against using `safe` with user-controlled data without stringent sanitization on the backend.
- Preconditions:
    - A Django Unicorn component is implemented to render user-controlled data in a template.
    - The developer has either explicitly marked the component field as `safe` in the `Meta` class, or there is a misunderstanding about when to use `safe`.
    - The application does not implement sufficient input sanitization to remove or neutralize malicious Javascript before it reaches the component.
- Source code analysis:
    1. Refer to `docs\source\views.md` (mentioned in the initial vulnerability description, but not provided in PROJECT FILES) which describes the `Meta` class and the `safe` attribute: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple."
    2. This documentation explicitly states that HTML encoding is the default mitigation against XSS, and that developers have the option to disable it using `safe`.
    3. The changelog for version `0.36.0` (mentioned in the initial vulnerability description, but not provided in PROJECT FILES) mentions "Security fix: for CVE-2021-42053 to prevent XSS attacks" and notes "responses will be HTML encoded going forward". This reinforces that prior to this version, or if `safe` is used incorrectly, XSS vulnerabilities could be present.
    4. Reviewing `django_unicorn\components\unicorn_view.py` (provided in PROJECT FILES) and `django_unicorn\components\unicorn_template_response.py` (provided in previous PROJECT FILES) confirms that HTML encoding is applied during template rendering for dynamic data unless the `safe` attribute is used. Specifically, `django_unicorn\components\unicorn_template_response.py` uses Django's built-in template engine which, by default, HTML-escapes variables. However, when a field is in the `safe` tuple, this escaping is skipped.
    5. Analyzing `django_unicorn\views\__init__.py` (provided in previous PROJECT FILES) shows that during component rendering within the `message` view function, there is explicit handling of `safe_fields`:

        ```python
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
        ```
        This code block confirms that fields listed in the `safe` tuple are explicitly marked as safe using Django's `mark_safe` utility *after* data is set to the component but *before* rendering. This means that any data assigned to a `safe` field is rendered without HTML escaping.
    6. The provided test file `tests\views\test_process_component_request.py` (provided in previous PROJECT FILES) includes tests `test_html_entities_encoded` and `test_safe_html_entities_not_encoded` which directly test this behavior, confirming that fields not marked `safe` are HTML encoded and those marked `safe` are not.
- Security test case:
    1. Create a Django Unicorn component named `xss_test` in a Django application.
    2. Define a component view `XssTestView` with a field `unsafe_data` initialized as an empty string.
    3. In the `Meta` class of `XssTestView`, set `safe = ("unsafe_data", )`. This intentionally disables HTML encoding for this field.
    4. Create a template `unicorn/xss-test.html` with the following content:
        ```html
        <div>
          <input type="text" unicorn:model.defer="unsafe_data" id="input-field">
          <div id="output-area">{{ unsafe_data }}</div>
        </div>
        ```
    5. Create a Django view and template to include the `xss_test` component on a page.
    6. Access the page in a browser.
    7. In the input field, enter the following Javascript payload: `<img src='x' onerror='alert("XSS Vulnerability")'>`.
    8. Click outside the input field to trigger the `lazy` model update (or remove `.defer` for immediate update).
    9. Observe that an alert box with "XSS Vulnerability" is displayed in the browser. This confirms that the Javascript code was executed, demonstrating the XSS vulnerability because `unsafe_data` was marked as `safe` and the input was not sanitized.
