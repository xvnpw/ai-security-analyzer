### Vulnerability 1: Reflected Cross-Site Scripting (XSS) in Component Properties

- Description:
    1. An attacker can inject malicious JavaScript code into a component property via user input.
    2. When the component is rendered, the injected JavaScript code is included in the HTML without proper sanitization.
    3. The browser executes the malicious script when rendering the HTML, leading to XSS.
    4. This can be triggered by manipulating component properties that are directly rendered in the template, especially those bound to user inputs via `unicorn:model`.

- Impact:
    - High. Successful XSS can lead to account takeover, session hijacking, defacement, redirection to malicious sites, or information theft.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - HTML encoding is applied to updated field values by default to prevent XSS attacks, as mentioned in `docs\source\views.md` and evidenced in `docs\source\changelog.md` (version 0.36.0). This is implemented in the `_desoupify` method within `UnicornTemplateResponse` by default encoding HTML entities.

- Missing Mitigations:
    - While default HTML encoding provides a general mitigation, it might not be sufficient in all contexts, especially if developers explicitly mark properties as `safe` or use `|safe` template filter, or if vulnerabilities exist in JavaScript integrations.
    - Context-aware output encoding is missing. The current mitigation is a blanket HTML encoding which might not be sufficient in all cases, especially when dealing with complex template logic or JavaScript interactions.

- Preconditions:
    - A component must render a property that is directly or indirectly influenced by user input.
    - The developer must not have adequately sanitized the output, for example, by marking a property as `safe` when it contains user-controlled data without proper escaping for the specific context.

- Source Code Analysis:
    1. **`django_unicorn\components\unicorn_template_response.py`**:
        - The `_desoupify` method in `UnicornTemplateResponse` encodes HTML entities using `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`. This is a general HTML encoding mitigation.
        - The `Meta.safe` attribute in `views.md` and `safe` template filter are mentioned as ways to bypass encoding, potentially leading to XSS if used improperly.
    2. **`django_unicorn\views\views.py`**:
        - The `_process_component_request` function renders the component and updates the DOM.
        - It checks for `Meta.safe` and applies `mark_safe` to fields listed in it.
        - It uses Django's form validation, which can help prevent some types of malicious input, but doesn't directly prevent XSS in all cases.
    3. **`docs\source\views.md`**:
        - Documents the `safe` Meta option, which if misused, can create XSS vulnerabilities.

- Security Test Case:
    1. Create a Django Unicorn component that displays a property bound to user input.
    2. In the component's template, render the property directly without additional sanitization or escaping (e.g., `{{ property_name }}`).
    3. In the component's view, do **not** include the property name in `Meta.safe`.
    4. Create a form or input field in a Django template that uses the component and binds to the vulnerable property using `unicorn:model`.
    5. As an attacker, input a JavaScript payload into the input field, such as `<script>alert('XSS')</script>`.
    6. Submit the form or trigger an update to the component.
    7. Observe if the JavaScript `alert('XSS')` is executed in the browser, confirming the XSS vulnerability.
