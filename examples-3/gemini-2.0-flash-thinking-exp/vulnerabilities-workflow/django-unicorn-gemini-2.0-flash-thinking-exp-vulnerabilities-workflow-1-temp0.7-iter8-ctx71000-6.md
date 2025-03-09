### Vulnerability List for django-unicorn Project

* Vulnerability Name: Cross-Site Scripting (XSS) due to Inadequate HTML Encoding in Component Rendering
* Description:
    1. An attacker can inject malicious JavaScript code into a component's data or template.
    2. When the component is rendered or updated, the injected JavaScript code is not properly HTML encoded due to developer using `Meta.safe` or insufficient default auto-escaping in certain contexts.
    3. The browser executes the malicious JavaScript code in the context of the user's session when the component is displayed.
* Impact:
    - Account Takeover: Attacker can steal session cookies or credentials, leading to account compromise.
    - Data Theft: Attacker can access sensitive user data or application data.
    - Defacement: Attacker can modify the content of the web page, redirect users to malicious sites, or perform other malicious actions.
    - Malicious Actions: Attacker can perform actions on behalf of the user, such as making unauthorized purchases or changes.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - Based on the changelog (v0.36.0), HTML encoding was implemented to prevent XSS attacks, mentioning "responses will be HTML encoded going forward".
    - Documentation for views (views.md) describes a `Meta.safe` option to explicitly disable HTML encoding for specific fields, suggesting default HTML encoding.
* Missing Mitigations:
    - Verification needed to ensure HTML encoding is consistently applied across all component rendering paths, including initial rendering and AJAX updates.
    - Secure usage of `Meta.safe` needs to be enforced and documented, limiting its use to only when absolutely necessary and with careful review of the data marked as safe.
    - Comprehensive testing is required to confirm that user-provided data in component attributes, actions, and models are consistently and properly encoded.
* Preconditions:
    - A django-unicorn application is deployed and publicly accessible.
    - An attacker must find a vector to inject malicious code. This could be through:
        - Exploiting a data input field that is bound to a component variable and rendered without proper encoding.
        - Manipulating arguments passed to component actions if these are rendered in the template without encoding.
        - Injecting data into models that are then rendered by components, especially if `Meta.safe` is used for these model fields.
* Source Code Analysis:
    - `django_unicorn/utils.py`: The `sanitize_html` function is present, but it is specifically designed for escaping HTML special characters for JSON output within HTML attributes (`unicorn:data`), not for general HTML sanitization of template context variables. It uses `html.translate(_json_script_escapes)` and `mark_safe`.
    - `django_unicorn/components/unicorn_template_response.py`: `UnicornTemplateResponse.render` renders the component template. The rendered `response.content` is parsed using `BeautifulSoup`. Component attributes, including `unicorn:data` (which contains JSON-serialized component data passed through `sanitize_html`), are added as HTML attributes to the root element. The HTML template rendering itself relies on Django's default auto-escaping for context variables unless `mark_safe` is explicitly used.
    - `django_unicorn/views/__init__.py`: `_process_component_request` handles `safe_fields` defined in `Meta.safe` of components. For fields listed in `Meta.safe`, if the value is a string, it's marked as safe using `mark_safe`, effectively bypassing HTML auto-escaping for these specific fields. This is intended for developers to opt-out of encoding when they deem content as safe, but introduces risk if misused.
    - `django_unicorn/views/utils.py`: The `set_property_from_data` function is used to update component properties based on data sent from the client-side during AJAX requests. This function handles deserialization and type conversion of data before setting it on the component instance. If the data processed by `set_property_from_data` originates from user input and is not properly sanitized *before* being sent to the client (or if it's re-rendered without encoding after being set), it could become an XSS vector, especially when combined with the use of `Meta.safe`.
    - **Vulnerability Point**: The risk of XSS arises from potential misuse of `Meta.safe` which disables Django's auto-escaping. If developers incorrectly mark user-provided data or data that could contain malicious content as safe, it will be rendered without encoding, leading to XSS. Furthermore, while Django's default auto-escaping is generally robust, specific contexts within django-unicorn's rendering process may have unintentional bypasses or areas where auto-escaping is not consistently applied, although current code analysis doesn't immediately reveal such areas beyond the explicit `Meta.safe`.
    - Visualization: Not needed for this part of analysis.
* Security Test Case:
    1. **Setup**: Create a django-unicorn component that renders a variable from its context in the template. Ensure no explicit escaping filters are used in the template, relying solely on Django's default auto-escaping.
    2. **Injection without `Meta.safe`**: In the component's Python code, set the context variable to a malicious string containing JavaScript, e.g., `<img src=x onerror=alert('XSS-default-escaping')>`. Render the component and observe if the JavaScript executes. If it does not execute and the HTML is encoded (e.g., `&lt;img src=x onerror=alert('XSS')&gt;`), Django's default auto-escaping is working as expected in this context.
    3. **Injection with `Meta.safe`**:
        - Modify the component to include a `Meta` class with `safe = ('variable_name',)` where `variable_name` is the context variable being rendered.
        - Again, set `variable_name` to the malicious JavaScript string: `<img src=x onerror=alert('XSS-meta-safe')>`.
        - Render the component. If the JavaScript executes (e.g., an alert box 'XSS-meta-safe' appears), it confirms that `Meta.safe` bypasses HTML encoding, and if misused with user-controlled data, leads to XSS.
    4. **Test different injection points**:
        - **Component data**: Test by setting the malicious string as a component attribute value in the Python code.
        - **Action arguments**: Create an action that takes an argument and renders it in the template. Call this action with the malicious string as an argument.
        - **Model data**: If applicable, fetch data from a model (where data could be influenced by an attacker, e.g., through another form or direct database manipulation in a test setup) and render it in the component, testing both with and without `Meta.safe`.
    5. **Verify Encoding**: In cases where XSS is not triggered, inspect the rendered HTML source to confirm that the malicious JavaScript payload is indeed HTML-encoded in the output (e.g., `<img` becomes `&lt;img`).
