### Vulnerabilities in django-unicorn

#### 1. Cross-Site Scripting (XSS) vulnerability due to improper handling of user input in templates

* Description:
    1. An attacker can inject malicious JavaScript code into various parts of a django-unicorn component through user-controlled data. This can be achieved via component properties bound using `unicorn:model`, arguments passed to component actions, component attributes, or even URL parameters passed as kwargs to the component.
    2. When a component is rendered or re-rendered, user-supplied data, if not properly sanitized, is inserted directly into the HTML template.
    3. If the injected data contains malicious JavaScript code (e.g., `<img src='x' onerror='alert("XSS Vulnerability!")'>` or `<script>alert("XSS")</script>`), and if the template renders this data without sufficient HTML encoding or escaping, the JavaScript code will be executed in the user's browser.
    4. Django templates by default offer auto-escaping, which can mitigate some XSS risks, but developers must be aware that django-unicorn, while providing default HTML encoding for component properties, might not consistently apply sanitization across all contexts, especially when developers use features like the `safe` attribute or filter, or when handling kwargs. Incorrect usage or misunderstanding of these features can lead to XSS vulnerabilities.

* Impact:
    * Critical. Successful XSS attacks can have severe consequences, including:
        - Account takeover: Attackers can steal user session cookies or credentials, gaining unauthorized access to user accounts.
        - Data theft: Attackers can steal sensitive data displayed on the page or accessible through the user's session.
        - Malware distribution: Attackers can redirect users to malicious websites or inject malware into the page.
        - Defacement: Attackers can modify the content of the web page, displaying misleading or harmful information.
        - Execution of arbitrary JavaScript: Any action achievable through JavaScript can be performed in the user's browser.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    * Default HTML Encoding: Since version 0.36.0, django-unicorn HTML encodes responses by default to prevent XSS attacks. This is documented in the changelog and views documentation.
    * `sanitize_html` function: The `django_unicorn.utils.sanitize_html` function is used to escape HTML characters for JSON output, specifically for the `init` script in `UnicornTemplateResponse.render`.
    * Tests: Tests like `test_html_entities_encoded` in `test_process_component_request.py` confirm that by default, component properties are HTML encoded.

* Missing mitigations:
    * Consistent Sanitization: While HTML encoding is default, it's unclear if it's consistently applied to *all* dynamic content rendered in templates, especially during component updates after user interactions. The current `sanitize_html` function is focused on JSON data, not general template variable rendering.
    * Explicit Security Guidance: Documentation should more prominently emphasize the security implications of using the `safe` filter and `Meta.safe` option. Developers should be strongly advised to treat user-provided data as unsafe by default and only use `safe` when necessary for trusted content.
    * Automated Checks: Lack of automated checks (e.g., linters, security scans) to detect potential misuse of `safe` filter/Meta option with user-provided data.
    * Content Security Policy (CSP): No automatic CSP integration or recommendation, which could further mitigate XSS impact.

* Preconditions:
    1. A django-unicorn component is used in a Django template.
    2. The component template dynamically renders user-controlled data or component properties (from `unicorn:model`, action arguments, attributes, or kwargs) into the HTML structure, e.g., using `{{ component_property }}` or `{{ kwarg_value }}`.
    3. The developer either relies solely on default Django template auto-escaping without explicit sanitization in component logic, or incorrectly uses `safe` filter/`Meta.safe`, or renders kwargs directly from user-controlled sources.
    4. The application is deployed and accessible to potential attackers.

* Source code analysis:
    * `django_unicorn/utils.py`: The `sanitize_html` function escapes HTML special characters for JSON output but is not used for general template rendering.
    * `django_unicorn/components/unicorn_template_response.py`: `sanitize_html` is used for `init` data within `<script>` tag, but not for general template rendering.
    * `django_unicorn/templatetags/unicorn.py`: Kwargs passed to the `unicorn` template tag are resolved directly from the template context without explicit sanitization.
    * `django_unicorn/views/__init__.py`: Processing of component requests and rendering relies on Django's template engine auto-escaping for properties not marked as `safe`. `Meta.safe` fields are marked as safe *before* template rendering, bypassing auto-escaping.  `set_property_from_data` in `django_unicorn/views/utils/set_property_from_data.py` updates component properties directly with user-provided data without sanitization.
    * `django_unicorn/serializer.py`: `orjson.dumps` used for serialization does not perform HTML escaping.
    * Tests in `django_unicorn/tests/views/test_process_component_request.py` demonstrate default HTML encoding and bypass with `Meta.safe`, but do not fully cover all contexts where XSS might occur, like kwargs.

* Security test case:
    1. Create a django-unicorn component with a property bound to user input and rendered in the template.
    2. Component Python code (`test_component.py`):
    ```python
    from django_unicorn.components import UnicornView

    class TestComponentView(UnicornView):
        user_input = ""

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
    7. Observe if the alert box "XSS Vulnerability!" is displayed when the component re-renders after input. If the alert box is *not* displayed, it indicates default HTML encoding is active and mitigating the XSS in this basic scenario.
    8. To test kwargs vulnerability, create a component that renders a kwarg and pass a malicious payload via URL parameter as kwarg.  Check if alert is triggered.
    9. To test `safe` attribute behavior, add `safe = ("user_input",)` to the Meta class and repeat steps 6-7 to ensure that XSS is possible when `safe` is explicitly used, highlighting the developer's responsibility in using this attribute carefully.

#### 2. Cross-Site Scripting (XSS) through `safe` template filter and `safe` Meta option

* Description:
    1. A developer intentionally or unintentionally uses the `safe` template filter in a django-unicorn component template or the `safe` Meta option in the component's view to bypass default HTML escaping.
    2. User-provided data is then rendered in the template with the `safe` filter or `safe` Meta option enabled for the property.
    3. A threat actor crafts a malicious payload (e.g., `<script>alert("XSS")</script>` or `<img src=x onerror=alert('XSS')>`).
    4. The threat actor injects this payload as user-provided data (e.g., through a form input, URL parameter, etc.) that gets bound to the component property marked as `safe` or rendered with `safe` filter.
    5. The component re-renders with the malicious payload.
    6. Because the `safe` filter or `safe` Meta option is used, the payload is rendered without HTML escaping.
    7. When a user views the page, the malicious script executes in their browser.

* Impact:
    * Critical. Using `safe` inappropriately directly leads to XSS vulnerabilities, with impacts including:
        - Account Takeover
        - Data Theft
        - Website Defacement
        - Malicious Redirection
        - Execution of Arbitrary JavaScript

* Vulnerability Rank: Critical

* Currently Implemented Mitigations:
    * Default HTML encoding is in place to prevent XSS in most cases, making `safe` an opt-in for bypassing this protection.
    * Documentation for `safe` Meta option mentions explicitly opting-in to allow unsafe rendering.

* Missing Mitigations:
    * Explicit Warnings in Documentation:  Stronger and more prominent warnings in documentation against using `safe` with user-provided data without rigorous sanitization.
    * Automated Detection: Lack of automated tools to detect potentially unsafe usage of `safe` filter/Meta option.

* Preconditions:
    1. The developer must use the `safe` template filter or the `safe` Meta option.
    2. User-provided data must be dynamically rendered in the template using the `safe` filter or `safe` Meta option.
    3. There must be a way for an attacker to inject malicious JavaScript code as user-provided data.

* Source Code Analysis:
    * `docs\source\views.md`: Documents `safe` Meta option, indicating it disables default HTML encoding.
    * `docs\source\templates.md`: Mentions Django templates and `safe` filter, highlighting potential bypass of auto-escaping.
    * `django_unicorn\components\unicorn_template_response.py`: `sanitize_html` is for JSON, not general template rendering. Relies on Django's auto-escaping which is bypassed by `safe`.
    * `django_unicorn\utils.py`: `sanitize_html` is for JSON encoding.
    * `tests\views\test_process_component_request.py`: `test_safe_html_entities_not_encoded` explicitly demonstrates that `safe` bypasses HTML encoding.

* Security Test Case:
    1. Create a django-unicorn component `xss_safe_component` with `safe` Meta option enabled for a property.
    2. Component view:
       ```python
       from django_unicorn.components import UnicornView

       class XssSafeView(UnicornView):
           text = ""

           class Meta:
               safe = ("text", )
       ```
    3. Component template:
       ```html
       <div>
           <input type="text" unicorn:model.defer="text">
           <div id="xss-output">{{ text }}</div>
       </div>
       ```
    4. Create Django view and template to render `xss_safe_component`.
    5. Access the page in browser.
    6. Inject JavaScript payload (e.g., `<img src=x onerror="alert('XSS - Safe Option')">`) in the input field.
    7. Trigger component update.
    8. Observe alert box with "XSS - Safe Option" displayed, confirming XSS when `safe` is used.
    9. Remove `safe` Meta option and repeat test, verifying XSS is mitigated when `safe` is not used, demonstrating default HTML encoding.


#### 3. Cross-Site Scripting (XSS) vulnerability due to unsafe string coercion in kwargs passed to components

* Description:
    1. An attacker crafts a malicious URL that includes a query parameter designed to be passed as a kwarg to a django-unicorn component via the `unicorn` template tag.
    2. The component's template directly renders this kwarg, for example, using `{{ my_kwarg }}`.
    3. If the attacker's crafted URL parameter contains malicious JavaScript code (e.g., `?kwarg=<script>alert("XSS-Kwarg")</script>`), and if the template renders this kwarg without explicit HTML sanitization, the script will execute in the user's browser.
    4. This occurs because the `unicorn` template tag directly resolves kwargs from the template context (including `request.GET`) and passes them to the component's template context. Django's default auto-escaping might not be sufficient if developers bypass it or expect kwargs to be automatically safe without explicit sanitization.

* Impact:
    * High. Exploitable XSS leading to:
        - Account hijacking.
        - Data theft.
        - Website defacement.
        - Redirection to malicious sites.

* Vulnerability Rank: High

* Currently implemented mitigations:
    * Django's default template auto-escaping is generally active, which can mitigate basic XSS.
    * `sanitize_html` function exists, but is not automatically applied to kwargs or general template rendering, focused on JSON data only.
    * Documentation mentions HTML encoding as a fix for XSS, likely referring to Django's auto-escaping.

* Missing mitigations:
    * No automatic input sanitization for kwargs passed to components via the `unicorn` template tag.
    * Lack of warnings against directly rendering kwargs from user-controlled sources in templates without sanitization.
    * No mechanism in django-unicorn to automatically sanitize kwargs before template rendering.

* Preconditions:
    1. The application uses django-unicorn components.
    2. A component is designed to accept kwargs via the `unicorn` template tag.
    3. The component template renders these kwargs directly using template variables.
    4. Kwargs are derived from user-controllable sources like URL parameters or form inputs, and passed to the component via the `unicorn` template tag.

* Source code analysis:
    * `django_unicorn\templatetags\unicorn.py`:  The `unicorn` template tag resolves kwargs directly from the template context (including `request.GET`) without sanitization.
    * `django_unicorn\components\unicorn_template_response.py`: `sanitize_html` is used for JSON data only, not general template kwargs.
    * `django_unicorn\utils.py`: `sanitize_html` is for JSON encoding.
    * Django's template auto-escaping is the primary mitigation, but can be bypassed or be insufficient.

* Security test case:
    1. Create a Django project with django-unicorn.
    2. Create a component `xss_kwarg_test` that renders a kwarg `value`.
    3. Component view:
    ```python
    from django_unicorn.components import UnicornView

    class XssKwargTestView(UnicornView):
        value = ""

        def mount(self, initial_value="default"):
            self.value = initial_value
    ```
    4. Component template:
    ```html
    <div>
        <p>Rendered Kwarg Value: {{ value }}</p>
    </div>
    ```
    5. Create a Django view and template to render `xss_kwarg_test` component, passing `request.GET.xss` as `initial_value` kwarg.
    6. Access URL `/?xss=<script>alert("XSS-Kwarg")</script>`.
    7. Observe if alert box "XSS-Kwarg" appears, confirming XSS vulnerability due to unsafe kwarg rendering.
