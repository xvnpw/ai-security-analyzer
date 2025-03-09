## Vulnerability Report

This report summarizes identified vulnerabilities, combining and de-duplicating findings from multiple lists.

### Vulnerability: Cross-Site Scripting (XSS) via Unsafe Template Rendering

* Description:
    1. An attacker can inject malicious JavaScript code by influencing component properties through user input.
    2. A developer, aiming for dynamic content rendering without HTML encoding, uses the `safe` meta attribute in the component's `Meta` class or the `safe` template filter. This is incorrectly applied to properties that are directly or indirectly controlled by user input.
    3. When the component is rendered or updated, the injected JavaScript code is executed in the user's browser because the output is not properly sanitized due to the intentional bypass of HTML encoding via the `safe` setting.

* Impact:
    * Critical. Successful exploitation enables an attacker to execute arbitrary JavaScript code within the victim's browser context. This can lead to severe security breaches, including account takeover, sensitive data theft, session hijacking, redirection to malicious websites, and application defacement.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    * Django-unicorn's default behavior is to HTML-encode updated field values, which serves as a general mitigation against XSS attacks in most scenarios.
    * The official documentation explicitly warns about the security implications of using the `safe` setting, advising developers to exercise extreme caution.

* Missing Mitigations:
    * There is no enforced mechanism to prevent developers from unsafely using `safe` on user-controlled input without proper sanitization.
    * The framework lacks a built-in feature to automatically sanitize data even when `safe` is employed, although this behavior may not be universally desirable as `safe` is intended to bypass sanitization.
    * No code analysis or linting tools are provided to automatically detect potentially insecure usages of the `safe` setting.
    * The framework does not enforce Content Security Policy (CSP) by default, which could act as an additional layer of security against XSS.

* Preconditions:
    * A developer must explicitly utilize the `safe` meta attribute or the `safe` template filter in a component.
    * The component property marked as `safe` must be directly or indirectly influenced by user-provided input.
    * A user must access a part of the application where the vulnerable component is rendered in their browser.

* Source Code Analysis:
    1. **`docs\source\views.md`**:  Documentation clearly states that `Meta.safe` disables default HTML encoding, highlighting potential security risks if misused.
    2. **`docs\source\templates.md`**: Mentions attributes, indicating that standard HTML attributes are also used, which is relevant to attribute-based injection vulnerabilities.
    3. **`docs\source\changelog.md`**: Records past XSS fixes, emphasizing the importance of HTML encoding and risks of bypassing it.
    4. **`django_unicorn\views\__init__.py`**: Code confirms that fields listed in `Meta.safe` are marked as safe using `mark_safe`, bypassing HTML encoding.
    ```python
    # django_unicorn\views\__init__.py
    # ...
    for field_name in safe_fields:
        value = getattr(component, field_name)
        if isinstance(value, str):
            setattr(component, field_name, mark_safe(value))  # noqa: S308
    # ...
    ```
    5. **`tests\views\test_process_component_request.py`**: Tests confirm that HTML entities are not encoded when `safe` is used, validating the intended behavior and potential vulnerability.
    6. **`django_unicorn\components\unicorn_template_response.py`**:  Responsible for template rendering but lacks specific attribute sanitization. `sanitize_html` function might not be robust enough for attribute contexts when `safe` is used.

* Security Test Case:
    1. Create a Django Unicorn component `xss_component` with a property `unsafe_data` and `safe = ("unsafe_data",)` in `Meta`.
    2. In `xss_component.html`, render `unsafe_data` within a div and bind an input field to it using `unicorn:model`.
    3. Include `xss_component` in a Django template accessible to an attacker.
    4. Run the Django application.
    5. Access the page in a browser.
    6. Input the payload `<img src=x onerror="alert('XSS Vulnerability')">` into the input field.
    7. Trigger a component update.
    8. Observe an alert box "XSS Vulnerability", confirming XSS due to bypassed HTML encoding by `safe`.


### Vulnerability: HTML Attribute Injection leading to Cross-Site Scripting (XSS)

* Description:
    1. An attacker can inject malicious HTML attributes, including JavaScript event handlers, by manipulating component properties that dynamically populate HTML attributes in Django Unicorn templates.
    2. When a component re-renders due to user interactions or data updates, HTML attributes are updated based on component properties.
    3. If developers dynamically set HTML attributes based on user-controlled component properties without sanitization, attackers can inject arbitrary attributes like `onload`, `onerror`, or `onmouseover`.
    4. Upon rendering or update in a user's browser, injected attributes are included in the DOM. Event handlers with embedded JavaScript code will then execute, leading to XSS.
    5. This vulnerability is exacerbated if developers mistakenly use the `safe` template filter or `Meta.safe` attribute in conjunction with attribute injection, intending to bypass default HTML encoding, thereby unintentionally enabling XSS.

* Impact:
    * Critical. Successful exploitation allows injection of arbitrary HTML attributes, potentially leading to JavaScript execution if event handler attributes are injected. This can result in actions similar to XSS, including data theft, redirection, or other malicious activities within the user's browser context.

* Vulnerability Rank: critical

* Currently Implemented Mitigations:
    * Django Unicorn's default HTML encoding mitigates XSS in HTML element content, but does not extend to HTML attributes.
    * There are no specific built-in mitigations to prevent HTML injection via attribute manipulation.

* Missing Mitigations:
    * Lack of input sanitization for component properties used to dynamically set HTML attributes.
    * No mechanism to automatically sanitize HTML attributes or restrict dynamically settable attribute types.
    * No documentation guidance to warn developers about the risks of dynamic attribute manipulation with user-controlled input.
    * Absence of code analysis or linting tools to detect unsafe dynamic attribute manipulation.
    * No Content Security Policy (CSP) enforced by default.

* Preconditions:
    * A developer must dynamically set HTML attributes based on component properties in the template.
    * At least one of these properties must be influenced by user-provided input.
    * The application must render the component and update it based on user input to trigger attribute injection.
    * Vulnerability is heightened if `safe` is also used in conjunction with attribute injection.

* Source Code Analysis:
    1. **`django_unicorn\components\unicorn_template_response.py`**: Renders component templates using `BeautifulSoup`. While BeautifulSoup escapes HTML content, it does not sanitize HTML attributes. Django templates insert attribute values directly without attribute-specific encoding after template processing.
    2. **`django_unicorn\templatetags\unicorn.py`, `django_unicorn\components\unicorn_view.py`**: Handle component rendering and data passing but lack attribute sanitization logic.
    3. **Absence of Attribute Sanitization**: Code review confirms no explicit HTML attribute sanitization in django-unicorn. Sanitization focus is on HTML tag content, not attributes, evidenced by the `safe` mechanism to bypass content sanitization but no parallel mechanism for attribute control or sanitization.

* Security Test Case:
    1. Create a Django Unicorn component `attribute_injection_component` with a property `dynamic_attribute`.
    2. In `attribute_injection_component.html`, set an attribute dynamically using `{{ dynamic_attribute }}`.
    3. Include `attribute_injection_component` in a Django template accessible to an attacker.
    4. Run the Django application.
    5. Access the page in a browser.
    6. Input payload `onload="alert('HTML Attribute Injection Vulnerability')"` into the input field.
    7. Trigger a component update.
    8. Observe an alert box "HTML Attribute Injection Vulnerability", confirming HTML attribute injection leading to XSS.
    9. Modify `attribute_xss.py` to include `safe = ("unsafe_input",)` in `Meta` and template to use `{{ unsafe_input|safe }}` in the `title` attribute to test `safe` usage exacerbating the vulnerability as shown in the second security test case in the original second list.

### Vulnerability: Potential Cross-Site Scripting (XSS) via Script Element Reload

* Description:
    1. With `RELOAD_SCRIPT_ELEMENTS` enabled (non-default setting), `<script>` elements in Unicorn components are reloaded and re-executed on component updates.
    2. If a component template includes inline `<script>` tags containing user-controlled content (especially if marked as `safe`), enabling `RELOAD_SCRIPT_ELEMENTS` will cause these scripts to re-execute on every component update.
    3. Malicious JavaScript within these `<script>` tags, if present, will be re-executed with each update, leading to persistent or repeated XSS.
    4. This vulnerability path is conditional on enabling a non-default setting and developers' insecurely embedding user input within `<script>` tags while using `safe`.

* Impact:
    * High. If exploited (requires `RELOAD_SCRIPT_ELEMENTS` and unsafe `<script>` usage), attackers can inject and repeatedly execute JavaScript, leading to account compromise, data theft, and other malicious actions. Although reliant on a non-default setting, the potential for XSS remains significant in misconfigured environments.

* Vulnerability Rank: high

* Currently Implemented Mitigations:
    * `RELOAD_SCRIPT_ELEMENTS` defaults to `False`, inherently mitigating the risk unless explicitly enabled.
    * Documentation does not encourage using `<script>` tags for dynamic content within components, reducing unintentional usage.
    * Default HTML encoding applies to `<script>` tag content (unless bypassed with `safe`), offering some protection if `safe` is not misused.

* Missing Mitigations:
    * No warnings or guidelines in documentation against using `<script>` tags with user-controlled, `safe` content, especially with `RELOAD_SCRIPT_ELEMENTS` enabled.
    * Consideration should be given to removing or strongly discouraging `RELOAD_SCRIPT_ELEMENTS` due to security risks. If retained, prominent warnings and discouraged usage are needed.
    * No default Content Security Policy (CSP) for defense-in-depth.

* Preconditions:
    * `RELOAD_SCRIPT_ELEMENTS` must be set to `True` in Django settings (non-default).
    * A developer must use `safe` and embed user-controlled data within inline `<script>` tags in a component template (discouraged pattern).

* Source Code Analysis:
    1. **`docs\source\custom-morphers.md`, `docs\source\settings.md`**: Document `RELOAD_SCRIPT_ELEMENTS` but lack security warnings about its use with user input in `<script>` tags.
    2. **`django_unicorn\components\unicorn_template_response.py`**: Implements script reloading based on `RELOAD_SCRIPT_ELEMENTS` setting, directly enabling re-execution of scripts and potential XSS if scripts contain malicious input.

* Security Test Case:
    1. Enable `RELOAD_SCRIPT_ELEMENTS: True` in Django settings.
    2. Create `script_reload_xss` component with `unsafe_script` property, `safe = ("unsafe_script",)` and a `toggle` property.
    3. In `script_reload_xss.html`, add a toggle button, conditional input bound to `unsafe_script`, and a `<script>{{ unsafe_script|safe }}` block, shown when toggled.
    4. Setup Django view and template to render the component.
    5. Run the Django application.
    6. Access the page in a browser.
    7. Toggle to show input and script, input payload `alert('Script Reload XSS')`.
    8. Toggle off then on to force component update and script reload.
    9. Observe repeated alert box "Script Reload XSS" after toggling, demonstrating XSS due to script re-execution.
