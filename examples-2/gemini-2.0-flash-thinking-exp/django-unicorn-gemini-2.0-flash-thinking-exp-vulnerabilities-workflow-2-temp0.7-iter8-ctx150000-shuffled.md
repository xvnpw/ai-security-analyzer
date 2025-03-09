### Vulnerability: Cross-Site Scripting (XSS) via Misuse of `safe` Meta Attribute or `safe` Template Filter

- Description:
    1. A developer, intending to render raw HTML or believing the data to be safe, uses the `safe` attribute in the `Meta` class of a Django Unicorn component or the `safe` template filter. This disables Django Unicorn's default HTML escaping for specific component fields or template variables.
    2. User-provided data or data from an untrusted source is bound to this field or variable, potentially through `unicorn:model` in the component's template or passed as context to the component.
    3. A malicious user inputs JavaScript code or otherwise an attacker injects malicious JavaScript code into the user-provided data.
    4. When the component updates or is initially rendered, the Django Unicorn backend renders the component and includes the user-provided, unescaped JavaScript code in the HTML response because of the `safe` attribute or filter.
    5. The frontend JavaScript merges the updated HTML into the DOM.
    6. The malicious JavaScript code is executed in the user's browser, leading to Cross-Site Scripting (XSS).

- Impact:
    Successful XSS attacks can allow threat actors to:
    - Steal session cookies, potentially gaining unauthorized access to user accounts (account takeover).
    - Redirect users to malicious websites.
    - Deface the web page.
    - Perform actions on behalf of the user, such as making unauthorized transactions or accessing sensitive data.
    - Execute arbitrary JavaScript code in the victim's browser, leading to a wide range of malicious activities.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - By default, Django Unicorn HTML-encodes all component data rendered in templates to prevent XSS. This is the standard behavior unless explicitly overridden by using `safe` Meta attribute or `safe` template filter.
    - Documentation warns against using `safe` with user-provided data and explains its purpose is for explicitly trusted content. (`docs\source\views.md`)
    - Changelog for version 0.36.0 highlights the introduction of default HTML encoding as a security fix for CVE-2021-42053, emphasizing the framework's awareness of XSS risks.

- Missing Mitigations:
    - No explicit warnings or checks in the code to prevent developers from using `safe` attribute or `safe` template filter with user-provided data.
    - It relies solely on developer awareness and correct usage based on documentation.
    - No built-in sanitization or escaping mechanisms are automatically applied when `safe` is used; the responsibility is entirely on the developer to implement proper sanitization.
    - The test suite lacks specific security test cases that explicitly target XSS vulnerabilities related to the `safe` Meta option and `safe` template filter.

- Preconditions:
    1. A Django Unicorn component is created and renders user-provided data or data from untrusted sources.
    2. The component's `Meta` class incorrectly uses the `safe` attribute for a field that is bound to user input or untrusted data, or the `safe` template filter is used to render such data.
    3. An attacker can provide malicious JavaScript code as input to the component through the UI, URL parameters, or other means of data injection.

- Source Code Analysis:
    1. **`django_unicorn\views\__init__.py`**: In the `_process_component_request` function, the code iterates through `safe_fields` defined in `Meta` class and marks them as safe using `mark_safe` from `django.utils.safestring`.
    ```python
    # Mark safe attributes as such before rendering
    for field_name in safe_fields:
        value = getattr(component, field_name)
        if isinstance(value, str):
            setattr(component, field_name, mark_safe(value))
    ```
    `mark_safe` marks a string as safe for HTML rendering, bypassing Django's automatic escaping.
    2. **`django_unicorn\components\unicorn_template_response.py`**: The `UnicornTemplateResponse.render()` method renders the component and includes the serialized data in the HTML. If `safe` is used (via `mark_safe`), the data is passed without encoding.
    3. **`docs\source\views.md`**: Documentation for `safe` meta option explains the default encoding and the opt-in for unencoded fields, but lacks strong warnings about XSS risks when used with user-provided data.

    ```python
    # Example of Safe usage in docs\source\views.md:

    # safe_example.py
    from django_unicorn.components import UnicornView

    class SafeExampleView(UnicornView):
        something_safe = ""

        class Meta:
            safe = ("something_safe", )
    ```
    In this example, `something_safe` will NOT be HTML encoded when rendered because it's listed in `Meta.safe`. If `something_safe` is directly bound to user input and rendered in the template without further escaping, it becomes vulnerable to XSS.

- Security Test Case:
    1. Create a Django Unicorn component named `xss_safe_test` in a Django app, e.g., `unicorn_xss_test`.
    2. In the component's Python view (`unicorn_xss_test/components/xss_safe_test.py`), define a field `user_input` and add `safe = ("user_input",)` to the `Meta` class:
    ```python
    # unicorn_xss_test/components/xss_safe_test.py
    from django_unicorn.components import UnicornView

    class XssSafeTestView(UnicornView):
        user_input = ""

        class Meta:
            safe = ("user_input", )
    ```
    3. Create a template for the component (`unicorn_xss_test/templates/unicorn/xss_safe_test.html`) that renders the `user_input` field:
    ```html
    {# unicorn_xss_test/templates/unicorn/xss_safe_test.html #}
    <div>
        <input type="text" unicorn:model="user_input">
        <div id="output">
            {{ user_input }}
        </div>
    </div>
    ```
    4. Create a Django view and URL to render a page with the `xss_safe_test` component.
    5. Access the URL in a web browser.
    6. In the input field, enter the following XSS payload: `<img src=x onerror="alert('XSS Vulnerability')">`.
    7. After typing or submitting the input, an alert box with "XSS Vulnerability" will appear, demonstrating the XSS vulnerability.

---

### Vulnerability: Cross-Site Scripting (XSS) via Unsafe HTML Attribute Injection

- Description:
    1. An attacker can inject malicious HTML attributes into DOM elements through user-controlled input fields by manipulating the data sent to the server during component updates.
    2. When a component updates, the server-side rendered HTML, which includes the injected attributes, is sent back to the client.
    3. The client-side JavaScript merges this HTML into the existing DOM using morphdom, effectively injecting the malicious attributes into the DOM elements.
    4. If these injected attributes are event handlers (e.g., `onload`, `onerror`, `onmouseover`), they can execute arbitrary JavaScript code when the element is processed by the browser.
    5. This vulnerability can be triggered through any input field that uses `unicorn:model` and whose value is reflected back into the HTML attributes of the component.

- Impact:
    - An attacker can execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, defacement of the website, or redirection to malicious sites.
    - If an administrative user is targeted, it could lead to account takeover and further compromise of the application and server.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - Django's automatic HTML escaping for template variables is used to prevent XSS in the HTML content itself.
    - CSRF protection is implemented to prevent cross-site request forgery attacks.
    - Checksum verification is used to ensure that component updates are valid and not tampered with.
    - HTML encoding of updated field values to prevent XSS attacks is implemented since v0.36.0, primarily focusing on HTML content.

- Missing Mitigations:
    - Input sanitization for HTML attributes is missing. While HTML content is encoded, HTML attributes are not systematically sanitized, allowing for attribute injection.
    - There is no clear mechanism to prevent users from injecting dangerous attributes into the DOM via `unicorn:model`.

- Preconditions:
    - The application must be using `django-unicorn` and have components with input fields that use `unicorn:model`.
    - An attacker needs to be able to interact with an input field that uses `unicorn:model` and influence the data that is sent to the server.

- Source Code Analysis:
    1. In `django_unicorn/components/unicorn_template_response.py`, the `UnicornTemplateResponse.render` method is responsible for rendering the component and updating the DOM.
    2. The server-rendered HTML is parsed using BeautifulSoup (`soup = BeautifulSoup(content, features="html.parser")`).
    3. The relevant part of the DOM is updated using morphdom library based on the HTML returned from the server.
    4. The `morphdom` library efficiently updates the DOM by diffing and patching the new HTML into the existing DOM. However, it does not sanitize HTML attributes.
    5. When the server returns HTML with malicious attributes injected by the attacker via `unicorn:model`, `morphdom` directly applies these attributes to the DOM elements.

- Security Test Case:
    1. Create a Django Unicorn component with an input field bound to a component property using `unicorn:model`, e.g., `name`.
    2. Render a page that includes this component.
    3. In the input field, enter a value that includes a malicious HTML attribute, such as `"/><img src=x onerror=alert('XSS')>`. To specifically test attribute injection, try injecting `test" onmouseover="alert('XSS')"`
    4. Trigger an update to the component.
    5. Hover over the input field. If a JavaScript alert box appears, the XSS vulnerability is confirmed.

---

### Vulnerability: Potential Cross-Site Scripting (XSS) via Client-Side DOM Manipulation Bypass

- Description:
    1. Django-unicorn uses `sanitize_html` function server-side to process and clean HTML content before sending it to the frontend.
    2. If Javascript code in frontend directly manipulates the DOM based on component updates without re-sanitization, it can re-introduce XSS vulnerabilities.
    3. Specifically, if component updates include seemingly safe HTML that is then manipulated by custom Javascript event listeners or functions, the sanitization applied server-side might be bypassed client-side.
    4. An attacker could craft a payload that is considered safe by `sanitize_html` but becomes malicious after client-side manipulation.

- Impact:
    - Cross-Site Scripting (XSS)
    - An attacker can execute arbitrary JavaScript code in the victim's browser by bypassing server-side sanitization through client-side DOM manipulation.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, or defacement of the website.

- Vulnerability Rank: Medium

- Currently Implemented Mitigations:
    - Server-side HTML sanitization using `django_unicorn.utils.sanitize_html` in `UnicornTemplateResponse._desoupify`.

- Missing Mitigations:
    - Client-side sanitization of any dynamically manipulated HTML content, especially if the manipulation is based on data from component updates.
    - Guidance in documentation discouraging direct DOM manipulation on the client-side based on component updates, and recommending secure practices for dynamic content handling.

- Preconditions:
    - The developer must implement custom Javascript code that directly manipulates the DOM in response to Django-unicorn component updates.
    - The component update must include HTML content that is considered safe by server-side sanitization but can be turned malicious through client-side manipulation.
    - The attacker needs to control part of the component data that influences the client-side DOM manipulation.

- Source Code Analysis:
    1. File: `django_unicorn/components/unicorn_template_response.py`
        - `UnicornTemplateResponse.render` method uses `UnicornTemplateResponse._desoupify(soup)` which calls `sanitize_html` server-side before sending the rendered HTML to the client.
    2. File: `django-unicorn/django_unicorn/utils.py`
        - `sanitize_html` function appears to be focused on sanitizing JSON data, not necessarily complex HTML structures after client-side manipulation.
    3. Client-side Javascript might be directly inserting HTML into the DOM without further sanitization, relying solely on server-side sanitization which might be insufficient if the client-side code re-interprets or manipulates the HTML.

- Security Test Case:
    1. Create a Django Unicorn component that updates a property with HTML content.
    2. Include this component in a Django template and add custom Javascript to manipulate the content when the component is updated using `unicorn:updated` event listener.
    3. In the Javascript event listener, manipulate the DOM by appending malicious HTML (e.g., `<img src=x onerror=alert("JS_XSS")>`) to the content area based on the component update event.
    4. Trigger a component update (e.g., by clicking a button that forces an update).
    5. Verify that the injected Javascript code via client-side DOM manipulation is executed, demonstrating the XSS vulnerability.
