- Vulnerability Name: Cross-Site Scripting (XSS) vulnerability due to misuse of `safe` Meta option

- Description:
    1. A developer uses `Meta: safe = ("field_name",)` in a Django-unicorn component to prevent HTML encoding for a specific field.
    2. The component template renders this `field_name` directly without any additional sanitization or escaping, for example using `{{ field_name }}`.
    3. An attacker injects malicious JavaScript code as user input for this `field_name` through UI or API.
    4. When the component re-renders (e.g., after a user interaction or data update), the injected malicious JavaScript code is included in the HTML response without encoding because of `Meta: safe`.
    5. The victim's browser executes the malicious JavaScript code when rendering the component, leading to XSS.

- Impact:
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code in the victim's browser in the context of the application. This can lead to:
    - Account takeover: Attacker can steal session cookies or other authentication tokens.
    - Data theft: Attacker can access sensitive data visible to the user.
    - Defacement: Attacker can modify the content of the web page seen by the user.
    - Redirection to malicious sites: Attacker can redirect the user to phishing or malware websites.
    - Execution of arbitrary actions: Attacker can perform actions on behalf of the user, such as making unauthorized transactions or changes.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - By default, Django-unicorn HTML encodes all updated field values to prevent XSS attacks. This is mentioned in `docs\source\views.md` under "Meta" section, describing `safe` option: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks."
    - The documentation in `docs\source\views.md` also mentions that to prevent XSS when needing to render HTML, the Django's `|safe` template filter should be used: "A context variable can also be marked as `safe` in the template with the normal Django template filter."
    - The changelog in `docs\source\changelog.md` for version 0.36.0 highlights a "Security fix: for CVE-2021-42053 to prevent XSS attacks" by enabling default HTML encoding, further emphasizing the framework's awareness of XSS risks and the intended mitigation strategy.

- Missing Mitigations:
    - No warnings or security checks are in place to alert developers when they are using `Meta: safe` which disables the default XSS protection.
    - The documentation warns about using `safe`, but it could be more prominent and include explicit security warnings and best practices for handling user-provided HTML.
    - No built-in sanitization or escaping mechanisms are automatically applied when `Meta: safe` is used; the responsibility is entirely on the developer to implement proper sanitization.
    - The test suite (`tests` directory) lacks specific security test cases that explicitly target XSS vulnerabilities related to the `safe` Meta option. While functional tests like those in `tests\views\message\test_sync_input.py` exist, they do not focus on security aspects or demonstrate exploitation scenarios.

- Preconditions:
    - The developer must explicitly set `Meta: safe = ("field_name",)` in the component's Python code.
    - The component template must render the `field_name` directly without using Django's `|safe` filter or any other sanitization mechanism.
    - An attacker must be able to influence the value of `field_name`, typically through user input either via UI form fields or API calls.

- Source Code Analysis:
    1. File: `docs\source\views.md`
    2. Section: "Meta" -> "safe"
    3. Description: This section explains the `safe` Meta option: "By default, `unicorn` HTML encodes updated field values to prevent XSS attacks. You need to explicitly opt-in to allow a field to be returned without being encoded by adding it to the `Meta` class's `safe` tuple." and provides example.
    4. Analysis: The documentation clearly states the security implications of using `safe`, indicating that developers need to be cautious when disabling default HTML encoding. However, it relies on developer awareness and doesn't enforce secure practices.
    5. File: `docs\source\changelog.md`
    6. Version: 0.36.0
    7. Description: "Security fix: for CVE-2021-42053 to prevent XSS attacks (reported by [Jeffallan](https://github.com/Jeffallan)). Breaking changes - responses will be HTML encoded going forward (to explicitly opt-in to previous behavior use [safe](views.md#safe))"
    8. Analysis: This changelog entry confirms the security motivation behind the default HTML encoding and explicitly links `safe` to opting out of this protection, reinforcing the vulnerability if misused.
    9. File: `django_unicorn\views\__init__.py`
    10. Function: `_process_component_request`
    11. Line:  The code iterates through `safe_fields` and marks the corresponding component attributes as safe using `mark_safe(value)`.
    12. Analysis: This part of the code confirms that when a field is listed in `Meta.safe`, Django's `mark_safe` is applied, which bypasses HTML encoding. This is the intended behavior, but it places the burden of ensuring the content is actually safe (i.e., properly sanitized) on the developer. There's no built-in sanitization within Django-unicorn itself when `safe` is used.

- Security Test Case:
    1. Create a new Django app (e.g., `xss_test`) and add it to `INSTALLED_APPS`.
    2. Create a Django-unicorn component named `XssSafeComponent` in `xss_test/components/xss_safe.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssSafeView(UnicornView):
        dangerous_input = ""

        class Meta:
            safe = ("dangerous_input",)
    ```
    3. Create a template for the component at `xss_test/templates/unicorn/xss-safe.html`:
    ```html
    <div>
        <input type="text" unicorn:model="dangerous_input" id="xss_input">
        <div id="output">
            {{ dangerous_input }}
        </div>
    </div>
    ```
    4. Create a Django view in `xss_test/views.py` to render a page with the component:
    ```python
    from django.shortcuts import render
    from xss_test.components.xss_safe import XssSafeView

    def xss_test_view(request):
        return render(request, 'xss_test/xss_page.html', {'component_name': 'xss-safe'})
    ```
    5. Create a template for the page at `xss_test/templates/xss_test/xss_page.html`:
    ```html
    {% load unicorn %}
    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test</title>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn component_name %}
    </body>
    </html>
    ```
    6. Add a URL pattern in `xss_test/urls.py` and include it in project's `urls.py` to access `xss_test_view`.
    7. Run the Django development server.
    8. Open the page in a browser (e.g., `http://127.0.0.1:8000/xss_page/`).
    9. In the input field with `id="xss_input"`, enter the following payload: `<img src=x onerror=alert('XSS')>`
    10. Click outside the input field to trigger `unicorn:model` update (or use `lazy` modifier and blur).
    11. Observe if an alert box with 'XSS' appears in the browser. If the alert box appears, the XSS vulnerability is confirmed because the injected JavaScript code was executed.
    12. Examine the HTML source of the page. You should see the injected `<img>` tag rendered directly within the `div` with `id="output"` without HTML encoding, confirming that `Meta: safe` bypassed the default XSS protection.
