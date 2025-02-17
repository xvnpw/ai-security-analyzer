### Vulnerability List for django-unicorn

* Vulnerability Name: Potential XSS vulnerability due to misuse of `safe` rendering
* Description:
    Django-unicorn, by leveraging Django templates, inherently HTML-encodes data to prevent XSS by default. However, developers have the option to bypass this encoding for specific component fields or template variables using the `safe` meta option or the `|safe` template filter.  If user-controlled data is intentionally rendered as "safe" without proper sanitization, it creates a Cross-Site Scripting (XSS) vulnerability. This is not a vulnerability in django-unicorn itself, but rather a potential security issue arising from the misapplication of Django's `safe` functionality within a django-unicorn component.

    Step-by-step trigger:
    1. A developer creates a django-unicorn component and designates a field to render user-provided content.
    2. To bypass default HTML encoding, the developer uses the `safe` option in the component's `Meta` class or the `|safe` filter in the template for this specific field.
    3. An attacker crafts malicious JavaScript code and injects it as user input targeting the field marked as `safe`.
    4. When the component is rendered (initially or upon updates), the injected malicious JavaScript is included directly into the HTML output without encoding.
    5. When a victim's browser processes the page, the malicious JavaScript executes, resulting in XSS.
* Impact:
    Cross-site scripting (XSS). Successful exploitation allows an attacker to execute arbitrary JavaScript code within a victim's browser session in the context of the vulnerable web application. This can have severe consequences, including:
    - Account takeover: Stealing session cookies or login credentials to gain unauthorized access to user accounts.
    - Data theft: Accessing and exfiltrating sensitive information displayed on the page, potentially including personal or financial data.
    - Defacement: Altering the visual content of the web page to mislead users or damage the website's reputation.
    - Redirection to malicious sites: Redirecting users to external websites hosting phishing attacks or malware.
    - Performing actions on behalf of the user: Making unauthorized requests to the server, potentially leading to privilege escalation or data manipulation.
* Vulnerability rank: High
* Currently implemented mitigations:
    - Default HTML encoding: Django templates, and by extension django-unicorn, automatically HTML-encode variables by default, providing a fundamental layer of XSS protection. This is a strong default behavior inherited from Django.
    - Explicit opt-in for disabling HTML encoding: Developers must consciously and explicitly use `safe` to disable HTML encoding. This design makes accidental disabling less likely and highlights the need for careful consideration when using `safe`. This is part of Django's intended template behavior, which django-unicorn respects.
* Missing mitigations:
    - Static analysis or linting: Lack of automated checks to identify potential insecure uses of `safe`. A dedicated linter rule could warn developers when `safe` is applied to fields that are likely to contain user-supplied data, prompting a review of sanitization practices.
    - Documentation enhancement: While the documentation mentions the `safe` option, it could be improved by adding a prominent security warning that explicitly details the risks of using `safe` with user-controlled data. It should strongly recommend and illustrate proper sanitization techniques for scenarios where `safe` is genuinely necessary.
    - Runtime warnings (development mode): Django-unicorn could potentially include a development-mode warning that triggers if a field marked as `safe` is updated with data originating from request parameters (indicating potential user input) without explicit sanitization steps being evident in the component's code.
* Preconditions:
    - The developer must intentionally use the `safe` meta option or the `|safe` template filter to disable Django's default HTML encoding for a specific component field or template variable.
    - The field or variable marked as `safe` must be intended to render data that originates from user input, external APIs, or any source that could be manipulated by an attacker.
    - The user input or external data rendered as safe is not subjected to any form of sanitization or validation to remove or escape potentially harmful JavaScript code before being displayed.
* Source code analysis:
    The `django-unicorn/components/unicorn_template_response.py` file handles component rendering. `UnicornTemplateResponse.render()` uses `BeautifulSoup` for HTML manipulation. Django-unicorn relies on Django's inherent template escaping as the primary XSS mitigation and delegates the responsibility of sanitization to developers when they choose to use the `safe` option.

    1. Default Data Encoding: Django templates, and thus django-unicorn templates, perform HTML encoding by default for variable output.
    2. `safe` Option Handling: The `safe` option is a standard Django template feature, directly honored by django-unicorn. It allows developers to explicitly bypass HTML encoding. Django-unicorn's code does not alter or intercept the functionality of `safe`; it behaves exactly as defined by Django templates.
    3. Sanitization Absence: While `django_unicorn/utils.py` includes `sanitize_html`, its purpose is specifically for escaping HTML within JSON data for `<script type="application/json">` tags, not for general template rendering of component data. Django-unicorn does not provide built-in sanitization for component data rendered in templates beyond Django's default escaping, and explicitly not when `safe` is used. The onus of sanitizing data when employing `safe` entirely falls on the developer.

    ```python
    # Example demonstrating 'safe' bypassing encoding (conceptual - not actual unicorn code, but illustrates Django template behavior)
    from django.template import Template, Context
    from django.utils.html import escape

    user_input = '<img src=x onerror=alert("XSS")>'

    # Default encoding
    template_default = Template('<div>{{ user_input }}</div>')
    context_default = Context({'user_input': user_input})
    rendered_default = template_default.render(context_default)
    print("Default encoding:", rendered_default)
    # Output: <div>&lt;img src=x onerror=alert(&quot;XSS&quot;)&gt;</div>

    # Using |safe filter
    template_safe_filter = Template('<div>{{ user_input|safe }}</div>')
    context_safe_filter = Context({'user_input': user_input})
    rendered_safe_filter = template_safe_filter.render(context_safe_filter)
    print("|safe filter:", rendered_safe_filter)
    # Output: <div><img src=x onerror=alert("XSS")></div>
    ```

    Source code analysis confirms that django-unicorn does not add sanitization beyond Django's default escaping and explicitly defers to Django's `safe` behavior. The potential vulnerability is a consequence of developer's insecure usage of the `safe` feature.

* Security test case:
    1. Set up a Django project with django-unicorn installed and configured.
    2. Create a new django-unicorn component named `unsafe_render`.
    3. Define a component view `UnsafeRenderView` with a field `user_input` initialized as an empty string.
    4. In the `UnsafeRenderView`'s `Meta` class, set `safe = ("user_input",)` to disable HTML encoding for the `user_input` field.
    5. In the component's template `unsafe_render.html`, render the `user_input` field: `<div>{{ user_input }}</div>`.
    6. Create a Django view that renders the `unsafe_render` component within a template.
    7. Access this Django view in a web browser.
    8. Open the browser's developer console and use JavaScript to modify the component's `user_input` field via `Unicorn.component('unsafe_render').set('user_input', '<img src=x onerror=alert(\'XSS\')>')`.
    9. Trigger a component update by invoking an action (e.g., add a button with `<button unicorn:click="$refresh">Refresh</button>` to the component).
    10. Observe if an alert box displaying 'XSS' appears in the browser. The appearance of the alert confirms successful execution of injected JavaScript, demonstrating an XSS vulnerability resulting from the misuse of `safe` rendering.
