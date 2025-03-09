### Vulnerability List

* Vulnerability Name: Cross-Site Scripting (XSS) Vulnerability through Unsafe HTML Rendering with `safe` Meta Option

* Description:
    1. A developer uses the `safe` Meta option within a Django Unicorn component to prevent Django's default HTML encoding for specific component properties. This is done by defining `Meta: safe = ("unsafe_content",)` in the component class.
    2. User-provided data, which is intended to be rendered in the component's template, is directly assigned to a property listed in the `safe` tuple without any sanitization or escaping. This user input can be provided through various means, such as form inputs bound with `unicorn:model`, URL parameters, or action arguments.
    3. In the component's template, the `safe` property is rendered using Django's template tags, such as `{{ unsafe_content }}`. Due to the `safe` meta option, Django will bypass HTML escaping for this property during template rendering.
    4. An attacker can inject malicious JavaScript code as user input. When the component re-renders (e.g., after a user interaction or component update), the injected JavaScript code is dynamically rendered into the HTML output without sanitization because the field is marked as `safe`.
    5. When a user views the page with the malicious component, the injected JavaScript code is executed in their browser, leading to Cross-Site Scripting.

* Impact:
    - Cross-Site Scripting (XSS). Successful exploitation of this vulnerability allows an attacker to execute arbitrary JavaScript code within the victim's browser in the context of the vulnerable web application. This can result in severe security consequences, including:
        - **Account Takeover (Session Hijacking):** An attacker can steal session cookies or other authentication credentials, potentially gaining full control of the user's account and performing actions on their behalf.
        - **Data Theft:** Sensitive information accessible to the user or displayed on the page can be stolen, including personal data, financial information, or confidential business data.
        - **Malware Distribution:** The attacker can redirect the user to malicious websites, trigger drive-by downloads of malware, or inject malicious content into the website to infect other users.
        - **Website Defacement:** The attacker can alter the visual appearance and content of the website, injecting misleading, offensive, or harmful information, damaging the website's reputation and user trust.
        - **Redirection to Malicious Sites:** Users can be silently redirected to attacker-controlled websites for phishing attacks or further exploitation.
        - **Performing Unauthorized Actions:** An attacker can perform actions on behalf of the user, such as making unauthorized purchases, changing account settings, or accessing restricted functionalities.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - **Default HTML Encoding:** Django Unicorn, by default, automatically HTML-encodes updated component property values before rendering them in templates. This default behavior serves as a primary mitigation against XSS vulnerabilities for most component properties. This is documented in `CHANGELOG.md` (v0.36.0) and `views.md`.
    - **Documentation Warning about `safe`:** The documentation in `views.md` explicitly warns developers about the security implications of using the `safe` Meta option. It clearly states that `safe` disables the default XSS prevention and requires developers to explicitly opt-in to bypass HTML encoding for specific fields.

* Missing Mitigations:
    - **Lack of Built-in Sanitization for `safe` Fields:** When the `safe` Meta option is used, there is no built-in mechanism within Django Unicorn to automatically sanitize or escape user inputs before rendering them in templates. The framework entirely relies on the developer to ensure the safety of content marked as `safe`.
    - **Insufficient Guidance and Best Practices for `safe` Usage:** While the documentation mentions the security risks of `safe`, it lacks comprehensive guidance and clear security best practices on how to use the `safe` Meta option securely. It should strongly discourage its use unless absolutely necessary and provide actionable steps and examples for sanitizing output when `safe` is unavoidable.
    - **No Context-Aware Output Encoding:**  Django Unicorn's mitigation primarily relies on default HTML encoding. However, context-aware output encoding, which adapts encoding based on the rendering context (e.g., HTML attributes, JavaScript code, CSS), is not explicitly implemented or enforced. This could lead to vulnerabilities in specific rendering scenarios where simple HTML encoding is insufficient.
    - **Missing Template Linting or Security Checks:** There are no template linting tools or built-in security checks to automatically detect potentially unsafe usage of the `safe` Meta option in conjunction with rendering user-controlled properties without explicit sanitization. Such checks could provide early warnings or errors during development to prevent vulnerabilities.

* Preconditions:
    1. **`safe` Meta Option Enabled:** A Django Unicorn component must explicitly define the `Meta: safe = ("field_name",)` option in its view class for a specific component property.
    2. **Unsafe Template Rendering:** The component's template must render the property marked as `safe` directly, typically using `{{ field_name }}`, without applying any additional HTML escaping template filters or sanitization measures within the template itself.
    3. **User Input Control:** An attacker must be able to control the value of the component property that is marked as `safe`. This is commonly achieved through user input fields bound to the property using `unicorn:model`, or by manipulating URL parameters, form data, or other means of influencing the component's state.

* Source Code Analysis:
    - **File:** `django_unicorn/views/__init__.py`
    - **Function:** `_process_component_request`
    - **Vulnerable Code Snippet:**
    ```python
        # Mark safe attributes as such before rendering
        for field_name in safe_fields:
            value = getattr(component, field_name)
            if isinstance(value, str):
                setattr(component, field_name, mark_safe(value))  # noqa: S308
    ```
    - **Analysis:**
        1. The `_process_component_request` function is the core handler for processing component requests in Django Unicorn.
        2. It identifies component attributes that are marked as 'safe' by checking for the `Meta.safe` tuple in the component's class definition.
        3. For each field name listed in `Meta.safe`, it retrieves the corresponding value from the component instance using `getattr(component, field_name)`.
        4. If the retrieved value is a string, it applies the `mark_safe(value)` function from `django.utils.safestring`. `mark_safe` tells Django's template engine that the string should be rendered as-is, without any HTML escaping.
        5. This effectively bypasses Django's default HTML encoding mechanism for the fields specified in `Meta.safe`. Consequently, if user-controlled data is assigned to these 'safe' fields and rendered in the component's template, it will be included in the HTML output without sanitization, potentially leading to XSS if the data contains malicious JavaScript.
    - **Visualization of Vulnerable Code Flow:**

    ```mermaid
    graph LR
        A[Incoming Request to _process_component_request] --> B{Check for Meta.safe};
        B -- Meta.safe exists --> C{Iterate through safe_fields};
        B -- Meta.safe does not exist --> D[Default HTML Encoding Applied];
        C --> E{Get field value};
        E --> F{Is value a string?};
        F -- Yes --> G[Apply mark_safe(value)];
        F -- No --> H[No action, default encoding applies if needed];
        G --> I[Template Rendering with 'safe' fields unescaped];
        D --> I;
        I --> J[HTML Response with potentially malicious script];
        J --> K[User's Browser executes script (XSS)];
    ```

* Security Test Case:
    1. **Setup:** Ensure you have a Django project with Django Unicorn installed and configured.
    2. **Create Component:** Create a new Django Unicorn component named `xss_test` in your Django app. Define a component view class `XssTestView` with a property `user_input` and enable the `safe` Meta option for it:
        ```python
        from django_unicorn.components import UnicornView

        class XssTestView(UnicornView):
            user_input = ""

            class Meta:
                safe = ("user_input",)
        ```
    3. **Create Component Template:** Create a template `xss-test.html` for the component and include an input field bound to `user_input` and render the `user_input` property within a `div`:
        ```html
        <div>
            <input type="text" unicorn:model="user_input">
            <div id="output">
                {{ user_input }}
            </div>
        </div>
        ```
    4. **Include Component in Django View and Template:** Create a Django view to render a template (e.g., `xss_test_page.html`) and include the `xss_test` component in this template using `{% unicorn 'xss-test' %}`. Ensure you load the `unicorn` template tags and include `{% unicorn_scripts %}` and `{% csrf_token %}` in your Django template.
        ```html
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            {% unicorn 'xss-test' %}
        </body>
        </html>
        ```
    5. **Configure URL:** Add a URL pattern in your `urls.py` to access the Django view rendering the `xss_test` component.
    6. **Access Vulnerable Page:** Run your Django development server and navigate to the URL you configured in step 5 in a web browser.
    7. **Inject XSS Payload:** In the input field of the `xss_test` component, enter the following JavaScript payload: `<script>alert("XSS Vulnerability - Unicorn Safe Meta")</script>`.
    8. **Trigger Component Update:** Interact with the component to trigger a re-render. This can be done by typing another character in the input field or clicking outside the input field to trigger a component update via AJAX.
    9. **Verify XSS:** Observe if an alert box with the message "XSS Vulnerability - Unicorn Safe Meta" is displayed in the browser window. If the alert box appears, it confirms the XSS vulnerability. Inspect the HTML source of the rendered component to verify that the `<script>` tag is rendered unescaped within the `<div id="output">` element.

This test case demonstrates that when the `safe` Meta option is used and user input is directly rendered without sanitization, it leads to a Cross-Site Scripting vulnerability in Django Unicorn.
