### Vulnerabilities List:

#### Vulnerability Name: Cross-Site Scripting (XSS) in Component Template Rendering

#### Description:
1. An attacker can inject malicious JavaScript code through user-controlled input fields within a Django Unicorn component.
2. If a component renders user input directly in Django templates, without proper HTML escaping or sanitization, the injected JavaScript code will be executed in the victim's browser when the component is rendered or updated.
3. This vulnerability occurs when component attributes, bound to user inputs via `unicorn:model`, are directly rendered in templates (e.g., using `{{ attribute }}`) without applying Django's HTML escaping filters or context-aware sanitization, and when developers intentionally bypass default HTML encoding by using the `safe` filter or `safe` Meta attribute.
4. Example scenario: A component displays a user-provided message. If the message is rendered directly without sanitization and `safe` is used, or default encoding is bypassed intentionally, an attacker can input a message containing `<script>alert("XSS")</script>`, which will execute JavaScript when the component is rendered in another user's browser.

#### Impact:
- Successful XSS attacks can lead to:
    - **Account Takeover:** Stealing user session cookies or credentials, potentially granting the attacker unauthorized access to user accounts.
    - **Data Theft:** Accessing sensitive user data or application data, compromising confidential information.
    - **Website Defacement:** Modifying the content of the web page seen by users, damaging the application's reputation and user trust.
    - **Redirection to Malicious Sites:** Redirecting users to phishing or malware-distributing websites, increasing the risk of further security breaches.
    - **Execution of Arbitrary JavaScript:** Performing actions on behalf of the user, like making unauthorized requests, or any other malicious activity limited only by the attacker's creativity within the browser environment.

#### Vulnerability Rank: High

#### Currently Implemented Mitigations:
- **HTML Encoding by Default:** Django Unicorn leverages Django's template engine auto-escaping, which is active by default. This system attempts to automatically escape HTML content during template rendering, providing a baseline level of defense against XSS attacks when developers use standard template constructs. Django Unicorn responses are HTML encoded by default to prevent XSS attacks. This is implemented in the `UnicornTemplateResponse` class within the `render()` method in `components/unicorn_template_response.py`. The template content is processed using BeautifulSoup, and then encoded during serialization via `UnicornTemplateResponse._desoupify(soup)` which utilizes `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`. BeautifulSoup, by default, escapes HTML entities, providing automatic HTML encoding for rendered content.
- **`safe` Template Filter and `safe` Meta Attribute:** Django Unicorn offers the `safe` template filter and `safe` Meta attribute (documented in `docs/source/views.md` and `docs/source/templates.md`). These mechanisms allow developers to explicitly designate specific component attributes as safe for HTML rendering. By using `safe`, developers intentionally bypass the default HTML encoding for designated attributes, taking on the responsibility of ensuring the rendered HTML is secure. Misusing `safe` with unsanitized user inputs can directly lead to XSS vulnerabilities.

#### Missing Mitigations:
- **Content Security Policy (CSP):** While Django Unicorn provides HTML encoding by default, it does not automatically implement or enforce Content Security Policy (CSP). Implementing CSP headers would provide an additional layer of security to mitigate XSS vulnerabilities by allowing developers to control the resources the browser is permitted to load and restrict inline JavaScript execution.
- **Context-aware output encoding:** The library lacks built-in, context-aware sanitization functions specifically designed for user inputs before rendering them in templates. This type of sanitization is crucial as it adapts escaping strategies based on the context of where the data is being inserted in the HTML (e.g., HTML tags, attributes, JavaScript contexts).
- **Input Sanitization Guidance & Developer Documentation:** The documentation should strongly emphasize the necessity of sanitizing user inputs *before* they are assigned to component attributes. Even with default HTML encoding during output rendering, backend input sanitization is crucial, especially when developers choose to use the `safe` filter or Meta attribute. There is a lack of explicit documentation and best practice guidelines for developers on how to securely handle user inputs and prevent XSS vulnerabilities when building Django Unicorn components. This should include clear instructions and examples on how to use Django's template escaping filters correctly, how to use `safe` meta attribute securely and avoid common pitfalls.
- **Security focused template linting/checks:** No automated security checks or template linters are provided to help developers identify potential XSS vulnerabilities during development. Such tools could automatically flag unsafe template patterns, encouraging developers to adopt secure coding practices.

#### Preconditions:
1. A Django Unicorn component must render user-controlled data directly in its template, and a developer must intentionally bypass the default HTML encoding by using the `safe` filter or `safe` Meta attribute, or forget to use proper escaping in template without using `safe`.
2. An attacker needs to be able to inject malicious JavaScript code into a user-controlled input that is bound to a component attribute via `unicorn:model`.

#### Source Code Analysis:
- **Default HTML Encoding Implementation**: The `UnicornTemplateResponse.render()` method in `components/unicorn_template_response.py` is responsible for rendering the component template. This method uses BeautifulSoup to parse the HTML template and the `_desoupify` method to serialize the parsed HTML. Within `_desoupify`, `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")` is used. BeautifulSoup, by default, encodes HTML entities, which effectively mitigates XSS in most cases where the `safe` mechanisms are not used.
- **`safe` Filter and `safe` Meta Attribute Behavior**: While the code doesn't explicitly detail the implementation of the `safe` filter or `safe` Meta attribute in bypassing encoding within these files, the documentation confirms their purpose. The `templatetags/unicorn.py` file defines the `unicorn` template tag, the main entry point for component rendering. However, the HTML encoding and the bypassing of it via `safe` is handled in the `UnicornTemplateResponse` class. Analysis of `django_unicorn\tests\views\test_process_component_request.py` shows that there is a `safe` Meta attribute which can be set for component properties. When a property is listed in `safe` attribute, the HTML auto-escaping is disabled for that property in templates. This feature is intended for trusted HTML content, but if a developer uses it with user-provided data without sanitization, it will create a direct XSS vulnerability.
- **User Input Processing and Lack of Sanitization**: Examining `views/action_parsers/sync_input.py` and `views/action_parsers/utils.py`, specifically the `set_property_value` function, reveals the mechanism for handling user inputs. When a `syncInput` action occurs, `set_property_value` is invoked to update a component attribute with user-supplied input. Type casting is performed based on type hints using logic in `views/utils.py` and `typer.py`. Crucially, **no explicit input sanitization is performed** within `set_property_value` or related input processing stages before setting the attribute value. The default HTML encoding is applied only during template rendering in `UnicornTemplateResponse`. This means that if a developer uses `safe`, or if attributes are rendered in JavaScript (e.g., via `unicorn.data.attribute`), the default HTML encoding is circumvented. If user input is not sanitized before being assigned to the component attribute in these scenarios, XSS vulnerabilities can be introduced. Review of `django_unicorn\tests\views\utils\test_set_property_from_data.py` confirms that tests for `set_property_from_data` function cover various data types and model interactions, but there are no tests that check for HTML sanitization or escaping of user-provided data. This absence of sanitization within `set_property_from_data` means that if user-provided data contains malicious HTML or JavaScript, it will be directly set as a component property without sanitization.
- **Template tags and component rendering logic** in `django_unicorn\templatetags\unicorn.py` and `django_unicorn\components\unicorn_template_response.py` do not include any explicit HTML sanitization steps for the component's main HTML output. The focus is on DOM manipulation, attribute setting, and lifecycle management, assuming that template rendering and Django's default auto-escaping will handle XSS prevention.
- **`django_unicorn\pyproject.toml` Review:** Review of `django_unicorn\pyproject.toml` shows that while `ruff` linter is configured, its ruleset is focused on general Python code quality and style. There are no specific security-focused rules enabled or custom rules configured that would target XSS prevention in Django templates or user input sanitization. This indicates a lack of automated security checks specifically for XSS vulnerabilities in the project's development workflow.

- **Code Snippet Visualization (Conceptual Rendering Process):**

    **Scenario 1: Default Rendering (HTML Encoding Active)**
    ```
    [User Input (Malicious Script)] --> unicorn:model Binding -->
    Component Attribute (Unsanitized) --> Template Rendering ({ attribute }) -->
    UnicornTemplateResponse.render() --> BeautifulSoup Processing (Default HTML Encoding) -->
    HTML Output (XSS Mitigated) --> Browser
    ```

    **Scenario 2: Rendering with `safe` Filter or `safe` Meta (HTML Encoding Bypass)**
    ```
    [User Input (Malicious Script)] --> unicorn:model Binding -->
    Component Attribute (Unsanitized) --> Template Rendering ({ attribute|safe } or safe Meta) -->
    UnicornTemplateResponse.render() --> BeautifulSoup Processing (NO HTML Encoding for 'safe' attributes) -->
    HTML Output (Potentially Vulnerable to XSS if input is not sanitized) --> Browser
    ```

    ```mermaid
    graph LR
        A[User Input] --> B(HTTP Request to /message/);
        B --> C{django_unicorn.views.message};
        C --> D{ComponentRequest Parsing};
        D --> E{_process_component_request};
        E --> F{set_property_from_data};
        F --> G{Property Update (No Sanitization)};
        G --> H{Template Rendering (Django Auto-escape)};
        H --> I{UnicornTemplateResponse.render};
        I --> J{Response with Rendered HTML};
        J --> K[Browser];
        K -- Renders HTML & Executes JS --> L{Potential XSS};
        style G fill:#f9f,stroke:#333,stroke-width:2px
        style L fill:#f9f,stroke:#333,stroke-width:2px
    ```

#### Security Test Case:
1. **Component Creation:** Create a Django Unicorn component named `xss_test` and place it in `components/xss_test.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        user_input: str = ""
    ```
2. **Template Creation:** Create a template for the component `unicorn/xss_test.html` inside your templates directory. This template will render the `user_input` attribute directly, without using any `safe` filter initially:
    ```html
    <div>
        <input type="text" unicorn:model="user_input">
        <div id="output">
            {{ user_input }}
        </div>
    </div>
    ```
3. **Page Template Creation:** Include the `xss_test` component in a Django template, for example, create `www/xss_test_page.html`:
    ```html
    {% load unicorn %}

    <!DOCTYPE html>
    <html>
    <head>
        <title>XSS Test Page</title>
        {% unicorn_scripts %}
    </head>
    <body>
        <h1>XSS Test</h1>
        {% component name="xss_test" %}
    </body>
    </html>
    ```
4. **View Creation:** Create a Django view in `www/views.py` to render the `xss_test_page.html` template:
    ```python
    from django.shortcuts import render

    def xss_test_view(request):
        return render(request, "www/xss_test_page.html")
    ```
5. **URL Configuration:** Configure URL patterns in `www/urls.py` to map `/xss-test/` to the `xss_test_view`:
    ```python
    from django.urls import path
    from . import views

    urlpatterns = [
        # ... other paths
        path('xss-test/', views.xss_test_view, name='xss_test_page'),
    ]
    ```
6. **Start Server:** Start the Django development server.
7. **Access Test Page:** As an attacker, open a web browser and navigate to `/xss-test/`.
8. **Inject XSS Payload:** In the input field provided by the component, enter the following XSS payload: `<img src=x onerror=alert('XSS Vulnerability!')>`
9. **Trigger Update:** Click outside the input field or interact with the component to trigger the `unicorn:model` update, sending the input to the server.
10. **Observe for Alert:** Observe the webpage for an alert box displaying "XSS Vulnerability!". If the alert appears when testing with `safe` filter/Meta attribute, it confirms the XSS vulnerability when default encoding is bypassed and input is not sanitized. If alert does not appear when testing without `safe`, it demonstrates the effectiveness of default HTML encoding as a mitigation.
11. **Test with `safe`:** Modify the component template `unicorn/xss_test.html`. First, apply the `safe` filter: `{{ user_input|safe }}`. Alternatively, to use the `safe` Meta attribute, add `safe = ("user_input",)` inside the `Meta` class of `XssTestView` component and revert the template back to `{{ user_input }}`. Repeat steps 7-10 for both scenarios to verify the bypass of default encoding when `safe` is used and the resulting vulnerability if inputs are not sanitized.
