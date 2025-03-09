### Vulnerability List:

- Vulnerability Name: Cross-Site Scripting (XSS) in Component Template Rendering

- Description:
    1. An attacker can inject malicious JavaScript code through user-controlled input fields within a Django Unicorn component.
    2. If a component renders user input without proper sanitization, the injected JavaScript code will be executed in the victim's browser when the component is rendered.
    3. This can occur when component attributes that are directly rendered in templates (e.g., using `{{ attribute }}`) are populated with unsanitized user input and the `safe` filter or `safe` Meta attribute is not used intentionally.
    4. Example scenario: A component displays a user-provided message. If the message is rendered directly without sanitization, an attacker can input a message containing `<script>alert("XSS")</script>`, which will execute JavaScript when the component is rendered in another user's browser.

- Impact:
    - Successful XSS attacks can lead to:
        - Account Takeover: Stealing user session cookies or credentials.
        - Data Theft: Accessing sensitive user data or application data.
        - Website Defacement: Modifying the content of the web page seen by users.
        - Redirection to Malicious Sites: Redirecting users to phishing or malware-distributing websites.
        - Execution of Arbitrary JavaScript: Performing actions on behalf of the user, like making unauthorized requests.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - HTML Encoding by Default: Django Unicorn responses are HTML encoded by default to prevent XSS attacks. This is implemented in the `UnicornTemplateResponse` class within the `render()` method in `components/unicorn_template_response.py`.  The template content is processed using BeautifulSoup, and then encoded during serialization via `UnicornTemplateResponse._desoupify(soup)` which utilizes `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")`. BeautifulSoup, by default, escapes HTML entities, providing automatic HTML encoding for rendered content.
    - `safe` Template Filter and `safe` Meta Attribute: Django Unicorn offers the `safe` template filter and `safe` Meta attribute (documented in `docs/source/views.md` and `docs/source/templates.md`). These mechanisms allow developers to explicitly designate specific component attributes as safe for HTML rendering. By using `safe`, developers intentionally bypass the default HTML encoding for designated attributes, taking on the responsibility of ensuring the rendered HTML is secure.

- Missing Mitigations:
    - Content Security Policy (CSP): While Django Unicorn provides HTML encoding by default, it does not automatically implement or enforce Content Security Policy (CSP). Implementing CSP headers would provide an additional layer of security to mitigate XSS vulnerabilities by allowing developers to control the resources the browser is permitted to load and restrict inline JavaScript execution.
    - Input Sanitization Guidance:  The documentation should strongly emphasize the necessity of sanitizing user inputs *before* they are assigned to component attributes. Even with default HTML encoding during output rendering, backend input sanitization is crucial. Developers should be guided to sanitize user inputs on the server-side to remove or escape potentially harmful code before it is incorporated into component attributes, thereby preventing malicious data from reaching the template rendering stage, especially when developers choose to use the `safe` filter or Meta attribute.

- Preconditions:
    1. A Django Unicorn component must render user-controlled data directly in its template, and a developer must intentionally bypass the default HTML encoding by using the `safe` filter or `safe` Meta attribute.
    2. An attacker needs to be able to inject malicious JavaScript code into a user-controlled input that is bound to a component attribute via `unicorn:model`.

- Source Code Analysis:
    - **Default HTML Encoding Implementation**: The `UnicornTemplateResponse.render()` method in `components/unicorn_template_response.py` is responsible for rendering the component template. This method uses BeautifulSoup to parse the HTML template and the `_desoupify` method to serialize the parsed HTML. Within `_desoupify`, `soup.encode(formatter=UnsortedAttributes()).decode("utf-8")` is used. BeautifulSoup, by default, encodes HTML entities, which effectively mitigates XSS in most cases where the `safe` mechanisms are not used.
    - **`safe` Filter and `safe` Meta Attribute Behavior**: While the code doesn't explicitly detail the implementation of the `safe` filter or `safe` Meta attribute in bypassing encoding within these files, the documentation confirms their purpose. The `templatetags/unicorn.py` file defines the `unicorn` template tag, the main entry point for component rendering. However, the HTML encoding and the bypassing of it via `safe` is handled in the `UnicornTemplateResponse` class.
    - **User Input Processing and Lack of Sanitization**: Examining `views/action_parsers/sync_input.py` and `views/action_parsers/utils.py`, specifically the `set_property_value` function, reveals the mechanism for handling user inputs. When a `syncInput` action occurs, `set_property_value` is invoked to update a component attribute with user-supplied input.  Type casting is performed based on type hints using logic in `views/utils.py` and `typer.py`. Crucially, **no explicit input sanitization is performed** within `set_property_value` or related input processing stages before setting the attribute value. The default HTML encoding is applied only during template rendering in `UnicornTemplateResponse`. This means that if a developer uses `safe`, or if attributes are rendered in JavaScript (e.g., via `unicorn.data.attribute`), the default HTML encoding is circumvented. If user input is not sanitized before being assigned to the component attribute in these scenarios, XSS vulnerabilities can be introduced.
    - **`test_set_property_from_data.py` Analysis**: Reviewing the tests in `tests/views/utils/test_set_property_from_data.py` further confirms the lack of input sanitization. These tests focus on verifying that data is correctly passed and assigned to component properties, covering various data types and scenarios including strings, integers, datetimes, lists, models, and querysets. The tests demonstrate how user-provided data, sent via `syncInput` actions and processed by `set_property_from_data`, is used to update component attributes.  The absence of any sanitization logic within these tests or the functions they exercise reinforces that user inputs are directly bound to component attributes without undergoing any security checks or sanitization at the input processing level. This makes it clear that the responsibility for sanitizing user inputs to prevent XSS falls entirely on the developer, especially when using the `safe` filter or Meta attribute.
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

- Security Test Case:
    1. Create a Django Unicorn component named `xss_test` and place it in `components/xss_test.py`:
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        user_input: str = ""
    ```
    2. Create a template for the component `unicorn/xss_test.html` inside your templates directory. This template will render the `user_input` attribute directly, without using any `safe` filter initially:
    ```html
    <div>
        <input type="text" unicorn:model="user_input">
        <div id="output">
            {{ user_input }}
        </div>
    </div>
    ```
    3. Include the `xss_test` component in a Django template, for example, create `www/xss_test_page.html`:
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
    4. Create a Django view in `www/views.py` to render the `xss_test_page.html` template:
    ```python
    from django.shortcuts import render

    def xss_test_view(request):
        return render(request, "www/xss_test_page.html")
    ```
    5. Configure URL patterns in `www/urls.py` to map `/xss-test/` to the `xss_test_view`:
    ```python
    from django.urls import path
    from . import views

    urlpatterns = [
        # ... other paths
        path('xss-test/', views.xss_test_view, name='xss_test_page'),
    ]
    ```
    6. Start the Django development server.
    7. As an attacker, open a web browser and navigate to `/xss-test/`.
    8. In the input field provided by the component, enter the following XSS payload: `<img src=x onerror=alert('XSS Vulnerability!')>`
    9. Click outside the input field or interact with the component to trigger the `unicorn:model` update, sending the input to the server.
    10. Observe the webpage for an alert box displaying "XSS Vulnerability!". If the alert appears, it confirms the XSS vulnerability. The JavaScript code from the input was executed because it was rendered without sufficient encoding.
    11. To test the mitigation and the impact of `safe`, modify the component template `unicorn/xss_test.html`. First, apply the `safe` filter: `{{ user_input|safe }}`. Alternatively, to use the `safe` Meta attribute, add `safe = ("user_input",)` inside the `Meta` class of `XssTestView` component and revert the template back to `{{ user_input }}`. Repeat steps 7-10 for both scenarios.
        - When testing without `safe` (default behavior - step 10), the alert should *not* appear, and the payload should be rendered as text, demonstrating the effectiveness of default HTML encoding as a mitigation.
        - When testing with `safe` (step 11), the alert *should* appear if input sanitization is not performed, and the payload should be rendered as an image tag if `safe` filter/Meta is used intentionally. This demonstrates that `safe` bypasses default encoding and makes the application vulnerable if inputs are not manually sanitized. This highlights the developer's responsibility to sanitize inputs when using `safe`.
