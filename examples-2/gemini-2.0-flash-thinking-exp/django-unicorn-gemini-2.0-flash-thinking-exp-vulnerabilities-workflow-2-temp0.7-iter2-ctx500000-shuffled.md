## Combined Vulnerability List

### Vulnerability Name: Improper use of `safe` Meta attribute leading to Cross-Site Scripting (XSS)

- **Description:**
    1. A developer uses Django Unicorn and wants to render user-provided content without HTML encoding within a Unicorn component.
    2. To achieve this, they incorrectly apply the `safe` Meta attribute to a component field, believing it will sanitize user input or indicate that the component handles sanitization.
    3. However, the `safe` Meta attribute in Django Unicorn only prevents *output* encoding of the field's value in the template. It does *not* sanitize user input, nor does it imply that the component handles sanitization.
    4. An attacker provides malicious JavaScript code as user input for this field.
    5. When the component re-renders (e.g., after a user interaction or poll update), the template renders the malicious JavaScript code directly into the HTML, bypassing browser-based XSS protection because Django Unicorn has marked the output as `safe`.
    6. The attacker's JavaScript code then executes in the victim's browser, leading to Cross-Site Scripting (XSS).

- **Impact:**
    - **High**
    - Cross-Site Scripting (XSS) allows an attacker to execute arbitrary JavaScript code in the victim's browser.
    - This can lead to session hijacking, cookie theft, redirection to malicious websites, defacement, or other malicious actions performed in the context of the user's session.
    - If an administrator account is compromised, it can lead to a full website takeover.

- **Vulnerability Rank:**
    - **High**

- **Currently Implemented Mitigations:**
    - By default, Django Unicorn HTML-encodes all output to prevent XSS, as introduced in version 0.36.0 (CVE-2021-42053). This is a global mitigation.
    - The documentation for `Meta.safe` ([views.md#safe](views.md#safe)) explains that this attribute *disables* HTML encoding for specific fields, explicitly warning about the security implications and requiring developers to handle sanitization themselves.

- **Missing Mitigations:**
    - No explicit code-level sanitization is automatically applied by Django Unicorn to user inputs before rendering, even when the `safe` Meta attribute is not used. Django Unicorn relies on Django's default template autoescaping and the developer's correct usage of `safe`.
    - There are no warnings or checks in the code to detect potentially unsafe usage of the `safe` Meta attribute, especially if developers misunderstand its purpose.

- **Preconditions:**
    1. A Django Unicorn component renders user-provided input from a field marked as `safe` in the component's Meta class.
    2. The developer incorrectly assumes that the `safe` Meta attribute sanitizes input or indicates that the component handles sanitization.
    3. The developer does not implement any other form of input sanitization for this field.
    4. An attacker can control the user-provided input for this specific field.

- **Source Code Analysis:**
    - **File:** `django_unicorn\views\unicorn_template_response.py`
    - **Function:** `UnicornTemplateResponse.render()`
    - **Code Snippet:**
      ```python
      # File: django_unicorn\django_unicorn\views\unicorn_template_response.py
      # ...
              # Mark safe attributes as such before rendering
              for field_name in safe_fields:
                  value = getattr(component, field_name)
                  if isinstance(value, str):
                      setattr(component, field_name, mark_safe(value))  # noqa: S308
      # ...
      response.content = rendered_template
      ```
    - **Analysis:**
        1. The code iterates through `safe_fields` defined in the component's `Meta` class.
        2. For each field name in `safe_fields`, it retrieves the corresponding value from the component.
        3. If the value is a string, it marks it as safe using `django.utils.safestring.mark_safe`.
        4. `mark_safe` tells Django templates *not* to escape this value during rendering.
        5. **Vulnerability:** If a developer adds a field to `Meta.safe` that contains unsanitized user input, this input will be rendered directly into the HTML without encoding, enabling XSS.
        6. **Visualization:**
           ```
           User Input --> Component Field (marked as safe) --> Template Rendering (no encoding) --> Browser (XSS)
           ```

- **Security Test Case:**
    1. Create a Django Unicorn component named `xss_safe_component` with a field `unsafe_content` and mark it as `safe` in the `Meta` class.
        ```python
        # components/xss_safe_component.py
        from django_unicorn.components import UnicornView

        class XssSafeComponentView(UnicornView):
            unsafe_content = ""

            class Meta:
                safe = ("unsafe_content",)
        ```
    2. Create a template `unicorn/xss_safe_component.html` that renders the `unsafe_content` field:
        ```html
        # templates/unicorn/xss_safe_component.html
        <div>
            <input type="text" unicorn:model="unsafe_content" />
            <div id="xss-test">{{ unsafe_content }}</div>
        </div>
        ```
    3. Create a Django view and template to include the `xss_safe_component`.
        ```python
        # views.py
        from django.shortcuts import render
        from django.views.generic import TemplateView

        class XSSView(TemplateView):
            template_name = 'xss_test.html'

        # urls.py
        from django.urls import path
        from .views import XSSView
        from unicorn.components.xss_safe_component import XssSafeComponentView

        urlpatterns = [
            path("xss-safe/", XSSView.as_view(), name="xss_safe"),
        ]
        ```
        ```html
        # templates/xss_test.html
        {% load unicorn %}
        <html>
        <head>
            {% unicorn_scripts %}
        </head>
        <body>
            {% csrf_token %}
            <h1>XSS Test</h1>
            {% unicorn 'xss-safe' %}
        </body>
        </html>
        ```
    4. Run the Django development server.
    5. Open the `xss-safe` view in a browser (e.g., `http://127.0.0.1:8000/xss-safe/`).
    6. In the input field, enter the following XSS payload: `<img src=x onerror=alert('XSS Vulnerability!')>`
    7. Click outside the input field to trigger a component update (or use `unicorn:model.lazy`).
    8. **Expected Result:** An alert box with "XSS Vulnerability!" should appear in the browser, demonstrating that the JavaScript code from the input was executed. This proves the XSS vulnerability due to the improper use of `safe` and lack of sanitization.

### Vulnerability Name: Reflected Cross-Site Scripting (XSS) in Component Rendering

- **Description:**
    1. An attacker crafts a malicious URL containing XSS payload in the component arguments.
    2. The user clicks on the malicious URL or the URL is otherwise executed (e.g., embedded in a webpage).
    3. The Django application, using django-unicorn, renders a component, passing the malicious payload from the URL as component arguments.
    4. Django-unicorn insufficiently sanitizes the component arguments when rendering the HTML template.
    5. The malicious JavaScript payload is reflected in the rendered HTML output.
    6. The user's browser executes the malicious script, leading to XSS.

- **Impact:**
    - Account Takeover: Attackers can steal session cookies or other sensitive information, potentially leading to account takeover.
    - Data Theft: Sensitive data displayed on the page can be exfiltrated.
    - Website Defacement: The attacker can modify the content of the webpage seen by the user.
    - Redirection to Malicious Sites: Users can be redirected to attacker-controlled websites, potentially leading to further attacks like phishing or malware distribution.

- **Vulnerability Rank:**
    - High

- **Currently Implemented Mitigations:**
    - The documentation mentions sanitization of initial JSON to prevent XSS in changelog of version 0.29.0 and security fix for CVE-2021-42053 in changelog of version 0.36.0, implying some efforts to address XSS.
    - HTML encoding of updated field values to prevent XSS attacks is mentioned in changelog of version 0.36.0.

- **Missing Mitigations:**
    - Input sanitization of component arguments passed via URL or other user-controlled sources is likely insufficient or missing, especially when rendering data within templates using `{{ }}` tags without explicit escaping.
    - Lack of context-aware output encoding in templates, specifically for django-unicorn components.

- **Preconditions:**
    - A django-unicorn component is rendered, and it accepts arguments that are reflected in the HTML output.
    - The application does not adequately sanitize user-provided input used as component arguments.
    - The attacker needs to deliver a crafted URL to a user or find a way to execute the malicious URL.

- **Source Code Analysis:**
    1. **File: ..\django-unicorn\docs\source\components.md**: This file describes how to pass data to components using the `unicorn` template tag: `{% unicorn 'hello-world' "Hello" name="World" %}`. It mentions that `args` and `kwargs` can be passed into the `unicorn` templatetag and are available in the component's `component_args` and `component_kwargs` instance methods. This is a potential entry point for user-controlled data.
    2. **File: ..\django-unicorn\docs\source\views.md**: This file details how views can access `component_args` and `component_kwargs`. It also mentions template rendering with context of public attributes.
    3. **File: ..\django-unicorn\docs\source\templates.md**:  This file explains that templates are normal Django HTML templates and any Django template functionality works. It highlights `unicorn:model` and accessing nested fields, but does not explicitly mention security considerations for user-provided data in component context.
    4. **File: ..\django-unicorn\docs\source\changelog.md**: Mentions security fix for CVE-2021-42053 in version 0.36.0 to prevent XSS attacks, implying prior vulnerability and ongoing concerns. It also mentions responses will be HTML encoded going forward.
    5. **File: ..\django-unicorn\django_unicorn\templatetags\unicorn.py**: The `unicorn` templatetag and `UnicornNode` class are responsible for rendering the component. The code shows that arguments and keyword arguments are resolved from the template context and passed to the component. There is no explicit sanitization of these arguments before rendering them in the component template.
    6. **File: ..\django-unicorn\django_unicorn\components\unicorn_template_response.py**: This file handles the rendering of the component and uses `BeautifulSoup` to manipulate the DOM. While it mentions `sanitize_html` in the context of initial data, it is not clear if it's consistently applied to all user-provided data rendered in templates, particularly component arguments.

    **Visualization:**

    ```
    [Attacker] --> Malicious URL (XSS payload in component args) --> [User Browser] --> [Django Application]
        [Django Application]
        1. Receives request with malicious URL.
        2. Parses component name and arguments from URL.
        3. Instantiates django-unicorn component.
        4. Passes URL arguments as component arguments.
        5. Renders component template with arguments (insufficient sanitization).
        6. Returns HTML with reflected XSS payload.
    [Django Application] --> HTML with XSS payload --> [User Browser]
        [User Browser]
        1. Receives HTML with XSS payload.
        2. Executes malicious JavaScript.
        [User Browser] --(XSS Impact)--> [Attacker]
    ```

- **Security Test Case:**
    1. Deploy a django-unicorn application with a component that renders component arguments in the template. For example, create a component `xss_test` with the following files:

    `# example/unicorn/components/xss_test.py`
    ```python
    from django_unicorn.components import UnicornView

    class XssTestView(UnicornView):
        message: str = ""

        def mount(self, message=""):
            self.message = message
    ```

    `# example/templates/unicorn/xss_test.html`
    ```html
    <div>
        {{ message }}
    </div>
    ```

    2. Include the component in a Django template, for example:

    `# example/templates/www/index.html`
    ```html
    {% load unicorn %}
    <html>
    <head>
        {% unicorn_scripts %}
    </head>
    <body>
        {% csrf_token %}
        {% unicorn 'xss_test' message=component_message %}
    </body>
    </html>
    ```

    3. Create a Django view to render the template and pass a variable `component_message` from URL parameters:

    `# example/www/views.py`
    ```python
    from django.shortcuts import render

    def index(request):
        component_message = request.GET.get('message', '')
        return render(request, 'www/index.html', {'component_message': component_message})
    ```

    4. Configure URL patterns in `urls.py`:

    ```python
    from django.urls import path, include
    from example.www import views

    urlpatterns = [
        path('', views.index, name='index'),
        path("unicorn/", include("django_unicorn.urls")),
    ]
    ```

    5. Access the application with a crafted URL containing a JavaScript XSS payload in the `message` parameter: `http://127.0.0.1:8000/?message=<script>alert("XSS")</script>`.
    6. Observe that an alert box with "XSS" is displayed in the browser, indicating successful XSS vulnerability.
    7. Inspect the page source and confirm that the `<script>alert("XSS")</script>` payload is directly embedded in the HTML within the component's `div`.
