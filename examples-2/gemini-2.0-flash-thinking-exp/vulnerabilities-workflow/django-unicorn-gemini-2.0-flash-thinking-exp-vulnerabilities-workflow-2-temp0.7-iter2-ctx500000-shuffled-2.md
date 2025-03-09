### Vulnerability List for django-unicorn project

* Vulnerability Name: Reflected Cross-Site Scripting (XSS) in Component Rendering

* Description:
    1. An attacker crafts a malicious URL containing XSS payload in the component arguments.
    2. The user clicks on the malicious URL or the URL is otherwise executed (e.g., embedded in a webpage).
    3. The Django application, using django-unicorn, renders a component, passing the malicious payload from the URL as component arguments.
    4. Django-unicorn insufficiently sanitizes the component arguments when rendering the HTML template.
    5. The malicious JavaScript payload is reflected in the rendered HTML output.
    6. The user's browser executes the malicious script, leading to XSS.

* Impact:
    - Account Takeover: Attackers can steal session cookies or other sensitive information, potentially leading to account takeover.
    - Data Theft: Sensitive data displayed on the page can be exfiltrated.
    - Website Defacement: The attacker can modify the content of the webpage seen by the user.
    - Redirection to Malicious Sites: Users can be redirected to attacker-controlled websites, potentially leading to further attacks like phishing or malware distribution.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The documentation mentions sanitization of initial JSON to prevent XSS in changelog of version 0.29.0 and security fix for CVE-2021-42053 in changelog of version 0.36.0, implying some efforts to address XSS.
    - HTML encoding of updated field values to prevent XSS attacks is mentioned in changelog of version 0.36.0.

* Missing Mitigations:
    - Input sanitization of component arguments passed via URL or other user-controlled sources is likely insufficient or missing, especially when rendering data within templates using `{{ }}` tags without explicit escaping.
    - Lack of context-aware output encoding in templates, specifically for django-unicorn components.

* Preconditions:
    - A django-unicorn component is rendered, and it accepts arguments that are reflected in the HTML output.
    - The application does not adequately sanitize user-provided input used as component arguments.
    - The attacker needs to deliver a crafted URL to a user or find a way to execute the malicious URL.

* Source Code Analysis:
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

* Security Test Case:
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
